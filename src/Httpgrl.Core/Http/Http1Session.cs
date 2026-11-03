using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Httpgrl.Core.Hosting;
using Httpgrl.Core.Modules;
using Httpgrl.Core.Pipeline;

namespace Httpgrl.Core.Http;

/// <summary>Drives one client connection: optional TLS handshake, then a keep-alive request loop.</summary>
internal sealed class Http1Session
{
    private const int DrainLimit = 64 << 10;
    private const int LingerMs = 2000;
    private const int MaxHeaders = 100;

    private readonly Connection _conn;
    private ListenBinding _binding;
    private HttpRuntime _rt;
    private readonly ConnectionManager _mgr;
    private VirtualHosts _hosts;
    /// <summary>This listener's current binding and configuration, or null once it's no longer configured.</summary>
    private readonly Func<(ListenBinding Binding, HttpRuntime Rt)?> _current;
    private Stream _transport = Stream.Null;
    /// <summary>The server whose TLS settings the handshake used (chosen by SNI).</summary>
    private ServerRt? _tlsServer;

    public Http1Session(Connection conn, ListenBinding binding, HttpRuntime rt, ConnectionManager mgr, Func<(ListenBinding, HttpRuntime)?> current)
    {
        _current = current;
        _conn = conn;
        _binding = binding;
        _rt = rt;
        _mgr = mgr;
        _hosts = binding.For(conn.Socket.LocalEndPoint);
    }

    public async Task RunAsync()
    {
        var info = new ConnectionInfo(_conn.Id, _conn.Socket.RemoteEndPoint, _conn.Socket.LocalEndPoint, _binding.Ssl);
        var core0 = _hosts.Default.Root.Core; // pre-Host limits come from the default server, as in nginx
        var input = new InputBuffer(4096);
        HttpContextImpl? ctx = null;
        try
        {
            Stream transport = new TransportStream(_conn);
            if (_binding.Ssl)
            {
                _conn.Phase = "tls handshake";
                _conn.BaseDeadline = Environment.TickCount64 + core0.SslHandshakeTimeoutMs;
                var ssl = new ClientAuthSslStream(transport);
                _transport = transport = ssl;
                await ssl.AuthenticateAsServerAsync(SelectTls, this, CancellationToken.None).ConfigureAwait(false);
                X509Certificate2? clientCert = null;
                string? verdict = null;
                if (_tlsServer!.ClientAuth is { } auth)
                {
                    clientCert = ssl.RemoteCertificate as X509Certificate2;
                    verdict = ssl.Verdict;
                    if (verdict is null)
                    {
                        // The callback didn't run (e.g. a resumed session): verify here, under the same policy.
                        (verdict, bool accept) = auth.Evaluate(clientCert);
                        if (!accept)
                        {
                            _rt.Log.Info("client certificate rejected", new("conn", _conn.Id), new("remote", info.RemoteAddress), new("reason", verdict));
                            return;
                        }
                    }
                }
                info.SetTls(TlsHost(ssl.TargetHostName), ssl.SslProtocol.ToString(), clientCert, verdict);
            }
            _transport = transport;

            ctx = new HttpContextImpl(_rt, _conn, info, input) { Transport = transport, Mgr = _mgr };
            var lim = new HeadLimits(core0.HeaderLineMax, core0.HeaderTotalMax, MaxHeaders);
            int keepaliveMs = core0.KeepaliveTimeoutMs;
            bool first = true;

            while (true)
            {
                // ---- wait for the start of the next request ----
                _conn.ReadOpTimeout = 0;
                if (input.Count == 0)
                {
                    if (first)
                    {
                        _conn.Phase = "request header";
                        _conn.BaseDeadline = Environment.TickCount64 + core0.ClientHeaderTimeoutMs;
                    }
                    else _conn.SetIdle(keepaliveMs);
                    int n = await input.FillAsync(transport, lim.TotalMax).ConfigureAwait(false);
                    if (n <= 0) return;
                    _conn.SetActive();
                }
                // A plaintext connection between requests carries no state from its configuration: after a reload it
                // continues under the new one instead of being closed (closing idle keep-alives races clients that
                // just sent a request, and they can't safely retry a POST). TLS connections were closed at reload:
                // their handshake belongs to the old certificates and client-certificate policy.
                if (_rt.Retired)
                {
                    if (_binding.Ssl || !Migrate()) return;
                    core0 = _hosts.Default.Root.Core;
                    lim = new HeadLimits(core0.HeaderLineMax, core0.HeaderTotalMax, MaxHeaders);
                    ctx = new HttpContextImpl(_rt, _conn, info, input) { Transport = transport, Mgr = _mgr };
                }
                if (!first)
                {
                    // The whole head must arrive within client_header_timeout of its first byte; trickling doesn't extend it.
                    _conn.Phase = "request header";
                    _conn.BaseDeadline = Environment.TickCount64 + core0.ClientHeaderTimeoutMs;
                }

                // RFC 9112 2.2: ignore at least one empty line before the request-line.
                for (int k = 0; k < 2 && input.Count >= 2 && input.Buf[input.Start] == '\r' && input.Buf[input.Start + 1] == '\n'; k++) input.Consume(2);

                // ---- read the head ----
                int headLen;
                int reject = 0;
                while ((headLen = RequestParser.FindHeadEnd(input)) < 0)
                {
                    reject = RequestParser.CheckIncomplete(input.Data, lim);
                    if (reject != 0) break;
                    int n = await input.FillAsync(transport, lim.TotalMax).ConfigureAwait(false);
                    if (n == 0) return;
                    if (n < 0) { reject = 431; break; }
                }
                _conn.BaseDeadline = 0;
                ctx.BeginRequest();
                info.CountRequest();
                var req = ctx.Req;
                if (reject == 0)
                {
                    reject = RequestParser.Parse(input.Data[..headLen], req, lim);
                    input.Consume(headLen);
                }

                ctx.ServerRt = reject == 0 ? _hosts.Resolve(req.HostValue) : _hosts.Default;
                // A client may complete the handshake for one name (SNI) and then ask for another (Host). Never let that
                // carry it past a client-certificate policy it wasn't checked against (cf. nginx's 421).
                if (reject == 0 && _tlsServer is not null && !ReferenceEquals(ctx.ServerRt.ClientAuth, _tlsServer.ClientAuth))
                    reject = 421;
                ctx.SelectLocation(ctx.ServerRt.Root, null);
                ctx.BodyReader.Reset(transport, reject == 0 ? req.ContentLengthValue : -1, reject == 0 && req.ChunkedValue);
                if (req.ExpectContinue) ctx.BodyReader.SendContinue = SendContinueAsync;

                bool wantsKeepAlive = req.VersionValue == HttpVersion.Http11 ? !req.ConnClose : req.ConnKeepAlive && !req.ConnClose;
                ctx.SetKeepAlive(reject == 0 && wantsKeepAlive && info.Requests < core0.KeepaliveRequestsMax && !_mgr.Stopping && !(_rt.Retired && _binding.Ssl));
                _conn.Phase = "processing";

                if (reject != 0) await RequestPipeline.RejectAsync(ctx, reject).ConfigureAwait(false);
                else await _rt.Pipeline.RunAsync(ctx).ConfigureAwait(false);

                // Dropped (444): nothing was written and nothing will be; fall through to close without lingering.
                bool clean = !ctx.Broken && !ctx.Dropped && await ctx.Resp.CompleteAsync().ConfigureAwait(false);
                ctx.Resp.ReturnBuffer();
                bool reusable = clean && ctx.KeepAlive && !ctx.Upgraded;
                if (reusable && !ctx.BodyReader.IsComplete)
                {
                    // A client still waiting for "100 Continue" never sent the body; we can't tell where the next request starts.
                    reusable = !(req.ExpectContinue && !ctx.BodyReader.Started) && await ctx.BodyReader.DrainAsync(DrainLimit).ConfigureAwait(false);
                }
                keepaliveMs = ctx.Loc.Core.KeepaliveTimeoutMs;

                await _rt.Pipeline.RunLogAsync(ctx).ConfigureAwait(false);
                ctx.EndRequest();
                _mgr.CountResponse(ctx.Resp.Status);

                if (!reusable || keepaliveMs <= 0 || (_rt.Retired && _binding.Ssl))
                {
                    if (!ctx.Upgraded && clean) await LingeringCloseAsync(transport, input).ConfigureAwait(false);
                    return;
                }
                first = false;
            }
        }
        catch (AuthenticationException e) when (_transport is ClientAuthSslStream { Verdict: { } v } && v != "SUCCESS")
        {
            _rt.Log.Info("client certificate rejected", new("conn", _conn.Id), new("remote", info.RemoteAddress), new("reason", v), new("detail", e.Message));
        }
        catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException or AuthenticationException or OperationCanceledException || (e is InvalidOperationException && _conn.IsAborted))
        {
            _rt.Log.Debug("connection closed", new("conn", _conn.Id), new("reason", _conn.AbortReason ?? e.Message));
        }
        catch (Exception e)
        {
            _rt.Log.Error("connection failed", new("conn", _conn.Id), new("error", e.GetType().Name), new("detail", e.Message), new("stack", e.StackTrace));
        }
        finally
        {
            ctx?.EndRequest(); // a request cut short still releases what it reserved
            ctx?.Resp.ReturnBuffer();
            input.Dispose();
            _mgr.Release(_conn);
            _rt.Release();
            try { await _transport.DisposeAsync().ConfigureAwait(false); } catch (Exception) { /* already torn down */ }
            _conn.Dispose();
        }
    }

    /// <summary>Move this connection to its listener's current configuration. False if the listener is gone.</summary>
    private bool Migrate()
    {
        while (true)
        {
            if (_current() is not { } st) return false;
            if (!st.Rt.TryAcquire()) continue; // retired again meanwhile: read the newest
            var old = _rt;
            _rt = st.Rt;
            _binding = st.Binding;
            _hosts = st.Binding.For(_conn.Socket.LocalEndPoint);
            _conn.Generation = st.Rt;
            old.Release();
            return true;
        }
    }

    private static readonly byte[] Continue100 = "HTTP/1.1 100 Continue\r\n\r\n"u8.ToArray();

    private ValueTask SendContinueAsync() => _transport.WriteAsync(Continue100);

    /// <summary>
    /// Half-close and discard what the client is still sending, so our response isn't destroyed by an RST
    /// triggered by unread data (cf. nginx lingering_close). Bounded in time and bytes.
    /// </summary>
    private async ValueTask LingeringCloseAsync(Stream transport, InputBuffer input)
    {
        _conn.Phase = "lingering close";
        _conn.BaseDeadline = Environment.TickCount64 + LingerMs;
        try
        {
            if (transport is SslStream ssl) await ssl.ShutdownAsync().ConfigureAwait(false);
            _conn.Socket.Shutdown(SocketShutdown.Send);
            input.Consume(input.Count);
            long seen = 0;
            while (seen < DrainLimit)
            {
                int n = await _conn.Socket.ReceiveAsync(input.Buf.AsMemory(), SocketFlags.None).ConfigureAwait(false);
                if (n <= 0) break;
                seen += n;
            }
        }
        catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException or InvalidOperationException) { }
    }

    private static ValueTask<SslServerAuthenticationOptions> SelectTls(SslStream stream, SslClientHelloInfo hello, object? state, CancellationToken ct)
    {
        var self = (Http1Session)state!;
        var srv = self._hosts.Resolve(TlsHost(hello.ServerName));
        if (srv.Tls is null) srv = self._hosts.Default.Tls is not null ? self._hosts.Default : self._hosts.Servers.Find(s => s.Tls is not null)
            ?? throw new AuthenticationException("no certificate");
        self._tlsServer = srv;
        return ValueTask.FromResult(srv.Tls!);
    }

    private static string? TlsHost(string? sni) => string.IsNullOrEmpty(sni) ? null : RequestParser.NormalizeHost(sni);
}
