using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using Httpgrl.Core.Hosting;
using Httpgrl.Core.Pipeline;

namespace Httpgrl.Core.Http;

/// <summary>Drives one client connection: optional TLS handshake, then a keep-alive request loop.</summary>
internal sealed class Http1Session
{
    private const int DrainLimit = 64 << 10;
    private const int LingerMs = 2000;
    private const int MaxHeaders = 100;

    private readonly Connection _conn;
    private readonly ListenBinding _binding;
    private readonly HttpRuntime _rt;
    private readonly ConnectionManager _mgr;
    private readonly VirtualHosts _hosts;
    private Stream _transport = Stream.Null;

    public Http1Session(Connection conn, ListenBinding binding, HttpRuntime rt, ConnectionManager mgr)
    {
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
                var ssl = new SslStream(transport, leaveInnerStreamOpen: false);
                await ssl.AuthenticateAsServerAsync(SelectTls, this, CancellationToken.None).ConfigureAwait(false);
                info.SetTls(TlsHost(ssl.TargetHostName), ssl.SslProtocol.ToString());
                transport = ssl;
            }
            _transport = transport;

            ctx = new HttpContextImpl(_rt, _conn, info, input) { Transport = transport };
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
                ctx.SelectLocation(ctx.ServerRt.Root, null);
                ctx.BodyReader.Reset(transport, reject == 0 ? req.ContentLengthValue : -1, reject == 0 && req.ChunkedValue);
                if (req.ExpectContinue) ctx.BodyReader.SendContinue = SendContinueAsync;

                bool wantsKeepAlive = req.VersionValue == HttpVersion.Http11 ? !req.ConnClose : req.ConnKeepAlive && !req.ConnClose;
                ctx.SetKeepAlive(reject == 0 && wantsKeepAlive && info.Requests < core0.KeepaliveRequestsMax && !_mgr.Stopping);
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

                if (!reusable || keepaliveMs <= 0)
                {
                    if (!ctx.Upgraded && clean) await LingeringCloseAsync(transport, input).ConfigureAwait(false);
                    return;
                }
                first = false;
            }
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
            ctx?.Resp.ReturnBuffer();
            input.Dispose();
            _mgr.Release(_conn);
            try { await _transport.DisposeAsync().ConfigureAwait(false); } catch (Exception) { /* already torn down */ }
            _conn.Dispose();
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
        var opts = srv.Tls ?? self._hosts.Default.Tls ?? self._hosts.Servers.Find(s => s.Tls is not null)?.Tls
            ?? throw new AuthenticationException("no certificate");
        return ValueTask.FromResult(opts);
    }

    private static string? TlsHost(string? sni) => string.IsNullOrEmpty(sni) ? null : RequestParser.NormalizeHost(sni);
}
