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

    /// <summary>Tunnel connections: the dialer's TLS stream (already handshaken) and its bookkeeping. Null when accepted.</summary>
    private readonly Stream? _established;
    private readonly ReadOnlyMemory<byte> _preread;
    private readonly TunnelLink? _link;

    public Http1Session(Connection conn, ListenBinding binding, HttpRuntime rt, ConnectionManager mgr, Func<(ListenBinding, HttpRuntime)?> current,
        Stream? established = null, ReadOnlyMemory<byte> preread = default, TunnelLink? link = null)
    {
        _established = established;
        _preread = preread;
        _link = link;
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
        var input = new InputBuffer(Math.Max(4096, _preread.Length));
        HttpContextImpl? ctx = null;
        try
        {
            Stream transport = _established ?? new TransportStream(_conn);
            _transport = transport;
            if (!_preread.IsEmpty)
            {
                // The remote sent its first request right behind the 101: it's the start of our input.
                _preread.Span.CopyTo(input.Buf);
                input.End = _preread.Length;
            }
            if (_binding.ProxyProtocol)
            {
                _conn.Phase = "proxy protocol";
                _conn.BaseDeadline = Environment.TickCount64 + core0.SslHandshakeTimeoutMs;
                var (rest, hdr) = await ReadProxyHeaderAsync(transport).ConfigureAwait(false);
                if (rest is null)
                {
                    _rt.Log.Info("invalid or missing PROXY protocol header; closing", new("conn", _conn.Id), new("remote", info.RemoteAddress));
                    return;
                }
                info.SetProxy(hdr.Source, hdr.Destination);
                if (rest.Value.Length > 0) transport = new PrefixedStream(rest.Value, transport);
                _transport = transport;
            }
            if (_binding.Ssl)
            {
                _conn.Phase = "tls handshake";
                _conn.BaseDeadline = Environment.TickCount64 + core0.SslHandshakeTimeoutMs;
                var ssl = new ClientAuthSslStream(transport);
                _transport = transport = ssl;
                await ssl.AuthenticateAsServerAsync(SelectTls, this, CancellationToken.None).ConfigureAwait(false);
                // Fail closed: the suite list is set on .NET's cached OpenSSL context (OpenSslContextAccess). Should the
                // runtime ever rebuild that context without it, a suite outside the list is caught here, not served.
                if (_tlsServer!.AllowedSuites is { } allowed && !allowed.Contains(ssl.NegotiatedCipherSuite))
                {
                    _rt.Log.Warn("negotiated a cipher suite outside ssl_ciphers; closing", new("conn", _conn.Id),
                        new("suite", ssl.NegotiatedCipherSuite.ToString()), new("remote", info.RemoteAddress));
                    return;
                }
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

            ctx = NewContext(info, input, transport);
            var lim = new HeadLimits(core0.HeaderLineMax, core0.HeaderTotalMax, MaxHeaders, core0.UnderscoresInHeaders == true);
            int keepaliveMs = core0.KeepaliveTimeoutMs;
            bool first = true;

            while (true)
            {
                // ---- wait for the start of the next request ----
                _conn.ReadOpTimeout = 0;
                if (input.Count == 0)
                {
                    if (_link is not null)
                    {
                        // Parked at the remote, which closes idle tunnel connections itself; ours is only a backstop.
                        _conn.SetIdle(_link.IdleTimeoutMs);
                        _link.Dialer.OnIdle(_link);
                    }
                    else if (first)
                    {
                        _conn.Phase = "request header";
                        _conn.BaseDeadline = Environment.TickCount64 + core0.ClientHeaderTimeoutMs;
                    }
                    else _conn.SetIdle(keepaliveMs);
                    int n = await input.FillAsync(transport, lim.TotalMax).ConfigureAwait(false);
                    if (n <= 0) return;
                    _conn.SetActive();
                }
                if (_link is not null) _link.Dialer.OnActive(_link);
                // A plaintext connection between requests carries no state from its configuration: after a reload it
                // continues under the new one instead of being closed (closing idle keep-alives races clients that
                // just sent a request, and they can't safely retry a POST). TLS connections were closed at reload:
                // their handshake belongs to the old certificates and client-certificate policy.
                if (_rt.Retired)
                {
                    if (_binding.Ssl || !Migrate()) return;
                    core0 = _hosts.Default.Root.Core;
                    lim = new HeadLimits(core0.HeaderLineMax, core0.HeaderTotalMax, MaxHeaders, core0.UnderscoresInHeaders == true);
                    ctx = NewContext(info, input, transport);
                }
                if (!first || _link is not null)
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

                reject = RequestLifecycle.Route(ctx, _hosts, _tlsServer, reject);
                _body!.Reset(transport, reject == 0 ? req.ContentLengthValue : -1, reject == 0 && req.ChunkedValue);
                if (req.ExpectContinue) ctx.BodyReader.SendContinue = SendContinueAsync;

                bool wantsKeepAlive = req.VersionValue == HttpVersion.Http11 ? !req.ConnClose : req.ConnKeepAlive && !req.ConnClose;
                ctx.SetKeepAlive(reject == 0 && wantsKeepAlive && info.Requests < core0.KeepaliveRequestsMax && !_mgr.Stopping && !(_rt.Retired && _binding.Ssl));
                _conn.Phase = "processing";

                // Not clean (broken, or dropped with 444): fall through to close without lingering.
                bool clean = await RequestLifecycle.RunAsync(ctx, reject).ConfigureAwait(false);
                bool reusable = clean && ctx.KeepAlive && !ctx.Upgraded;
                if (reusable && !ctx.BodyReader.IsComplete)
                {
                    // A client still waiting for "100 Continue" never sent the body; we can't tell where the next request starts.
                    reusable = !(req.ExpectContinue && !ctx.BodyReader.Started) && await ctx.BodyReader.DrainAsync(DrainLimit).ConfigureAwait(false);
                }
                keepaliveMs = ctx.Loc.Core.KeepaliveTimeoutMs;

                await RequestLifecycle.FinishAsync(ctx, _mgr).ConfigureAwait(false);

                // A tunnel connection stays open between requests whatever keepalive_timeout says: the remote decides when
                // it's done with it (closing it from here races a request the remote may be sending).
                if (!reusable || (keepaliveMs <= 0 && _link is null) || (_rt.Retired && _binding.Ssl))
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
            if (_link is not null) _link.Dialer.OnClosed(_link);
            _mgr.Release(_conn);
            _rt.Release();
            try { await _transport.DisposeAsync().ConfigureAwait(false); } catch (Exception) { /* already torn down */ }
            _conn.Dispose();
        }
    }

    private BodyStream? _body;

    /// <summary>The exchange for this connection's requests: the connection's timing, HTTP/1.1 body and wire, raw upgrades.</summary>
    private HttpContextImpl NewContext(ConnectionInfo info, InputBuffer input, Stream transport)
    {
        _body = new BodyStream(_conn, input);
        return new HttpContextImpl(_rt, info, _conn, _body, new Http1ResponseWire(transport))
        {
            Upgrader = () => new UpgradedStream(input, transport),
            Mgr = _mgr,
        };
    }

    /// <summary>
    /// Read the mandatory PROXY header (deadline enforced by the sweeper). Returns what followed it in the same reads
    /// (the start of the TLS handshake or HTTP request), or null if there's no valid header.
    /// </summary>
    private static async ValueTask<(ReadOnlyMemory<byte>? Tail, ProxyHeader Header)> ReadProxyHeaderAsync(Stream s)
    {
        var buf = new byte[ProxyProtocol.V2Max];
        int have = 0;
        while (true)
        {
            int r = ProxyProtocol.TryParse(buf.AsSpan(0, have), out var hdr);
            if (r < 0) return (null, default);
            if (r > 0) return (buf.AsMemory(r, have - r), hdr);
            if (have == buf.Length) return (null, default);
            int n = await s.ReadAsync(buf.AsMemory(have)).ConfigureAwait(false);
            if (n <= 0) return (null, default);
            have += n;
        }
    }

    /// <summary>Move this connection to its listener's current configuration. False if the listener is gone.</summary>
    private bool Migrate()
    {
        while (true)
        {
            if (_current() is not { } st) return false;
            // The address now speaks something else (plaintext -> TLS, PROXY protocol on or off): what this connection
            // was accepted as no longer applies. Continuing would run the new TLS/mTLS policy without a handshake.
            if (st.Binding.Ssl != _binding.Ssl || st.Binding.ProxyProtocol != _binding.ProxyProtocol) return false;
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
            if (transport is SslStream ssl) await ssl.ShutdownAsync().ConfigureAwait(false); // TLS servers and dialed tunnels alike
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
        // ssl_reject_handshake: SNI (or its absence) routes to a server that presents nothing. Refuse before any
        // certificate is sent, so a scan of the IP learns no names (no fallback to another server's certificate).
        if (srv.RejectHandshake) throw new AuthenticationException("handshake rejected (ssl_reject_handshake)");
        if (srv.Tls is null) srv = self._hosts.Default.Tls is not null ? self._hosts.Default : self._hosts.Servers.Find(s => s.Tls is not null)
            ?? throw new AuthenticationException("no certificate");
        self._tlsServer = srv;
        srv.Stapler?.OnHandshake();
        return ValueTask.FromResult(srv.Tls!);
    }

    private static string? TlsHost(string? sni) => string.IsNullOrEmpty(sni) ? null : RequestParser.NormalizeHost(sni);
}
