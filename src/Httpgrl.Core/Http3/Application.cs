using System.Net;
using Httpgrl.Core.Hosting;
using Httpgrl.Core.Modules;
using Httpgrl.Core.Pipeline;
using Httpgrl.Core.Quic;

namespace Httpgrl.Core.Http3;

/// <summary>
/// HTTP/3 on one <c>listen ... quic</c> socket. It follows reloads: a new connection starts under the configuration
/// current at that moment (its servers' TLS contexts and limits) and keeps it for life; after a reload, older
/// connections get GOAWAY and are closed by reload_drain_timeout. Runs on the endpoint's thread.
/// </summary>
internal sealed class Http3Application(ConnectionManager mgr) : IQuicApplication
{
    private volatile State _current = null!;
    private QuicEndpoint _ep = null!;
    private readonly Dictionary<QuicConnection, Http3Connection> _conns = new(ReferenceEqualityComparer.Instance);
    private State? _accepting;
    private static long _ids = 1L << 40; // connection IDs for the log, apart from TCP's

    private sealed record State(ListenBinding Binding, HttpRuntime Rt, QuicAccept? Accept, HttpCoreConf Core);

    public void Attach(QuicEndpoint ep) => _ep = ep;

    /// <summary>The configuration new connections get (at start, and on every reload).</summary>
    public void Update(ListenBinding binding, HttpRuntime rt)
    {
        var def = binding.Hosts.Default;
        var core = def.Root.Core;
        // OpenSSL needs a context to start a handshake with: the default server's, or (when it has none, e.g. with
        // ssl_reject_handshake) any HTTP/3 server's. SNI then picks the server that answers; a name (or no name)
        // leading to a server without a context refuses the handshake, so a scan by IP learns no names.
        var tls = def.Scope.Get<SslConf>().QuicTls ?? binding.Hosts.Servers.Select(x => x.Scope.Get<SslConf>().QuicTls).FirstOrDefault(c => c is not null);
        QuicAccept? accept = null;
        if (tls is not null)
        {
            var o = new QuicOptions
            {
                MaxIdleTimeoutMs = (int)Math.Clamp(core.KeepaliveTimeoutMs, 1000, 600_000),
                HandshakeTimeoutMs = (int)Math.Clamp(core.ClientHeaderTimeoutMs, 1000, 60_000),
                MaxStreamsBidi = core.Http3MaxStreams,
                MaxStreamsUni = 3,
            };
            // SNI picks the server whose certificate is presented. Servers that require client certificates have no
            // QUIC context (not over HTTP/3 yet), so their names refuse the handshake.
            accept = new QuicAccept(tls, sni =>
            {
                var s = sni is null ? def : binding.Hosts.Resolve(sni);
                return s.Scope.Get<SslConf>().QuicTls;
            }, o);
        }
        _current = new State(binding, rt, accept, core);
    }

    public QuicAccept? Accept(EndPoint remote)
    {
        var st = _current;
        if (st.Accept is null || !st.Rt.TryAcquire()) return null;
        _accepting = st;
        return st.Accept;
    }

    public void Started(QuicConnection c)
    {
        var st = _accepting!;
        _accepting = null;
        _conns[c] = new Http3Connection(c, _ep, st.Rt, st.Binding.Hosts, mgr, st.Core, Interlocked.Increment(ref _ids));
        _rts[c] = st.Rt;
    }

    private readonly Dictionary<QuicConnection, HttpRuntime> _rts = new(ReferenceEqualityComparer.Instance);

    public void OnEvent(QuicConnection c, in QuicEvent e, long now)
    {
        if (_conns.TryGetValue(c, out var h)) h.OnEvent(e, now);
    }

    public void Closed(QuicConnection c)
    {
        if (_conns.Remove(c, out var h)) h.Closed();
        if (_rts.Remove(c, out var rt)) rt.Release();
    }

    public void Tick(long now)
    {
        foreach (var h in _conns.Values) h.Tick(now);
    }

    /// <summary>Shutdown: every connection gets GOAWAY (its requests finish; the server's shutdown timeout bounds them).</summary>
    public void GoAwayAll()
    {
        foreach (var h in _conns.Values) h.GoAway();
    }

    public int Connections => _conns.Count;
}
