using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using Httpgrl.Core.Http;
using Httpgrl.Core.Modules;
using Httpgrl.Core.Pipeline;

namespace Httpgrl.Core.Hosting;

/// <summary>
/// Keeps a <c>listen tunnel:NAME</c> supplied with connections: dials the remote (mTLS), sends the Upgrade handshake,
/// and hands each connection to an ordinary <see cref="Http1Session"/>, as if it had been accepted. It aims for
/// <see cref="TunnelSpec.Pool"/> idle connections (each parked at the remote, waiting for a request), dials a
/// replacement as soon as one starts serving, and backs off exponentially while the remote is unreachable or refuses.
/// Like a listener, its binding and configuration are swapped on reload when the tunnel's identity is unchanged.
/// </summary>
internal sealed class TunnelDialer
{
    private const int MaxBackoffMs = 30_000;

    private readonly ConnectionManager _mgr;
    private readonly CancellationTokenSource _stop = new();
    private readonly SemaphoreSlim _wake = new(0);
    private readonly object _lock = new();
    private readonly HashSet<TunnelLink> _links = new();
    private int _idle, _dialing, _failures;
    private long _nextAttempt;

    public volatile State Current;
    /// <summary>Set when a reload drops this tunnel (or changes its identity): its connections can't migrate.</summary>
    public volatile bool Closed;
    public sealed record State(ListenBinding Binding, HttpRuntime Rt);
    public (ListenBinding, HttpRuntime)? Now() => Closed ? null : (Current.Binding, Current.Rt);

    public TunnelDialer(ListenBinding binding, HttpRuntime rt, ConnectionManager mgr)
    {
        Current = new State(binding, rt);
        _mgr = mgr;
    }

    public TunnelSpec Spec => Current.Binding.Tunnel!;

    public void Start() => _ = Task.Run(LoopAsync);

    /// <summary>A reload kept this tunnel: new connections use the new configuration (existing ones migrate per request).</summary>
    public void Update(ListenBinding binding, HttpRuntime rt)
    {
        Current = new State(binding, rt);
        Wake();
    }

    /// <summary>Stop dialing and close idle connections; busy ones finish their request.</summary>
    public void Close()
    {
        Closed = true;
        try { _stop.Cancel(); } catch (ObjectDisposedException) { }
        List<TunnelLink> idle;
        lock (_lock) idle = _links.Where(l => l.Idle).ToList();
        foreach (var l in idle) l.Conn.Abort("tunnel removed", graceful: true);
    }

    private void Wake()
    {
        if (_wake.CurrentCount == 0) _wake.Release();
    }

    private async Task LoopAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            var st = Current;
            var spec = st.Binding.Tunnel!;
            int start = 0, waitMs = Timeout.Infinite;
            long now = Environment.TickCount64;
            lock (_lock)
            {
                int deficit = Math.Min(spec.Pool - _idle - _dialing, spec.Max - _links.Count - _dialing);
                if (deficit > 0)
                {
                    if (now >= _nextAttempt) { start = _failures > 0 ? 1 : deficit; _dialing += start; } // one probe at a time while failing
                    else waitMs = (int)Math.Min(_nextAttempt - now, int.MaxValue);
                }
            }
            for (int k = 0; k < start; k++) _ = DialAsync(st);
            try { await _wake.WaitAsync(waitMs, _stop.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
        }
    }

    private async Task DialAsync(State st)
    {
        var spec = st.Binding.Tunnel!;
        var log = st.Rt.Log;
        Connection? conn = null;
        SslStream? ssl = null;
        bool pinned = false, admitted = false;
        string? failure = null;
        try
        {
            var socket = await ConnectAsync(spec).ConfigureAwait(false);
            conn = new Connection(_mgr.NextId(), socket, IpKey.From(socket.RemoteEndPoint));
            // Pin a generation, as the accept loop does; a reload between reading and pinning just means we read again.
            while (!(pinned = (st = Current).Rt.TryAcquire()) && !Closed) { }
            if (!pinned) throw new OperationCanceledException("tunnel removed");
            conn.Generation = st.Rt;
            if (!_mgr.TryAdmit(conn, out var why)) throw new IOException("not admitted: " + why);
            admitted = true;

            // Handshake under the sweeper: TLS plus the Upgrade exchange must finish within connect_timeout.
            conn.Phase = "tunnel handshake";
            conn.ReadOpTimeout = conn.WriteOpTimeout = spec.ConnectTimeoutMs;
            conn.BaseDeadline = Environment.TickCount64 + spec.ConnectTimeoutMs;
            ssl = new SslStream(new TransportStream(conn), leaveInnerStreamOpen: false);
            await ssl.AuthenticateAsClientAsync(spec.Ssl, conn.AbortToken).ConfigureAwait(false);
            await ssl.WriteAsync(TunnelHandshake.Request(spec), conn.AbortToken).ConfigureAwait(false);
            var (head, status, rest) = await ReadHandshakeAsync(ssl, conn.AbortToken).ConfigureAwait(false);
            if (head < 0) throw new TunnelRefusedException(status == 101 ? "remote switched to another protocol" : status > 0 ? $"remote answered {status}" : "malformed handshake response");
            conn.BaseDeadline = 0;
            conn.ReadOpTimeout = conn.WriteOpTimeout = 0;

            var link = new TunnelLink(this, conn);
            lock (_lock)
            {
                if (Closed) throw new OperationCanceledException("tunnel removed");
                _dialing--;
                _links.Add(link);
                _idle++;
                if (_failures > 0) log.Info("tunnel connected", new("tunnel", spec.Name), new("remote", spec.Host + ":" + spec.Port));
                _failures = 0;
                _nextAttempt = 0;
            }
            var session = new Http1Session(conn, st.Binding, st.Rt, _mgr, Now, ssl, rest, link);
            conn = null; // the session owns it now (it releases the generation and the slot)
            ThreadPool.UnsafeQueueUserWorkItem(static s => _ = s.RunAsync(), session, preferLocal: false);
        }
        catch (Exception e) when (e is SocketException or IOException or AuthenticationException or OperationCanceledException
                                      or TunnelRefusedException or ObjectDisposedException or InvalidOperationException)
        {
            failure = conn?.AbortReason ?? e.Message;
        }
        finally
        {
            if (conn is not null)
            {
                if (ssl is not null) try { ssl.Dispose(); } catch (Exception) { /* torn down */ }
                if (admitted) _mgr.Release(conn);
                if (pinned) st.Rt.Release();
                conn.Dispose();
            }
        }
        if (failure is not null)
        {
            int failures;
            lock (_lock)
            {
                _dialing--;
                failures = ++_failures;
                int backoff = Math.Min(MaxBackoffMs, 1000 << Math.Min(failures - 1, 5));
                _nextAttempt = Environment.TickCount64 + backoff / 2 + Random.Shared.Next(backoff / 2 + 1);
            }
            // The first failure, then each doubling: a remote that's down for an hour doesn't flood the log.
            if (!_stop.IsCancellationRequested && (failures & (failures - 1)) == 0)
                log.Warn("tunnel connect failed", new("tunnel", spec.Name), new("remote", spec.Host + ":" + spec.Port),
                    new("error", failure), new("failures", (long)failures));
        }
        Wake();
    }

    private static async Task<Socket> ConnectAsync(TunnelSpec spec)
    {
        IPAddress[] addrs;
        if (IPAddress.TryParse(spec.Host, out var ip)) addrs = [ip];
        else if (IsLocalhost(spec.Host)) addrs = [IPAddress.Loopback, IPAddress.IPv6Loopback];
        else
        {
            using var dns = new CancellationTokenSource(spec.ConnectTimeoutMs);
            addrs = await Dns.GetHostAddressesAsync(spec.Host, dns.Token).ConfigureAwait(false);
            if (addrs.Length == 0) throw new IOException($"host not found: {spec.Host}");
        }
        Exception? last = null;
        foreach (var a in addrs)
        {
            var s = new Socket(a.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            using var cts = new CancellationTokenSource(spec.ConnectTimeoutMs);
            try
            {
                await s.ConnectAsync(new IPEndPoint(a, spec.Port), cts.Token).ConfigureAwait(false);
                KeepAlive(s);
                return s;
            }
            catch (Exception e) when (e is SocketException or OperationCanceledException)
            {
                s.Dispose();
                last = e is OperationCanceledException ? new IOException($"connect to {a} timed out") : e;
            }
        }
        throw last ?? new IOException("no address");
    }

    /// <summary>
    /// An idle tunnel connection carries nothing for minutes: TCP keep-alives notice a remote (or a NAT on the way)
    /// that silently went away, so a dead connection doesn't count toward the pool.
    /// </summary>
    private static void KeepAlive(Socket s)
    {
        try
        {
            s.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            s.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 30);
            s.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 10);
            s.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 3);
        }
        catch (SocketException) { /* best effort; the remote's idle timeout still recycles connections */ }
    }

    /// <summary>RFC 6761 6.3: "localhost" is loopback and isn't looked up (the resolver may add the host's own addresses).</summary>
    private static bool IsLocalhost(string host)
    {
        var h = host.AsSpan().TrimEnd('.');
        return h.Equals("localhost", StringComparison.OrdinalIgnoreCase) || h.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The remote's answer to the Upgrade: the head length (-1 if refused or malformed), its status code (0 if no
    /// status line was read), and whatever followed the head (the remote may send the first request right behind it).
    /// </summary>
    private static async Task<(int Head, int Status, ReadOnlyMemory<byte> Tail)> ReadHandshakeAsync(Stream s, CancellationToken ct)
    {
        var buf = new byte[TunnelHandshake.MaxHead];
        int have = 0;
        while (true)
        {
            int r = TunnelHandshake.Parse(buf.AsSpan(0, have), out int status);
            if (r != 0) return (r, status, r > 0 ? buf.AsMemory(r, have - r) : default);
            int n = await s.ReadAsync(buf.AsMemory(have), ct).ConfigureAwait(false);
            if (n == 0) throw new IOException(have == 0 ? "remote closed the connection during the handshake" : "remote closed the connection mid-handshake");
            have += n;
        }
    }

    // ---- called by sessions (any thread) ----

    internal void OnIdle(TunnelLink l)
    {
        lock (_lock) { if (l.Idle || !_links.Contains(l)) return; l.Idle = true; _idle++; }
    }

    internal void OnActive(TunnelLink l)
    {
        lock (_lock) { if (!l.Idle) return; l.Idle = false; _idle--; }
        Wake(); // this one is serving now: park a replacement at the remote
    }

    internal void OnClosed(TunnelLink l)
    {
        lock (_lock)
        {
            if (!_links.Remove(l)) return;
            if (l.Idle) { l.Idle = false; _idle--; }
        }
        Wake();
    }

    /// <summary>For tests and status: idle and total live connections.</summary>
    internal (int Idle, int Total) Counts()
    {
        lock (_lock) return (_idle, _links.Count);
    }
}

/// <summary>One dialed connection, as its dialer sees it. Idle at birth: it's parked at the remote straight away.</summary>
internal sealed class TunnelLink(TunnelDialer dialer, Connection conn)
{
    public readonly TunnelDialer Dialer = dialer;
    public readonly Connection Conn = conn;
    public bool Idle = true; // guarded by the dialer's lock
    public int IdleTimeoutMs => Dialer.Spec.IdleTimeoutMs;
}

internal sealed class TunnelRefusedException(string message) : Exception(message);
