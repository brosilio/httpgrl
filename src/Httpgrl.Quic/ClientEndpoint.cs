using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Httpgrl.Quic;

/// <summary>
/// A client's UDP socket: one socket for any number of outgoing connections, routed by the connection IDs we issue.
/// One thread owns the socket and all its connections (as on the server, no connection state needs locks); other
/// threads hand it work through <see cref="Post"/> and <see cref="Run"/>. What happens on a connection reaches the
/// <see cref="IQuicApplication"/> on that thread (<see cref="IQuicApplication.Accept"/> is a server's and is never
/// called).
///
/// It's optional: a <see cref="QuicConnection"/> is free of I/O, so a game loop can also drive one on its own socket
/// and clock, as this does.
/// </summary>
public sealed class QuicClientEndpoint : IQuicDispatcher, IDisposable
{
    public const int CidLength = 8;

    private sealed class Conn(QuicConnection c)
    {
        public readonly QuicConnection C = c;
        public readonly List<CidKey> Cids = new();
        public long Queued;
    }

    private readonly Socket _socket;
    private readonly Socket _waker;
    private readonly EndPoint _wakeAt;
    private readonly IQuicApplication _app;
    private readonly IQuicLog _log;
    private readonly Dictionary<CidKey, Conn> _cids = new();
    private readonly List<Conn> _conns = new();
    private readonly Dictionary<QuicConnection, Conn> _byConn = new(ReferenceEqualityComparer.Instance);
    private readonly PriorityQueue<Conn, long> _timers = new();
    private readonly Queue<Action> _posted = new();
    private readonly byte[] _out = new byte[1500];
    private Thread? _thread;
    private volatile bool _stop;

    // Counters (for tests and diagnostics).
    public long Datagrams, DatagramsSent, Unroutable;
    public int Connections => _conns.Count;
    public EndPoint LocalEndPoint => _socket.LocalEndPoint!;

    /// <summary>
    /// A client endpoint on a new UDP socket bound to <paramref name="bind"/>: by default, any address and an ephemeral
    /// port, IPv6 and IPv4 both (dual-stack). Call <see cref="Start"/> before connecting.
    /// </summary>
    public QuicClientEndpoint(IQuicApplication app, IQuicLog? log = null, IPEndPoint? bind = null)
    {
        _app = app;
        _log = log ?? NullQuicLog.Instance;
        bind ??= new IPEndPoint(IPAddress.IPv6Any, 0);
        _socket = new Socket(bind.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            if (bind.AddressFamily == AddressFamily.InterNetworkV6 && bind.Address.Equals(IPAddress.IPv6Any)) _socket.DualMode = true;
            _socket.Bind(bind);
        }
        catch
        {
            _socket.Dispose();
            throw;
        }
        int port = ((IPEndPoint)_socket.LocalEndPoint!).Port;
        _wakeAt = new IPEndPoint(bind.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Loopback : IPAddress.Loopback, port);
        _waker = new Socket(bind.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
    }

    public void Start()
    {
        _thread = new Thread(Loop) { IsBackground = true, Name = "quic client " + _socket.LocalEndPoint };
        _thread.Start();
    }

    /// <summary>
    /// Start a connection to <paramref name="server"/> (any thread). <paramref name="serverName"/> goes in SNI, and
    /// the server's certificate must match it unless <paramref name="tls"/> doesn't verify. The connection is the
    /// endpoint thread's from here on: touch it only from the application's callbacks or through <see cref="Run"/>.
    /// <see cref="QuicEventKind.Connected"/> reports the handshake's end; a failure arrives as a close.
    /// </summary>
    public QuicConnection Connect(EndPoint server, string serverName, string[] alpn, QuicTlsContext tls, QuicOptions? options = null)
    {
        server = Normalize(server);
        var c = QuicConnection.Client(tls, serverName, alpn, options ?? new QuicOptions(), NewCid, server, QuicClock.Now());
        Post(() =>
        {
            var conn = new Conn(c);
            _conns.Add(conn);
            _byConn[c] = conn;
            Map(conn, c.SourceCid);
            try { _app.Started(c); }
            catch (Exception x) when (x is not OutOfMemoryException) { _log.Error("quic application start failed", ("error", x.Message), ("stack", x.StackTrace)); }
            Service(conn, QuicClock.Now());
        });
        return c;
    }

    private static (byte[], byte[]) NewCid() => (RandomNumberGenerator.GetBytes(CidLength), RandomNumberGenerator.GetBytes(16));

    /// <summary>Run <paramref name="a"/> on the endpoint's thread.</summary>
    public void Post(Action a)
    {
        bool wake;
        lock (_posted)
        {
            wake = _posted.Count == 0;
            _posted.Enqueue(a);
        }
        if (wake) Wake();
    }

    public void Run(QuicConnection c, Action<QuicConnection> work) => Post(() =>
    {
        if (!_byConn.TryGetValue(c, out var conn)) return;
        work(c);
        Service(conn, QuicClock.Now());
    });

    private void Wake()
    {
        try { _waker.SendTo([0], _wakeAt); } // a one-byte datagram the loop ignores, to end its wait
        catch (SocketException) { }
        catch (ObjectDisposedException) { }
    }

    /// <summary>IPv4 addresses as IPv4, also when a dual-stack socket reports them IPv4-mapped: paths compare equal.</summary>
    private static EndPoint Normalize(EndPoint ep) =>
        ep is IPEndPoint { Address.IsIPv4MappedToIPv6: true } ip ? new IPEndPoint(ip.Address.MapToIPv4(), ip.Port) : ep;

    private void Loop()
    {
        var buf = new byte[65536];
        EndPoint from = new IPEndPoint(_socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
        while (!_stop)
        {
            try
            {
                long now = QuicClock.Now();
                RunTimers(now);
                RunPosted();
                try { _app.Tick(now); }
                catch (Exception x) when (x is not OutOfMemoryException) { _log.Error("quic application tick failed", ("error", x.Message), ("stack", x.StackTrace)); }
                long next = _timers.TryPeek(out _, out long t) ? t : now + 1_000_000;
                int waitUs = (int)Math.Clamp(next - now, 0, 1_000_000);
                if (!_socket.Poll(waitUs, SelectMode.SelectRead)) continue;
                now = QuicClock.Now();
                for (int i = 0; i < 256 && _socket.Available > 0; i++)
                {
                    int n = _socket.ReceiveFrom(buf, ref from);
                    Datagrams++;
                    if (n > 1) Handle(buf.AsSpan(0, n), Normalize(from), now);
                }
            }
            catch (SocketException e) when (e.SocketErrorCode is SocketError.ConnectionReset or SocketError.MessageSize) { }
            catch (ObjectDisposedException) { return; }
            catch (Exception e) when (!_stop)
            {
                _log.Error("quic client endpoint error", ("error", e.GetType().Name), ("detail", e.Message), ("stack", e.StackTrace));
            }
        }
    }

    private void RunPosted()
    {
        while (true)
        {
            Action a;
            lock (_posted)
            {
                if (_posted.Count == 0) return;
                a = _posted.Dequeue();
            }
            try { a(); }
            catch (Exception x) when (x is not OutOfMemoryException) { _log.Error("quic posted work failed", ("error", x.Message), ("stack", x.StackTrace)); }
        }
    }

    private void RunTimers(long now)
    {
        while (_timers.TryPeek(out var c, out long t) && t <= now)
        {
            _timers.Dequeue();
            if (c.Queued != t || !_byConn.ContainsKey(c.C)) continue; // superseded or gone
            c.Queued = 0;
            c.C.OnTimeout(now);
            Service(c, now);
        }
    }

    private void Handle(Span<byte> d, EndPoint from, long now)
    {
        if (Packets.TryParse(d, CidLength, out var h) && _cids.TryGetValue(CidKey.From(h.Dcid(d)), out var conn))
        {
            conn.C.Receive(d, from, now);
            Service(conn, now);
            return;
        }
        // Not addressed to a connection ID of ours: maybe a stateless reset (RFC 9000 10.3.1), which can't carry one.
        // Only a connection talking to that address can recognise its token.
        Unroutable++;
        if ((d[0] & 0xC0) != 0x40 || d.Length < 21) return;
        for (int i = _conns.Count - 1; i >= 0; i--)
        {
            var c = _conns[i];
            if (!c.C.Path.Equals(from)) continue;
            c.C.Receive(d, from, now);
            Service(c, now);
        }
    }

    private void Map(Conn c, ReadOnlySpan<byte> cid)
    {
        var k = CidKey.From(cid);
        _cids[k] = c;
        c.Cids.Add(k);
    }

    private void Service(Conn c, long now)
    {
        while (c.C.TryGetEvent(out var e))
        {
            switch (e.Kind)
            {
                case QuicEventKind.CidIssued: Map(c, e.Cid); break;
                case QuicEventKind.CidRetired:
                {
                    var k = CidKey.From(e.Cid);
                    if (_cids.TryGetValue(k, out var x) && ReferenceEquals(x, c)) _cids.Remove(k);
                    c.Cids.Remove(k);
                    break;
                }
                case QuicEventKind.Closed: break;
                default:
                    try { _app.OnEvent(c.C, e, now); }
                    catch (Exception x) when (x is not OutOfMemoryException)
                    {
                        _log.Error("quic application error", ("error", x.GetType().Name), ("detail", x.Message), ("stack", x.StackTrace));
                        c.C.Close(0x0102 /* H3_INTERNAL_ERROR */, "internal error", now);
                    }
                    break;
            }
        }
        int n;
        while ((n = c.C.Send(_out, now, out var to)) > 0)
        {
            DatagramsSent++;
            try { _socket.SendTo(_out.AsSpan(0, n), SocketFlags.None, to); }
            catch (SocketException) { } // unreachable: QUIC's problem (loss), not ours
        }
        if (c.C.IsClosed)
        {
            Remove(c);
            return;
        }
        long d = c.C.Deadline;
        if (d != 0 && d != c.Queued)
        {
            c.Queued = d;
            _timers.Enqueue(c, d);
        }
    }

    private void Remove(Conn c)
    {
        if (!_byConn.Remove(c.C)) return;
        _conns.Remove(c);
        foreach (var k in c.Cids)
            if (_cids.TryGetValue(k, out var x) && ReferenceEquals(x, c)) _cids.Remove(k);
        try { _app.Closed(c.C); }
        catch (Exception x) when (x is not OutOfMemoryException) { _log.Error("quic application close failed", ("error", x.Message), ("stack", x.StackTrace)); }
        c.C.Dispose();
    }

    public void Dispose()
    {
        _stop = true;
        Wake();
        _thread?.Join(2000);
        foreach (var c in _conns)
        {
            try { _app.Closed(c.C); }
            catch (Exception x) when (x is not OutOfMemoryException) { _log.Error("quic application close failed", ("error", x.Message)); }
            c.C.Dispose();
        }
        _conns.Clear();
        _byConn.Clear();
        _cids.Clear();
        _socket.Dispose();
        _waker.Dispose();
    }
}
