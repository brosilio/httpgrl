using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Httpgrl.Core.Hosting;

namespace Httpgrl.Core.Quic;

/// <summary>What a new connection gets: the TLS contexts and limits of the configuration it starts under.</summary>
internal readonly record struct QuicAccept(QuicTlsContext Tls, Func<string?, QuicTlsContext?> Select, QuicOptions Options);

/// <summary>What runs on a QUIC endpoint (HTTP/3, or a test protocol). Every call is on the endpoint's thread.</summary>
internal interface IQuicApplication
{
    /// <summary>The configuration a new connection from <paramref name="remote"/> starts under; null: the endpoint's own.</summary>
    QuicAccept? Accept(EndPoint remote) => null;
    void Started(QuicConnection c) { }
    void OnEvent(QuicConnection c, in QuicEvent e, long now);
    /// <summary>The connection is gone (closed, timed out, or forgotten).</summary>
    void Closed(QuicConnection c) { }
    /// <summary>Once per turn of the endpoint's loop, at least every second.</summary>
    void Tick(long now) { }
}

internal sealed class QuicEndpointOptions
{
    public int MaxConnections = 10_000;
    public int MaxConnectionsPerClient = 256;
    /// <summary>Always validate addresses with Retry before keeping any state (quic_retry on).</summary>
    public bool Retry;
    /// <summary>Retry anyway once this many connections are still handshaking (load shedding).</summary>
    public int RetryAboveHandshakes = 1_000;
    public int StatelessResetsPerSecond = 100;
    /// <summary>Send runs of datagrams with one system call through UDP GSO (Linux UDP_SEGMENT), when the kernel has it.</summary>
    public bool Gso = true;
    public QuicOptions Connection = new();
}

/// <summary>
/// A server's UDP socket: routes datagrams to connections by connection ID, starts connections for new clients
/// (with Retry when asked or under load), answers unknown versions with Version Negotiation and unknown connection
/// IDs with stateless resets, and runs every connection's timers. One thread owns the socket and all its
/// connections, so none of the connection state needs locks; other threads hand it work through <see cref="Post"/>.
/// </summary>
internal sealed class QuicEndpoint : IDisposable
{
    public const int CidLength = 8;
    private const long RetryTokenLifetimeUs = 10_000_000;

    private sealed class Conn(QuicConnection c, IpKey client)
    {
        public readonly QuicConnection C = c;
        /// <summary>Whose per-client allowance it counts against: the address it started from, then each validated one.</summary>
        public IpKey Client = client;
        public readonly List<CidKey> Cids = new();
        public long Queued;
        public bool Handshaking = true;
    }

    /// <summary>A connection ID as a dictionary key without allocating: up to 20 bytes in three words.</summary>
    private readonly record struct CidKey(ulong A, ulong B, uint C, byte Len)
    {
        public static CidKey From(ReadOnlySpan<byte> cid)
        {
            Span<byte> b = stackalloc byte[24];
            b.Clear();
            cid[..Math.Min(cid.Length, 20)].CopyTo(b);
            return new(BinaryPrimitives.ReadUInt64LittleEndian(b), BinaryPrimitives.ReadUInt64LittleEndian(b[8..]), BinaryPrimitives.ReadUInt32LittleEndian(b[16..]), (byte)cid.Length);
        }
    }

    private readonly Socket _socket;
    private readonly Socket _waker;
    private QuicEndpointOptions _o;
    private readonly QuicTlsContext? _defaultTls;
    private readonly Func<string?, QuicTlsContext?> _selectTls;
    private readonly IQuicApplication _app;
    private readonly ILogger _log;
    private readonly Dictionary<CidKey, Conn> _cids = new();
    private readonly HashSet<Conn> _conns = new();
    private readonly Dictionary<QuicConnection, Conn> _byConn = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<IpKey, int> _perClient = new();
    private readonly PriorityQueue<Conn, long> _timers = new();
    private readonly Queue<Action> _posted = new();
    private readonly AesGcm _tokenAead;
    private readonly byte[] _resetKey = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _out = new byte[1500];

    // GSO (UDP_SEGMENT): consecutive datagrams for one address, all of the segment size but the last, go out in one
    // send; the kernel cuts them apart. Off if the option isn't there (or a send with it fails).
    private const int SolUdp = 17, UdpSegment = 103, MaxSegments = 64;
    private bool _gso;
    private readonly int _segment;
    private readonly byte[] _batch = new byte[MaxSegments * 1500];
    private int _batchLen, _batchCount;
    private bool _batchClosed;
    private EndPoint? _batchTo;
    public bool GsoActive => _gso;
    public long SendCalls, DatagramsSent;
    private Thread? _thread;
    private volatile bool _stop;
    private int _handshaking;
    private double _resetBudget;
    private long _resetBudgetAt;

    // Counters (for stub_status and tests).
    public long Datagrams, Accepted, Refused, Retries, VersionNegotiations, StatelessResets;
    public int Connections => _conns.Count;
    public EndPoint LocalEndPoint => _socket.LocalEndPoint!;

    public QuicEndpoint(Socket socket, QuicTlsContext? defaultTls, Func<string?, QuicTlsContext?> selectTls, IQuicApplication app, ILogger log, QuicEndpointOptions? options = null)
    {
        _socket = socket;
        _defaultTls = defaultTls;
        _selectTls = selectTls;
        _app = app;
        _log = log;
        _o = options ?? new QuicEndpointOptions();
        _tokenAead = new AesGcm(RandomNumberGenerator.GetBytes(32), 16);
        _waker = new Socket(socket.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        _segment = _o.Connection.MaxDatagramSize;
        if (_o.Gso && OperatingSystem.IsLinux())
        {
            Span<byte> v = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(v, _segment);
            try { socket.SetRawSocketOption(SolUdp, UdpSegment, v); _gso = true; }
            catch (SocketException) { }
        }
    }

    private static readonly long ClockStart = Stopwatch.GetTimestamp();

    /// <summary>
    /// Microseconds on a monotonic clock that starts at one second when the process first uses QUIC: always positive
    /// (connections use 0 for "no deadline"), and divided before it's multiplied (ticks × 10^6 overflows a long after
    /// a few hours of uptime at nanosecond resolution).
    /// </summary>
    public static long Now()
    {
        long t = Stopwatch.GetTimestamp() - ClockStart, f = Stopwatch.Frequency;
        return 1_000_000 + t / f * 1_000_000 + t % f * 1_000_000 / f;
    }

    public void Start()
    {
        _thread = new Thread(Loop) { IsBackground = true, Name = "quic " + _socket.LocalEndPoint };
        _thread.Start();
    }

    /// <summary>Run <paramref name="a"/> on the endpoint's thread (the only one that may touch its connections).</summary>
    public void Post(Action a)
    {
        bool wake;
        lock (_posted)
        {
            wake = _posted.Count == 0; // one wakeup per batch: the loop drains the whole queue
            _posted.Enqueue(a);
        }
        if (wake) Wake();
    }

    /// <summary>
    /// Do <paramref name="work"/> on <paramref name="c"/> from any thread: on the endpoint's thread, if the connection
    /// still exists; then send whatever it produced.
    /// </summary>
    public void Run(QuicConnection c, Action<QuicConnection> work) => Post(() =>
    {
        if (!_byConn.TryGetValue(c, out var conn)) return;
        work(c);
        Service(conn, Now());
    });

    /// <summary>Change the endpoint's settings (a reload); the new ones apply to new connections.</summary>
    public void Update(QuicEndpointOptions o) => Post(() => _o = o);

    private void Wake()
    {
        try { _waker.SendTo([0], _socket.LocalEndPoint!); } // an empty datagram the loop ignores, to end its wait
        catch (SocketException) { }
        catch (ObjectDisposedException) { }
    }

    private void Loop()
    {
        var buf = new byte[65536];
        EndPoint from = new IPEndPoint(_socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
        while (!_stop)
        {
            try
            {
                long now = Now();
                RunTimers(now);
                RunPosted(now);
                try { _app.Tick(now); }
                catch (Exception x) when (x is not OutOfMemoryException) { _log.Error("quic application tick failed", new LogField("error", x.Message), new LogField("stack", x.StackTrace)); }
                long next = _timers.TryPeek(out _, out long t) ? t : now + 1_000_000;
                int waitUs = (int)Math.Clamp(next - now, 0, 1_000_000);
                if (!_socket.Poll(waitUs, SelectMode.SelectRead)) continue;
                now = Now();
                // Drain what's queued, but keep timers honest under a flood.
                for (int i = 0; i < 256 && _socket.Available > 0; i++)
                {
                    int n = _socket.ReceiveFrom(buf, ref from);
                    Datagrams++;
                    if (n > 1) Handle(buf.AsSpan(0, n), from, now);
                }
            }
            catch (SocketException e) when (e.SocketErrorCode is SocketError.ConnectionReset or SocketError.MessageSize) { } // ICMP noise, oversize datagrams
            catch (ObjectDisposedException) { return; }
            catch (Exception e) when (!_stop)
            {
                _log.Error("quic endpoint error", new LogField("error", e.GetType().Name), new LogField("detail", e.Message), new LogField("stack", e.StackTrace));
            }
        }
    }

    private void RunPosted(long now)
    {
        while (true)
        {
            Action? a;
            lock (_posted) if (!_posted.TryDequeue(out a)) return;
            a();
        }
    }

    private void RunTimers(long now)
    {
        while (_timers.TryPeek(out var c, out long t) && t <= now)
        {
            _timers.Dequeue();
            if (c.Queued != t || !_conns.Contains(c)) continue; // superseded or gone
            c.Queued = 0;
            c.C.OnTimeout(now);
            Service(c, now);
        }
    }

    private void Handle(Span<byte> d, EndPoint from, long now)
    {
        if (!Packets.TryParse(d, CidLength, out var h)) return;
        if (_cids.TryGetValue(CidKey.From(h.Dcid(d)), out var conn))
        {
            // From anywhere: the connection decides whether a new address is a migration (RFC 9000 9).
            conn.C.Receive(d, from, now);
            Service(conn, now);
            return;
        }
        if ((d[0] & 0x80) == 0)
        {
            StatelessReset(h.Dcid(d), d.Length, from, now);
            return;
        }
        if (h.Type == PacketType.UnknownVersion)
        {
            // Only for datagrams big enough to be a client's first flight (RFC 9000 6.1), and never for version 0.
            if (d.Length >= Packets.MinInitialDatagram && h.Version != 0)
            {
                int n = Packets.WriteVersionNegotiation(_out, h.Dcid(d), h.Scid(d), (byte)RandomNumberGenerator.GetInt32(256));
                VersionNegotiations++;
                SendTo(_out.AsSpan(0, n), from);
            }
            return;
        }
        if (h.Type != PacketType.Initial || d.Length < Packets.MinInitialDatagram || h.DcidLength < 8) return;
        // No state for an Initial that doesn't authenticate (garbage, or corrupted in flight).
        if (!QuicConnection.IsAuthenticInitial(d, h)) { Refused++; return; }
        NewConnection(d, h, from, now);
    }

    private void NewConnection(Span<byte> d, PacketHeader h, EndPoint from, long now)
    {
        var client = IpKey.From(from);
        _perClient.TryGetValue(client, out int mine);
        if (_conns.Count >= _o.MaxConnections || mine >= _o.MaxConnectionsPerClient)
        {
            Refused++;
            return;
        }
        var dcid = h.Dcid(d).ToArray();
        byte[] originalDcid = dcid;
        byte[]? retryScid = null;
        bool validated = false;
        var token = h.Token(d);
        if (!token.IsEmpty)
        {
            // Only our Retry tokens exist (no NEW_TOKEN yet): a bad one is dropped, as if never seen.
            if (!OpenToken(token, from, dcid, now, out originalDcid)) { Refused++; return; }
            retryScid = dcid;
            validated = true;
        }
        else if (_o.Retry || _handshaking >= _o.RetryAboveHandshakes)
        {
            var newScid = RandomNumberGenerator.GetBytes(CidLength);
            var t = SealToken(from, dcid, newScid, now);
            int n = Packets.WriteRetry(_out, h.Scid(d), newScid, t, dcid, (byte)RandomNumberGenerator.GetInt32(256));
            Retries++;
            SendTo(_out.AsSpan(0, n), from);
            return;
        }
        var scid = RandomNumberGenerator.GetBytes(CidLength);
        // The application's configuration, else the endpoint's own; neither: nothing to answer with.
        var accept = _app.Accept(from) ?? (_defaultTls is null ? (QuicAccept?)null : new QuicAccept(_defaultTls, _selectTls, _o.Connection));
        if (accept is not { } acc) { Refused++; return; }
        QuicConnection qc;
        try
        {
            qc = QuicConnection.Server(acc.Tls, acc.Select, acc.Options, dcid, h.Scid(d).ToArray(), originalDcid, retryScid, validated,
                scid, ResetToken(scid), NewCid, from, now);
        }
        catch (Exception e) when (e is QuicException or InvalidOperationException)
        {
            _log.Warn("quic connection setup failed", new LogField("error", e.Message));
            return;
        }
        var conn = new Conn(qc, client);
        _conns.Add(conn);
        _byConn[qc] = conn;
        _app.Started(qc);
        _handshaking++;
        _perClient[client] = mine + 1;
        Accepted++;
        Map(conn, scid);
        Map(conn, dcid); // the client keeps using its chosen DCID until it hears from us
        qc.Receive(d, from, now);
        Service(conn, now);
    }

    private (byte[], byte[]) NewCid()
    {
        var cid = RandomNumberGenerator.GetBytes(CidLength);
        return (cid, ResetToken(cid));
    }

    /// <summary>The stateless reset token for one of our connection IDs: a keyed hash, so it needs no state (RFC 9000 10.3.2).</summary>
    private byte[] ResetToken(ReadOnlySpan<byte> cid)
    {
        Span<byte> mac = stackalloc byte[32];
        HMACSHA256.HashData(_resetKey, cid, mac);
        return mac[..16].ToArray();
    }

    private void Map(Conn c, ReadOnlySpan<byte> cid)
    {
        var k = CidKey.From(cid);
        _cids[k] = c;
        c.Cids.Add(k);
    }

    /// <summary>After anything happened to a connection: its events, then whatever it has to send, then its next timer.</summary>
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
                    _cids.Remove(k);
                    c.Cids.Remove(k);
                    break;
                }
                case QuicEventKind.Closed: break;
                case QuicEventKind.PathValidated:
                {
                    // Per-client limits follow the validated address.
                    var moved = IpKey.From(c.C.Path);
                    if (moved != c.Client)
                    {
                        Release(c.Client);
                        _perClient[moved] = (_perClient.TryGetValue(moved, out int m) ? m : 0) + 1;
                        c.Client = moved;
                    }
                    break;
                }
                case QuicEventKind.Connected:
                    if (c.Handshaking) { c.Handshaking = false; _handshaking--; }
                    goto default;
                default:
                    try { _app.OnEvent(c.C, e, now); }
                    catch (Exception x) when (x is not OutOfMemoryException)
                    {
                        _log.Error("quic application error", new LogField("error", x.GetType().Name), new LogField("detail", x.Message), new LogField("stack", x.StackTrace));
                        c.C.Close(0x0102 /* H3_INTERNAL_ERROR */, "internal error", now);
                    }
                    break;
            }
        }
        int n;
        while ((n = c.C.Send(_out, now, out var to)) > 0) Queue(_out.AsSpan(0, n), to);
        Flush();
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
        if (!_conns.Remove(c)) return;
        _byConn.Remove(c.C);
        try { _app.Closed(c.C); }
        catch (Exception x) when (x is not OutOfMemoryException) { _log.Error("quic application close failed", new LogField("error", x.Message), new LogField("stack", x.StackTrace)); }
        if (c.Handshaking) { c.Handshaking = false; _handshaking--; }
        foreach (var k in c.Cids)
            if (_cids.TryGetValue(k, out var x) && ReferenceEquals(x, c)) _cids.Remove(k);
        Release(c.Client);
        c.C.Dispose();
    }

    private void Release(IpKey client)
    {
        if (_perClient.TryGetValue(client, out int n))
        {
            if (n <= 1) _perClient.Remove(client); else _perClient[client] = n - 1;
        }
    }

    private void SendTo(ReadOnlySpan<byte> d, EndPoint to)
    {
        SendCalls++;
        try { _socket.SendTo(d, SocketFlags.None, to); }
        catch (SocketException) { } // unreachable peers are QUIC's problem (loss), not ours
    }

    private void Queue(ReadOnlySpan<byte> d, EndPoint to)
    {
        DatagramsSent++;
        if (!_gso) { SendTo(d, to); return; }
        if (_batchCount > 0 && (_batchClosed || _batchCount >= MaxSegments || !to.Equals(_batchTo))) Flush();
        d.CopyTo(_batch.AsSpan(_batchLen));
        _batchLen += d.Length;
        _batchCount++;
        _batchTo = to;
        _batchClosed = d.Length != _segment; // a shorter datagram can only be a batch's last
    }

    private void Flush()
    {
        if (_batchCount == 0) return;
        var to = _batchTo!;
        int len = _batchLen, count = _batchCount;
        _batchLen = _batchCount = 0;
        _batchClosed = false;
        if (count == 1) { SendTo(_batch.AsSpan(0, len), to); return; }
        SendCalls++;
        try { _socket.SendTo(_batch.AsSpan(0, len), SocketFlags.None, to); }
        catch (SocketException e) when (e.SocketErrorCode is not (SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.ConnectionRefused))
        {
            // The route or device won't segment (EIO and friends): stop using GSO, and send these one by one.
            _gso = false;
            try { _socket.SetRawSocketOption(SolUdp, UdpSegment, new byte[4]); } catch (SocketException) { }
            _log.Warn("quic: UDP GSO failed, sending datagrams one at a time", new LogField("error", e.SocketErrorCode.ToString()));
            for (int at = 0; at < len; at += _segment) SendTo(_batch.AsSpan(at, Math.Min(_segment, len - at)), to);
        }
        catch (SocketException) { }
    }

    /// <summary>
    /// A stateless reset for a short-header packet to an unknown connection ID (RFC 9000 10.3): random bytes ending in
    /// the token, always smaller than what provoked it (so two endpoints can't loop), and rate-limited.
    /// </summary>
    private void StatelessReset(ReadOnlySpan<byte> cid, int received, EndPoint to, long now)
    {
        if (received <= 21 + 1) return;
        _resetBudget = Math.Min(_o.StatelessResetsPerSecond, _resetBudget + (now - _resetBudgetAt) / 1e6 * _o.StatelessResetsPerSecond);
        _resetBudgetAt = now;
        if (_resetBudget < 1) return;
        _resetBudget--;
        int n = Math.Min(received - 1, 43);
        var d = _out.AsSpan(0, n);
        RandomNumberGenerator.Fill(d[..^16]);
        d[0] = (byte)(0x40 | (d[0] & 0x3F));
        ResetToken(cid).CopyTo(d[^16..]);
        StatelessResets++;
        SendTo(d, to);
    }

    // Retry tokens: AES-GCM under a key that never leaves this process, binding the client's address, the time, the
    // client's original DCID and the SCID we gave it (RFC 9000 8.1.4).
    private byte[] SealToken(EndPoint client, ReadOnlySpan<byte> originalDcid, ReadOnlySpan<byte> retryScid, long now)
    {
        Span<byte> plain = stackalloc byte[8 + 1 + originalDcid.Length + 1 + retryScid.Length];
        BinaryPrimitives.WriteInt64BigEndian(plain, now);
        plain[8] = (byte)originalDcid.Length;
        originalDcid.CopyTo(plain[9..]);
        plain[9 + originalDcid.Length] = (byte)retryScid.Length;
        retryScid.CopyTo(plain[(10 + originalDcid.Length)..]);
        var token = new byte[12 + plain.Length + 16];
        RandomNumberGenerator.Fill(token.AsSpan(0, 12));
        _tokenAead.Encrypt(token.AsSpan(0, 12), plain, token.AsSpan(12, plain.Length), token.AsSpan(12 + plain.Length), Address(client));
        return token;
    }

    private bool OpenToken(ReadOnlySpan<byte> token, EndPoint client, ReadOnlySpan<byte> dcid, long now, out byte[] originalDcid)
    {
        originalDcid = [];
        if (token.Length < 12 + 10 + 16 || token.Length > 12 + 10 + 40 + 16) return false;
        Span<byte> plain = stackalloc byte[token.Length - 28];
        try { _tokenAead.Decrypt(token[..12], token[12..^16], token[^16..], plain, Address(client)); }
        catch (AuthenticationTagMismatchException) { return false; }
        long issued = BinaryPrimitives.ReadInt64BigEndian(plain);
        if (now - issued > RetryTokenLifetimeUs || issued > now) return false;
        int ol = plain[8];
        if (9 + ol + 1 > plain.Length) return false;
        int rl = plain[9 + ol];
        if (10 + ol + rl != plain.Length) return false;
        // The client must be using the connection ID we handed it in the Retry.
        if (!plain.Slice(10 + ol, rl).SequenceEqual(dcid)) return false;
        originalDcid = plain.Slice(9, ol).ToArray();
        return true;
    }

    private static byte[] Address(EndPoint ep)
    {
        var ip = (IPEndPoint)ep;
        var a = ip.Address.MapToIPv6().GetAddressBytes();
        var r = new byte[18];
        a.CopyTo(r, 0);
        BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(16), (ushort)ip.Port);
        return r;
    }

    /// <summary>For tests: forget every connection without a word, as a restarted server would.</summary>
    internal void ForgetAll() => Post(() =>
    {
        foreach (var c in _conns.ToArray()) Remove(c);
    });

    public void Dispose()
    {
        _stop = true;
        Wake();
        _thread?.Join(2000);
        foreach (var c in _conns)
        {
            try { _app.Closed(c.C); } // the application lets go of what it holds (a configuration generation)
            catch (Exception x) when (x is not OutOfMemoryException) { _log.Error("quic application close failed", new LogField("error", x.Message)); }
            c.C.Dispose();
        }
        _conns.Clear();
        _byConn.Clear();
        _cids.Clear();
        _tokenAead.Dispose();
        _waker.Dispose();
    }
}
