using System.Net;
using System.Security.Cryptography;
using Httpgrl.Core.Quic;

namespace Httpgrl.Tests;

/// <summary>
/// A deterministic network for two QUIC connections: a virtual clock (microseconds), seeded randomness, and
/// configurable loss, delay, jitter (hence reordering), duplication and bandwidth. Nothing here is real time, so a
/// test of retransmission after loss runs in milliseconds and the same way every time.
/// </summary>
internal sealed class QuicNet : IDisposable
{
    public long Now = 1_000_000;
    public double Loss, Duplicate;
    /// <summary>Probability that a datagram arrives with one byte changed (the receiver must drop it, not choke on it).</summary>
    public double Corrupt;
    /// <summary>Apply loss and corruption only while this holds (null: always), e.g. only during the handshake.</summary>
    public Func<bool>? Impair;
    public long DelayUs = 10_000, JitterUs;
    /// <summary>Bytes per second each way; 0: unlimited.</summary>
    public long Bandwidth;
    /// <summary>Drop datagrams in this direction while the predicate says so (targeted loss).</summary>
    public Func<bool, byte[], bool>? DropIf;
    public long Delivered, Dropped, Corrupted;
    /// <summary>Print every datagram (QUICNET_TRACE=1), for chasing a failing scenario.</summary>
    public bool Trace = Environment.GetEnvironmentVariable("QUICNET_TRACE") == "1";

    /// <summary>Where the client's datagrams come from (change it to simulate a NAT rebinding or a migration).</summary>
    public EndPoint ClientAddress = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 40000);
    public readonly EndPoint ServerAddress = new IPEndPoint(IPAddress.Parse("198.51.100.1"), 443);
    /// <summary>The most data-carrying datagrams the server sent at one instant (pacing spreads them out).</summary>
    public int MaxServerBurst;
    /// <summary>Where the server sent each datagram, for tests of paths.</summary>
    public readonly List<EndPoint> ServerSentTo = new();

    private readonly Random _rng;
    private readonly PriorityQueue<(byte[] Data, bool ToServer, EndPoint From), (long, long)> _wire = new();
    private long _seq;
    private readonly long[] _linkFree = new long[2];

    public QuicConnection Client = null!;
    public QuicConnection? Server;
    public readonly QuicTlsContext ServerTls, ClientTls;
    public readonly QuicOptions ServerOptions, ClientOptions;
    private readonly string _dir;
    /// <summary>Server-side datagrams before the server connection exists (to test what the first flight carries).</summary>
    public long ServerBytesBeforeValidation = -1;

    public static Func<(byte[], byte[])> Cids => () => (RandomNumberGenerator.GetBytes(8), RandomNumberGenerator.GetBytes(16));

    public QuicNet(int seed = 1, QuicOptions? server = null, QuicOptions? client = null, string[]? alpn = null, string? clientSuites = null)
    {
        _rng = new Random(seed);
        _dir = Directory.CreateTempSubdirectory("httpgrl-quicnet-").FullName;
        ProxyTests.MakeCert("quic.test", _dir, "q").Dispose();
        ServerTls = QuicTlsContext.Server(Path.Combine(_dir, "q.crt"), Path.Combine(_dir, "q.key"), ["test"]);
        ClientTls = QuicTlsContext.Client(Path.Combine(_dir, "q.crt"), suites: clientSuites);
        ServerOptions = server ?? new QuicOptions();
        ClientOptions = client ?? new QuicOptions();
        Client = QuicConnection.Client(ClientTls, "quic.test", alpn ?? ["test"], ClientOptions, Cids, ServerAddress, Now);
    }

    private void Put(byte[] data, bool toServer, EndPoint from)
    {
        bool impair = Impair?.Invoke() ?? true;
        string kinds = "";
        if (Trace) { int at2 = 0; while (at2 < data.Length && Packets.TryParse(data.AsSpan(at2), 8, out var th)) { kinds += th.Type + "/" + th.Length + " "; at2 += th.Length; } }
        int corruptedNow = -1;
        if ((impair && _rng.NextDouble() < Loss) || DropIf?.Invoke(toServer, data) == true) { Dropped++; if (Trace) Console.WriteLine($"    TRACE t={(Now - 1_000_000) / 1000}ms {(toServer ? "C->S" : "S->C")} {data.Length}B [{kinds}] DROPPED"); return; }
        if (impair && Corrupt > 0 && _rng.NextDouble() < Corrupt)
        {
            data = (byte[])data.Clone();
            int where = _rng.Next(data.Length);
            data[where] ^= (byte)(1 + _rng.Next(255));
            Corrupted++;
            corruptedNow = where;
        }
        long at = Now;
        if (Bandwidth > 0)
        {
            int dir = toServer ? 0 : 1;
            long start = Math.Max(Now, _linkFree[dir]);
            _linkFree[dir] = start + data.Length * 1_000_000L / Bandwidth;
            at = _linkFree[dir];
        }
        at += DelayUs + (JitterUs > 0 ? _rng.NextInt64(JitterUs) : 0);
        if (Trace) Console.WriteLine($"    TRACE t={(Now - 1_000_000) / 1000}ms {(toServer ? "C->S" : "S->C")} {data.Length}B [{kinds}] corrupted={corruptedNow}");
        _wire.Enqueue((data, toServer, from), (at, _seq++));
        if (_rng.NextDouble() < Duplicate) _wire.Enqueue(((byte[])data.Clone(), toServer, from), (at + 1000, _seq++));
    }

    private void Flush()
    {
        var buf = new byte[1500];
        int n;
        while ((n = Client.Send(buf, Now, out _)) > 0)
        {
            ClientSent?.Invoke(buf[..n]);
            Put(buf[..n], toServer: true, RewriteClientFrom?.Invoke(ClientAddress) ?? ClientAddress);
        }
        if (Server is null) return;
        int burst = 0;
        while ((n = Server.Send(buf, Now, out var to)) > 0)
        {
            ServerSentTo.Add(to);
            if (n > 200) MaxServerBurst = Math.Max(MaxServerBurst, ++burst); // data-carrying datagrams sent at one instant
            if (to.Equals(ClientAddress)) Put(buf[..n], toServer: false, ServerAddress); // only the client's current address is reachable
            else Dropped++;
        }
    }

    private void Deliver(byte[] data, bool toServer, EndPoint from)
    {
        Delivered++;
        if (!toServer) { Client.Receive(data, from, Now); return; }
        if (Server is null)
        {
            if (!Packets.TryParse(data, 8, out var h) || h.Type != PacketType.Initial || data.Length < 1200) return;
            if (!QuicConnection.IsAuthenticInitial(data, h)) return; // as the endpoint does: no state for garbage
            var dcid = h.Dcid(data).ToArray();
            var (scid, token) = Cids();
            Server = QuicConnection.Server(ServerTls, _ => ServerTls, ServerOptions, dcid, h.Scid(data).ToArray(), dcid, null, false, scid, token, Cids, from, Now);
        }
        Server.Receive(data, from, Now);
    }

    /// <summary>Run until <paramref name="done"/> holds, nothing more can happen, or <paramref name="maxUs"/> of virtual time passes. True if done.</summary>
    public bool Run(Func<bool> done, long maxUs = 60_000_000)
    {
        long until = Now + maxUs;
        for (int steps = 0; steps < 2_000_000; steps++)
        {
            Flush();
            if (done()) return true;
            long next = long.MaxValue;
            if (_wire.TryPeek(out _, out var pri)) next = pri.Item1;
            foreach (var c in new[] { Client, Server })
                if (c is not null && c.Deadline != 0) next = Math.Min(next, c.Deadline);
            if (next == long.MaxValue || next > until) return done();
            if (next > Now) Now = next;
            while (_wire.TryPeek(out var item, out pri) && pri.Item1 <= Now)
            {
                _wire.Dequeue();
                Deliver(item.Data, item.ToServer, item.From);
            }
            foreach (var c in new[] { Client, Server })
                if (c is not null && c.Deadline != 0 && c.Deadline <= Now) c.OnTimeout(Now);
        }
        throw new Exception("simulation didn't settle");
    }

    public bool Connected => Client.HandshakeComplete && Server is { HandshakeComplete: true };

    /// <summary>Drain a connection's events, returning them.</summary>
    public static List<QuicEvent> Events(QuicConnection c)
    {
        var l = new List<QuicEvent>();
        while (c.TryGetEvent(out var e)) l.Add(e);
        return l;
    }

    /// <summary>Hand the server a copy of a datagram as if from <paramref name="from"/> (spoofing and replay tests).</summary>
    public void Inject(byte[] data, EndPoint from) => _wire.Enqueue((data, true, from), (Now + DelayUs, _seq++));

    /// <summary>Called with each datagram the client sends (to capture one for replay).</summary>
    public Action<byte[]>? ClientSent;
    /// <summary>Rewrite the source of the client's datagrams in flight (an on-path attacker); null keeps it.</summary>
    public Func<EndPoint, EndPoint?>? RewriteClientFrom;

    public void Dispose()
    {
        Client.Dispose();
        Server?.Dispose();
        ServerTls.Dispose();
        ClientTls.Dispose();
        try { Directory.Delete(_dir, true); } catch (IOException) { }
    }
}
