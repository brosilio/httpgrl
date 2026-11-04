using Httpgrl.Core.Quic;

namespace Httpgrl.Tests;

/// <summary>QUIC connections end to end over the virtual network: handshake, streams, loss recovery, limits, closing.</summary>
internal static class QuicConnectionTests
{
    /// <summary>
    /// Echo: the client sends <paramref name="size"/> bytes on a new bidirectional stream and finishes; the server
    /// sends everything back and finishes. True if the client got it all back, byte for byte.
    /// </summary>
    internal static bool Echo(QuicNet net, int size, long maxUs = 120_000_000, int streams = 1)
    {
        var data = new byte[size];
        new Random(size).NextBytes(data);
        var ids = new List<long>();
        var written = new Dictionary<long, int>();
        var back = new Dictionary<long, MemoryStream>();
        var done = new HashSet<long>();
        var got = new Dictionary<long, MemoryStream>();     // server: what each stream brought
        var echo = new Dictionary<long, (byte[] Data, int Sent)>();
        var buf = new byte[65536];
        bool Step()
        {
            if (!net.Connected) return false;
            var c = net.Client;
            var s = net.Server!;
            while (ids.Count < streams)
            {
                long id = c.OpenStream(bidi: true);
                if (id < 0) return false;
                ids.Add(id);
                written[id] = 0;
                back[id] = new MemoryStream();
            }
            foreach (var id in ids)
                if (written[id] < size)
                {
                    int n = c.StreamWrite(id, data.AsSpan(written[id]), fin: true); // the FIN goes with the last of it
                    if (n > 0) written[id] += n;
                }
            while (s.TryGetEvent(out var e))
                if (e.Kind is QuicEventKind.StreamOpened or QuicEventKind.StreamReadable) got.TryAdd(e.StreamId, new MemoryStream());
            foreach (var (sid, ms) in got)
            {
                if (echo.ContainsKey(sid)) continue;
                int n;
                bool fin = false, f;
                while ((n = s.StreamRead(sid, buf, out f, out _)) > 0 | f) { ms.Write(buf, 0, n); fin |= f; if (f) break; }
                if (fin) echo[sid] = (ms.ToArray(), 0);
            }
            foreach (var sid in echo.Keys.ToArray())
            {
                var (d, sent) = echo[sid];
                if (sent >= d.Length) continue;
                int n = s.StreamWrite(sid, d.AsSpan(sent), fin: true);
                if (n > 0) echo[sid] = (d, sent + n);
            }
            while (c.TryGetEvent(out _)) { }
            foreach (var id in ids)
            {
                if (done.Contains(id)) continue;
                int m;
                bool cfin;
                while ((m = c.StreamRead(id, buf, out cfin, out _)) > 0 | cfin) { back[id].Write(buf, 0, m); if (cfin) { done.Add(id); break; } }
            }
            return done.Count == streams;
        }
        bool ok = net.Run(Step, maxUs) && ids.TrueForAll(id => back[id].ToArray().AsSpan().SequenceEqual(data));
        if (!ok)
            Console.WriteLine($"    echo {streams}x{size}: written [{string.Join(",", written.Values)}], server got [{string.Join(",", got.Select(g => $"{g.Key}:{g.Value.Length}"))}], echo [{string.Join(",", echo.Select(g => $"{g.Key}:{g.Value.Sent}/{g.Value.Data.Length}"))}], back [{string.Join(",", back.Values.Select(b => b.Length))}], " +
                $"client close {net.Client.CloseCode} {net.Client.CloseReason}, server close {net.Server?.CloseCode} {net.Server?.CloseReason}, t {(net.Now - 1_000_000) / 1000} ms, lost {net.Client.Recovery.LostPackets}/{net.Server?.Recovery.LostPackets}");
        return ok;
    }

    public static void Register()
    {
        T.Add("quic connection: a clean handshake; ALPN, confirmation, and the server within 3x what it received until validated", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using var net = new QuicNet();
            long maxRatioViolation = 0;
            T.True(net.Run(() =>
            {
                if (net.Server is { AddressValidated: false } s && s.BytesSent > 3 * s.BytesReceived) maxRatioViolation = s.BytesSent - 3 * s.BytesReceived;
                return net.Connected && net.Client.HandshakeConfirmed;
            }));
            T.Eq(0L, maxRatioViolation);
            T.Eq("test", net.Client.Alpn);
            T.Eq("test", net.Server!.Alpn);
            T.Eq("quic.test", net.Server.ServerName);
            T.True(net.Server.HandshakeConfirmed);
            T.True(QuicNet.Events(net.Client).Exists(e => e.Kind == QuicEventKind.Connected));
            T.True(QuicNet.Events(net.Server).Exists(e => e.Kind == QuicEventKind.Connected));
            // Roughly two round trips of 20 ms (10 ms each way), not timeouts.
            T.True(net.Now - 1_000_000 < 200_000);
        });

        T.Add("quic connection: echo on a stream, 1 MiB each way, clean and then through 5% loss, jitter and duplication", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using (var net = new QuicNet())
                T.True(Echo(net, 1 << 20));
            using (var net = new QuicNet(seed: 7) { Loss = 0.05, JitterUs = 15_000, Duplicate = 0.02 })
            {
                T.True(Echo(net, 1 << 20));
                T.True(net.Client.Recovery.LostPackets + net.Server!.Recovery.LostPackets > 0);
            }
        });

        T.Add("quic connection: the handshake survives 30% loss, and a lost first flight is retransmitted by the probe timer", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            for (int seed = 1; seed <= 5; seed++)
            {
                using var net = new QuicNet(seed) { Loss = 0.3 };
                T.True(net.Run(() => net.Connected && net.Client.HandshakeConfirmed && net.Server!.HandshakeConfirmed));
                T.True(Echo(net, 50_000));
            }
            // Every one of the client's first two datagrams lost: the client's probe timer resends its Initial.
            using (var net = new QuicNet())
            {
                int drops = 2;
                net.DropIf = (toServer, _) => toServer && drops-- > 0;
                T.True(net.Run(() => net.Connected));
            }
        });

        T.Add("quic connection: randomized networks (16 seeds: up to 20% loss, jitter, duplication, slow links) all deliver intact", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            for (int seed = 1; seed <= 16; seed++)
            {
                var r = new Random(seed * 31);
                using var net = new QuicNet(seed)
                {
                    Loss = r.NextDouble() * 0.2,
                    JitterUs = r.Next(0, 40_000),
                    DelayUs = r.Next(1_000, 80_000),
                    Duplicate = r.NextDouble() * 0.05,
                    Bandwidth = r.Next(2) == 0 ? 0 : r.Next(1_000_000, 50_000_000),
                };
                int size = r.Next(1, 300_000);
                if (!Echo(net, size, streams: 3)) throw new Exception($"seed {seed}: loss {net.Loss:F2}, jitter {net.JitterUs}, delay {net.DelayUs}, bandwidth {net.Bandwidth}, {size} bytes");
            }
        });

        T.Add("quic connection: small flow-control windows and a slow link still move 2 MiB (window updates, blocking)", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            var small = new QuicOptions { StreamReceiveWindow = 16 << 10, ConnectionReceiveWindow = 32 << 10, StreamSendBuffer = 64 << 10 };
            using var net = new QuicNet(server: small, client: new QuicOptions { StreamReceiveWindow = 16 << 10, ConnectionReceiveWindow = 32 << 10 })
            { Bandwidth = 10_000_000, DelayUs = 20_000 };
            T.True(Echo(net, 2 << 20));
        });

        T.Add("quic connection: application close reaches the peer with its code; both sides finish after draining", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using var net = new QuicNet();
            T.True(net.Run(() => net.Connected && net.Client.HandshakeConfirmed));
            net.Client.Close(0x42, "bye", net.Now);
            T.True(net.Run(() => net.Client.IsClosed && net.Server!.IsClosed));
            T.True(net.Server!.ClosedByPeer);
            T.Eq(QuicError.ApplicationError, net.Server.CloseCode);
            T.Eq(0x42UL, net.Server.ApplicationCloseCode);
            T.Eq("bye", net.Server.CloseReason);
        });

        T.Add("quic connection: an idle connection times out on both sides at the negotiated idle timeout", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using var net = new QuicNet(server: new QuicOptions { MaxIdleTimeoutMs = 2000 }, client: new QuicOptions { MaxIdleTimeoutMs = 30000 });
            T.True(net.Run(() => net.Connected && net.Client.HandshakeConfirmed));
            long t0 = net.Now;
            T.True(net.Run(() => net.Client.IsClosed && net.Server!.IsClosed));
            T.True(net.Now - t0 is > 1_900_000 and < 3_000_000); // the smaller of the two, 2 s
            T.Eq("idle timeout", net.Client.CloseReason);
        });

        T.Add("quic connection: MAX_STREAMS caps the streams a peer opens, and finished streams free more", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using var net = new QuicNet(server: new QuicOptions { MaxStreamsBidi = 4 });
            T.True(net.Run(() => net.Connected && net.Client.HandshakeConfirmed));
            var ids = new List<long>();
            for (int i = 0; i < 6; i++) { long id = net.Client.OpenStream(true); if (id >= 0) ids.Add(id); }
            T.Eq(4, ids.Count);
            foreach (var id in ids) net.Client.StreamWrite(id, "x"u8, fin: true);
            var buf = new byte[16];
            int done = 0;
            // The server reads each to the end and finishes its side; then the client may open more.
            T.True(net.Run(() =>
            {
                while (net.Server!.TryGetEvent(out var e))
                    if (e.Kind == QuicEventKind.StreamReadable)
                    {
                        net.Server.StreamRead(e.StreamId, buf, out bool fin, out _);
                        if (!fin) net.Server.StreamRead(e.StreamId, buf, out fin, out _);
                        if (fin) { net.Server.StreamWrite(e.StreamId, default, fin: true); done++; }
                    }
                return done == 4 && net.Client.OpenStream(true) >= 0;
            }));
        });

        T.Add("quic connection: datagrams flow both ways when negotiated, and are refused when not", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using (var net = new QuicNet(server: new QuicOptions { MaxDatagramFrameSize = 1200 }, client: new QuicOptions { MaxDatagramFrameSize = 1200 }))
            {
                T.True(net.Run(() => net.Connected && net.Client.HandshakeConfirmed));
                T.True(net.Client.SendDatagram("ping"u8));
                byte[]? got = null;
                T.True(net.Run(() => net.Server!.TryReceiveDatagram(out got)));
                T.True(got.AsSpan().SequenceEqual("ping"u8));
                T.True(net.Server!.SendDatagram("pong"u8));
                T.True(net.Run(() => net.Client.TryReceiveDatagram(out got)));
                T.True(got.AsSpan().SequenceEqual("pong"u8));
            }
            using (var net = new QuicNet())
            {
                T.True(net.Run(() => net.Connected && net.Client.HandshakeConfirmed));
                T.True(!net.Client.SendDatagram("ping"u8)); // the server didn't offer DATAGRAM
            }
        });

        T.Add("quic connection: a reset stream reaches the reader with its code; STOP_SENDING makes the writer reset", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using var net = new QuicNet();
            T.True(net.Run(() => net.Connected && net.Client.HandshakeConfirmed));
            long a = net.Client.OpenStream(true), b = net.Client.OpenStream(true);
            net.Client.StreamWrite(a, new byte[5000], fin: false);
            net.Client.StreamWrite(b, new byte[5000], fin: false);
            var buf = new byte[8192];
            T.True(net.Run(() => net.Server!.StreamExists(b)));
            net.Client.ResetStream(a, 7);
            net.Server!.StopSending(b, 9);
            ulong? reset = null;
            T.True(net.Run(() =>
            {
                net.Server.StreamRead(a, buf, out _, out reset);
                return reset is not null;
            }));
            T.Eq(7UL, reset!.Value);
            // The client answers STOP_SENDING by resetting b with the same code.
            ulong? resetB = null;
            T.True(net.Run(() =>
            {
                while (net.Client.TryGetEvent(out var e)) { }
                net.Server.StreamRead(b, buf, out _, out resetB);
                return resetB is not null;
            }));
            T.Eq(9UL, resetB!.Value);
        });
    }
}
