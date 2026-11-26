using Httpgrl.Quic;

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
                if (!Echo(net, size, streams: 3, maxUs: 300_000_000)) throw new Exception($"seed {seed}: loss {net.Loss:F2}, jitter {net.JitterUs}, delay {net.DelayUs}, bandwidth {net.Bandwidth}, {size} bytes");
            }
        });

        T.Add("quic connection: 1-RTT key updates every 40 packets, both sides and one side, through loss and reordering", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using (var net = new QuicNet(seed: 3, server: new QuicOptions { KeyUpdateAfter = 40 }, client: new QuicOptions { KeyUpdateAfter = 40 })
                { Loss = 0.03, JitterUs = 20_000 })
            {
                T.True(Echo(net, 1 << 20));
                T.True(net.Client.KeyUpdates > 5 && net.Server!.KeyUpdates > 5);
            }
            // Only the client initiates; the server follows each time (its own limit is never reached).
            using (var net = new QuicNet(seed: 4, client: new QuicOptions { KeyUpdateAfter = 30 }) { JitterUs = 10_000 })
            {
                T.True(Echo(net, 300_000));
                T.True(net.Client.KeyUpdates > 3);
                T.True(net.Server!.KeyUpdates >= net.Client.KeyUpdates - 1);
            }
        });

        T.Add("quic migration: a NAT rebinding mid-transfer moves the server (congestion state kept); a new address resets it and changes connection ID", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            var a = new System.Net.IPEndPoint(System.Net.IPAddress.Parse("192.0.2.1"), 40000);
            var rebound = new System.Net.IPEndPoint(System.Net.IPAddress.Parse("192.0.2.1"), 40001);
            var moved = new System.Net.IPEndPoint(System.Net.IPAddress.Parse("192.0.2.77"), 5000);
            using (var net = new QuicNet())
            {
                T.True(net.Run(() => net.Connected && net.Client.HandshakeConfirmed));
                long switchAt = net.Now + 100_000;
                bool switched = false;
                long cwndBefore = 0;
                net.DropIf = (toServer, _) =>
                {
                    if (!switched && net.Now >= switchAt) { switched = true; cwndBefore = net.Server!.Recovery.Cwnd; net.ClientAddress = rebound; }
                    return false;
                };
                T.True(Echo(net, 1 << 20));
                T.Eq(1, net.Server!.Migrations);
                T.Eq((System.Net.EndPoint)rebound, net.Server.Path);
                T.True(net.Server.AddressValidated);
                T.True(net.Server.Recovery.Cwnd >= cwndBefore / 2); // not reset to the initial window
            }
            using (var net = new QuicNet())
            {
                T.True(net.Run(() => net.Connected && net.Client.HandshakeConfirmed));
                var cidBefore = net.Server!.DestinationCid;
                long switchAt = net.Now + 100_000;
                bool switched = false;
                net.DropIf = (toServer, _) =>
                {
                    if (!switched && net.Now >= switchAt) { switched = true; net.ClientAddress = moved; }
                    return false;
                };
                T.True(Echo(net, 500_000));
                T.Eq(1, net.Server!.Migrations);
                T.Eq((System.Net.EndPoint)moved, net.Server.Path);
                T.True(net.Server.AddressValidated);
                T.True(!net.Server.DestinationCid.AsSpan().SequenceEqual(cidBefore)); // a fresh connection ID for the new path
            }
        });

        T.Add("quic migration: a replayed datagram from a spoofed address moves nothing; a rewritten source is undone by the next real packet", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            var attacker = new System.Net.IPEndPoint(System.Net.IPAddress.Parse("203.0.113.66"), 6666);
            using (var net = new QuicNet())
            {
                T.True(net.Run(() => net.Connected && net.Client.HandshakeConfirmed));
                byte[]? captured = null;
                net.ClientSent = d => captured ??= (d[0] & 0x80) == 0 ? d.ToArray() : null; // a 1-RTT datagram
                T.True(Echo(net, 20_000));
                T.True(captured is not null);
                net.Inject(captured!, attacker);
                net.Run(() => false, maxUs: 500_000);
                T.Eq(0, net.Server!.Migrations);
                T.Eq(net.ClientAddress, net.Server.Path);
                T.True(!net.ServerSentTo.Exists(e => e.Equals(attacker)) || net.ServerSentTo.FindAll(e => e.Equals(attacker)).Count <= 1);
            }
            using (var net = new QuicNet())
            {
                T.True(net.Run(() => net.Connected && net.Client.HandshakeConfirmed));
                var home = net.ClientAddress;
                int rewrites = 1;
                long at = net.Now + 50_000;
                net.RewriteClientFrom = from => net.Now >= at && rewrites-- > 0 ? attacker : null;
                T.True(Echo(net, 300_000));
                T.Eq(home, net.Server!.Path); // moved to the attacker's address, then straight back
                T.True(net.Server.Migrations >= 2);
                T.True(net.Server.AddressValidated);
            }
        });

        T.Add("quic migration: a new path that never answers its challenge falls back to the old, validated one", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            var attacker = new System.Net.IPEndPoint(System.Net.IPAddress.Parse("203.0.113.66"), 6666);
            using var net = new QuicNet();
            T.True(net.Run(() => net.Connected && net.Client.HandshakeConfirmed));
            var home = net.ClientAddress;
            // One datagram's source rewritten, then the client silent for 5 s: the challenge to the bogus address times out.
            long quietUntil = 0;
            int rewrites = 1;
            net.RewriteClientFrom = from => { if (rewrites-- > 0) { quietUntil = net.Now + 5_000_000; return attacker; } return null; };
            net.DropIf = (toServer, _) => toServer && rewrites < 0 && net.Now < quietUntil;
            long id = net.Client.OpenStream(true);
            net.Client.StreamWrite(id, "hello"u8, false);
            T.True(net.Run(() => net.Server is { Migrations: 1 }));
            T.Eq((System.Net.EndPoint)attacker, net.Server!.Path);
            T.True(net.Run(() => net.Server.Path.Equals(home) && net.Server.AddressValidated, maxUs: 10_000_000));
            T.Eq(1, net.Server.Migrations);
            T.True(!net.Server.IsClosed);
        });

        T.Add("quic congestion: CUBIC beats NewReno on a long fat path with light loss; pacing bounds bursts", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            long Transfer(CongestionControl cc, bool pacing, out int maxBurst, long bandwidth = 12_500_000, double loss = 0.002)
            {
                var o = new QuicOptions { CongestionControl = cc, Pacing = pacing, StreamReceiveWindow = 16 << 20, ConnectionReceiveWindow = 32 << 20, StreamSendBuffer = 16 << 20 };
                using var net = new QuicNet(seed: 9, server: o, client: o) { DelayUs = 40_000, Loss = loss, Bandwidth = bandwidth };
                long t0 = net.Now;
                T.True(Echo(net, 4 << 20, maxUs: 600_000_000));
                maxBurst = net.MaxServerBurst;
                return net.Now - t0;
            }
            long cubic = Transfer(CongestionControl.Cubic, true, out _);
            long reno = Transfer(CongestionControl.NewReno, true, out _);
            T.True(cubic < reno);
            // On an unlimited link a window's ACKs come back together: unpaced, the next window goes out at once.
            Transfer(CongestionControl.Cubic, true, out int pacedBurst, bandwidth: 0, loss: 0);
            Transfer(CongestionControl.Cubic, false, out int unpacedBurst, bandwidth: 0, loss: 0);
            T.True(pacedBurst <= 12);          // the initial window's worth, at most
            T.True(unpacedBurst > pacedBurst * 2);
        });

        T.Add("quic connection: a client offering only ChaCha20-Poly1305 gets it, through loss and key updates", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using var net = new QuicNet(seed: 11, server: new QuicOptions { KeyUpdateAfter = 60 }, client: new QuicOptions { KeyUpdateAfter = 60 },
                clientSuites: "TLS_CHACHA20_POLY1305_SHA256") { Loss = 0.03, JitterUs = 10_000 };
            T.True(Echo(net, 500_000));
            T.Eq(QuicCipher.ChaCha20, net.Server!.Cipher);
            T.True(net.Server.KeyUpdates > 0);
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
