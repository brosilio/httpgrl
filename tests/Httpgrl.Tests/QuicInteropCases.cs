using System.Net;
using System.Net.Sockets;
using Httpgrl.Core.Quic;

namespace Httpgrl.Tests;

/// <summary>
/// The QUIC interop runner's test cases (github.com/quic-interop-runner), as far as they concern a server and can be
/// reproduced deterministically: the same scenarios over the virtual network, run in CI. Not covered here: chacha20
/// (we offer AES-GCM only), zerortt (refused by design), resumption, v2, ecn, and http3 (Phase 3).
/// </summary>
internal static class QuicInteropCases
{
    private static void Case(string name, Action body) => T.Add("quic interop case: " + name, () =>
    {
        if (QuicTls.Unavailable is not null) return;
        body();
    });

    public static void Register()
    {
        Case("handshake (a clean handshake and a small transfer)", () =>
        {
            using var net = new QuicNet();
            T.True(QuicConnectionTests.Echo(net, 10_000));
        });

        Case("transfer (several streams, 2 MiB in all)", () =>
        {
            using var net = new QuicNet();
            T.True(QuicConnectionTests.Echo(net, 512 << 10, streams: 4));
        });

        Case("multiconnect (many handshakes in a row, each through 30% loss)", () =>
        {
            for (int seed = 10; seed < 30; seed++)
            {
                using var net = new QuicNet(seed) { Loss = 0.3 };
                T.True(net.Run(() => net.Connected && net.Client.HandshakeConfirmed && net.Server!.HandshakeConfirmed));
            }
        });

        foreach (var (name, loss, corrupt) in new[] { ("handshakeloss (30% loss during the handshake)", 0.3, 0.0), ("handshakecorruption (30% corruption during the handshake)", 0.0, 0.3) })
            Case(name, () =>
            {
                // The runner's clients wait far longer than our 10 s default; so do we, here.
                var o = new QuicOptions { HandshakeTimeoutMs = 60_000 };
                for (int seed = 1; seed <= 10; seed++)
                {
                    QuicNet? n = null;
                    using var net = n = new QuicNet(seed, server: o, client: new QuicOptions { HandshakeTimeoutMs = 60_000 }) { Loss = loss, Corrupt = corrupt };
                    net.Impair = () => !(n.Client.HandshakeConfirmed && n.Server is { HandshakeConfirmed: true });
                    if (!QuicConnectionTests.Echo(net, 20_000))
                        throw new Exception($"seed {seed}: corrupted {net.Corrupted}, dropped {net.Dropped}, server {(net.Server is null ? "never created" : $"{net.Server.CloseCode} {net.Server.CloseReason} hs={net.Server.HandshakeComplete}")}, client {net.Client.CloseCode} {net.Client.CloseReason} hs={net.Client.HandshakeComplete}");
                }
            });

        Case("transferloss and transfercorruption (2% loss and 2% corruption, 1 MiB)", () =>
        {
            using var net = new QuicNet(seed: 5) { Loss = 0.02, Corrupt = 0.02, JitterUs = 5_000 };
            T.True(QuicConnectionTests.Echo(net, 1 << 20));
            T.True(net.Corrupted > 20);
            T.True(!net.Client.IsClosed && !net.Server!.IsClosed); // corruption is dropped, never a connection error
        });

        Case("keyupdate (the client updates keys during the transfer; the server follows)", () =>
        {
            using var net = new QuicNet(client: new QuicOptions { KeyUpdateAfter = 100 });
            T.True(QuicConnectionTests.Echo(net, 1 << 20));
            T.True(net.Client.KeyUpdates > 0 && net.Server!.KeyUpdates > 0);
        });

        Case("amplificationlimit (the server's first flight stays within 3x what it got, while the client's ACKs are lost)", () =>
        {
            using var net = new QuicNet();
            int clientDatagrams = 0;
            // Only the client's first Initial reaches the server; everything after is lost for a while.
            net.DropIf = (toServer, _) => toServer && ++clientDatagrams > 2 && net.Now < 1_500_000;
            long worst = 0;
            net.Run(() =>
            {
                if (net.Server is { AddressValidated: false } s) worst = Math.Max(worst, s.BytesSent - 3 * s.BytesReceived);
                return net.Now > 1_400_000;
            });
            T.True(worst <= 0);
            T.True(net.Run(() => net.Connected));
        });

        Case("portrebinding and addressrebinding (the client's NAT mapping changes mid-transfer)", () =>
        {
            foreach (var to in new EndPoint[] { new IPEndPoint(IPAddress.Parse("192.0.2.1"), 41234), new IPEndPoint(IPAddress.Parse("192.0.2.200"), 41234) })
            {
                using var net = new QuicNet();
                T.True(net.Run(() => net.Connected && net.Client.HandshakeConfirmed));
                long at = net.Now + 80_000;
                bool done = false;
                net.DropIf = (_, _) => { if (!done && net.Now >= at) { done = true; net.ClientAddress = to; } return false; };
                T.True(QuicConnectionTests.Echo(net, 1 << 20));
                T.Eq(to, net.Server!.Path);
            }
        });

        Case("retry and versionnegotiation (on real UDP: see the endpoint tests), and ipv6", () =>
        {
            using var s = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
            try { s.Bind(new IPEndPoint(IPAddress.IPv6Loopback, 0)); }
            catch (SocketException) { Console.WriteLine("    (skipped: no IPv6 loopback)"); return; }
            var dir = Directory.CreateTempSubdirectory("httpgrl-quic6-").FullName;
            try
            {
                ProxyTests.MakeCert("quic.test", dir, "q").Dispose();
                using var tls = QuicTlsContext.Server(Path.Combine(dir, "q.crt"), Path.Combine(dir, "q.key"), ["echo"]);
                using var ctls = QuicTlsContext.Client(Path.Combine(dir, "q.crt"));
                using var ep = new QuicEndpoint(s, tls, _ => tls, new QuicEndpointTests.EchoApp(), new QuicEndpointTests.ErrorCounter(), new QuicEndpointOptions { Retry = true });
                ep.Start();
                using var c = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
                c.Bind(new IPEndPoint(IPAddress.IPv6Loopback, 0));
                var conn = QuicConnection.Client(ctls, "quic.test", ["echo"], new QuicOptions(), QuicNet.Cids, s.LocalEndPoint!, QuicEndpoint.Now());
                var buf = new byte[65536];
                EndPoint from = new IPEndPoint(IPAddress.IPv6Any, 0);
                long id = -1;
                var back = new MemoryStream();
                bool fin = false;
                long until = Environment.TickCount64 + 10_000;
                while (!fin && Environment.TickCount64 < until)
                {
                    long now = QuicEndpoint.Now();
                    int n;
                    while ((n = conn.Send(buf, now, out _)) > 0) c.SendTo(buf.AsSpan(0, n), s.LocalEndPoint!);
                    if (conn.HandshakeComplete && id < 0) { id = conn.OpenStream(true); conn.StreamWrite(id, "over IPv6"u8, true); }
                    if (c.Poll(20_000, SelectMode.SelectRead)) { n = c.ReceiveFrom(buf, ref from); conn.Receive(buf.AsSpan(0, n), from, QuicEndpoint.Now()); }
                    if (conn.Deadline != 0 && conn.Deadline <= QuicEndpoint.Now()) conn.OnTimeout(QuicEndpoint.Now());
                    while (conn.TryGetEvent(out _)) { }
                    if (id >= 0) { while ((n = conn.StreamRead(id, buf, out bool f, out _)) > 0 | f) { back.Write(buf, 0, n); fin |= f; if (f) break; } }
                }
                T.Eq("over IPv6", System.Text.Encoding.ASCII.GetString(back.ToArray()));
                T.True(ep.Retries >= 1);
                conn.Dispose();
            }
            finally { Directory.Delete(dir, true); }
        });
    }
}
