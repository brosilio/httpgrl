using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Httpgrl.Quic;

namespace Httpgrl.Tests;

/// <summary>
/// The QUIC client side as a library consumer uses it: the client endpoint over real UDP, server verification, a
/// pluggable TLS provider, Version Negotiation, and connections driven entirely by the caller's clock.
/// </summary>
internal static class QuicClientTests
{
    /// <summary>Per connection: sends <see cref="Payload"/> on one stream once connected, and collects the echo.</summary>
    private sealed class EchoClient(byte[] payload) : IQuicApplication
    {
        public readonly byte[] Payload = payload;
        public readonly ConcurrentDictionary<QuicConnection, MemoryStream> Echoed = new(ReferenceEqualityComparer.Instance);
        public readonly ConcurrentDictionary<QuicConnection, bool> Done = new(ReferenceEqualityComparer.Instance);
        public readonly ConcurrentDictionary<QuicConnection, bool> Connected = new(ReferenceEqualityComparer.Instance);
        public readonly ConcurrentDictionary<QuicConnection, bool> Gone = new(ReferenceEqualityComparer.Instance);
        private readonly Dictionary<QuicConnection, (long Id, int Sent)> _send = new(ReferenceEqualityComparer.Instance);
        private readonly byte[] _buf = new byte[65536];

        public void OnEvent(QuicConnection c, in QuicEvent e, long now)
        {
            switch (e.Kind)
            {
                case QuicEventKind.Connected:
                    Connected[c] = true;
                    if (Payload.Length == 0) return;
                    _send[c] = (c.OpenStream(bidi: true), 0);
                    Write(c);
                    break;
                case QuicEventKind.StreamWritable: Write(c); break;
                case QuicEventKind.StreamReadable:
                {
                    var ms = Echoed.GetOrAdd(c, _ => new MemoryStream());
                    int n;
                    while ((n = c.StreamRead(e.StreamId, _buf, out bool fin, out _)) > 0 || fin)
                    {
                        ms.Write(_buf, 0, n);
                        if (fin) { Done[c] = true; break; }
                    }
                    break;
                }
            }
        }

        private void Write(QuicConnection c)
        {
            if (!_send.TryGetValue(c, out var s) || s.Sent == Payload.Length) return;
            int n = c.StreamWrite(s.Id, Payload.AsSpan(s.Sent), fin: true);
            if (n > 0) _send[c] = (s.Id, s.Sent + n);
        }

        public void Closed(QuicConnection c) => Gone[c] = true;
    }

    private static bool WaitFor(Func<bool> cond, int ms = 10_000)
    {
        long until = Environment.TickCount64 + ms;
        while (!cond())
        {
            if (Environment.TickCount64 > until) return cond();
            Thread.Sleep(5);
        }
        return true;
    }

    /// <summary>Wraps another provider's contexts and sessions, counting what QUIC asks of them.</summary>
    private sealed class CountingTls(QuicTlsContext inner) : QuicTlsContext
    {
        public readonly QuicTlsContext Inner = inner;
        public int Sessions, Receives, Advances;

        public override IQuicTlsSession CreateServerSession(Func<string?, QuicTlsContext?> selectServer, IQuicTlsHost host)
        {
            Interlocked.Increment(ref Sessions);
            return new Session(Inner.CreateServerSession(sni => selectServer(sni) is CountingTls t ? t.Inner : null, host), this);
        }

        public override IQuicTlsSession CreateClientSession(string serverName, string[] alpn, byte[] transportParameters, IQuicTlsHost host)
        {
            Interlocked.Increment(ref Sessions);
            return new Session(Inner.CreateClientSession(serverName, alpn, transportParameters, host), this);
        }

        public override void Dispose() => Inner.Dispose();

        private sealed class Session(IQuicTlsSession s, CountingTls owner) : IQuicTlsSession
        {
            public bool HandshakeComplete => s.HandshakeComplete;
            public QuicError? Error => s.Error;
            public string? ErrorReason => s.ErrorReason;
            public string? ServerName => s.ServerName;
            public string? Alpn => s.Alpn;
            public QuicTlsContext Context => owner;
            public X509Certificate2? PeerCertificate => s.PeerCertificate;
            public X509Certificate2Collection PeerChain => s.PeerChain;
            public void Receive(QuicLevel level, ReadOnlySpan<byte> data) { Interlocked.Increment(ref owner.Receives); s.Receive(level, data); }
            public bool Advance() { Interlocked.Increment(ref owner.Advances); return s.Advance(); }
            public void Dispose() => s.Dispose();
        }
    }

    public static void Register()
    {
        T.Add("quic client endpoint: three connections share one socket, each echoes 200 KB, and are forgotten once closed", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using var s = new QuicEndpointTests.Server();
            var payload = new byte[200_000];
            new Random(7).NextBytes(payload);
            var app = new EchoClient(payload);
            using var ep = new QuicClientEndpoint(app);
            ep.Start();
            var server = new IPEndPoint(IPAddress.Loopback, ((IPEndPoint)s.EndPoint).Port);
            var conns = Enumerable.Range(0, 3).Select(_ => ep.Connect(server, "quic.test", ["echo"], s.ClientTls)).ToArray();
            T.True(WaitFor(() => conns.All(c => app.Done.ContainsKey(c))), "all echoes complete");
            foreach (var c in conns) T.True(app.Echoed[c].ToArray().AsSpan().SequenceEqual(payload), "echo matches");
            T.Eq(3, s.Endpoint.Connections);
            foreach (var c in conns) ep.Run(c, q => q.Close(0, "done", QuicClock.Now()));
            T.True(WaitFor(() => ep.Connections == 0 && conns.All(c => app.Gone.ContainsKey(c))), "client forgets closed connections");
            T.True(WaitFor(() => s.Endpoint.Connections == 0), "server forgets them too");
        });

        T.Add("quic client endpoint: dual-stack socket reaches an IPv4 server, and the path stays IPv4 (no spurious migration)", () =>
        {
            if (QuicTls.Unavailable is not null || !Socket.OSSupportsIPv6) return;
            using var s = new QuicEndpointTests.Server();
            var app = new EchoClient([1, 2, 3]);
            using var ep = new QuicClientEndpoint(app); // [::]:0, dual mode
            ep.Start();
            var c = ep.Connect(new IPEndPoint(IPAddress.Loopback.MapToIPv6(), ((IPEndPoint)s.EndPoint).Port), "quic.test", ["echo"], s.ClientTls);
            T.True(WaitFor(() => app.Done.ContainsKey(c)));
            T.Eq(AddressFamily.InterNetwork, ((IPEndPoint)c.Path).AddressFamily);
            T.Eq(0, c.Migrations);
        });

        T.Add("quic client: the server is verified by default: wrong name, untrusted CA, system roots for a private CA and no common ALPN all fail the handshake", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using var s = new QuicEndpointTests.Server();
            var server = new IPEndPoint(IPAddress.Loopback, ((IPEndPoint)s.EndPoint).Port);
            ProxyTests.MakeCert("other.test", s.Dir, "o").Dispose();
            using var otherCa = QuicTlsContext.Client(Path.Combine(s.Dir, "o.crt"));
            using var systemRoots = QuicTlsContext.Client();
            var app = new EchoClient([]);
            using var ep = new QuicClientEndpoint(app);
            ep.Start();
            var cases = new (string Why, QuicConnection C)[]
            {
                ("name mismatch", ep.Connect(server, "not-quic.test", ["echo"], s.ClientTls)),
                ("untrusted CA", ep.Connect(server, "quic.test", ["echo"], otherCa)),
                ("system roots don't know a private CA", ep.Connect(server, "quic.test", ["echo"], systemRoots)),
                ("no common ALPN", ep.Connect(server, "quic.test", ["h3"], s.ClientTls)),
            };
            foreach (var (why, c) in cases)
            {
                T.True(WaitFor(() => app.Gone.ContainsKey(c)), why + ": closed");
                T.True(!app.Connected.ContainsKey(c), why + ": never connected");
                T.True(c.CloseCode is >= QuicError.CryptoError and <= QuicError.CryptoError + 255, why + ": closed with a TLS alert, got " + c.CloseCode);
            }
        });

        T.Add("quic client: verification can be turned off only explicitly (ClientWithoutVerification connects to an unknown server)", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using var s = new QuicEndpointTests.Server();
            using var insecure = QuicTlsContext.ClientWithoutVerification();
            var app = new EchoClient([9]);
            using var ep = new QuicClientEndpoint(app);
            ep.Start();
            var c = ep.Connect(new IPEndPoint(IPAddress.Loopback, ((IPEndPoint)s.EndPoint).Port), "anything.example", ["echo"], insecure);
            T.True(WaitFor(() => app.Done.ContainsKey(c)));
        });

        T.Add("quic tls: a third-party provider (QuicTlsContext subclass) drives both handshakes, and the endpoints never know", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            var dir = Directory.CreateTempSubdirectory("httpgrl-quictlsprov-").FullName;
            try
            {
                ProxyTests.MakeCert("quic.test", dir, "q").Dispose();
                using var serverTls = new CountingTls(QuicTlsContext.Server(Path.Combine(dir, "q.crt"), Path.Combine(dir, "q.key"), ["echo"]));
                using var clientTls = new CountingTls(QuicTlsContext.Client(Path.Combine(dir, "q.crt")));
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                using var sep = new QuicEndpoint(socket, serverTls, _ => serverTls, new QuicEndpointTests.EchoApp(), NullQuicLog.Instance);
                sep.Start();
                var app = new EchoClient(new byte[50_000]);
                using var ep = new QuicClientEndpoint(app);
                ep.Start();
                var c = ep.Connect(socket.LocalEndPoint!, "quic.test", ["echo"], clientTls);
                T.True(WaitFor(() => app.Done.ContainsKey(c)));
                T.Eq(50_000, (int)app.Echoed[c].Length);
                T.Eq(1, serverTls.Sessions);
                T.Eq(1, clientTls.Sessions);
                T.True(serverTls.Receives > 0 && serverTls.Advances > 0 && clientTls.Receives > 0 && clientTls.Advances > 0);
                T.True(ReferenceEquals(c.TlsContext, clientTls), "the connection reports the provider's context");
            }
            finally { try { Directory.Delete(dir, true); } catch (IOException) { } }
        });

        T.Add("quic tls: the OpenSSL provider refuses a context of another provider picked by SNI (no handshake under a foreign context)", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            var dir = Directory.CreateTempSubdirectory("httpgrl-quictlsprov-").FullName;
            try
            {
                ProxyTests.MakeCert("quic.test", dir, "q").Dispose();
                using var openssl = QuicTlsContext.Server(Path.Combine(dir, "q.crt"), Path.Combine(dir, "q.key"), ["echo"]);
                using var foreign = new CountingTls(QuicTlsContext.Server(Path.Combine(dir, "q.crt"), Path.Combine(dir, "q.key"), ["echo"]));
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                using var sep = new QuicEndpoint(socket, openssl, _ => foreign, new QuicEndpointTests.EchoApp(), NullQuicLog.Instance);
                sep.Start();
                using var ctls = QuicTlsContext.Client(Path.Combine(dir, "q.crt"));
                var app = new EchoClient([1]);
                using var ep = new QuicClientEndpoint(app);
                ep.Start();
                var c = ep.Connect(socket.LocalEndPoint!, "quic.test", ["echo"], ctls);
                T.True(WaitFor(() => app.Gone.ContainsKey(c)));
                T.True(!app.Connected.ContainsKey(c));
            }
            finally { try { Directory.Delete(dir, true); } catch (IOException) { } }
        });

        T.Add("quic openssl: library names are per platform, and can't change once OpenSSL is loaded", () =>
        {
            var (ssl, crypto) = QuicOpenSsl.Names;
            if (OperatingSystem.IsLinux()) { T.Eq("libssl.so.3", ssl); T.Eq("libcrypto.so.3", crypto); }
            if (QuicTls.Unavailable is not null) return; // that loaded it (or tried)
            T.Throws<InvalidOperationException>(() => QuicOpenSsl.UseLibraries("libssl.so.99", "libcrypto.so.99"));
            T.Eq(ssl, QuicOpenSsl.Names.Ssl);
        });

        T.Add("quic client: Version Negotiation ends the attempt only when it echoes our IDs and leaves out v1; anything else is ignored", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using var net = new QuicNet();
            var c = net.Client;
            var buf = new byte[1500];
            c.Send(buf, net.Now, out _); // the first Initial goes out
            byte[] Vn(ReadOnlySpan<byte> dcid, ReadOnlySpan<byte> scid, params uint[] versions)
            {
                var d = new List<byte> { 0x80, 0, 0, 0, 0, (byte)dcid.Length };
                d.AddRange(dcid.ToArray());
                d.Add((byte)scid.Length);
                d.AddRange(scid.ToArray());
                foreach (var v in versions) d.AddRange([(byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v]);
                return [.. d];
            }
            // Ours echoes the client's IDs swapped: DCID = client's SCID, SCID = client's DCID.
            c.Receive(Vn(c.SourceCid, c.DestinationCid, 1, 0xff00001d), net.ServerAddress, net.Now);
            T.True(!c.IsClosed && !c.IsDraining, "a VN listing v1 is ignored");
            c.Receive(Vn([9, 9, 9, 9, 9, 9, 9, 9], c.DestinationCid, 0xff00001d), net.ServerAddress, net.Now);
            T.True(!c.IsClosed && !c.IsDraining, "a VN not for our SCID is ignored");
            c.Receive(Vn(c.SourceCid, [7, 7, 7, 7, 7, 7, 7, 7], 0xff00001d), net.ServerAddress, net.Now);
            T.True(!c.IsClosed && !c.IsDraining, "a VN not echoing our DCID is ignored");
            c.Receive([.. Vn(c.SourceCid, c.DestinationCid), 1, 2], net.ServerAddress, net.Now);
            T.True(!c.IsClosed && !c.IsDraining, "a malformed version list is ignored");
            c.Receive(Vn(c.SourceCid, c.DestinationCid, 0xff00001d, 0x6b3343cf), net.ServerAddress, net.Now);
            T.Eq(QuicError.ConnectionRefused, c.CloseCode);

            // After the server has spoken, no VN counts.
            using var net2 = new QuicNet();
            T.True(net2.Run(() => net2.Connected));
            var c2 = net2.Client;
            c2.Receive(Vn(c2.SourceCid, c2.DestinationCid, 0xff00001d), net2.ServerAddress, net2.Now);
            T.True(!c2.IsClosed && !c2.IsDraining, "a VN after the handshake is ignored");
        });

        T.Add("quic connection: runs only on the caller's clock (handshake, PTO probes and the idle timeout far from the process clock)", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            // Days ahead of the process clock: anything reading a real clock would see a huge jump (or none at all).
            using var net = new QuicNet(server: new QuicOptions { MaxIdleTimeoutMs = 5000 }, client: new QuicOptions { MaxIdleTimeoutMs = 5000 }, start: 400_000_000_000L);
            long realStart = QuicClock.Now();
            T.True(net.Run(() => net.Connected && net.Server!.HandshakeConfirmed));
            // A lost flight: probes go out on the virtual clock (no real time needed).
            net.Loss = 1;
            long before = net.Client.BytesSent;
            long t0 = net.Now;
            net.Client.StreamWrite(net.Client.OpenStream(bidi: true), new byte[100], fin: false);
            net.Run(() => net.Client.BytesSent > before + 300, maxUs: 3_000_000);
            T.True(net.Client.BytesSent > before + 300, "retransmitted (PTO) on the virtual clock");
            // Silence: both sides time out at the negotiated idle timeout of virtual time.
            T.True(net.Run(() => net.Client.IsClosed && net.Server!.IsClosed, maxUs: 30_000_000));
            long idle = net.Now - t0;
            T.True(idle >= 5_000_000 && idle < 7_000_000, "idle timeout after ~5 s of virtual time, took " + idle + " us");
            T.True(QuicClock.Now() - realStart < 5_000_000, "and well under 5 s of real time");
        });
    }
}
