using System.Net;
using System.Net.Sockets;
using Httpgrl.Core.Quic;

namespace Httpgrl.Tests;

/// <summary>The QUIC endpoint on real UDP sockets: routing, Retry, Version Negotiation, stateless resets.</summary>
internal static class QuicEndpointTests
{
    /// <summary>Echoes every stream back as it arrives, finishing when the client does.</summary>
    internal sealed class EchoApp : IQuicApplication
    {
        private readonly byte[] _buf = new byte[65536];
        public void OnEvent(QuicConnection c, in QuicEvent e, long now)
        {
            if (e.Kind != QuicEventKind.StreamReadable) return;
            int n;
            bool fin;
            while ((n = c.StreamRead(e.StreamId, _buf, out fin, out _)) > 0 | fin)
            {
                c.StreamWrite(e.StreamId, _buf.AsSpan(0, n), fin);
                if (fin) break;
            }
        }
    }

    /// <summary>Our QUIC client on a UDP socket, run synchronously until a condition holds.</summary>
    internal sealed class UdpClient : IDisposable
    {
        public readonly Socket Socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        public readonly QuicConnection C;
        private readonly EndPoint _server;
        private readonly byte[] _buf = new byte[65536];

        public UdpClient(EndPoint server, QuicTlsContext tls, string alpn = "echo", QuicOptions? o = null)
        {
            _server = server;
            Socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            C = QuicConnection.Client(tls, "quic.test", [alpn], o ?? new QuicOptions(), QuicNet.Cids, QuicEndpoint.Now());
        }

        public bool Run(Func<bool> done, int timeoutMs = 10_000)
        {
            long until = Environment.TickCount64 + timeoutMs;
            EndPoint from = new IPEndPoint(IPAddress.Any, 0);
            while (Environment.TickCount64 < until)
            {
                long now = QuicEndpoint.Now();
                int n;
                while ((n = C.Send(_buf, now)) > 0) Socket.SendTo(_buf.AsSpan(0, n), _server);
                if (done()) return true;
                if (C.IsClosed) return done();
                long d = C.Deadline;
                int waitUs = (int)Math.Clamp(d == 0 ? 50_000 : d - now, 0, 50_000);
                if (Socket.Poll(waitUs, SelectMode.SelectRead))
                {
                    n = Socket.ReceiveFrom(_buf, ref from);
                    C.Receive(_buf.AsSpan(0, n), QuicEndpoint.Now());
                }
                now = QuicEndpoint.Now();
                if (C.Deadline != 0 && C.Deadline <= now) C.OnTimeout(now);
            }
            return done();
        }

        public void Dispose()
        {
            C.Dispose();
            Socket.Dispose();
        }
    }

    internal sealed class Server : IDisposable
    {
        public readonly string Dir = Directory.CreateTempSubdirectory("httpgrl-quicep-").FullName;
        public readonly Socket Socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        public readonly QuicTlsContext Tls, ClientTls;
        public readonly QuicEndpoint Endpoint;
        public readonly ErrorCounter Log = new();
        public EndPoint EndPoint => Socket.LocalEndPoint!;

        public Server(QuicEndpointOptions? o = null, string alpn = "echo")
        {
            ProxyTests.MakeCert("quic.test", Dir, "q").Dispose();
            Tls = QuicTlsContext.Server(Path.Combine(Dir, "q.crt"), Path.Combine(Dir, "q.key"), [alpn]);
            ClientTls = QuicTlsContext.Client(Path.Combine(Dir, "q.crt"));
            Socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            Endpoint = new QuicEndpoint(Socket, Tls, _ => Tls, new EchoApp(), Log, o);
            Endpoint.Start();
        }

        public void Dispose()
        {
            Endpoint.Dispose();
            Socket.Dispose();
            ClientTls.Dispose();
            Tls.Dispose();
            try { Directory.Delete(Dir, true); } catch (IOException) { }
        }
    }

    /// <summary>Counts error-level lines (an endpoint must never log one in these tests).</summary>
    internal sealed class ErrorCounter : ILogger
    {
        public int Errors;
        public string? Last;
        public bool IsEnabled(LogLevel level) => level >= LogLevel.Warn;
        public void Write(LogLevel level, string msg, ReadOnlySpan<LogField> fields)
        {
            if (level < LogLevel.Error) return;
            Errors++;
            Last = msg;
        }
    }

    private static bool Echo(UdpClient client, int size)
    {
        var data = new byte[size];
        new Random(size).NextBytes(data);
        long id = -1;
        int written = 0;
        var back = new MemoryStream();
        var buf = new byte[65536];
        bool fin = false;
        bool ok = client.Run(() =>
        {
            var c = client.C;
            if (!c.HandshakeComplete) return false;
            if (id < 0 && (id = c.OpenStream(true)) < 0) return false;
            if (written < size) { int n = c.StreamWrite(id, data.AsSpan(written), true); if (n > 0) written += n; }
            while (c.TryGetEvent(out _)) { }
            int m;
            bool f;
            while ((m = c.StreamRead(id, buf, out f, out _)) > 0 | f) { back.Write(buf, 0, m); fin |= f; if (f) break; }
            return fin;
        });
        return ok && back.ToArray().AsSpan().SequenceEqual(data);
    }

    public static void Register()
    {
        T.Add("quic endpoint: a client connects over UDP and echoes 300 KB; the endpoint forgets the connection when it closes", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using var s = new Server();
            using var client = new UdpClient(s.EndPoint, s.ClientTls);
            T.True(Echo(client, 300_000));
            T.Eq(1L, s.Endpoint.Accepted);
            client.C.Close(0, "done", QuicEndpoint.Now());
            T.True(client.Run(() => client.C.IsClosed));
            T.True(SpinUntil(() => s.Endpoint.Connections == 0, 5000));
            T.Eq(0, s.Log.Errors);
        });

        T.Add("quic endpoint: with Retry on, the client is validated first; a forged token makes no connection", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using var s = new Server(new QuicEndpointOptions { Retry = true });
            using (var client = new UdpClient(s.EndPoint, s.ClientTls))
                T.True(Echo(client, 10_000));
            // A post-quantum ClientHello (X25519MLKEM768) spans two Initials: each gets a Retry; the client uses the first.
            T.True(s.Endpoint.Retries >= 1);
            T.Eq(1L, s.Endpoint.Accepted);

            // An Initial carrying a token that isn't ours: dropped, no state, no reply.
            using var raw = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            raw.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            var initial = new byte[1200];
            int p = 0;
            initial[p++] = 0xC3;
            initial[p++] = 0; initial[p++] = 0; initial[p++] = 0; initial[p++] = 1;
            initial[p++] = 8; p += 8;
            initial[p++] = 0;
            initial[p++] = 40; p += 40; // a 40-byte token of zeros
            initial[p++] = 0x44; initial[p++] = 0x00;
            raw.SendTo(initial, s.EndPoint);
            T.True(!raw.Poll(300_000, SelectMode.SelectRead));
            T.Eq(1L, s.Endpoint.Accepted);
            T.True(s.Endpoint.Refused >= 1);
        });

        T.Add("quic endpoint: unknown versions get Version Negotiation (v1); small or version-0 packets get nothing", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using var s = new Server();
            using var raw = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            raw.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            var pkt = new byte[1200];
            Convert.FromHexString("c00a0a0a0a" + "08" + "0102030405060708" + "04" + "a1a2a3a4").CopyTo(pkt, 0);
            raw.SendTo(pkt, s.EndPoint);
            T.True(raw.Poll(2_000_000, SelectMode.SelectRead));
            var buf = new byte[1500];
            int n = raw.Receive(buf);
            T.Eq("00000000" + "04a1a2a3a4" + "080102030405060708" + "00000001", Convert.ToHexStringLower(buf.AsSpan(1, n - 1)));
            T.True((buf[0] & 0x80) != 0);
            raw.SendTo(pkt.AsSpan(0, 600), s.EndPoint); // too small to be a first flight
            T.True(!raw.Poll(300_000, SelectMode.SelectRead));
        });

        T.Add("quic endpoint: unknown connection IDs get a smaller stateless reset; a client whose server forgot it notices", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using var s = new Server();
            using var raw = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            raw.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            var pkt = new byte[100];
            new Random(1).NextBytes(pkt);
            pkt[0] = 0x41;
            raw.SendTo(pkt, s.EndPoint);
            T.True(raw.Poll(2_000_000, SelectMode.SelectRead));
            var buf = new byte[1500];
            int n = raw.Receive(buf);
            T.True(n is < 100 and >= 22);
            T.True((buf[0] & 0xC0) == 0x40); // looks like a short header
            raw.SendTo(pkt.AsSpan(0, 21), s.EndPoint); // too small to answer with something smaller
            T.True(!raw.Poll(300_000, SelectMode.SelectRead));

            using var client = new UdpClient(s.EndPoint, s.ClientTls);
            T.True(Echo(client, 1000));
            s.Endpoint.ForgetAll();
            T.True(SpinUntil(() => s.Endpoint.Connections == 0, 5000));
            long id = client.C.OpenStream(true);
            client.C.StreamWrite(id, "anyone there?"u8, true);
            T.True(client.Run(() => client.C.IsClosed, 5000));
            T.Eq("stateless reset", client.C.CloseReason);
        });
    }

    /// <summary>
    /// --quic-echo [port] [retry]: an echo server for interop checks with other QUIC implementations (openssl s_client
    /// -quic, curl's ngtcp2). Prints its port and the certificate to trust, logs to stdout, runs until killed.
    /// </summary>
    public static int RunEchoCli(string[] args)
    {
        if (QuicTls.Unavailable is { } why) { Console.WriteLine(why); return 1; }
        int port = args.Length > 1 ? int.Parse(args[1]) : 0;
        var o = new QuicEndpointOptions { Retry = args.Contains("retry") };
        var dir = Directory.CreateTempSubdirectory("httpgrl-quic-echo-").FullName;
        ProxyTests.MakeCert("quic.test", dir, "q").Dispose();
        using var tls = QuicTlsContext.Server(Path.Combine(dir, "q.crt"), Path.Combine(dir, "q.key"), ["echo"]);
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, port));
        using var log = new Httpgrl.Core.Logging.JsonLogger(Console.OpenStandardOutput(), LogLevel.Debug);
        using var ep = new QuicEndpoint(socket, tls, _ => tls, new EchoApp(), log, o);
        ep.Start();
        Console.WriteLine($"quic echo on {socket.LocalEndPoint}, ALPN echo, trust {Path.Combine(dir, "q.crt")}");
        Thread.Sleep(Timeout.Infinite);
        return 0;
    }

    private static bool SpinUntil(Func<bool> f, int ms)
    {
        long until = Environment.TickCount64 + ms;
        while (!f()) { if (Environment.TickCount64 > until) return false; Thread.Sleep(10); }
        return true;
    }
}
