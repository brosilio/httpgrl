using System.Net;
using System.Net.Sockets;
using Httpgrl.Core.Quic;

namespace Httpgrl.Tests;

/// <summary>The QUIC endpoint on real UDP sockets: routing, Retry, Version Negotiation, stateless resets.</summary>
internal static class QuicEndpointTests
{
    /// <summary>
    /// Echoes every stream back as it arrives, finishing when the client does. What a stream can't take yet waits in
    /// a backlog (up to 16 MB), and reading goes on meanwhile: a client that writes without reading (openssl
    /// s_client) would otherwise deadlock against our flow control.
    /// </summary>
    internal sealed class EchoApp : IQuicApplication
    {
        private const int MaxBacklog = 16 << 20;
        private readonly byte[] _buf = new byte[65536];
        private sealed class Backlog { public readonly Queue<byte[]> Chunks = new(); public int Off, Bytes; public bool Fin; }
        private readonly Dictionary<(QuicConnection, long), Backlog> _backlog = new();

        public void OnEvent(QuicConnection c, in QuicEvent e, long now)
        {
            if (e.Kind is not (QuicEventKind.StreamReadable or QuicEventKind.StreamWritable)) return;
            var key = (c, e.StreamId);
            if (!_backlog.TryGetValue(key, out var b)) _backlog[key] = b = new Backlog();
            int n;
            bool fin = false;
            while (b.Bytes < MaxBacklog && ((n = c.StreamRead(e.StreamId, _buf, out fin, out _)) > 0 | fin))
            {
                if (n > 0) { b.Chunks.Enqueue(_buf.AsSpan(0, n).ToArray()); b.Bytes += n; }
                if (fin) { b.Fin = true; break; }
            }
            while (b.Chunks.TryPeek(out var chunk))
            {
                bool last = b.Fin && b.Chunks.Count == 1;
                int w = c.StreamWrite(e.StreamId, chunk.AsSpan(b.Off), last);
                if (w < 0) { _backlog.Remove(key); return; }
                b.Off += w;
                b.Bytes -= w;
                if (b.Off < chunk.Length) return; // the stream is full: the rest when it says it's writable
                b.Chunks.Dequeue();
                b.Off = 0;
            }
            if (b.Fin)
            {
                c.StreamWrite(e.StreamId, default, fin: true); // an empty stream, or a FIN after the last chunk
                _backlog.Remove(key);
            }
        }
    }

    /// <summary>Our QUIC client on a UDP socket, run synchronously until a condition holds.</summary>
    internal sealed class UdpClient : IDisposable
    {
        public Socket Socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        public readonly QuicConnection C;
        private readonly EndPoint _server;
        private readonly byte[] _buf = new byte[65536];

        public UdpClient(EndPoint server, QuicTlsContext tls, string alpn = "echo", QuicOptions? o = null, string sni = "quic.test")
        {
            _server = server;
            Socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            C = QuicConnection.Client(tls, sni, [alpn], o ?? new QuicOptions(), QuicNet.Cids, server, QuicEndpoint.Now());
        }

        public void Rebind(string address)
        {
            Socket.Dispose();
            Socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            Socket.Bind(new IPEndPoint(IPAddress.Parse(address), 0));
        }

        public bool Run(Func<bool> done, int timeoutMs = 10_000)
        {
            long until = Environment.TickCount64 + timeoutMs;
            EndPoint from = new IPEndPoint(IPAddress.Any, 0);
            while (Environment.TickCount64 < until)
            {
                long now = QuicEndpoint.Now();
                int n;
                while ((n = C.Send(_buf, now, out _)) > 0) Socket.SendTo(_buf.AsSpan(0, n), _server);
                if (done()) return true;
                if (C.IsClosed) return done();
                long d = C.Deadline;
                int waitUs = (int)Math.Clamp(d == 0 ? 50_000 : d - now, 0, 50_000);
                if (Socket.Poll(waitUs, SelectMode.SelectRead))
                {
                    // Everything queued, then one round of sending and checking (not one per datagram).
                    for (int i = 0; i < 256 && (i == 0 || Socket.Available > 0); i++)
                    {
                        n = Socket.ReceiveFrom(_buf, ref from);
                        C.Receive(_buf.AsSpan(0, n), from, QuicEndpoint.Now());
                    }
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
        public string? LastEvent;
        public int Errors;
        public string? Last;
        public bool IsEnabled(LogLevel level) => level >= LogLevel.Warn;
        public void Write(LogLevel level, string msg, ReadOnlySpan<LogField> fields)
        {
            foreach (var field in fields) if (field.Key == "event") LastEvent = field.Str;
            if (level < LogLevel.Error) return;
            Errors++;
            Last = msg;
        }
    }

    private static bool Echo(UdpClient client, int size)
    {
        bool ok = EchoInner(client, size, out long back, out int written);
        if (!ok) Console.WriteLine($"    echo {size}: written {written}, back {back}, client {client.C.CloseCode} {client.C.CloseReason}");
        return ok;
    }

    private static bool EchoInner(UdpClient client, int size, out long backLen, out int writtenOut)
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
        }, timeoutMs: 20_000);
        backLen = back.Length;
        writtenOut = written;
        return ok && back.ToArray().AsSpan().SequenceEqual(data);
    }

    public static void Register()
    {
        T.Add("quic endpoint: migration enforces destination connection limit", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using var s = new Server(new QuicEndpointOptions { MaxConnectionsPerClient = 1 });
            using var first = new UdpClient(s.EndPoint, s.ClientTls);
            T.True(Echo(first, 1000));
            T.True(first.Run(() => first.C.HandshakeConfirmed));
            using var second = new UdpClient(s.EndPoint, s.ClientTls);
            second.Rebind("127.0.0.2");
            T.True(Echo(second, 1000));
            T.True(second.Run(() => second.C.HandshakeConfirmed));
            second.Rebind("127.0.0.1");
            long id = second.C.OpenStream(true);
            second.C.StreamWrite(id, "move"u8, true);
            T.True(second.Run(() => second.C.IsDraining || second.C.IsClosed, 5000));
            T.Eq(QuicError.NoViablePath, second.C.CloseCode);
            T.Eq("migration_limit_exceeded", s.Log.LastEvent);
            T.True(SpinUntil(() => s.Endpoint.Connections == 1, 5000));
            T.True(Echo(first, 1000));
            using var replacement = new UdpClient(s.EndPoint, s.ClientTls);
            replacement.Rebind("127.0.0.2");
            T.True(Echo(replacement, 1000)); // original address's accounting was released
            T.Eq(0, s.Log.Errors);
        });

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

        T.Add("quic endpoint: 4 MB echoed with 64 KB windows each way (back-pressure through the application), sent with GSO", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using var s = new Server();
            var small = new QuicOptions { StreamReceiveWindow = 64 << 10, ConnectionReceiveWindow = 128 << 10 };
            using var client = new UdpClient(s.EndPoint, s.ClientTls, o: small);
            T.True(Echo(client, 4 << 20));
            T.Eq(0, s.Log.Errors);
            // On Linux GSO is on and batches formed. Pacing sends one datagram per slot in steady state, so batches come
            // from bursts (the initial window at least): fewer sends than datagrams, by no fixed factor.
            if (OperatingSystem.IsLinux()) { T.True(s.Endpoint.GsoActive); T.True(s.Endpoint.SendCalls < s.Endpoint.DatagramsSent); }
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

        T.Add("quic endpoint: an Initial that doesn't authenticate creates no connection (garbage costs no TLS state)", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            using var s = new Server();
            using var raw = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            raw.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            var junk = new byte[1200];
            new Random(5).NextBytes(junk);
            Convert.FromHexString("c3000000010801020304050607080000449e").CopyTo(junk, 0); // a well-formed Initial header, random payload
            for (int i = 0; i < 50; i++) { junk[10] = (byte)i; raw.SendTo(junk, s.EndPoint); }
            T.True(!raw.Poll(300_000, SelectMode.SelectRead));
            T.Eq(0L, s.Endpoint.Accepted);
            T.Eq(0, s.Endpoint.Connections);
            T.True(s.Endpoint.Refused >= 50);
            // And a real client still gets in.
            using var client = new UdpClient(s.EndPoint, s.ClientTls);
            T.True(Echo(client, 1000));
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

/// <summary>--bench-quic [MiB] [repeat]: a loopback download through the endpoint (server-side throughput, the HTTP/3 case).</summary>
internal static class QuicBench
{
    /// <summary>Serves each stream's request ("N", in bytes) with N bytes, writing more as the stream drains.</summary>
    private sealed class DownloadApp : IQuicApplication
    {
        private readonly byte[] _chunk = new byte[256 << 10];
        private readonly Dictionary<(QuicConnection, long), long> _left = new();
        private readonly byte[] _buf = new byte[64];

        public void OnEvent(QuicConnection c, in QuicEvent e, long now)
        {
            var key = (c, e.StreamId);
            if (e.Kind == QuicEventKind.StreamReadable && !_left.ContainsKey(key))
            {
                int n = c.StreamRead(e.StreamId, _buf, out bool fin, out _);
                if (n > 0) _left[key] = long.Parse(System.Text.Encoding.ASCII.GetString(_buf, 0, n));
            }
            if (_left.TryGetValue(key, out long left) && left > 0)
            {
                while (left > 0)
                {
                    int w = c.StreamWrite(e.StreamId, _chunk.AsSpan(0, (int)Math.Min(_chunk.Length, left)), fin: left <= _chunk.Length);
                    if (w <= 0) break;
                    left -= w;
                }
                _left[key] = left;
            }
        }
    }

    /// <summary>CPU per thread, in jiffies (1/100 s): name/tid → utime + stime, from /proc.</summary>
    private static Dictionary<string, long> ThreadCpu()
    {
        var d = new Dictionary<string, long>();
        foreach (var t in Directory.GetDirectories("/proc/self/task"))
        {
            try
            {
                var comm = File.ReadAllText(Path.Combine(t, "comm")).Trim();
                var f = File.ReadAllText(Path.Combine(t, "stat"));
                var parts = f[(f.LastIndexOf(')') + 2)..].Split(' ');
                d[comm + "/" + Path.GetFileName(t)] = long.Parse(parts[11]) + long.Parse(parts[12]);
            }
            catch (IOException) { }
        }
        return d;
    }

    public static int RunCli(string[] args)
    {
        if (QuicTls.Unavailable is { } why) { Console.WriteLine(why); return 1; }
        long size = (args.Length > 1 ? long.Parse(args[1]) : 256) << 20;
        int repeat = args.Length > 2 ? int.Parse(args[2]) : 3;
        bool gso = !args.Contains("nogso");
        var dir = Directory.CreateTempSubdirectory("httpgrl-quic-bench-").FullName;
        ProxyTests.MakeCert("quic.test", dir, "q").Dispose();
        using var tls = QuicTlsContext.Server(Path.Combine(dir, "q.crt"), Path.Combine(dir, "q.key"), ["bench"]);
        using var ctls = QuicTlsContext.Client(Path.Combine(dir, "q.crt"));
        using var socket = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp);
        socket.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0));
        socket.ReceiveBufferSize = socket.SendBufferSize = 8 << 20;
        var o = new QuicOptions { StreamReceiveWindow = 16 << 20, ConnectionReceiveWindow = 32 << 20, StreamSendBuffer = 8 << 20 };
        using var ep = new QuicEndpoint(socket, tls, _ => tls, new DownloadApp(), new QuicEndpointTests.ErrorCounter(), new QuicEndpointOptions { Connection = o, Gso = gso });
        ep.Start();
        var before = ThreadCpu();
        for (int run = 0; run < repeat; run++)
        {
            using var client = new QuicEndpointTests.UdpClient(socket.LocalEndPoint!, ctls, "bench", o);
            client.Socket.ReceiveBufferSize = client.Socket.SendBufferSize = 8 << 20;
            long id = -1, got = 0;
            var buf = new byte[1 << 20];
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var cpu0 = Environment.ProcessorCount > 0 ? System.Diagnostics.Process.GetCurrentProcess().TotalProcessorTime : TimeSpan.Zero;
            bool ok = client.Run(() =>
            {
                var c = client.C;
                if (!c.HandshakeComplete) return false;
                if (id < 0) { id = c.OpenStream(true); c.StreamWrite(id, System.Text.Encoding.ASCII.GetBytes(size.ToString()), true); sw.Restart(); }
                while (c.TryGetEvent(out _)) { }
                int n;
                while ((n = c.StreamRead(id, buf, out bool fin, out _)) > 0) got += n;
                return got >= size;
            }, timeoutMs: 120_000);
            double s = sw.Elapsed.TotalSeconds;
            var cpu = System.Diagnostics.Process.GetCurrentProcess().TotalProcessorTime - cpu0;
            var threads = ThreadCpu();
            string top = string.Join(", ", threads.Where(t => t.Value - (before.TryGetValue(t.Key, out var b) ? b : 0) > s * 5)
                .Select(t => $"{t.Key} {(t.Value - (before.TryGetValue(t.Key, out var b) ? b : 0)) / s:F0}%"));
            before = threads;
            Console.WriteLine($"bench-quic: {got >> 20} MiB in {s:F2} s = {got / s / (1 << 20):F0} MiB/s ({got * 8 / s / 1e9:F2} Gb/s), process CPU {cpu.TotalSeconds / s * 100:F0}%, " +
                $"ok {ok}; gso {ep.GsoActive}, {ep.SendCalls} sends; threads: {top}");
            client.C.Close(0, "", QuicEndpoint.Now());
            client.Run(() => client.C.IsClosed, 1000);
        }
        return 0;
    }
}
