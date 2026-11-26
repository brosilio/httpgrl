using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Text;

namespace Httpgrl.Tests;

/// <summary>
/// Soak test (Linux): runs the real server binary as a child process for a while under mixed traffic and abuse,
/// reloading it every few seconds, and checks it doesn't leak (file descriptors, memory), log errors, stop serving
/// or fail to shut down cleanly.
///
///   dotnet run -c Release --project tests/Httpgrl.Tests -- --soak artifacts/linux-x64/httpgrl 300
/// </summary>
internal static class Soak
{
    private sealed class Stats
    {
        public long Ok, Limited, Failed, Ws, Abuse, H2, H2Ws, H3, H3Reconnects;
        public readonly System.Collections.Concurrent.ConcurrentDictionary<string, long> Errors = new();
        public void Fail(string what) { Interlocked.Increment(ref Failed); Errors.AddOrUpdate(what, 1, (_, n) => n + 1); }
    }

    public static int RunCli(string[] args)
    {
        if (!OperatingSystem.IsLinux()) { Console.WriteLine("soak: Linux only (reads /proc)"); return 2; }
        var binary = Path.GetFullPath(args.Length > 1 ? args[1] : "artifacts/linux-x64/httpgrl");
        int seconds = args.Length > 2 ? int.Parse(args[2]) : 60;
        bool reload = !args.Contains("--no-reload");
        return RunAsync(binary, seconds, reload).GetAwaiter().GetResult();
    }

    private static async Task<int> RunAsync(string binary, int seconds, bool reload)
    {
        var dir = Path.Combine(Path.GetTempPath(), "httpgrl-soak-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(Path.Combine(dir, "www"));
        File.WriteAllText(Path.Combine(dir, "www", "small.txt"), "hello");
        File.WriteAllBytes(Path.Combine(dir, "www", "big.bin"), new byte[1 << 20]);
        File.WriteAllText(Path.Combine(dir, "www", "text.txt"), string.Concat(Enumerable.Range(0, 20_000).Select(i => $"row {i} {i * 7919 % 10007}\n")));
        File.WriteAllText(Path.Combine(dir, "www", "limited"), "limited");

        await using var up = FakeUpstream.Echo();
        await using var wsUp = FakeUpstream.WebSocketEcho();
        int port = FreePort(), h2port = FreePort();
        ProxyTests.MakeCert("soak.test", dir, "soak");
        var conf = Path.Combine(dir, "httpgrl.conf");
        File.WriteAllText(conf, $$"""
            {{(Environment.GetEnvironmentVariable("SOAK_LOG") is { Length: > 0 } ? "error_log stderr debug;" : "")}}
            worker_shutdown_timeout 3s; reload_drain_timeout 4s;
            events { worker_connections 4096; connections_per_client 4096; }
            http {
              access_log off;
              gzip on; brotli on; gzip_types *;
              limit_req_zone $remote_net zone=lim:1m rate=50r/s;
              limit_conn_zone $remote_net zone=conn:1m;
              upstream up { server 127.0.0.1:{{up.Port}}; keepalive 32; }
              add_header X-Soak yes always;
              server {
                listen 127.0.0.1:{{port}};
                root {{dir}}/www;
                client_header_timeout 3s; client_body_timeout 3s; send_timeout 5s;
                location / { }
                location /proxy/ { proxy_pass http://up/; }
                location /ws { proxy_pass http://127.0.0.1:{{wsUp.Port}}; proxy_read_timeout 10s; }
                location = /limited { limit_req zone=lim burst=20 nodelay; }
                location = /status.json { stub_status json; allow 127.0.0.1; deny all; }
                location /set { set $v "$arg_x"; if ($v ~ "^(\d+)$") { return 200 "n=$1"; } return 200 "s=$v"; }
              }
              server {
                listen 127.0.0.1:{{h2port}} ssl; listen 127.0.0.1:{{h2port}} quic; server_name soak.test; http2 on; http3 on;
                ssl_certificate {{dir}}/soak.crt; ssl_certificate_key {{dir}}/soak.key;
                root {{dir}}/www;
                client_header_timeout 3s; client_body_timeout 3s; send_timeout 5s;
                location / { }
                location /proxy/ { proxy_pass http://up/; }
                location /ws { proxy_pass http://127.0.0.1:{{wsUp.Port}}; proxy_read_timeout 10s; }
                location = /limited { limit_req zone=lim burst=20 nodelay; }
                location /set { set $v "$arg_x"; if ($v ~ "^(\d+)$") { return 200 "n=$1"; } return 200 "s=$v"; }
              }
            }
            """);

        var psi = new ProcessStartInfo(binary, ["-c", conf]) { RedirectStandardOutput = true, RedirectStandardError = true };
        using var server = Process.Start(psi)!;
        var log = new StringBuilder();
        long errorLines = 0;
        // SOAK_LOG=file keeps every server line, for chasing a failure.
        using var all = Environment.GetEnvironmentVariable("SOAK_LOG") is { Length: > 0 } f ? new StreamWriter(f) : null;
        server.OutputDataReceived += (_, e) =>
        {
            if (e.Data is null) return;
            if (all is not null) lock (all) all.WriteLine(e.Data);
            if (e.Data.Contains("\"level\":\"error\"", StringComparison.Ordinal))
            {
                Interlocked.Increment(ref errorLines);
                lock (log) if (log.Length < 20_000) log.AppendLine(e.Data);
            }
        };
        server.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is null) return;
            if (all is not null) lock (all) all.WriteLine(e.Data);
            else lock (log) log.AppendLine("stderr: " + e.Data);
        };
        server.BeginOutputReadLine();
        server.BeginErrorReadLine();
        int pid = server.Id;
        Console.WriteLine($"soak: pid {pid}, port {port}, {seconds}s");

        using var http = new HttpClient(new SocketsHttpHandler { AutomaticDecompression = System.Net.DecompressionMethods.All, MaxConnectionsPerServer = 64, PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30) })
        { BaseAddress = new Uri($"http://127.0.0.1:{port}/"), Timeout = TimeSpan.FromSeconds(15) };
        for (int k = 0; k < 50 && !await Up(http); k++) await Task.Delay(100);

        var stats = new Stats();
        using var stop = new CancellationTokenSource();
        var workers = new List<Task>();
        for (int k = 0; k < 48; k++) workers.Add(Traffic(http, stats, k, stop.Token));
        // HTTP/2: one multiplexed connection pool, its own traffic and WebSockets over HTTP/2.
        var h2Handler = new SocketsHttpHandler
        {
            AutomaticDecompression = System.Net.DecompressionMethods.All,
            SslOptions = { RemoteCertificateValidationCallback = (_, _, _, _) => true, TargetHost = "soak.test" },
            EnableMultipleHttp2Connections = true,
        };
        using var h2 = new HttpClient(h2Handler)
        {
            BaseAddress = new Uri($"https://127.0.0.1:{h2port}/"), Timeout = TimeSpan.FromSeconds(15),
            DefaultRequestVersion = System.Net.HttpVersion.Version20, DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
        for (int k = 0; k < 24; k++) workers.Add(Traffic(h2, stats, 100 + k, stop.Token, http2: true));
        for (int k = 0; k < 2; k++) workers.Add(WebSockets(h2port, stats, stop.Token, http2: true));
        // HTTP/3: a few connections of our own client, each on its own thread, reconnecting after a reload's GOAWAY.
        if (Httpgrl.Quic.QuicTls.Unavailable is null)
            for (int k = 0; k < 6; k++)
            {
                int id = 200 + k;
                workers.Add(Task.Factory.StartNew(() => Http3Traffic(h2port, Path.Combine(dir, "soak.crt"), stats, id, stop.Token), TaskCreationOptions.LongRunning));
            }
        for (int k = 0; k < 4; k++) workers.Add(WebSockets(port, stats, stop.Token));
        for (int k = 0; k < 8; k++) workers.Add(Abuse(port, stats, k, stop.Token));

        // Warm up, then take the baseline.
        await Task.Delay(TimeSpan.FromSeconds(Math.Min(10, seconds / 5.0)));
        var (rss0, fd0, th0) = Sample(pid);
        Console.WriteLine($"soak: baseline rss {rss0 / 1024} MB, fds {fd0}, threads {th0}");
        long peakRss = rss0;
        var sw = Stopwatch.StartNew();
        int ticks = 0, reloads = 0;
        while (sw.Elapsed.TotalSeconds < seconds)
        {
            await Task.Delay(2000);
            if (++ticks % 2 == 0 && reload) { Process.Start("kill", ["-HUP", pid.ToString()])!.WaitForExit(); reloads++; }
            var (rss, fd, th) = Sample(pid);
            peakRss = Math.Max(peakRss, rss);
            var mem = await Memory(http);
            Console.WriteLine($"soak: t={sw.Elapsed.TotalSeconds:F0}s rss {rss / 1024} MB {mem} fds {fd} threads {th} ok {stats.Ok} (h2 {stats.H2}, h3 {stats.H3}) limited {stats.Limited} ws {stats.Ws} (h2 {stats.H2Ws}) abuse {stats.Abuse} failed {stats.Failed}");
        }
        stop.Cancel();
        try { await Task.WhenAll(workers); } catch (OperationCanceledException) { }
        http.Dispose();
        h2.Dispose();

        // Let idle keep-alives, slow clients and old configurations drain.
        await Task.Delay(8000);
        var (rssEnd, fdEnd, thEnd) = Sample(pid);
        using var probe = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        bool alive = await Up(probe, port);
        Process.Start("kill", ["-TERM", pid.ToString()])!.WaitForExit();
        bool exited = server.WaitForExit(10_000);

        var problems = new List<string>();
        if (!alive) problems.Add("server stopped answering");
        if (!exited) { problems.Add("server did not exit within 10s of SIGTERM"); server.Kill(); }
        else if (server.ExitCode != 0) problems.Add($"exit code {server.ExitCode}");
        if (fdEnd > fd0 + 16) problems.Add($"file descriptors: {fd0} at baseline, {fdEnd} after draining (leak?)");
        if (rssEnd > Math.Max(rss0 * 3, rss0 + 300 * 1024)) problems.Add($"memory: {rss0 / 1024} MB at baseline, {rssEnd / 1024} MB after draining");
        if (errorLines > 0) problems.Add($"{errorLines} error-level log lines");
        long total = stats.Ok + stats.Limited + stats.Failed;
        if (stats.Failed > total / 1000 + 10) problems.Add($"{stats.Failed} of {total} requests failed");

        Console.WriteLine($"soak: done. {total} requests ({stats.Ok} ok, {stats.H2} over HTTP/2, {stats.H3} over HTTP/3, {stats.Limited} rate-limited, {stats.Failed} failed), {stats.Ws} websocket sessions ({stats.H2Ws} over HTTP/2), {stats.Abuse} abusive connections, {reloads} reloads, {stats.H3Reconnects} HTTP/3 reconnects");
        if (stats.H2 == 0) problems.Add("no HTTP/2 requests succeeded");
        if (stats.H3 == 0 && Httpgrl.Quic.QuicTls.Unavailable is null) problems.Add("no HTTP/3 requests succeeded");
        Console.WriteLine($"soak: rss {rss0 / 1024} -> peak {peakRss / 1024} -> {rssEnd / 1024} MB; fds {fd0} -> {fdEnd}; threads {th0} -> {thEnd}");
        foreach (var (what, n) in stats.Errors.OrderByDescending(e => e.Value).Take(8)) Console.WriteLine($"  failure: {what} x{n}");
        lock (log) if (log.Length > 0) Console.WriteLine(log.ToString());
        try { Directory.Delete(dir, true); } catch (IOException) { }
        if (problems.Count == 0) { Console.WriteLine("soak: PASS"); return 0; }
        foreach (var p in problems) Console.WriteLine("soak: FAIL: " + p);
        return 1;
    }

    private static async Task Traffic(HttpClient http, Stats s, int id, CancellationToken stop, bool http2 = false)
    {
        var r = new Random(id);
        string proto = http2 ? "h2 " : "";
        string[] paths = ["small.txt", "small.txt", "text.txt", "big.bin", "proxy/x?id=" + id, "proxy/y", "limited", "set?x=42", "set?x=abc", "missing"];
        while (!stop.IsCancellationRequested)
        {
            var path = paths[r.Next(paths.Length)];
            try
            {
                using var req = new HttpRequestMessage(path.StartsWith("proxy/y", StringComparison.Ordinal) ? HttpMethod.Post : HttpMethod.Get, path);
                // A hand-made request doesn't take the client's defaults: without these it's HTTP/1.1, whatever the client says.
                req.Version = http.DefaultRequestVersion;
                req.VersionPolicy = http.DefaultVersionPolicy;
                if (req.Method == HttpMethod.Post) req.Content = new ByteArrayContent(new byte[r.Next(1, 200_000)]);
                using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseContentRead, stop);
                int code = (int)resp.StatusCode;
                if (code == 429) Interlocked.Increment(ref s.Limited);
                else if (code == 200 || (path == "missing" && code == 404))
                {
                    Interlocked.Increment(ref s.Ok);
                    if (resp.Version.Major == 2) Interlocked.Increment(ref s.H2);
                }
                else s.Fail($"{proto}{path.Split('?')[0]} -> {code}");
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { return; }
            catch (HttpRequestException e) // reload races are rare but possible
            {
                s.Fail($"{proto}{path.Split('?')[0]}: {e.HttpRequestError}");
                if (Environment.GetEnvironmentVariable("SOAK_LOG") is { Length: > 0 }) lock (s) Console.WriteLine($"soak: {DateTime.UtcNow:HH:mm:ss.fff} {proto}{path}: {e}");
            }
            catch (TaskCanceledException) { s.Fail($"{proto}{path.Split('?')[0]}: timeout"); }
        }
    }

    /// <summary>
    /// HTTP/3 requests from our client: files, uploads through the proxy, a few at a time. A request refused after a
    /// GOAWAY (H3_REQUEST_REJECTED) wasn't processed, so it's retried on a new connection, as browsers do.
    /// </summary>
    private static void Http3Traffic(int port, string ca, Stats s, int id, CancellationToken stop)
    {
        var r = new Random(id);
        string[] paths = ["small.txt", "text.txt", "big.bin", "proxy/x?id=" + id, "proxy/y", "missing"];
        H3Client? c = null;
        try
        {
            while (!stop.IsCancellationRequested)
            {
                if (c is null || c.C.IsClosed || c.C.IsDraining)
                {
                    if (c is not null) Interlocked.Increment(ref s.H3Reconnects);
                    c?.Dispose();
                    c = new H3Client(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, port), ca, "soak.test");
                    if (!c.Connect()) { s.Fail("h3: handshake"); c.Dispose(); c = null; Thread.Sleep(100); continue; }
                }
                var path = paths[r.Next(paths.Length)];
                byte[]? body = path == "proxy/y" ? new byte[r.Next(1, 200_000)] : null;
                H3Client.Response resp;
                try
                {
                    long sid = c.Send(body is null ? "GET" : "POST", "/" + path, body, true, body is null ? [] : [("content-length", body.Length.ToString())]);
                    resp = c.Wait(sid, 15_000);
                }
                catch (Exception e) when (e.Message == "no stream credit") { c.C.Close(0, "", Httpgrl.Quic.QuicEndpoint.Now()); continue; }
                if (resp.Reset == (ulong)Httpgrl.Http3.H3Error.RequestRejected) continue; // after GOAWAY: retry elsewhere
                if (resp.Status == "200" || (path == "missing" && resp.Status == "404")) { Interlocked.Increment(ref s.Ok); Interlocked.Increment(ref s.H3); }
                else if (resp.Status == "429") Interlocked.Increment(ref s.Limited);
                else if (resp.Status is null && (c.C.IsClosed || c.C.IsDraining)) continue; // the connection went away under it (reload): retry
                else s.Fail($"h3 {path.Split('?')[0]} -> {resp.Status ?? "reset " + resp.Reset}");
            }
        }
        finally { c?.Dispose(); }
    }

    private static async Task WebSockets(int port, Stats s, CancellationToken stop, bool http2 = false)
    {
        var buf = new byte[256];
        using var handler = new SocketsHttpHandler { SslOptions = { RemoteCertificateValidationCallback = (_, _, _, _) => true, TargetHost = "soak.test" } };
        using var invoker = new HttpMessageInvoker(handler);
        while (!stop.IsCancellationRequested)
        {
            using var ws = new ClientWebSocket();
            try
            {
                if (http2)
                {
                    ws.Options.HttpVersion = System.Net.HttpVersion.Version20;
                    ws.Options.HttpVersionPolicy = HttpVersionPolicy.RequestVersionExact;
                    await ws.ConnectAsync(new Uri($"wss://127.0.0.1:{port}/ws"), invoker, stop);
                    Interlocked.Increment(ref s.H2Ws);
                }
                else await ws.ConnectAsync(new Uri($"ws://127.0.0.1:{port}/ws"), stop);
                for (int k = 0; k < 20 && !stop.IsCancellationRequested; k++)
                {
                    await ws.SendAsync("ping"u8.ToArray(), WebSocketMessageType.Text, true, stop);
                    var res = await ws.ReceiveAsync(buf, stop);
                    if (res.Count != 4) { s.Fail("ws: bad echo"); break; }
                    await Task.Delay(100, stop);
                }
                Interlocked.Increment(ref s.Ws);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { return; }
            catch (Exception e) when (e is WebSocketException or IOException)
            {
                // Expected when a reload's drain timeout cuts a tunnel; reconnect, as a real client would.
                Interlocked.Increment(ref s.Ws);
            }
        }
    }

    /// <summary>Slow-loris, garbage, oversized heads, mid-response resets, half-sent bodies.</summary>
    private static async Task Abuse(int port, Stats s, int id, CancellationToken stop)
    {
        var r = new Random(1000 + id);
        while (!stop.IsCancellationRequested)
        {
            using var c = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                await c.ConnectAsync(IPAddress.Loopback, port, stop);
                switch (r.Next(5))
                {
                    case 0: // slow-loris: one byte at a time until the header timeout kills it
                        foreach (byte b in "GET / HTTP/1.1\r\nHost: t\r\nX-a: "u8.ToArray()) { await c.SendAsync(new[] { b }, SocketFlags.None, stop); await Task.Delay(400, stop); }
                        break;
                    case 1: // garbage
                        var junk = new byte[r.Next(1, 4096)];
                        r.NextBytes(junk);
                        await c.SendAsync(junk, SocketFlags.None, stop);
                        break;
                    case 2: // oversized header
                        await c.SendAsync(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: t\r\nX: " + new string('a', 100_000) + "\r\n\r\n"), SocketFlags.None, stop);
                        break;
                    case 3: // reset mid-download
                        await c.SendAsync((r.Next(2) == 0 ? "GET /big.bin HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\n\r\n"u8 : "GET /text.txt HTTP/1.1\r\nHost: t\r\nAccept-Encoding: br\r\n\r\n"u8).ToArray(), SocketFlags.None, stop);
                        await c.ReceiveAsync(new byte[1024], SocketFlags.None, stop);
                        c.LingerState = new LingerOption(true, 0);
                        break;
                    default: // body promised, never sent
                        await c.SendAsync("POST /proxy/z HTTP/1.1\r\nHost: t\r\nContent-Length: 100000\r\n\r\nabc"u8.ToArray(), SocketFlags.None, stop);
                        await Task.Delay(r.Next(100, 1500), stop);
                        break;
                }
                Interlocked.Increment(ref s.Abuse);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { return; }
            catch (SocketException) { Interlocked.Increment(ref s.Abuse); } // the server hanging up on abuse is the point
        }
    }

    /// <summary>Managed heap vs GC-committed memory from the server's own status endpoint (to tell managed from native growth).</summary>
    private static async Task<string> Memory(HttpClient http)
    {
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(await http.GetStringAsync("status.json"));
            var m = doc.RootElement.GetProperty("memory");
            return $"(heap {m.GetProperty("managed_heap_bytes").GetInt64() >> 20} MB, gc-committed {m.GetProperty("gc_committed_bytes").GetInt64() >> 20} MB, gen2 {m.GetProperty("gen2_collections").GetInt64()})";
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException) { return "(heap ?)"; }
    }

    private static async Task<bool> Up(HttpClient http, int? port = null)
    {
        try { return (await http.GetAsync(port is null ? "small.txt" : $"http://127.0.0.1:{port}/small.txt")).IsSuccessStatusCode; }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException) { return false; }
    }

    /// <summary>RSS (KiB), open file descriptors, threads.</summary>
    private static (long Rss, int Fds, int Threads) Sample(int pid)
    {
        long rss = 0;
        int threads = 0;
        foreach (var line in File.ReadLines($"/proc/{pid}/status"))
        {
            if (line.StartsWith("VmRSS:", StringComparison.Ordinal)) rss = long.Parse(line.Split(' ', StringSplitOptions.RemoveEmptyEntries)[1]);
            else if (line.StartsWith("Threads:", StringComparison.Ordinal)) threads = int.Parse(line.Split('\t', StringSplitOptions.RemoveEmptyEntries)[1].Trim());
        }
        return (rss, Directory.GetFiles($"/proc/{pid}/fd").Length, threads);
    }

    private static int FreePort()
    {
        using var l = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        l.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)l.LocalEndPoint!).Port;
    }
}
