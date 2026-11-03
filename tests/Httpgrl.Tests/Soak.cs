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
        public long Ok, Limited, Failed, Ws, Abuse;
        public readonly System.Collections.Concurrent.ConcurrentDictionary<string, long> Errors = new();
        public void Fail(string what) { Interlocked.Increment(ref Failed); Errors.AddOrUpdate(what, 1, (_, n) => n + 1); }
    }

    public static int RunCli(string[] args)
    {
        if (!OperatingSystem.IsLinux()) { Console.WriteLine("soak: Linux only (reads /proc)"); return 2; }
        var binary = Path.GetFullPath(args.Length > 1 ? args[1] : "artifacts/linux-x64/httpgrl");
        int seconds = args.Length > 2 ? int.Parse(args[2]) : 60;
        return RunAsync(binary, seconds).GetAwaiter().GetResult();
    }

    private static async Task<int> RunAsync(string binary, int seconds)
    {
        var dir = Path.Combine(Path.GetTempPath(), "httpgrl-soak-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(Path.Combine(dir, "www"));
        File.WriteAllText(Path.Combine(dir, "www", "small.txt"), "hello");
        File.WriteAllBytes(Path.Combine(dir, "www", "big.bin"), new byte[1 << 20]);
        File.WriteAllText(Path.Combine(dir, "www", "limited"), "limited");

        await using var up = FakeUpstream.Echo();
        await using var wsUp = FakeUpstream.WebSocketEcho();
        int port = FreePort();
        var conf = Path.Combine(dir, "httpgrl.conf");
        File.WriteAllText(conf, $$"""
            worker_shutdown_timeout 3s; reload_drain_timeout 4s;
            events { worker_connections 4096; connections_per_client 4096; }
            http {
              access_log off;
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
                location /set { set $v "$arg_x"; if ($v ~ "^(\d+)$") { return 200 "n=$1"; } return 200 "s=$v"; }
              }
            }
            """);

        var psi = new ProcessStartInfo(binary, ["-c", conf]) { RedirectStandardOutput = true, RedirectStandardError = true };
        using var server = Process.Start(psi)!;
        var log = new StringBuilder();
        long errorLines = 0;
        server.OutputDataReceived += (_, e) =>
        {
            if (e.Data is null) return;
            if (e.Data.Contains("\"level\":\"error\"", StringComparison.Ordinal))
            {
                Interlocked.Increment(ref errorLines);
                lock (log) if (log.Length < 20_000) log.AppendLine(e.Data);
            }
        };
        server.ErrorDataReceived += (_, e) => { if (e.Data is not null) lock (log) log.AppendLine("stderr: " + e.Data); };
        server.BeginOutputReadLine();
        server.BeginErrorReadLine();
        int pid = server.Id;
        Console.WriteLine($"soak: pid {pid}, port {port}, {seconds}s");

        using var http = new HttpClient(new SocketsHttpHandler { MaxConnectionsPerServer = 64, PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30) })
        { BaseAddress = new Uri($"http://127.0.0.1:{port}/"), Timeout = TimeSpan.FromSeconds(15) };
        for (int k = 0; k < 50 && !await Up(http); k++) await Task.Delay(100);

        var stats = new Stats();
        using var stop = new CancellationTokenSource();
        var workers = new List<Task>();
        for (int k = 0; k < 48; k++) workers.Add(Traffic(http, stats, k, stop.Token));
        for (int k = 0; k < 4; k++) workers.Add(WebSockets(port, stats, stop.Token));
        for (int k = 0; k < 8; k++) workers.Add(Abuse(port, stats, k, stop.Token));

        // Warm up, then take the baseline.
        await Task.Delay(TimeSpan.FromSeconds(Math.Min(10, seconds / 5.0)));
        var (rss0, fd0, th0) = Sample(pid);
        Console.WriteLine($"soak: baseline rss {rss0 / 1024} MB, fds {fd0}, threads {th0}");
        long peakRss = rss0;
        var sw = Stopwatch.StartNew();
        int reloads = 0;
        while (sw.Elapsed.TotalSeconds < seconds)
        {
            await Task.Delay(2000);
            if (++reloads % 2 == 0) Process.Start("kill", ["-HUP", pid.ToString()])!.WaitForExit();
            var (rss, fd, th) = Sample(pid);
            peakRss = Math.Max(peakRss, rss);
            Console.WriteLine($"soak: t={sw.Elapsed.TotalSeconds:F0}s rss {rss / 1024} MB fds {fd} threads {th} ok {stats.Ok} limited {stats.Limited} ws {stats.Ws} abuse {stats.Abuse} failed {stats.Failed}");
        }
        stop.Cancel();
        try { await Task.WhenAll(workers); } catch (OperationCanceledException) { }
        http.Dispose();

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

        Console.WriteLine($"soak: done. {total} requests ({stats.Ok} ok, {stats.Limited} rate-limited, {stats.Failed} failed), {stats.Ws} websocket sessions, {stats.Abuse} abusive connections, {reloads / 2} reloads");
        Console.WriteLine($"soak: rss {rss0 / 1024} -> peak {peakRss / 1024} -> {rssEnd / 1024} MB; fds {fd0} -> {fdEnd}; threads {th0} -> {thEnd}");
        foreach (var (what, n) in stats.Errors.OrderByDescending(e => e.Value).Take(8)) Console.WriteLine($"  failure: {what} x{n}");
        lock (log) if (log.Length > 0) Console.WriteLine(log.ToString());
        try { Directory.Delete(dir, true); } catch (IOException) { }
        if (problems.Count == 0) { Console.WriteLine("soak: PASS"); return 0; }
        foreach (var p in problems) Console.WriteLine("soak: FAIL: " + p);
        return 1;
    }

    private static async Task Traffic(HttpClient http, Stats s, int id, CancellationToken stop)
    {
        var r = new Random(id);
        string[] paths = ["small.txt", "small.txt", "small.txt", "big.bin", "proxy/x?id=" + id, "proxy/y", "limited", "set?x=42", "set?x=abc", "missing"];
        while (!stop.IsCancellationRequested)
        {
            var path = paths[r.Next(paths.Length)];
            try
            {
                using var req = new HttpRequestMessage(path.StartsWith("proxy/y", StringComparison.Ordinal) ? HttpMethod.Post : HttpMethod.Get, path);
                if (req.Method == HttpMethod.Post) req.Content = new ByteArrayContent(new byte[r.Next(1, 200_000)]);
                using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseContentRead, stop);
                int code = (int)resp.StatusCode;
                if (code == 429) Interlocked.Increment(ref s.Limited);
                else if (code == 200 || (path == "missing" && code == 404)) Interlocked.Increment(ref s.Ok);
                else s.Fail($"{path.Split('?')[0]} -> {code}");
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { return; }
            catch (HttpRequestException e) { s.Fail($"{path.Split('?')[0]}: {e.HttpRequestError}"); } // reload races are rare but possible
            catch (TaskCanceledException) { s.Fail($"{path.Split('?')[0]}: timeout"); }
        }
    }

    private static async Task WebSockets(int port, Stats s, CancellationToken stop)
    {
        var buf = new byte[256];
        while (!stop.IsCancellationRequested)
        {
            using var ws = new ClientWebSocket();
            try
            {
                await ws.ConnectAsync(new Uri($"ws://127.0.0.1:{port}/ws"), stop);
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
                        await c.SendAsync("GET /big.bin HTTP/1.1\r\nHost: t\r\n\r\n"u8.ToArray(), SocketFlags.None, stop);
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
