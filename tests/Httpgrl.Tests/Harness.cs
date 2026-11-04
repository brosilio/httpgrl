using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using Httpgrl.Core.Hosting;
using Httpgrl.Core.Logging;

namespace Httpgrl.Tests;

/// <summary>Minimal test runner: no dependencies, no reflection-driven discovery.</summary>
internal static class T
{
    private static readonly List<(string Name, Func<Task> Body)> Tests = new();

    public static void Add(string name, Func<Task> body) => Tests.Add((name, body));
    public static void Add(string name, Action body) => Tests.Add((name, () => { body(); return Task.CompletedTask; }));

    public static async Task<int> RunAsync(string? filter)
    {
        int pass = 0, fail = 0;
        var sw = Stopwatch.StartNew();
        foreach (var (name, body) in Tests)
        {
            if (filter is not null && !name.Contains(filter, StringComparison.OrdinalIgnoreCase)) continue;
            var t = Stopwatch.StartNew();
            try
            {
                var task = body();
                if (await Task.WhenAny(task, Task.Delay(20_000)) != task) throw new TimeoutException("test exceeded 20s");
                await task;
                pass++;
                Console.WriteLine($"  ok   {name} ({t.ElapsedMilliseconds} ms)");
            }
            catch (Exception e)
            {
                fail++;
                Console.WriteLine($"  FAIL {name}: {e.GetType().Name}: {e.Message}");
            }
        }
        Console.WriteLine($"{pass} passed, {fail} failed in {sw.Elapsed.TotalSeconds:0.0}s");
        return fail == 0 ? 0 : 1;
    }

    public static void Eq<TV>(TV expected, TV actual, [CallerArgumentExpression(nameof(actual))] string? expr = null)
    {
        if (!EqualityComparer<TV>.Default.Equals(expected, actual))
            throw new Exception($"{expr}: expected <{expected}>, got <{actual}>");
    }

    public static void True(bool cond, [CallerArgumentExpression(nameof(cond))] string? expr = null)
    {
        if (!cond) throw new Exception($"expected true: {expr}");
    }

    public static void Contains(string needle, string hay)
    {
        if (!hay.Contains(needle, StringComparison.Ordinal)) throw new Exception($"expected to contain <{needle}>, got <{Trunc(hay)}>");
    }

    public static void NotContains(string needle, string hay)
    {
        if (hay.Contains(needle, StringComparison.Ordinal)) throw new Exception($"expected NOT to contain <{needle}>, got <{Trunc(hay)}>");
    }

    public static TEx Throws<TEx>(Action a) where TEx : Exception
    {
        try { a(); }
        catch (TEx e) { return e; }
        catch (Exception e) { throw new Exception($"expected {typeof(TEx).Name}, got {e.GetType().Name}: {e.Message}"); }
        throw new Exception($"expected {typeof(TEx).Name}, nothing thrown");
    }

    private static string Trunc(string s) => s.Length > 600 ? s[..600] + "..." : s;
}

/// <summary>A disposable live server on an ephemeral loopback port, serving a temp directory.</summary>
internal sealed class TestServer : IAsyncDisposable
{
    public readonly string Dir;
    public readonly HttpServer Server;
    private readonly JsonLogger _log;
    private readonly MemoryStream _logStream = new();
    public int Port => ((IPEndPoint)Server.EndPoints[0]).Port;
    /// <summary>The first quic (HTTP/3) listener's UDP endpoint.</summary>
    public IPEndPoint QuicEndPoint => (IPEndPoint)Server.QuicEndPoints[0];

    private TestServer(string dir, HttpServer server, JsonLogger log, MemoryStream ms)
    {
        Dir = dir;
        Server = server;
        _log = log;
        _logStream = ms;
    }

    /// <param name="dns">Replaces the system resolver for the proxy module (hostname -> addresses).</param>
    public static TestServer Start(string config, Action<string>? populate = null, IEnumerable<IModule>? extra = null,
        Func<string, CancellationToken, Task<IPAddress[]>>? dns = null)
    {
        var dir = Path.Combine(Path.GetTempPath(), "httpgrl-test-" + Guid.NewGuid().ToString("N")[..12]);
        Directory.CreateDirectory(dir);
        populate?.Invoke(dir);
        var ms = new MemoryStream();
        var log = new JsonLogger(Stream.Synchronized(ms), LogLevel.Debug);
        var text = config.Replace("{DIR}", dir, StringComparison.Ordinal);
        var mods = extra?.ToArray() ?? [];
        var server = ServerBuilder.LoadText(text, dir, () => Modules(mods, dns), log);
        server.Start();
        return new TestServer(dir, server, log, ms) { _extra = mods, _dns = dns };
    }

    private IModule[] _extra = [];
    private Func<string, CancellationToken, Task<IPAddress[]>>? _dns;

    private static IModule[] Modules(IModule[] extra, Func<string, CancellationToken, Task<IPAddress[]>>? dns) =>
        [new Httpgrl.Modules.Rewrite.RewriteModule(), new Httpgrl.Modules.Rewrite.MapModule(), new Httpgrl.Modules.Headers.HeadersModule(), new Httpgrl.Modules.Limits.LimitReqModule(), new Httpgrl.Modules.Limits.LimitConnModule(), new Httpgrl.Modules.Access.AccessModule(), new Httpgrl.Modules.Status.StatusModule(), new Httpgrl.Modules.Compression.CompressionModule(), new Httpgrl.Modules.Proxy.ProxyModule(dns), .. Httpgrl.Modules.StaticFiles.StaticFiles.Modules(), .. extra];

    /// <summary>Swap in a new configuration ({DIR} expands as in Start). Fresh first-party modules; test modules are reused.</summary>
    public Task<bool> Reload(string config) =>
        Server.ReloadAsync(prev => ServerBuilder.BuildText(config.Replace("{DIR}", Dir, StringComparison.Ordinal), Dir, Modules(_extra, _dns), _log, prev));

    /// <summary>The log so far, without waiting for stragglers (fuzzing checks it often).</summary>
    public string LogNow()
    {
        lock (_logStream) return Encoding.UTF8.GetString(_logStream.ToArray());
    }

    public string LogText()
    {
        Thread.Sleep(100);
        lock (_logStream) return Encoding.UTF8.GetString(_logStream.ToArray());
    }

    public Task<string> Raw(string request, int readTimeoutMs = 5000) => Client.Raw(Port, request, readTimeoutMs);

    public async ValueTask DisposeAsync()
    {
        await Server.StopAsync(1000);
        _log.Dispose();
        try { Directory.Delete(Dir, true); } catch (IOException) { }
    }
}

internal static class Client
{
    /// <summary>Send bytes, read until the server closes (or timeout). Returns Latin-1 text.</summary>
    public static async Task<string> Raw(int port, string request, int readTimeoutMs = 5000)
    {
        using var s = await Connect(port);
        await s.SendAsync(Encoding.Latin1.GetBytes(request));
        return await ReadToClose(s, readTimeoutMs);
    }

    public static async Task<Socket> Connect(int port)
    {
        var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        await s.ConnectAsync(IPAddress.Loopback, port);
        return s;
    }

    public static async Task<string> ReadToClose(Socket s, int timeoutMs)
    {
        var sb = new StringBuilder();
        var buf = new byte[65536];
        using var cts = new CancellationTokenSource(timeoutMs);
        try
        {
            while (true)
            {
                int n = await s.ReceiveAsync(buf, SocketFlags.None, cts.Token);
                if (n == 0) break;
                sb.Append(Encoding.Latin1.GetString(buf, 0, n));
            }
        }
        catch (OperationCanceledException) { sb.Append("<<TIMEOUT>>"); }
        catch (SocketException) { sb.Append("<<RESET>>"); }
        return sb.ToString();
    }

    /// <summary>Read exactly one response with a Content-Length body (keep-alive tests).</summary>
    public static async Task<string> ReadOne(Socket s, int timeoutMs = 5000)
    {
        var data = new List<byte>();
        var buf = new byte[1];
        using var cts = new CancellationTokenSource(timeoutMs);
        while (true)
        {
            int n = await s.ReceiveAsync(buf, SocketFlags.None, cts.Token);
            if (n == 0) throw new IOException("closed before head");
            data.Add(buf[0]);
            int c = data.Count;
            if (c >= 4 && data[c - 4] == '\r' && data[c - 3] == '\n' && data[c - 2] == '\r' && data[c - 1] == '\n') break;
        }
        var head = Encoding.Latin1.GetString(data.ToArray());
        int len = 0;
        foreach (var line in head.Split("\r\n"))
            if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)) len = int.Parse(line[15..].Trim());
        var body = new byte[len];
        int got = 0;
        while (got < len)
        {
            int n = await s.ReceiveAsync(body.AsMemory(got), SocketFlags.None, cts.Token);
            if (n == 0) throw new IOException("closed mid-body");
            got += n;
        }
        return head + Encoding.Latin1.GetString(body);
    }

    public static int Status(string response) =>
        response.StartsWith("HTTP/1.1 ", StringComparison.Ordinal) ? int.Parse(response.AsSpan(9, 3)) : -1;

    public static string Body(string response)
    {
        int i = response.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        return i < 0 ? "" : response[(i + 4)..];
    }

    /// <summary>The body with chunked framing removed (strictly: a malformed or unterminated body throws).</summary>
    public static string Dechunked(string response)
    {
        var b = Body(response);
        if (!string.Equals(Header(response, "Transfer-Encoding"), "chunked", StringComparison.OrdinalIgnoreCase)) return b;
        var sb = new StringBuilder();
        int i = 0;
        while (true)
        {
            int eol = b.IndexOf("\r\n", i, StringComparison.Ordinal);
            if (eol < 0) throw new FormatException("unterminated chunked body");
            int size = Convert.ToInt32(b[i..eol], 16);
            i = eol + 2;
            if (size == 0) return b.AsSpan(i).SequenceEqual("\r\n") ? sb.ToString() : throw new FormatException("bad chunked end");
            sb.Append(b, i, size);
            i += size;
            if (!b.AsSpan(i).StartsWith("\r\n")) throw new FormatException("missing chunk terminator");
            i += 2;
        }
    }

    public static string? Header(string response, string name)
    {
        int end = response.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        foreach (var line in response[..(end < 0 ? response.Length : end)].Split("\r\n"))
            if (line.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase)) return line[(name.Length + 1)..].Trim();
        return null;
    }
}
