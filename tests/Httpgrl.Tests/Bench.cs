using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Httpgrl.Tests;

/// <summary>
/// Minimal keep-alive load generator (no wrk needed):
///   dotnet run -c Release --project tests/Httpgrl.Tests -- --bench http://127.0.0.1:8080/path [seconds=10] [connections=64]
/// </summary>
internal static class Bench
{
    public static int RunCli(string[] args)
    {
        var uri = new Uri(args[1]);
        int seconds = args.Length > 2 ? int.Parse(args[2]) : 10;
        int conns = args.Length > 3 ? int.Parse(args[3]) : 64;
        var req = Encoding.ASCII.GetBytes($"GET {uri.PathAndQuery} HTTP/1.1\r\nHost: {uri.Authority}\r\n\r\n");
        long done = 0, bytes = 0, errors = 0;
        var stop = Stopwatch.StartNew();
        var until = TimeSpan.FromSeconds(seconds);
        var tasks = Enumerable.Range(0, conns).Select(_ => Task.Run(async () =>
        {
            var buf = new byte[256 << 10];
            while (stop.Elapsed < until)
            {
                using var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await s.ConnectAsync(IPAddress.Parse(uri.Host), uri.Port);
                    while (stop.Elapsed < until)
                    {
                        await s.SendAsync(req, SocketFlags.None);
                        var (body, close) = await ReadResponse(s, buf);
                        if (body < 0) { Interlocked.Increment(ref errors); break; }
                        Interlocked.Increment(ref done);
                        Interlocked.Add(ref bytes, body);
                        if (close) break; // the server announced it (keepalive_requests): reconnect, not an error
                    }
                }
                catch (SocketException) { Interlocked.Increment(ref errors); }
            }
        })).ToArray();
        Task.WaitAll(tasks);
        double secs = stop.Elapsed.TotalSeconds;
        Console.WriteLine($"bench {uri}: {done / secs:F0} req/s, {bytes / secs / (1 << 20):F1} MiB/s body, {errors} errors, {conns} connections, {secs:F1}s");
        return 0;
    }

    /// <summary>Reads one Content-Length response; returns the body length, or -1 on close/unsupported framing.</summary>
    private static async Task<(long Body, bool Close)> ReadResponse(Socket s, byte[] buf)
    {
        int have = 0, headEnd;
        while ((headEnd = buf.AsSpan(0, have).IndexOf("\r\n\r\n"u8)) < 0)
        {
            int n = await s.ReceiveAsync(buf.AsMemory(have), SocketFlags.None);
            if (n == 0) return (-1, true);
            have += n;
        }
        var head = Encoding.ASCII.GetString(buf, 0, headEnd);
        int cl = head.IndexOf("\r\ncontent-length:", StringComparison.OrdinalIgnoreCase);
        if (cl < 0) return (-1, true);
        bool close = head.Contains("\r\nconnection: close", StringComparison.OrdinalIgnoreCase);
        int eol = head.IndexOf('\r', cl + 2);
        long len = long.Parse(head.AsSpan(cl + 17, (eol < 0 ? head.Length : eol) - cl - 17).Trim());
        long remaining = len - (have - headEnd - 4);
        while (remaining > 0)
        {
            int n = await s.ReceiveAsync(buf, SocketFlags.None);
            if (n == 0) return (-1, true);
            remaining -= n;
        }
        return (len, close);
    }
}
