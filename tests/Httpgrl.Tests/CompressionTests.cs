using System.IO.Compression;
using System.Text;
using Httpgrl.Modules.Compression;
using static Httpgrl.Tests.Client;

namespace Httpgrl.Tests;

/// <summary>gzip / brotli.</summary>
internal static class CompressionTests
{
    private static readonly string Text = string.Concat(Enumerable.Range(0, 400).Select(i => $"line {i}: the quick brown fox jumps over the lazy dog\n"));

    private static string Conf(string extra = "", string up = "") => $$"""
        http {
          include_types_placeholder;
          {{extra}}
          server { listen 127.0.0.1:0; root {DIR}/www;
            location /up/ { proxy_pass http://127.0.0.1:{{up}}/; }
          }
        }
        """.Replace("include_types_placeholder;", "types { text/plain txt; text/html html; image/png png; text/css css; }");

    private static void Www(string d)
    {
        Directory.CreateDirectory(Path.Combine(d, "www"));
        File.WriteAllText(Path.Combine(d, "www", "big.txt"), Text);
        File.WriteAllText(Path.Combine(d, "www", "tiny.txt"), "hi");
        File.WriteAllBytes(Path.Combine(d, "www", "img.png"), Encoding.ASCII.GetBytes(Text));
    }

    private static string Get(string path, string ae, string method = "GET", string extra = "") =>
        $"{method} {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n{(ae.Length > 0 ? "Accept-Encoding: " + ae + "\r\n" : "")}{extra}\r\n";

    public static void Register()
    {
        T.Add("compression: gzip and brotli on the wire decode to the original; headers fixed up", async () =>
        {
            await using var s = TestServer.Start(Conf("gzip on; brotli on;", "1"), Www);
            var gz = await s.Raw(Get("/big.txt", "gzip"));
            T.Eq(200, Status(gz));
            T.Eq("gzip", Header(gz, "Content-Encoding"));
            T.Eq("chunked", Header(gz, "Transfer-Encoding"));
            T.Eq(null, Header(gz, "Content-Length"));
            T.Eq(null, Header(gz, "Accept-Ranges"));
            T.Eq("Accept-Encoding", Header(gz, "Vary"));
            T.True(Header(gz, "ETag")!.StartsWith("W/\"", StringComparison.Ordinal));
            var wire = Dechunk(gz);
            T.True(wire.Length < Text.Length / 5, $"{wire.Length} bytes");
            T.Eq(Text, Decode(wire, "gzip"));

            var br = await s.Raw(Get("/big.txt", "gzip, deflate, br"));
            T.Eq("br", Header(br, "Content-Encoding"));
            T.Eq(Text, Decode(Dechunk(br), "br"));

            var plain = await s.Raw(Get("/big.txt", ""));
            T.Eq(null, Header(plain, "Content-Encoding"));
            T.Eq(Text.Length.ToString(), Header(plain, "Content-Length"));
            T.Eq("Accept-Encoding", Header(plain, "Vary")); // varies even when not compressed
            T.Eq(Text, Body(plain));
        });

        T.Add("compression: skips small, non-text, ranged and already-encoded responses; HEAD gets headers only", async () =>
        {
            await using var up = new FakeUpstream(async (st, rd) =>
            {
                var (head, _) = await rd.ReadRequestAsync();
                var body = head.Contains("/pre", StringComparison.Ordinal) ? "already-encoded-bytes" : Text;
                var enc = head.Contains("/pre", StringComparison.Ordinal) ? "Content-Encoding: gzip\r\n" : "";
                var nt = head.Contains("/nt", StringComparison.Ordinal) ? "Cache-Control: no-transform\r\n" : "";
                await st.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n{enc}{nt}Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n{body.Length:x}\r\n{body}\r\n0\r\n\r\n"));
            });
            await using var s = TestServer.Start(Conf("gzip on;", up.Port.ToString()), Www);
            T.Eq(null, Header(await s.Raw(Get("/tiny.txt", "gzip")), "Content-Encoding"));
            var png = await s.Raw(Get("/img.png", "gzip"));
            T.Eq(null, Header(png, "Content-Encoding"));
            T.Eq(null, Header(png, "Vary"));
            var ranged = await s.Raw(Get("/big.txt", "gzip", extra: "Range: bytes=0-9\r\n"));
            T.Eq(206, Status(ranged));
            T.Eq(null, Header(ranged, "Content-Encoding"));
            T.Eq("line 0: th", Body(ranged));
            var head = await s.Raw(Get("/big.txt", "gzip", "HEAD"));
            T.Eq("gzip", Header(head, "Content-Encoding"));
            T.Eq("", Body(head));

            var proxied = await s.Raw(Get("/up/x", "gzip"));
            T.Eq("gzip", Header(proxied, "Content-Encoding"));    // upstream streamed plain text: compressed here
            T.Eq(Text, Decode(Dechunk(proxied), "gzip"));
            var pre = await s.Raw(Get("/up/pre", "gzip"));
            T.Eq("already-encoded-bytes", Encoding.Latin1.GetString(Dechunk(pre))); // passed through untouched
            T.Eq(null, Header(await s.Raw(Get("/up/nt", "gzip")), "Content-Encoding"));
        });

        T.Add("compression: a streamed response is flushed through the compressor, not held back", async () =>
        {
            var release = new TaskCompletionSource();
            await using var up = new FakeUpstream(async (st, rd) =>
            {
                await rd.ReadRequestAsync();
                await st.WriteAsync("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nevent 1\n\r\n"u8.ToArray());
                await release.Task;
                await st.WriteAsync("8\r\nevent 2\n\r\n0\r\n\r\n"u8.ToArray());
            });
            await using var s = TestServer.Start(Conf("gzip on; gzip_min_length 0;", up.Port.ToString()), Www);
            using var c = await Connect(s.Port);
            await c.SendAsync(Encoding.ASCII.GetBytes(Get("/up/stream", "gzip")));
            // Before the upstream finishes, what arrived must already decode to the first event.
            var got = new MemoryStream();
            var buf = new byte[4096];
            string decoded = "";
            using var cts = new CancellationTokenSource(3000);
            while (!decoded.Contains("event 1", StringComparison.Ordinal))
            {
                int n = await c.ReceiveAsync(buf, System.Net.Sockets.SocketFlags.None, cts.Token);
                if (n == 0) break;
                got.Write(buf, 0, n);
                decoded = DecodePartial(Encoding.Latin1.GetString(got.ToArray()));
            }
            T.Contains("event 1", decoded);
            release.SetResult();
        });

        T.Add("gzip_static/brotli_static: precompressed siblings by Accept-Encoding; always; fallbacks", async () =>
        {
            byte[] Pack(string coding)
            {
                var ms = new MemoryStream();
                using (Stream z = coding == "br" ? new BrotliStream(ms, CompressionLevel.SmallestSize, true) : new GZipStream(ms, CompressionLevel.SmallestSize, true))
                    z.Write(Encoding.UTF8.GetBytes(Text));
                return ms.ToArray();
            }
            var gzBytes = Pack("gz");
            var brBytes = Pack("br");
            await using var s = TestServer.Start("""
                http { types { application/javascript js; text/plain txt; }
                  server { listen 127.0.0.1:0; root {DIR}/www;
                    location / { gzip_static on; brotli_static on; }
                    location /always/ { alias {DIR}/www/; gzip_static always; }
                    location /onlygz/ { alias {DIR}/www/; gzip_static on; gzip on; gzip_min_length 0; }
                  }
                }
                """, d =>
            {
                Www(d);
                File.WriteAllText(Path.Combine(d, "www", "app.js"), Text);
                File.WriteAllBytes(Path.Combine(d, "www", "app.js.gz"), gzBytes);
                File.WriteAllBytes(Path.Combine(d, "www", "app.js.br"), brBytes);
            });
            var br = await s.Raw(Get("/app.js", "gzip, br"));
            T.Eq("br", Header(br, "Content-Encoding"));
            T.Eq("application/javascript", Header(br, "Content-Type"));
            T.Eq(brBytes.Length.ToString(), Header(br, "Content-Length")); // served as a file: length known, no chunking
            T.Eq(Text, Decode(Encoding.Latin1.GetBytes(Body(br)), "br"));
            T.Eq("Accept-Encoding", Header(br, "Vary"));

            var gz = await s.Raw(Get("/app.js", "gzip, br;q=0"));
            T.Eq("gzip", Header(gz, "Content-Encoding"));
            T.Eq(Text, Decode(Encoding.Latin1.GetBytes(Body(gz)), "gzip"));

            var plain = await s.Raw(Get("/app.js", ""));
            T.Eq(null, Header(plain, "Content-Encoding"));
            T.Eq(Text, Body(plain));
            T.Eq("Accept-Encoding", Header(plain, "Vary"));

            T.Eq("gzip", Header(await s.Raw(Get("/always/app.js", "")), "Content-Encoding")); // always: no Accept-Encoding needed
            // No precompressed sibling: the original, which on-the-fly gzip may still compress.
            var dyn = await s.Raw(Get("/onlygz/big.txt", "gzip"));
            T.Eq("gzip", Header(dyn, "Content-Encoding"));
            T.Eq("chunked", Header(dyn, "Transfer-Encoding"));
            T.Eq(Text, Decode(Dechunk(dyn), "gzip"));
            // A precompressed file isn't compressed again.
            var once = await s.Raw(Get("/onlygz/app.js", "gzip"));
            T.Eq(gzBytes.Length.ToString(), Header(once, "Content-Length"));
            T.Contains("invalid value", T.Throws<ConfigException>(() => TestServer.Start("http { server { listen 127.0.0.1:0; gzip_static sometimes; } }")).Message);
        });

        T.Add("compression: Accept-Encoding negotiation (q-values, *, refusals, garbage)", () =>
        {
            var G = ContentCoding.Gzip;
            var B = ContentCoding.Brotli;
            var N = ContentCoding.Identity;
            T.Eq(B, AcceptEncoding.Choose("gzip, br", true, true));
            T.Eq(G, AcceptEncoding.Choose("gzip, br", true, false));
            T.Eq(G, AcceptEncoding.Choose("br;q=0, gzip", true, true));
            T.Eq(G, AcceptEncoding.Choose("br;q=0.5, gzip;q=0.9", true, true));
            T.Eq(B, AcceptEncoding.Choose("*", true, true));
            T.Eq(G, AcceptEncoding.Choose("*;q=0.1, br;q=0", true, true));
            T.Eq(N, AcceptEncoding.Choose("gzip;q=0", true, true));
            T.Eq(N, AcceptEncoding.Choose("identity", true, true));
            T.Eq(N, AcceptEncoding.Choose(";;;,,q=,gzip;q=abc, br;q=2", true, true));
            T.Eq(G, AcceptEncoding.Choose("X-GZIP", true, true));
            return Task.CompletedTask;
        });

        T.Add("compression: an aborted compressed download doesn't break the server; config errors", async () =>
        {
            await using var s = TestServer.Start(Conf("gzip on; brotli on;", "1"), d =>
            {
                Www(d);
                var big = new StringBuilder();
                for (int k = 0; k < 40_000; k++) big.Append(k).Append(" pseudo-random-ish text ").Append(k * 7919 % 10007).Append('\n');
                File.WriteAllText(Path.Combine(d, "www", "huge.txt"), big.ToString());
            });
            for (int k = 0; k < 20; k++)
            {
                using var c = await Connect(s.Port);
                await c.SendAsync(Encoding.ASCII.GetBytes(Get("/huge.txt", k % 2 == 0 ? "br" : "gzip")));
                await c.ReceiveAsync(new byte[512], System.Net.Sockets.SocketFlags.None);
                c.LingerState = new System.Net.Sockets.LingerOption(true, 0);
            }
            T.Eq(Text, Decode(Dechunk(await s.Raw(Get("/big.txt", "br"))), "br"));
            T.True(!s.LogText().Contains("\"level\":\"error\"", StringComparison.Ordinal));

            string Err(string d) => T.Throws<ConfigException>(() => TestServer.Start(Conf(d, "1"), Www)).Message;
            T.Contains("1..9", Err("gzip_comp_level 10;"));
            T.Contains("0..11", Err("brotli_comp_level 12;"));
            T.Contains("invalid MIME type", Err("gzip_types text;"));
        });
    }

    /// <summary>The body bytes of a chunked response, de-chunked.</summary>
    private static byte[] Dechunk(string resp)
    {
        var b = Encoding.Latin1.GetBytes(Body(resp));
        var o = new MemoryStream();
        int p = 0;
        while (true)
        {
            int nl = Array.IndexOf(b, (byte)'\n', p);
            int size = Convert.ToInt32(Encoding.ASCII.GetString(b, p, nl - 1 - p), 16);
            p = nl + 1;
            if (size == 0) return o.ToArray();
            o.Write(b, p, size);
            p += size + 2;
        }
    }

    /// <summary>Decode whatever complete chunks of a gzip response have arrived (a sync-flushed prefix).</summary>
    private static string DecodePartial(string resp)
    {
        int end = resp.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (end < 0) return "";
        var b = Encoding.Latin1.GetBytes(resp[(end + 4)..]);
        var o = new MemoryStream();
        int p = 0;
        while (true)
        {
            int nl = Array.IndexOf(b, (byte)'\n', p);
            if (nl < 0) break;
            int size = Convert.ToInt32(Encoding.ASCII.GetString(b, p, nl - 1 - p), 16);
            if (size == 0 || nl + 1 + size + 2 > b.Length) break;
            o.Write(b, nl + 1, size);
            p = nl + 1 + size + 2;
        }
        o.Position = 0;
        using var gz = new GZipStream(o, CompressionMode.Decompress);
        var outp = new MemoryStream();
        var tmp = new byte[4096];
        try { int n; while ((n = gz.Read(tmp)) > 0) outp.Write(tmp, 0, n); }
        catch (InvalidDataException) { }
        return Encoding.UTF8.GetString(outp.ToArray());
    }

    private static string Decode(byte[] data, string coding)
    {
        using var input = new MemoryStream(data);
        using Stream d = coding == "br" ? new BrotliStream(input, CompressionMode.Decompress) : new GZipStream(input, CompressionMode.Decompress);
        using var r = new StreamReader(d, Encoding.UTF8);
        return r.ReadToEnd();
    }
}
