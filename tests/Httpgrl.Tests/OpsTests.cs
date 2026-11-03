using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using static Httpgrl.Tests.Client;

namespace Httpgrl.Tests;

/// <summary>$request_id, allow/deny, stub_status.</summary>
internal static class OpsTests
{
    private static string Get(string path, string method = "GET") => $"{method} {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";

    private static void Www(string d)
    {
        foreach (var sub in new[] { "", "open", "closed", "lan" })
        {
            Directory.CreateDirectory(Path.Combine(d, "www", sub));
            File.WriteAllText(Path.Combine(d, "www", sub, "f.txt"), "file");
        }
    }

    public static void Register()
    {
        T.Add("ops: $request_id is random, stable within a request, and in the access log", async () =>
        {
            await using var s = TestServer.Start("""http { server { listen 127.0.0.1:0; add_header X-Request-ID $request_id always; location / { return 200 "$request_id"; } } }""");
            var a = await s.Raw(Get("/"));
            var b = await s.Raw(Get("/"));
            T.True(Regex.IsMatch(Body(a), "^[0-9a-f]{32}$"), Body(a));
            T.Eq(Body(a), Header(a, "X-Request-ID"));
            T.True(Body(a) != Body(b));
            T.Contains($"\"request_id\":\"{Body(a)}\"", s.LogText());
        });

        T.Add("access: allow/deny in order, first match wins; inner rules replace outer; 403 can be dropped", async () =>
        {
            async Task<int> St(string rules, string path = "/f.txt")
            {
                await using var s = TestServer.Start($$"""http { server { listen 127.0.0.1:0; root {DIR}/www; {{rules}} } }""", Www);
                return Status(await s.Raw(Get(path)));
            }
            T.Eq(200, await St("allow 127.0.0.0/8; deny all;"));
            T.Eq(403, await St("deny 127.0.0.1; allow all;"));
            T.Eq(403, await St("allow 10.0.0.0/8; deny all;"));
            T.Eq(403, await St("allow ::1; deny all;"));                 // an IPv6 rule doesn't match an IPv4 client
            T.Eq(200, await St("allow 192.168.0.0/16;"));                // no match: allowed
            T.Eq(-1, await St("deny all; error_page 403 =444;"));         // dropped, nothing sent

            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0; root {DIR}/www;
                  deny all;
                  location /open/ { allow all; }
                  location /lan/ { allow 10.0.0.0/8; }   # replaces the server's list: no match, so allowed
                  location /closed/ { }
                } }
                """, Www);
            T.Eq(200, Status(await s.Raw(Get("/open/f.txt"))));
            T.Eq(200, Status(await s.Raw(Get("/lan/f.txt"))));
            T.Eq(403, Status(await s.Raw(Get("/closed/f.txt"))));
            T.Eq(403, Status(await s.Raw(Get("/f.txt"))));
            T.Contains("access forbidden by rule", s.LogText());

            string Err(string d) => T.Throws<ConfigException>(() => TestServer.Start($$"""http { server { listen 127.0.0.1:0; {{d}} } }""")).Message;
            T.Contains("host bits set; did you mean 192.168.1.0/24", Err("allow 192.168.1.1/24;"));
            T.Contains("invalid address", Err("deny example.com;"));
            T.Contains("IPv4-mapped", Err("allow ::ffff:10.0.0.1;"));
        });

        T.Add("stub_status: nginx, prometheus and json formats; counts connections, requests and responses", async () =>
        {
            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0; root {DIR}/www;
                  location = /status { stub_status; }
                  location = /metrics { stub_status prometheus; allow 127.0.0.1; deny all; }
                  location = /status.json { stub_status json; }
                } }
                """, Www);
            T.Eq(200, Status(await s.Raw(Get("/f.txt"))));
            T.Eq(404, Status(await s.Raw(Get("/missing"))));
            using var idle = await Connect(s.Port);   // an idle keep-alive connection
            await idle.SendAsync(Encoding.ASCII.GetBytes("GET /f.txt HTTP/1.1\r\nHost: t\r\n\r\n"));
            await ReadOne(idle);
            await Task.Delay(50);

            var nginx = await s.Raw(Get("/status"));
            T.Eq("text/plain", Header(nginx, "Content-Type"));
            T.Eq("no-store", Header(nginx, "Cache-Control"));
            var m = Regex.Match(Body(nginx), @"^Active connections: (\d+) \nserver accepts handled requests\n (\d+) (\d+) (\d+) \nReading: (\d+) Writing: (\d+) Waiting: (\d+) \n$");
            T.True(m.Success, Body(nginx));
            T.True(int.Parse(m.Groups[1].Value) >= 2);  // the idle one and this request
            T.True(int.Parse(m.Groups[4].Value) >= 3);  // three completed before this one
            T.True(int.Parse(m.Groups[6].Value) >= 1);  // writing: this request
            T.True(int.Parse(m.Groups[7].Value) >= 1);  // waiting: the idle one

            var prom = Body(await s.Raw(Get("/metrics")));
            T.Contains("# TYPE httpgrl_requests_total counter\n", prom);
            T.Contains("httpgrl_responses_total{class=\"4xx\"} 1\n", prom);
            T.Contains("httpgrl_connections{state=\"waiting\"} 1\n", prom);
            T.True(Regex.IsMatch(prom, "httpgrl_build_info\\{version=\"[0-9.]+\"\\} 1\n"));

            using var doc = JsonDocument.Parse(Body(await s.Raw(Get("/status.json"))));
            T.True(doc.RootElement.GetProperty("requests").GetInt64() >= 4);
            T.Eq(1L, doc.RootElement.GetProperty("responses").GetProperty("4xx").GetInt64());
            T.True(doc.RootElement.GetProperty("connections").GetProperty("accepted").GetInt64() >= 5);

            T.Eq(405, Status(await s.Raw("POST /status HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")));
            T.Contains("unknown format", T.Throws<ConfigException>(() => TestServer.Start("http { server { listen 127.0.0.1:0; location /s { stub_status xml; } } }")).Message);
        });
    }
}
