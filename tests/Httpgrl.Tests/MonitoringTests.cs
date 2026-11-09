using System.Text;
using System.Text.Json;
using Httpgrl.Core.Logging;

namespace Httpgrl.Tests;

internal static class MonitoringTests
{
    public static void Register()
    {
        T.Add("monitoring: diagnostics redact query secrets, identify process, and mark field truncation", () =>
        {
            using var ms = new MemoryStream();
            using (var log = new JsonLogger(ms))
                log.Warn("diagnostic", new("uri", "/a?token=DO_NOT_LOG"), new("referer", "https://user:DO_NOT_LOG@host/x"), new("ua", new string('x', 5000)), new("schema", 999L), new("process_id", "forged"));
            string line = Encoding.UTF8.GetString(ms.ToArray());
            T.NotContains("DO_NOT_LOG", line);
            using var doc = JsonDocument.Parse(line);
            var r = doc.RootElement;
            T.Eq("/a", r.GetProperty("uri").GetString());
            T.True(r.GetProperty("truncated").GetBoolean());
            T.Eq(2, r.GetProperty("schema").GetInt32());
            T.Eq(32, r.GetProperty("process_id").GetString()!.Length);
            T.True(r.GetProperty("version").GetString()!.Length > 0);
        });
        T.Add("monitoring: access outcomes and security decisions correlate without query or Referer secrets", async () =>
        {
            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0; server_name audit.test;
                  location /ok { return 200 hello; }
                  location /denied { deny all; }
                  location /silent { access_log off; deny all; }
                  location /drop { return 444; }
                } }
                """);
            foreach (string path in new[] { "/ok", "/denied", "/silent", "/drop" })
                await s.Raw($"GET {path}?token=DO_NOT_LOG HTTP/1.1\r\nHost: audit.test\r\nReferer: https://user:DO_NOT_LOG@host/\r\nConnection: close\r\n\r\n");
            string log = s.LogText();
            T.NotContains("DO_NOT_LOG", log);
            var access = new Dictionary<string, string>();
            var events = new Dictionary<string, string>();
            foreach (string line in log.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                using var doc = JsonDocument.Parse(line);
                var r = doc.RootElement;
                if (!r.TryGetProperty("event", out var e)) continue;
                if (e.GetString() == "http_access")
                {
                    string path = r.GetProperty("path").GetString()!;
                    T.True(access.TryAdd(path, r.GetProperty("request_id").GetString()!));
                    T.Eq(path == "/drop" ? "dropped" : "complete", r.GetProperty("outcome").GetString());
                    T.Eq("audit.test", r.GetProperty("server").GetString());
                    T.True(r.GetProperty("query_present").GetBoolean());
                }
                if (e.GetString() == "access_denied") events[r.GetProperty("path").GetString()!] = r.GetProperty("request_id").GetString()!;
            }
            T.Eq(3, access.Count);
            T.Eq(access["/denied"], events["/denied"]);
            T.True(events.ContainsKey("/silent"));
        });
        T.Add("monitoring: upstream truncated 200 is logged once as incomplete with upstream identity", async () =>
        {
            await using var up = new FakeUpstream(async (st, rd) =>
            {
                await rd.ReadRequestAsync();
                await st.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort"u8.ToArray());
            });
            await using var s = TestServer.Start($$"""
                http { server { listen 127.0.0.1:0;
                  location / { proxy_pass http://127.0.0.1:{{up.Port}}; proxy_buffering off; }
                } }
                """);
            await s.Raw("GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
            int count = 0;
            foreach (string line in s.LogText().Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                using var doc = JsonDocument.Parse(line);
                var r = doc.RootElement;
                if (!r.TryGetProperty("event", out var e) || e.GetString() != "http_access") continue;
                count++;
                T.Eq(200, r.GetProperty("status").GetInt32());
                T.Eq("incomplete", r.GetProperty("outcome").GetString());
                T.Eq("200", r.GetProperty("upstream_status").GetString());
                T.Contains(up.Port.ToString(), r.GetProperty("upstream").GetString()!);
            }
            T.Eq(1, count);
        });
    }
}
