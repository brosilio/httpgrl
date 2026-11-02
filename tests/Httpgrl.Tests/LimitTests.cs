using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Httpgrl.Modules.Limits;
using static Httpgrl.Tests.Client;

namespace Httpgrl.Tests;

/// <summary>limit_req / limit_conn.</summary>
internal static class LimitTests
{
    // Limits run in the access phase, after "return" (as in nginx), so these serve files.
    private static string Conf(string http, string server = "") => $$"""
        http {
          {{http}}
          add_header X-Limit "$limit_req_status" always;
          add_header X-Conn "$limit_conn_status" always;
          server { listen 127.0.0.1:0; root {DIR}/www; index index.html;
            {{server}}
            location /ws { echo_upgrade; }
          }
        }
        """;

    private static void Www(string d)
    {
        Directory.CreateDirectory(Path.Combine(d, "www"));
        File.WriteAllText(Path.Combine(d, "www", "index.html"), "home");
        File.WriteAllText(Path.Combine(d, "www", "f.txt"), "file");
    }

    private static TestServer Start(string conf, Action<string> populate) => TestServer.Start(conf, populate, [new TestModule()]);

    private static string Get(string path) => $"GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";

    public static void Register()
    {
        T.Add("limit_req: rate without burst rejects with 429; the bucket drains over time", async () =>
        {
            await using var s = Start(Conf("limit_req_zone $remote_net zone=one:64k rate=10r/s;", "limit_req zone=one;"), Www);
            var a = await s.Raw(Get("/f.txt"));
            T.Eq(200, Status(a));
            T.Eq("PASSED", Header(a, "X-Limit"));
            var b = await s.Raw(Get("/f.txt"));
            T.Eq(429, Status(b));
            T.Eq("REJECTED", Header(b, "X-Limit"));
            await Task.Delay(150); // 10r/s: one request's worth drains in 100 ms
            T.Eq(200, Status(await s.Raw(Get("/f.txt"))));
            T.Contains("limit_req rejected request", s.LogText());
        });

        T.Add("limit_req: burst queues requests to the rate; nodelay serves the burst at once", async () =>
        {
            await using (var s = Start(Conf("limit_req_zone $remote_net zone=one:64k rate=10r/s;", "limit_req zone=one burst=5;"), Www))
            {
                var sw = Stopwatch.StartNew();
                var all = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => s.Raw(Get("/f.txt"))));
                T.True(all.All(r => Status(r) == 200));
                T.True(sw.ElapsedMilliseconds >= 250, $"took {sw.ElapsedMilliseconds} ms"); // 0, 100, 200, 300 ms
                T.True(all.Count(r => Header(r, "X-Limit") == "DELAYED") >= 2);
            }
            await using (var s = Start(Conf("limit_req_zone $remote_net zone=one:64k rate=1r/m;", "limit_req zone=one burst=3 nodelay;"), Www))
            {
                var sw = Stopwatch.StartNew();
                for (int k = 0; k < 4; k++) T.Eq(200, Status(await s.Raw(Get("/f.txt"))));
                T.True(sw.ElapsedMilliseconds < 1000);
                T.Eq(429, Status(await s.Raw(Get("/f.txt"))));
            }
        });

        T.Add("limit_req: several zones; a rejection by one doesn't charge the others; empty keys are exempt", async () =>
        {
            await using var s = Start(Conf("""
                limit_req_zone $remote_net zone=all:64k rate=1r/m;
                limit_req_zone $arg_k zone=perk:64k rate=1r/m;
                """, "limit_req zone=all burst=1 nodelay; limit_req zone=perk;"), Www);
            T.Eq(200, Status(await s.Raw(Get("/f.txt?k=1"))));
            T.Eq(429, Status(await s.Raw(Get("/f.txt?k=1"))));   // perk rejects; "all" is refunded...
            T.Eq(200, Status(await s.Raw(Get("/f.txt?k=2"))));   // ...so this still fits its burst
            T.Eq(429, Status(await s.Raw(Get("/f.txt?k=3"))));   // now "all" is spent

            await using var s2 = Start(Conf("""
                map $arg_vip $limit_key { yes ""; default $remote_net; }
                limit_req_zone $limit_key zone=one:64k rate=1r/m;
                """, "limit_req zone=one;"), Www);
            T.Eq(200, Status(await s2.Raw(Get("/f.txt"))));
            T.Eq(429, Status(await s2.Raw(Get("/f.txt"))));
            for (int k = 0; k < 5; k++) T.Eq(200, Status(await s2.Raw(Get("/f.txt?vip=yes"))));
        });

        T.Add("limit_req: counted once per request across internal redirects; levels merge; off; dry run; 444", async () =>
        {
            await using (var s = Start(Conf("limit_req_zone $remote_net zone=one:64k rate=1r/m;", "limit_req zone=one burst=1 nodelay;"), Www))
            {
                T.Eq("home", Body(await s.Raw(Get("/"))));          // index: an internal redirect to /index.html
                T.Eq("home", Body(await s.Raw(Get("/"))));
                T.Eq(429, Status(await s.Raw(Get("/"))));
            }
            await using (var s = Start(Conf("""
                limit_req_zone $remote_net zone=wide:64k rate=1r/m;
                limit_req_zone $remote_net zone=login:64k rate=1r/m;
                limit_req zone=wide burst=2 nodelay;
                """, """
                location /login { limit_req zone=login burst=1 nodelay; }
                location /open { limit_req off; }
                location /dry { limit_req_dry_run on; }
                location /drop { limit_req_status 444; }
                """), d => { Www(d); foreach (var x in new[] { "login", "open", "dry", "drop" }) { Directory.CreateDirectory(Path.Combine(d, "www", x)); File.WriteAllText(Path.Combine(d, "www", x, "f"), x); } }))
            {
                T.Eq(200, Status(await s.Raw(Get("/login/f"))));    // wide 1/3, login 1/2
                T.Eq(200, Status(await s.Raw(Get("/login/f"))));    // wide 2/3, login 2/2
                T.Eq(429, Status(await s.Raw(Get("/login/f"))));    // login full
                T.Eq(200, Status(await s.Raw(Get("/f.txt"))));      // wide 3/3: still inherited at server level
                T.Eq(429, Status(await s.Raw(Get("/f.txt"))));
                for (int k = 0; k < 3; k++) T.Eq(200, Status(await s.Raw(Get("/open/f"))));
                var dry = await s.Raw(Get("/dry/f"));
                T.Eq(200, Status(dry));
                T.Eq("REJECTED_DRY_RUN", Header(dry, "X-Limit"));
                T.Eq("", await s.Raw(Get("/drop/f")));              // 444: closed without a byte
            }
        });

        T.Add("limit_req: state survives a reload unless the zone changes", async () =>
        {
            var conf = Conf("limit_req_zone $remote_net zone=one:64k rate=1r/m;", "limit_req zone=one;");
            await using var s = Start(conf, Www);
            T.Eq(200, Status(await s.Raw(Get("/f.txt"))));
            T.True(await s.Reload(conf));
            T.Eq(429, Status(await s.Raw(Get("/f.txt"))));      // same zone: same counters
            T.True(await s.Reload(conf.Replace("zone=one:64k", "zone=one:128k")));
            T.Eq(200, Status(await s.Raw(Get("/f.txt"))));      // resized: a new zone
        });

        T.Add("limit_conn: concurrent requests per key, released on close or reset, shared across reloads", async () =>
        {
            var conf = Conf("limit_conn_zone $remote_net zone=addr:64k;", "limit_conn addr 2;");
            await using var s = Start(conf, Www);
            using var t1 = await Tunnel(s.Port);
            var t2 = await Tunnel(s.Port);
            using var c3 = await Connect(s.Port);
            await c3.SendAsync(Encoding.ASCII.GetBytes("GET /ws HTTP/1.1\r\nHost: t\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n"));
            var third = await ReadOne(c3);
            T.Eq(429, Status(third));
            T.Eq("REJECTED", Header(third, "X-Conn"));

            t2.LingerState = new LingerOption(true, 0);
            t2.Dispose();                                          // RST mid-tunnel: the slot must come back
            await Eventually(async () => Status(await s.Raw(Get("/f.txt"))) == 200);

            using var t3 = await Tunnel(s.Port);
            T.True(await s.Reload(conf));
            T.Eq(429, Status(await s.Raw(Get("/f.txt"))));      // both slots held by old-configuration tunnels
        });

        T.Add("limits: config errors", () =>
        {
            string Err(string http, string server = "") => T.Throws<ConfigException>(() => Start(Conf(http, server), Www)).Message;
            T.Contains("unknown limit_req_zone \"nope\"", Err("", "limit_req zone=nope;"));
            T.Contains("unknown limit_conn_zone \"nope\"", Err("", "limit_conn nope 1;"));
            T.Contains("invalid rate", Err("limit_req_zone $remote_net zone=a:64k rate=10r/h;"));
            T.Contains("at least 32k", Err("limit_req_zone $remote_net zone=a:1k rate=1r/s;"));
            T.Contains("mutually exclusive", Err("limit_req_zone $remote_net zone=a:64k rate=1r/s;", "limit_req zone=a burst=2 nodelay delay=1;"));
            T.Contains("duplicate zone", Err("limit_conn_zone $remote_net zone=a:64k; limit_conn_zone $uri zone=a:64k;"));
            T.Contains("400..599 or 444", Err("", "limit_req_status 200;"));
            T.Contains("at least 1", Err("limit_conn_zone $remote_net zone=a:64k;", "limit_conn a 0;"));
            return Task.CompletedTask;
        });

        T.Add("limits: zones stay within their memory budget; $remote_net groups IPv6 by /64", () =>
        {
            var z = new ReqZone(32 * 1024);
            for (int k = 0; k < 20_000; k++) z.Account("client-" + k + new string('x', k % 300), 1000, 0, 0, out _);
            T.True(z.Used <= 32 * 1024, $"used {z.Used}");
            T.True(!z.Account(new string('k', 64 * 1024), 1000, 0, 0, out _)); // can't be tracked: fail closed

            var c = new ConnZone(32 * 1024);
            int admitted = 0;
            for (int k = 0; k < 1000; k++) if (c.TryAcquire("k" + k + new string('x', 100), 5)) admitted++;
            T.True(admitted is > 0 and < 1000, $"admitted {admitted}");   // full zone refuses new keys

            var v6 = new ConnectionInfo(1, new IPEndPoint(IPAddress.Parse("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), 5), null, false);
            T.Eq("2001:db8:1:2::/64", v6.RemoteNet);
            var v4 = new ConnectionInfo(1, new IPEndPoint(IPAddress.Parse("::ffff:192.0.2.7"), 5), null, false);
            T.Eq("192.0.2.7", v4.RemoteNet);
            return Task.CompletedTask;
        });
    }

    private static async Task<Socket> Tunnel(int port)
    {
        var c = await Connect(port);
        await c.SendAsync(Encoding.ASCII.GetBytes("GET /ws HTTP/1.1\r\nHost: t\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n"));
        var buf = new byte[4096];
        var sb = new StringBuilder();
        while (!sb.ToString().Contains("\r\n\r\n", StringComparison.Ordinal))
        {
            int n = await c.ReceiveAsync(buf, SocketFlags.None);
            if (n == 0) throw new IOException("closed during upgrade: " + sb);
            sb.Append(Encoding.ASCII.GetString(buf, 0, n));
        }
        T.Eq(101, Status(sb.ToString()));
        return c;
    }

    private static async Task Eventually(Func<Task<bool>> cond)
    {
        for (int k = 0; k < 50; k++)
        {
            if (await cond()) return;
            await Task.Delay(50);
        }
        throw new Exception("condition not met within 2.5 s");
    }
}
