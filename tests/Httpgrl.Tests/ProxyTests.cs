using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static Httpgrl.Tests.Client;

namespace Httpgrl.Tests;

internal static class ProxyTests
{
    private static readonly ConcurrentQueue<string> up_heads = new();

    private static int Count(string hay, string needle)
    {
        int n = 0;
        for (int i = hay.IndexOf(needle, StringComparison.Ordinal); i >= 0; i = hay.IndexOf(needle, i + 1, StringComparison.Ordinal)) n++;
        return n;
    }

    private static string Get(string path, string extra = "") => $"GET {path} HTTP/1.1\r\nHost: front.test\r\nConnection: close\r\n{extra}\r\n";

    private static string Conf(string locations, string http = "") => $$"""
        http { {{http}} server { listen 127.0.0.1:0; root {DIR}; {{locations}} } }
        """;

    public static void Register()
    {
        T.Add("proxy: smuggling: the upstream sees exactly the messages we parsed, re-framed", async () =>
        {
            // A raw recorder upstream: every byte it receives is kept, and it answers each request it can frame.
            var raw = new MemoryStream();
            await using var up = new FakeUpstream(async (st, rd) =>
            {
                var tee = new TeeStream(st, raw);
                var reader = new RequestReader(tee, new System.Collections.Concurrent.ConcurrentQueue<string>());
                while (true)
                {
                    var (head, body) = await reader.ReadRequestAsync();
                    if (head.Length == 0) return;
                    up_heads.Enqueue(head.Split("\r\n")[0]);
                    await st.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\n\r\n"));
                    await st.WriteAsync(body);
                }
            });
            await using var s = TestServer.Start(Conf($"location / {{ proxy_pass http://127.0.0.1:{up.Port}; }}"));

            // 1. A body that looks like a request, pipelined ahead of a real one: two requests upstream, not three.
            var hidden = "GET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n";
            var r = await s.Raw($"POST /a HTTP/1.1\r\nHost: f\r\nContent-Length: {hidden.Length}\r\n\r\n{hidden}GET /b HTTP/1.1\r\nHost: f\r\nConnection: close\r\n\r\n");
            T.Eq(2, Count(r, "HTTP/1.1 200 OK"));
            // 2. Chunk extensions and trailers from the client are dropped: the body is re-chunked from what we decoded.
            r = await s.Raw("POST /c HTTP/1.1\r\nHost: f\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                + "3;ext=\"0\\r\\n\\r\\nGET /ext HTTP/1.1\"\r\nabc\r\n0\r\nX-Trailer: injected\r\n\r\n");
            T.Eq(200, Status(r));
            T.True(Body(r) == "abc");
            await Task.Delay(100);
            var heads = string.Join("|", up_heads);
            T.Eq("POST /a HTTP/1.1|GET /b HTTP/1.1|POST /c HTTP/1.1", heads);
            var seen = Encoding.Latin1.GetString(raw.ToArray());
            T.NotContains("ext=", seen);
            T.NotContains("X-Trailer", seen);
            T.Contains("\r\n\r\n3\r\nabc\r\n0\r\n\r\n", seen);
        });

        T.Add("proxy: a declared body over client_max_body_size is refused before the upstream is contacted", async () =>
        {
            await using var up = FakeUpstream.Echo();
            await using var s = TestServer.Start(Conf($"client_max_body_size 10; location / {{ proxy_pass http://127.0.0.1:{up.Port}; }}"));
            var r = await s.Raw("POST /p HTTP/1.1\r\nHost: f\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world");
            T.Eq(413, Status(r));
            T.Eq(0, up.Accepted); // nothing half-sent upstream
            T.Eq(200, Status(await s.Raw("POST /p HTTP/1.1\r\nHost: f\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhelloworld")));
        });

        T.Add("proxy: underscored header names never reach the upstream (CGI header-folding spoof)", async () =>
        {
            await using var up = FakeUpstream.Echo();
            var loc = $"location / {{ proxy_pass http://127.0.0.1:{up.Port}; proxy_set_header X-Client-Verify NONE; }}";
            await using (var s = TestServer.Start(Conf(loc)))
            {
                var body = Body(await s.Raw(Get("/", "X_Client_Verify: SUCCESS\r\nX-Client_Verify: SUCCESS\r\n")));
                T.Contains("X-Client-Verify: NONE", body);
                T.NotContains("SUCCESS", body);
            }
            // Opted in (http or server level), they pass through as sent.
            await using (var s = TestServer.Start(Conf(loc, "underscores_in_headers on;")))
                T.Contains("X_Custom: 1", Body(await s.Raw(Get("/", "X_Custom: 1\r\n"))));
        });

        T.Add("proxy: a malformed answer on a pooled connection is reported, not quietly retried as a stale connection", async () =>
        {
            // The first request on the connection is answered properly; the second gets ambiguous framing. Retrying that
            // on a fresh connection (as if the pooled one had just gone stale) would hide the upstream's misbehaviour.
            await using var up = new FakeUpstream(async (st, rd) =>
            {
                int n = 0;
                while (true)
                {
                    var (head, _) = await rd.ReadRequestAsync();
                    if (head.Length == 0) return;
                    if (n++ == 0) await st.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"u8.ToArray());
                    else await st.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"u8.ToArray());
                }
            });
            await using var s = TestServer.Start(Conf($"location / {{ proxy_pass http://127.0.0.1:{up.Port}; }}"));
            T.Eq(200, Status(await s.Raw(Get("/a"))));
            T.Eq(502, Status(await s.Raw(Get("/b"))));
            T.Eq(1, up.Accepted);
            T.Contains("both Content-Length and Transfer-Encoding", s.LogText());
        });

        T.Add("proxy_buffering: a slow client doesn't hold the upstream connection; off and X-Accel-Buffering: no stream", async () =>
        {
            var big = new byte[8 << 20];
            async Task<int> UpstreamConnectionsUsed(string proxyConf, bool accelNo)
            {
                await using var up = new FakeUpstream(async (st, rd) =>
                {
                    while (true)
                    {
                        var (head, _) = await rd.ReadRequestAsync();
                        if (head.Length == 0) return;
                        bool small = head.Contains("/small", StringComparison.Ordinal);
                        var body = small ? "ok"u8.ToArray() : big;
                        await st.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\n{(accelNo ? "X-Accel-Buffering: no\r\n" : "")}\r\n"));
                        await st.WriteAsync(body);
                    }
                });
                await using var s = TestServer.Start(Conf($"location / {{ proxy_pass http://up; {proxyConf} }}", $"upstream up {{ server 127.0.0.1:{up.Port}; keepalive 4; }}"));
                // A client that never reads, with a tiny receive window.
                using var slow = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ReceiveBufferSize = 4096 };
                await slow.ConnectAsync(System.Net.IPAddress.Loopback, s.Port);
                await slow.SendAsync(Encoding.ASCII.GetBytes("GET /big HTTP/1.1\r\nHost: t\r\n\r\n"));
                await Task.Delay(1500); // let the server read what it's allowed to
                var r = await s.Raw(Get("/small"));
                T.Eq("ok", Body(r));
                var header = new byte[4096];
                int n = await slow.ReceiveAsync(header, SocketFlags.None);
                T.True(!Encoding.ASCII.GetString(header, 0, n).Contains("X-Accel-Buffering", StringComparison.OrdinalIgnoreCase));
                return up.Accepted;
            }
            T.Eq(1, await UpstreamConnectionsUsed("proxy_buffers 64 1m;", accelNo: false)); // body fully buffered: connection reused
            T.Eq(2, await UpstreamConnectionsUsed("proxy_buffers 64 1m; proxy_buffering off;", accelNo: false));
            T.Eq(2, await UpstreamConnectionsUsed("proxy_buffers 64 1m;", accelNo: true));
        });

        T.Add("proxy: variables in proxy_pass choose among upstream blocks only (never an arbitrary host)", async () =>
        {
            await using var a = new FakeUpstream(Answers("A"));
            await using var b = new FakeUpstream(Answers("B"));
            await using var echo = FakeUpstream.Echo();
            await using var s = TestServer.Start(Conf("""
                location / { proxy_pass http://$backend; }
                location /open/ { proxy_pass http://$arg_to; }
                location /uri/ { proxy_pass http://echo/fixed$is_args$args; }
                location /raw/ { proxy_pass http://$which$uri; }
                """, $$"""
                upstream tenant_a { server 127.0.0.1:{{a.Port}}; }
                upstream main { server 127.0.0.1:{{b.Port}}; }
                upstream echo { server 127.0.0.1:{{echo.Port}}; }
                map $http_x_tenant $backend { acme tenant_a; default main; }
                map $uri $which { default echo; }
                """));
            T.Eq("A", Body(await s.Raw("GET / HTTP/1.1\r\nHost: front.test\r\nX-Tenant: acme\r\nConnection: close\r\n\r\n")));
            T.Eq("B", Body(await s.Raw(Get("/"))));
            T.Eq("B", Body(await s.Raw(Get("/open/?to=main"))));
            // A request-controlled variable naming an address gets nowhere: that would be an open proxy.
            T.Eq(502, Status(await s.Raw(Get($"/open/?to=127.0.0.1:{a.Port}"))));
            T.Contains("name an upstream block", s.LogText());

            var fixedUri = Body(await s.Raw(Get("/uri/x?y=1")));
            T.Contains("GET /fixed?y=1 HTTP/1.1", fixedUri);       // a URI part with variables replaces the request URI
            T.Contains("Host: echo", fixedUri);
            var raw = Body(await s.Raw(Get("/raw/a%20b%C3%A9")));
            T.Contains("GET /raw/a%20b%C3%A9 HTTP/1.1", raw);       // a decoded $uri can't break the request line
            T.Eq(400, Status(await s.Raw(Get("/raw/a%0d%0aX:%201")))); // and control characters never get in at all

            T.Contains("needs upstream blocks", T.Throws<ConfigException>(() => TestServer.Start(Conf("location / { proxy_pass http://$host; }"))).Message);
        });

        T.Add("proxy: active health checks take failing peers out of rotation and bring them back", async () =>
        {
            int bHealth = 200, aHealth = 200;
            Func<Stream, RequestReader, Task> Peer(string name, Func<int> health) => async (st, rd) =>
            {
                while (true)
                {
                    var (head, _) = await rd.ReadRequestAsync();
                    if (head.Length == 0) return;
                    bool check = head.StartsWith("GET /healthz ", StringComparison.Ordinal);
                    int code = check ? health() : 200;
                    var body = check ? "" : name;
                    await st.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {code} X\r\nContent-Length: {body.Length}\r\n{(check ? "Connection: close\r\n" : "")}\r\n{body}"));
                    if (check) return;
                }
            };
            await using var a = new FakeUpstream(Peer("A", () => Volatile.Read(ref aHealth)));
            await using var b = new FakeUpstream(Peer("B", () => Volatile.Read(ref bHealth)));
            await using var s = TestServer.Start(Conf("location / { proxy_pass http://app; }", $$"""
                upstream app { server 127.0.0.1:{{a.Port}}; server 127.0.0.1:{{b.Port}}; health_check uri=/healthz interval=100ms timeout=1s fails=2 passes=2; }
                """));
            async Task<string> Bodies(int n) { var sb = new StringBuilder(); for (int k = 0; k < n; k++) sb.Append(Body(await s.Raw(Get("/")))); return sb.ToString(); }
            T.True((await Bodies(6)).Contains('B'));

            Volatile.Write(ref bHealth, 503);
            await Eventually(async () => await Bodies(6) == "AAAAAA");
            T.Contains("out of rotation", s.LogText());

            Volatile.Write(ref bHealth, 200);
            await Eventually(async () => (await Bodies(6)).Contains('B'));
            T.Contains("back in rotation", s.LogText());

            Volatile.Write(ref aHealth, 500);
            Volatile.Write(ref bHealth, 500);
            await Eventually(async () => Status(await s.Raw(Get("/"))) == 502); // all actively down: no blind retries

            string Err(string hc) => T.Throws<ConfigException>(() => TestServer.Start(Conf("location / { proxy_pass http://app; }", $"upstream app {{ server 127.0.0.1:1; health_check {hc}; }}"))).Message;
            T.Contains("invalid status", Err("status=600"));
            T.Contains("at least 100ms", Err("interval=10ms"));
            T.Contains("invalid uri", Err("uri=healthz"));
            T.Contains("invalid parameter", Err("bogus=1"));
            // One verdict per peer serves every location: they must reach the peers the same way.
            T.Contains("different schemes", T.Throws<ConfigException>(() => TestServer.Start(Conf(
                "location /a { proxy_pass http://app; } location /b { proxy_pass https://app; }",
                "upstream app { server 127.0.0.1:1; health_check; }"))).Message);
            T.Contains("different schemes", T.Throws<ConfigException>(() => TestServer.Start(Conf(
                "location /a { proxy_pass https://app; } location /b { proxy_pass https://app; proxy_ssl_verify off; }",
                "upstream app { server 127.0.0.1:1; health_check; }"))).Message);
            TestServer.Start(Conf( // agreeing references are fine
                "location /a { proxy_pass http://app; } location /b { proxy_pass http://app/x/; }",
                "upstream app { server 127.0.0.1:1; health_check; }")).DisposeAsync().AsTask().GetAwaiter().GetResult();
            // A size that would wrap count * size negative is refused, not loaded.
            T.Contains("at most 64m", T.Throws<ConfigException>(() => TestServer.Start(Conf(
                "location / { proxy_pass http://127.0.0.1:1; proxy_buffers 2 9007199254740991k; }"))).Message);
        });

        T.Add("proxy: localhost is loopback only (RFC 6761), never looked up", async () =>
        {
            int lookups = 0;
            Task<System.Net.IPAddress[]> Resolve(string host, CancellationToken ct)
            {
                Interlocked.Increment(ref lookups);
                // What .NET returned on Debian for "localhost": the machine's 127.0.1.1 alias as well.
                return Task.FromResult(new[] { System.Net.IPAddress.Parse("127.0.1.1"), System.Net.IPAddress.Loopback });
            }
            await using var up = new FakeUpstream(Answers("up"));
            await using var s = TestServer.Start(Conf($$"""
                location / { proxy_pass http://localhost:{{up.Port}}/; }
                location /sub/ { proxy_pass http://app.LocalHost.:{{up.Port}}/; }
                location /grp/ { proxy_pass http://g/; }
                """, $"upstream g {{ server localhost:{up.Port}; }} upstream_resolve_interval 100ms;"), dns: Resolve);
            for (int k = 0; k < 6; k++)
            {
                T.Eq("up", Body(await s.Raw(Get("/"))));
                T.Eq("up", Body(await s.Raw(Get("/sub/"))));
                T.Eq("up", Body(await s.Raw(Get("/grp/"))));
            }
            await Task.Delay(300); // past a re-resolution interval
            T.Eq(0, lookups);
            T.True(!s.LogText().Contains("127.0.1.1", StringComparison.Ordinal));
            var L = Httpgrl.Modules.Proxy.ProxyModule.IsLocalhost;
            T.True(L("LOCALHOST") && L("a.b.localhost.") && !L("localhost.example") && !L("notlocalhost"));
        });

        T.Add("proxy: upstream hostnames are re-resolved; DNS failures keep the last good addresses", async () =>
        {
            int port = FreePort();
            await using var a = new FakeUpstream(Answers("A"), new System.Net.IPEndPoint(System.Net.IPAddress.Parse("127.0.0.1"), port));
            await using var b = new FakeUpstream(Answers("B"), new System.Net.IPEndPoint(System.Net.IPAddress.Parse("127.0.0.2"), port));
            var dns = new System.Collections.Concurrent.ConcurrentDictionary<string, string>();
            dns["app.test"] = "127.0.0.1";
            dns["late.test"] = "";
            Task<System.Net.IPAddress[]> Resolve(string host, CancellationToken ct) => dns.TryGetValue(host, out var v)
                ? v == "fail" ? throw new SocketException((int)SocketError.HostNotFound) : Task.FromResult(v.Length == 0 ? [] : new[] { System.Net.IPAddress.Parse(v) })
                : throw new SocketException((int)SocketError.HostNotFound);
            await using var s = TestServer.Start(Conf($$"""
                location /direct/ { proxy_pass http://app.test:{{port}}/; }
                location /grouped/ { proxy_pass http://grp/; }
                location /late/ { proxy_pass http://lategrp/; }
                """, $$"""
                upstream_resolve_interval 150ms;
                upstream grp { server app.test:{{port}}; }
                upstream lategrp { server late.test:{{port}} resolve; }
                """), dns: Resolve);
            T.Eq("A", Body(await s.Raw(Get("/direct/"))));
            T.Eq("A", Body(await s.Raw(Get("/grouped/"))));
            T.Eq(502, Status(await s.Raw(Get("/late/"))));        // started without addresses ("resolve")

            dns["app.test"] = "127.0.0.2";
            dns["late.test"] = "127.0.0.1";
            await Eventually(async () => Body(await s.Raw(Get("/direct/"))) == "B");
            await Eventually(async () => Body(await s.Raw(Get("/grouped/"))) == "B");
            await Eventually(async () => Body(await s.Raw(Get("/late/"))) == "A");

            dns["app.test"] = "fail";
            await Task.Delay(500);
            T.Eq("B", Body(await s.Raw(Get("/direct/"))));       // a failed lookup changes nothing
            dns["app.test"] = "";
            await Task.Delay(500);
            T.Eq("B", Body(await s.Raw(Get("/grouped/"))));      // neither does an empty answer
            var log = s.LogText();
            T.Contains("upstream addresses changed", log);
            T.Contains("keeping previous addresses", log);

            // An upstream that starts with no addresses must recover on its own: nothing else starts the refresher here.
            var dns2 = new System.Collections.Concurrent.ConcurrentDictionary<string, string>();
            Task<System.Net.IPAddress[]> Resolve2(string host, CancellationToken ct) =>
                Task.FromResult(dns2.TryGetValue(host, out var v) ? new[] { System.Net.IPAddress.Parse(v) } : []);
            await using (var s2 = TestServer.Start(Conf("location / { proxy_pass http://only/; }", $"upstream_resolve_interval 150ms; upstream only {{ server late.test:{port} resolve; }}"), dns: Resolve2))
            {
                T.Eq(502, Status(await s2.Raw(Get("/"))));
                dns2["late.test"] = "127.0.0.2";
                await Eventually(async () => Body(await s2.Raw(Get("/"))) == "B");
            }

            // Without "resolve", an unknown host is still a config error.
            T.Contains("host not found", T.Throws<ConfigException>(() => TestServer.Start(Conf("location / { proxy_pass http://nope.test/; }"), dns: Resolve)).Message);
        });

        T.Add("proxy_redirect: default maps the upstream URL back to the location; custom, regex and off; Refresh too", async () =>
        {
            int p = 0;
            await using var up = new FakeUpstream(async (st, rd) =>
            {
                var (head, _) = await rd.ReadRequestAsync();
                var path = head.Split(' ')[1];
                // The app redirects to itself, as apps behind a proxy do.
                await st.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{p}{path}next\r\nRefresh: 3; url=http://127.0.0.1:{p}{path}r\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
            });
            p = up.Port;
            await using var s = TestServer.Start(Conf($$"""
                location /one/ { proxy_pass http://127.0.0.1:{{p}}/two/; }
                location /plain/ { proxy_pass http://127.0.0.1:{{p}}; }
                location /custom/ { proxy_pass http://127.0.0.1:{{p}}/; proxy_redirect http://127.0.0.1:{{p}}/ https://$host/custom/; }
                location /re/ { proxy_pass http://127.0.0.1:{{p}}/; proxy_redirect ~^http://[^/]+/(.*)$ /moved/$1; }
                location /off/ { proxy_pass http://127.0.0.1:{{p}}/; proxy_redirect off; }
                location ~ ^/rx/ { proxy_pass http://127.0.0.1:{{p}}; }
                """));
            var one = await s.Raw(Get("/one/a"));
            T.Eq("/one/anext", Header(one, "Location"));
            T.Eq("3; url=/one/ar", Header(one, "Refresh"));
            T.Eq("/plain/anext", Header(await s.Raw(Get("/plain/a")), "Location"));
            T.Eq("https://front.test/custom/anext", Header(await s.Raw(Get("/custom/a")), "Location"));
            T.Eq("/moved/anext", Header(await s.Raw(Get("/re/a")), "Location"));
            T.Eq($"http://127.0.0.1:{p}/anext", Header(await s.Raw(Get("/off/a")), "Location"));
            T.Eq($"http://127.0.0.1:{p}/rx/anext", Header(await s.Raw(Get("/rx/a")), "Location")); // regex location: no default mapping
            T.Contains("can't be combined", T.Throws<ConfigException>(() => TestServer.Start(Conf($"location / {{ proxy_pass http://127.0.0.1:{p}; proxy_redirect off; proxy_redirect /a /b; }}"))).Message);
        });

        T.Add("proxy: basic pass-through to a real upstream (httpgrl static)", async () =>
        {
            await using var origin = TestServer.Start("http { server { listen 127.0.0.1:0; root {DIR}; } }",
                d => File.WriteAllText(Path.Combine(d, "f.txt"), "from origin"));
            await using var s = TestServer.Start(Conf($"location / {{ proxy_pass http://127.0.0.1:{origin.Port}; }}"));
            var r = await s.Raw(Get("/f.txt"));
            T.Eq(200, Status(r));
            T.Eq("from origin", Body(r));
            T.Eq("text/plain", Header(r, "Content-Type"));
            T.Eq(null, Header(r, "Server"));
            T.True(Header(r, "ETag") is not null);
            T.Eq(404, Status(await s.Raw(Get("/missing"))));
            T.Eq(304, Status(await s.Raw(Get("/f.txt", $"If-None-Match: {Header(r, "ETag")}\r\n"))));
        });

        T.Add("proxy: URI mapping (prefix replacement, normalized path, raw mode)", async () =>
        {
            await using var up = FakeUpstream.Echo();
            await using var s = TestServer.Start(Conf($$"""
                location /api/ { proxy_pass http://127.0.0.1:{{up.Port}}/v1/; }
                location = /exact { proxy_pass http://127.0.0.1:{{up.Port}}/other; }
                location /raw/ { proxy_pass http://127.0.0.1:{{up.Port}}; proxy_pass_raw_uri on; }
                location / { proxy_pass http://127.0.0.1:{{up.Port}}; }
                """));
            T.Contains("GET /v1/users/7?x=1 HTTP/1.1", Body(await s.Raw(Get("/api/users/7?x=1"))));
            T.Contains("GET /other HTTP/1.1", Body(await s.Raw(Get("/exact"))));
            // The backend gets our canonical path, never the client's traversal or double-encoding tricks.
            T.Contains("GET /b/sp%20ace HTTP/1.1", Body(await s.Raw(Get("/a/../b/./sp%20ace"))));
            T.Contains("GET /x%25252e HTTP/1.1", Body(await s.Raw(Get("/x%25252e"))));
            T.Contains("GET /raw/%7e/a//b HTTP/1.1", Body(await s.Raw(Get("/raw/%7e/a//b"))));
        });

        T.Add("proxy: request headers (Host, set/remove, hop-by-hop and Connection-listed stripped)", async () =>
        {
            await using var up = FakeUpstream.Echo();
            await using var s = TestServer.Start(Conf($$"""
                location /default/ { proxy_pass http://127.0.0.1:{{up.Port}}; }
                location / {
                    proxy_pass http://127.0.0.1:{{up.Port}};
                    proxy_set_header Host $host;
                    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                    proxy_set_header X-Real-IP $remote_addr;
                    proxy_set_header Accept-Encoding "";
                    proxy_set_header Connection "upgrade";
                }
                """));
            var echo = Body(await s.Raw(Get("/default/x")));
            T.Contains($"Host: 127.0.0.1:{up.Port}\r\n", echo);
            echo = Body(await s.Raw("GET /x HTTP/1.1\r\nHost: front.test\r\nConnection: close, X-Secret\r\nX-Secret: s\r\n" +
                "Proxy-Authorization: Basic eA==\r\nKeep-Alive: 5\r\nTE: trailers\r\nAccept-Encoding: gzip\r\nX-Forwarded-For: 10.0.0.1\r\nX-Keep: k\r\n\r\n"));
            T.Contains("Host: front.test\r\n", echo);
            T.Contains("X-Forwarded-For: 10.0.0.1, 127.0.0.1\r\n", echo);
            T.Contains("X-Real-IP: 127.0.0.1\r\n", echo);
            T.Contains("X-Keep: k\r\n", echo);
            foreach (var gone in new[] { "X-Secret", "Proxy-Authorization", "Keep-Alive", "TE:", "Accept-Encoding", "Connection: upgrade" })
                T.NotContains(gone, echo);
        });

        T.Add("proxy: request bodies (Content-Length, chunked, 100-continue)", async () =>
        {
            await using var up = FakeUpstream.Echo();
            await using var s = TestServer.Start(Conf($"location / {{ proxy_pass http://127.0.0.1:{up.Port}; }}"));
            var echo = Body(await s.Raw("POST /p HTTP/1.1\r\nHost: f\r\nConnection: close\r\nContent-Length: 5\r\n\r\nhello"));
            T.Contains("Content-Length: 5\r\n", echo);
            T.True(echo.EndsWith("\r\n\r\nhello", StringComparison.Ordinal));
            echo = Body(await s.Raw("POST /p HTTP/1.1\r\nHost: f\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n"));
            T.Contains("Transfer-Encoding: chunked\r\n", echo);
            T.True(echo.EndsWith("\r\n\r\nabcdefg", StringComparison.Ordinal));
            using var c = await Connect(s.Port);
            await c.SendAsync(Encoding.ASCII.GetBytes("POST /p HTTP/1.1\r\nHost: f\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n"));
            var buf = new byte[64];
            int n = await c.ReceiveAsync(buf, SocketFlags.None);
            T.Eq("HTTP/1.1 100 Continue\r\n\r\n", Encoding.ASCII.GetString(buf, 0, n));
            await c.SendAsync(Encoding.ASCII.GetBytes("ok"));
            var resp = await ReadOne(c);
            T.NotContains("Expect:", resp);
            T.True(resp.EndsWith("\r\n\r\nok", StringComparison.Ordinal));
        });

        T.Add("proxy: chunked upstream body is streamed and flushed as it arrives", async () =>
        {
            await using var up = new FakeUpstream(async (st, rd) =>
            {
                await rd.ReadRequestAsync();
                await st.WriteAsync("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nfirst\n\r\n"u8.ToArray());
                await Task.Delay(1200);
                await st.WriteAsync("7\r\nsecond\n\r\n0\r\n\r\n"u8.ToArray());
            });
            await using var s = TestServer.Start(Conf($"location / {{ proxy_pass http://127.0.0.1:{up.Port}; }}"));
            using var c = await Connect(s.Port);
            await c.SendAsync(Encoding.ASCII.GetBytes(Get("/events")));
            var sw = Stopwatch.StartNew();
            var sb = new StringBuilder();
            var buf = new byte[4096];
            while (!sb.ToString().Contains("first", StringComparison.Ordinal))
                sb.Append(Encoding.ASCII.GetString(buf, 0, await c.ReceiveAsync(buf, SocketFlags.None)));
            T.True(sw.ElapsedMilliseconds < 900); // not held back until the upstream finished
            var all = sb + await ReadToClose(c, 5000);
            T.Contains("second", all);
            T.Contains("\r\n0\r\n\r\n", all);
        });

        T.Add("proxy: upstream keep-alive pool reuses connections", async () =>
        {
            await using var up = FakeUpstream.Echo();
            await using var s = TestServer.Start(Conf($$"""
                location /pool/ { proxy_pass http://u1; }
                location /nopool/ { proxy_pass http://u2; }
                """, $$"""
                upstream u1 { server 127.0.0.1:{{up.Port}}; keepalive 8; }
                upstream u2 { server 127.0.0.1:{{up.Port}}; keepalive 0; }
                """));
            for (int i = 0; i < 5; i++) T.Eq(200, Status(await s.Raw(Get("/pool/x"))));
            T.Eq(1, up.Accepted);
            for (int i = 0; i < 3; i++) T.Eq(200, Status(await s.Raw(Get("/nopool/x"))));
            T.Eq(4, up.Accepted);
            T.Contains("Connection: close", up.Requests.Last());
        });

        T.Add("proxy: failover, passive health, 502 and 504", async () =>
        {
            int dead = FreePort();
            await using var up = FakeUpstream.Echo();
            await using var silent = new FakeUpstream(async (st, rd) => { await rd.ReadRequestAsync(); await Task.Delay(5000); });
            await using var s = TestServer.Start(Conf($$"""
                location /ha/ { proxy_pass http://ha; }
                location /dead/ { proxy_pass http://127.0.0.1:{{dead}}; }
                location /slow/ { proxy_pass http://127.0.0.1:{{silent.Port}}; proxy_read_timeout 1s; }
                """, $$"""upstream ha { server 127.0.0.1:{{dead}} max_fails=1 fail_timeout=30s; server 127.0.0.1:{{up.Port}}; }"""));
            for (int i = 0; i < 4; i++) T.Eq(200, Status(await s.Raw(Get("/ha/x"))));
            T.Eq(1, s.LogText().Split("upstream connect failed").Length - 1); // marked down after one failure
            T.Eq(502, Status(await s.Raw(Get("/dead/x"))));
            var sw = Stopwatch.StartNew();
            T.Eq(504, Status(await s.Raw(Get("/slow/x"))));
            T.True(sw.ElapsedMilliseconds is > 800 and < 3000);
        });

        T.Add("proxy: an upstream that answers before reading the whole body is relayed, not turned into a 502/504", async () =>
        {
            // Reads only the head, refuses at once, then neither reads nor closes (the case that used to wait out
            // proxy_send_timeout and answer 504).
            await using var up = new FakeUpstream(async (st, rd) =>
            {
                var buf = new byte[4096];
                var seen = new StringBuilder();
                while (!seen.ToString().Contains("\r\n\r\n", StringComparison.Ordinal))
                {
                    int n = await st.ReadAsync(buf);
                    if (n == 0) return;
                    seen.Append(Encoding.Latin1.GetString(buf, 0, n));
                }
                await st.WriteAsync("HTTP/1.1 413 Payload Too Large\r\nContent-Length: 4\r\n\r\nnope"u8.ToArray());
                await Task.Delay(10_000);
            });
            await using var s = TestServer.Start(Conf($$"""
                location / { proxy_pass http://127.0.0.1:{{up.Port}}; proxy_send_timeout 20s; proxy_read_timeout 20s; }
                """, "client_max_body_size 0;"));
            using var c = await Connect(s.Port);
            await c.SendAsync(Encoding.ASCII.GetBytes("POST /upload HTTP/1.1\r\nHost: t\r\nContent-Length: 104857600\r\n\r\n"));
            var pump = Task.Run(async () =>
            {
                var chunk = new byte[64 << 10];
                try { while (true) await c.SendAsync(chunk); } catch (Exception) { }
            });
            var sw = Stopwatch.StartNew();
            var r = await ReadOne(c, 5000);
            T.Eq(413, Status(r));
            T.Eq("nope", Body(r));
            T.True(sw.ElapsedMilliseconds < 4000, $"{sw.ElapsedMilliseconds}ms");
            c.Dispose(); // the rest of the body was abandoned: this connection can't carry another request anyway
            await pump;

            // An ordinary upload still works, and its connection stays reusable.
            await using var echo = FakeUpstream.Echo();
            await using var s2 = TestServer.Start(Conf($$"""location / { proxy_pass http://127.0.0.1:{{echo.Port}}; }"""));
            using var c2 = await Connect(s2.Port);
            for (int i = 0; i < 2; i++)
            {
                await c2.SendAsync(Encoding.ASCII.GetBytes("POST /e HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\n\r\nhello"));
                T.Eq(200, Status(await ReadOne(c2)));
            }
        });

        T.Add("proxy: an upgraded tunnel whose client stops reading is cut, even while the client keeps sending", async () =>
        {
            // The upstream floods; the client reads nothing but trickles bytes in. Each inbound byte completes a read,
            // which must not clear the deadline of the outbound write stalled at the same moment.
            await using var up = new FakeUpstream(async (st, rd) =>
            {
                await rd.ReadRequestAsync();
                await st.WriteAsync("HTTP/1.1 101 Switching Protocols\r\nUpgrade: flood\r\nConnection: Upgrade\r\n\r\n"u8.ToArray());
                _ = Task.Run(async () => { var sink = new byte[4096]; try { while (await st.ReadAsync(sink) > 0) { } } catch (Exception) { } });
                var junk = new byte[64 << 10];
                while (true) await st.WriteAsync(junk);
            });
            await using var s = TestServer.Start(Conf($$"""location / { proxy_pass http://127.0.0.1:{{up.Port}}; proxy_read_timeout 1s; }"""));
            using var c = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ReceiveBufferSize = 4096 };
            await c.ConnectAsync(IPAddress.Loopback, s.Port);
            await c.SendAsync(Encoding.ASCII.GetBytes("GET /ws HTTP/1.1\r\nHost: t\r\nConnection: Upgrade\r\nUpgrade: flood\r\n\r\n"));
            var one = new byte[1];
            var head = new StringBuilder();
            while (!head.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
            {
                T.True(await c.ReceiveAsync(one, SocketFlags.None) == 1, "closed during upgrade");
                head.Append((char)one[0]);
            }
            T.Eq(101, Status(head.ToString()));
            var sw = Stopwatch.StartNew();
            bool cut = false;
            while (sw.ElapsedMilliseconds < 8000 && !cut)
            {
                try { await c.SendAsync("x"u8.ToArray()); } catch (SocketException) { cut = true; break; }
                await Task.Delay(200);
                cut = s.LogText().Contains("upgraded i/o timeout", StringComparison.Ordinal);
            }
            T.True(cut, "the stalled write was never timed out");
        });

        T.Add("proxy: malicious or broken upstream responses are refused", async () =>
        {
            static FakeUpstream Says(string raw) => new(async (st, rd) => { await rd.ReadRequestAsync(); await st.WriteAsync(Encoding.Latin1.GetBytes(raw)); });
            await using var both = Says("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
            await using var twoCl = Says("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!");
            await using var fold = Says("HTTP/1.1 200 OK\r\nX-A: a\r\n b\r\nContent-Length: 0\r\n\r\n");
            await using var split = Says("HTTP/1.1 200 OK\r\nX-A: a\rSet-Cookie: x=1\r\nContent-Length: 0\r\n\r\n");
            await using var bigHead = Says("HTTP/1.1 200 OK\r\nX-Big: " + new string('x', 20000) + "\r\nContent-Length: 0\r\n\r\n");
            await using var badLine = Says("HTTP/1.1 2OO OK\r\nContent-Length: 0\r\n\r\n");
            await using var badTe = Says("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n");
            await using var short_ = Says("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nonly-some");
            await using var badChunk = Says("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n");
            await using var sameCl = Says("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello");
            await using var st600 = Says("HTTP/1.1 600 Weird\r\nContent-Length: 0\r\n\r\n");
            await using var badTrailer = Says("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX: a\r\r\n\r\n");
            await using var badExt = Says("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;a\rb\r\nhello\r\n0\r\n\r\n");
            // An endless stream of interim heads (each one within proxy_read_timeout) used to hold the request forever.
            await using var interim = Says(string.Concat(Enumerable.Repeat("HTTP/1.1 100 Continue\r\n\r\n", 17)) + "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            var locs = new StringBuilder();
            foreach (var (name, u) in new[] { ("both", both), ("twocl", twoCl), ("fold", fold), ("split", split), ("big", bigHead), ("line", badLine), ("te", badTe), ("short", short_), ("chunk", badChunk),
                                              ("samecl", sameCl), ("st600", st600), ("trailer", badTrailer), ("ext", badExt), ("interim", interim) })
                locs.Append($"location /{name} {{ proxy_pass http://127.0.0.1:{u.Port}; }}\n");
            locs.Append($"location /streamed-short {{ proxy_pass http://127.0.0.1:{short_.Port}; proxy_buffering off; }}\n");
            await using var s = TestServer.Start(Conf(locs.ToString()));
            foreach (var p in new[] { "/both", "/twocl", "/fold", "/split", "/big", "/line", "/te", "/samecl", "/st600", "/interim" })
            {
                var r = await s.Raw(Get(p));
                if (Status(r) != 502) throw new Exception($"{p}: expected 502, got {Status(r)}");
                T.NotContains("Set-Cookie", r);
            }
            // Buffered: if the truncation is noticed before anything reached the client, a clean 502; if the partial body
            // was already flushed, a cut connection. Never a message that looks complete.
            var buf = await s.Raw(Get("/short"));
            T.True(Status(buf) == 502 || (Status(buf) == 200 && Body(buf).Length < 100), buf);
            // Streamed, the head already went out: the client must see a cut connection, not a complete message.
            var trunc = await s.Raw(Get("/streamed-short"));
            T.Eq(200, Status(trunc));
            T.Eq("only-some", Body(trunc));
            // Either nothing reached the client or a cut-off body: never a terminated chunked message.
            var chunk = await s.Raw(Get("/chunk"));
            T.True(Status(chunk) is 502 or 200, chunk);
            T.NotContains("\r\n0\r\n\r\n", Body(chunk));
            foreach (var p in new[] { "/trailer", "/ext" })
            {
                var r = await s.Raw(Get(p));
                T.True(Status(r) == 502 || (Status(r) == 200 && !r.Contains("\r\n0\r\n\r\n", StringComparison.Ordinal)), $"{p}: {r}");
            }
            T.Contains("too many interim responses", s.LogText());
        });

        T.Add("proxy: 101 without an upgrade request is refused; h2c upgrade is never forwarded", async () =>
        {
            await using var rogue = new FakeUpstream(async (st, rd) => { await rd.ReadRequestAsync(); await st.WriteAsync("HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\nConnection: upgrade\r\n\r\n"u8.ToArray()); });
            await using var echo = FakeUpstream.Echo();
            await using var s = TestServer.Start(Conf($$"""
                location /rogue { proxy_pass http://127.0.0.1:{{rogue.Port}}; }
                location / { proxy_pass http://127.0.0.1:{{echo.Port}}; }
                """));
            T.Eq(502, Status(await s.Raw(Get("/rogue"))));
            var r = await s.Raw("GET /x HTTP/1.1\r\nHost: f\r\nConnection: Upgrade, HTTP2-Settings, close\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n");
            T.Eq(200, Status(r));
            T.NotContains("Upgrade", Body(r));
            T.NotContains("HTTP2-Settings", Body(r));
        });

        T.Add("proxy: WebSocket end-to-end (handshake, echo, binary, close)", async () =>
        {
            await using var up = FakeUpstream.WebSocketEcho();
            await using var s = TestServer.Start(Conf($"location /ws/ {{ proxy_pass http://127.0.0.1:{up.Port}; }}"));
            using var ws = new ClientWebSocket();
            ws.Options.KeepAliveInterval = TimeSpan.Zero;
            ws.Options.AddSubProtocol("chat");
            await ws.ConnectAsync(new Uri($"ws://127.0.0.1:{s.Port}/ws/room"), default);
            T.Eq(WebSocketState.Open, ws.State);
            T.Eq("chat", ws.SubProtocol);
            T.Eq("hello", await Echo(ws, "hello"));
            var big = new string('z', 200_000); // multi-frame, larger than any proxy buffer
            T.Eq(big, await Echo(ws, big));
            var bin = RandomNumberGenerator.GetBytes(4096);
            await ws.SendAsync(bin, WebSocketMessageType.Binary, true, default);
            var back = new byte[8192];
            var rr = await ws.ReceiveAsync(back, default);
            T.Eq(WebSocketMessageType.Binary, rr.MessageType);
            T.True(back.AsSpan(0, rr.Count).SequenceEqual(bin));
            await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", default);
            T.Eq(WebSocketCloseStatus.NormalClosure, ws.CloseStatus);
            T.Contains("\"status\":101", s.LogText());
        });

        T.Add("proxy: WebSocket idle timeout counts both directions", async () =>
        {
            await using var up = FakeUpstream.WebSocketEcho();
            await using var s = TestServer.Start(Conf($"location /ws/ {{ proxy_pass http://127.0.0.1:{up.Port}; proxy_read_timeout 1s; }}"));
            using var ws = new ClientWebSocket();
            ws.Options.KeepAliveInterval = TimeSpan.Zero;
            await ws.ConnectAsync(new Uri($"ws://127.0.0.1:{s.Port}/ws/"), default);
            // Server pushes every 400 ms for ~2.4 s while the client stays silent: must survive a 1 s idle timeout.
            await ws.SendAsync("push"u8.ToArray(), WebSocketMessageType.Text, true, default);
            var buf = new byte[256];
            for (int i = 0; i < 6; i++)
            {
                var r = await ws.ReceiveAsync(buf, default);
                T.Eq("tick", Encoding.ASCII.GetString(buf, 0, r.Count));
            }
            // Now nobody talks: the tunnel must be torn down shortly after the idle timeout.
            var sw = Stopwatch.StartNew();
            try
            {
                using var cts = new CancellationTokenSource(5000);
                var r = await ws.ReceiveAsync(buf, cts.Token);
                T.True(r.MessageType == WebSocketMessageType.Close);
            }
            catch (WebSocketException) { }
            T.True(sw.ElapsedMilliseconds < 3000);
        });

        T.Add("proxy: WebSocket over TLS on both sides (wss -> https upstream, verified)", async () =>
        {
            var dir = Path.Combine(Path.GetTempPath(), "httpgrl-wss-" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(dir);
            using var upCert = MakeCert("localhost", dir, "up");
            await using var up = FakeUpstream.WebSocketEcho(upCert);
            await using var s = TestServer.Start($$"""
                http { server {
                    listen 127.0.0.1:0 ssl; ssl_certificate {DIR}/front.crt; ssl_certificate_key {DIR}/front.key; root {DIR};
                    location /ws/ { proxy_pass https://127.0.0.1:{{up.Port}}; proxy_ssl_name localhost; proxy_ssl_trusted_certificate {{dir}}/up.crt; }
                } }
                """, d => MakeCert("front.test", d, "front").Dispose());
            using var ws = new ClientWebSocket();
            ws.Options.KeepAliveInterval = TimeSpan.Zero;
            ws.Options.RemoteCertificateValidationCallback = (_, _, _, _) => true;
            await ws.ConnectAsync(new Uri($"wss://127.0.0.1:{s.Port}/ws/"), default);
            T.Eq("secure", await Echo(ws, "secure"));
            await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, null, default);
            Directory.Delete(dir, true);
        });

        T.Add("proxy: upstream TLS is verified by default", async () =>
        {
            var dir = Path.Combine(Path.GetTempPath(), "httpgrl-tls-" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(dir);
            using var cert = MakeCert("localhost", dir, "up");
            await using var up = FakeUpstream.Echo(cert);
            await using var s = TestServer.Start(Conf($$"""
                location /strict/ { proxy_pass https://127.0.0.1:{{up.Port}}; proxy_ssl_name localhost; }
                location /trusted/ { proxy_pass https://127.0.0.1:{{up.Port}}; proxy_ssl_name localhost; proxy_ssl_trusted_certificate {{dir}}/up.crt; }
                location /wrongname/ { proxy_pass https://127.0.0.1:{{up.Port}}; proxy_ssl_name other.test; proxy_ssl_trusted_certificate {{dir}}/up.crt; }
                location /lax/ { proxy_pass https://127.0.0.1:{{up.Port}}; proxy_ssl_verify off; }
                """));
            T.Eq(502, Status(await s.Raw(Get("/strict/x"))));    // self-signed, not in the system store
            T.Eq(200, Status(await s.Raw(Get("/trusted/x"))));
            T.Eq(502, Status(await s.Raw(Get("/wrongname/x"))));
            T.Eq(200, Status(await s.Raw(Get("/lax/x"))));
            Directory.Delete(dir, true);
        });

        T.Add("proxy: unix socket upstream and intercept_errors", async () =>
        {
            if (OperatingSystem.IsWindows()) return;
            var sock = Path.Combine(Path.GetTempPath(), "hg-" + Guid.NewGuid().ToString("N")[..8] + ".sock");
            await using var up = new FakeUpstream(async (st, rd) =>
            {
                var (head, _) = await rd.ReadRequestAsync();
                var body = head.Contains("/err", StringComparison.Ordinal) ? "upstream error page" : "via unix";
                var status = head.Contains("/err", StringComparison.Ordinal) ? "503 Service Unavailable" : "200 OK";
                await st.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {status}\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n{body}"));
            }, new UnixDomainSocketEndPoint(sock));
            await using var s = TestServer.Start(Conf($$"""
                location /u/ { proxy_pass http://unix:{{sock}}:/; }
                location /i/ { proxy_pass http://unix:{{sock}}:/; proxy_intercept_errors on; error_page 503 /mine.txt; }
                location = /mine.txt { }
                """), d => File.WriteAllText(Path.Combine(d, "mine.txt"), "our page"));
            T.Eq("via unix", Body(await s.Raw(Get("/u/x"))));
            var r = await s.Raw(Get("/u/err"));
            T.Eq(503, Status(r));
            T.Eq("upstream error page", Body(r));
            r = await s.Raw(Get("/i/err"));
            T.Eq(503, Status(r));
            T.Eq("our page", Body(r));
            File.Delete(sock);
        });

        T.Add("proxy: config validation", () =>
        {
            T.Contains("URI part", T.Throws<ConfigException>(() => TestServer.Start(Conf("location ~ x { proxy_pass http://127.0.0.1:1/a; }"))).Message);
            T.Contains("variables", T.Throws<ConfigException>(() => TestServer.Start(Conf("location / { proxy_pass http://127.0.0.1:1$uri; }"))).Message);
            T.Contains("no servers", T.Throws<ConfigException>(() => TestServer.Start(Conf("location / { proxy_pass http://e; }", "upstream e { }"))).Message);
            T.Contains("duplicate", T.Throws<ConfigException>(() => TestServer.Start(Conf("location / { proxy_pass http://127.0.0.1:1; proxy_pass http://127.0.0.1:2; }"))).Message);
            T.Contains("host not found", T.Throws<ConfigException>(() => TestServer.Start(Conf("location / { proxy_pass http://no-such-host.invalid; }"))).Message);
        });
    }

    private static async Task<string> Echo(ClientWebSocket ws, string text)
    {
        await ws.SendAsync(Encoding.UTF8.GetBytes(text), WebSocketMessageType.Text, true, default);
        var ms = new MemoryStream();
        var buf = new byte[16384];
        WebSocketReceiveResult r;
        do
        {
            r = await ws.ReceiveAsync(buf, default);
            ms.Write(buf, 0, r.Count);
        } while (!r.EndOfMessage);
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    /// <summary>Keep-alive upstream that answers every request with <paramref name="body"/>.</summary>
    private static Func<Stream, RequestReader, Task> Answers(string body) => async (st, rd) =>
    {
        while (true)
        {
            var (head, _) = await rd.ReadRequestAsync();
            if (head.Length == 0) return;
            await st.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\n\r\n{body}"));
        }
    };

    private static async Task Eventually(Func<Task<bool>> cond)
    {
        for (int k = 0; k < 60; k++)
        {
            if (await cond()) return;
            await Task.Delay(50);
        }
        throw new Exception("condition not met within 3 s");
    }

    private static int FreePort()
    {
        using var l = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        l.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)l.LocalEndPoint!).Port; // closed on dispose: connects are refused
    }

    internal static X509Certificate2 MakeCert(string name, string dir, string file)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(name);
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        File.WriteAllText(Path.Combine(dir, file + ".crt"), cert.ExportCertificatePem());
        File.WriteAllText(Path.Combine(dir, file + ".key"), key.ExportPkcs8PrivateKeyPem());
        return cert;
    }
}

/// <summary>Scriptable upstream: TCP, TLS or unix socket; one handler invocation per accepted connection.</summary>
internal sealed class FakeUpstream : IAsyncDisposable
{
    private readonly Socket _listener;
    private readonly CancellationTokenSource _stop = new();
    private int _accepted;
    public readonly ConcurrentQueue<string> Requests = new();
    public int Port => _listener.LocalEndPoint is IPEndPoint ip ? ip.Port : 0;
    public int Accepted => Volatile.Read(ref _accepted);

    public FakeUpstream(Func<Stream, RequestReader, Task> handler, EndPoint? at = null, X509Certificate2? cert = null)
    {
        at ??= new IPEndPoint(IPAddress.Loopback, 0);
        _listener = at is UnixDomainSocketEndPoint
            ? new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified)
            : new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listener.Bind(at);
        _listener.Listen(64);
        _ = Task.Run(async () =>
        {
            while (!_stop.IsCancellationRequested)
            {
                Socket s;
                try { s = await _listener.AcceptAsync(_stop.Token); }
                catch (Exception) { return; }
                Interlocked.Increment(ref _accepted);
                _ = Task.Run(async () =>
                {
                    Stream st = new NetworkStream(s, ownsSocket: true);
                    try
                    {
                        if (cert is not null)
                        {
                            var ssl = new SslStream(st);
                            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = cert });
                            st = ssl;
                        }
                        await handler(st, new RequestReader(st, Requests));
                    }
                    catch (Exception) { }
                    finally { await st.DisposeAsync(); }
                });
            }
        });
    }

    /// <summary>Keep-alive echo: body = request head + body as received.</summary>
    public static FakeUpstream Echo(X509Certificate2? cert = null) => new(async (st, rd) =>
    {
        while (true)
        {
            var (head, body) = await rd.ReadRequestAsync();
            if (head.Length == 0) return;
            var payload = Encoding.Latin1.GetBytes(head).Concat(body).ToArray();
            bool close = head.Contains("Connection: close", StringComparison.OrdinalIgnoreCase);
            await st.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {payload.Length}\r\nServer: fake\r\n{(close ? "Connection: close\r\n" : "")}\r\n"));
            await st.WriteAsync(payload);
            if (close) return;
        }
    }, null, cert);

    /// <summary>RFC 6455 server via the BCL: echoes messages; "push" makes it send six "tick"s 400 ms apart.</summary>
    public static FakeUpstream WebSocketEcho(X509Certificate2? cert = null) => new(async (st, rd) =>
    {
        var (head, _) = await rd.ReadRequestAsync();
        string? H(string n) => head.Split("\r\n").FirstOrDefault(l => l.StartsWith(n + ":", StringComparison.OrdinalIgnoreCase))?[(n.Length + 1)..].Trim();
        if (!string.Equals(H("Upgrade"), "websocket", StringComparison.OrdinalIgnoreCase)) return;
        var accept = Convert.ToBase64String(SHA1.HashData(Encoding.ASCII.GetBytes(H("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
        var proto = H("Sec-WebSocket-Protocol") is { } p ? $"Sec-WebSocket-Protocol: {p.Split(',')[0].Trim()}\r\n" : "";
        await st.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n{proto}\r\n"));
        using var ws = WebSocket.CreateFromStream(st, new WebSocketCreationOptions { IsServer = true, KeepAliveInterval = TimeSpan.Zero });
        var buf = new byte[1 << 20];
        while (true)
        {
            var r = await ws.ReceiveAsync(buf.AsMemory(), default);
            if (r.MessageType == WebSocketMessageType.Close) { await ws.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, null, default); return; }
            int len = r.Count;
            while (!r.EndOfMessage) { r = await ws.ReceiveAsync(buf.AsMemory(len), default); len += r.Count; }
            if (r.MessageType == WebSocketMessageType.Text && len == 4 && Encoding.ASCII.GetString(buf, 0, 4) == "push")
            {
                for (int i = 0; i < 6; i++) { await Task.Delay(400); await ws.SendAsync("tick"u8.ToArray(), WebSocketMessageType.Text, true, default); }
                continue;
            }
            await ws.SendAsync(buf.AsMemory(0, len), r.MessageType, true, default);
        }
    }, null, cert);

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        _listener.Dispose();
        await Task.Delay(10);
    }
}

/// <summary>Reads HTTP/1.1 requests (Content-Length or chunked) off a stream, keeping leftovers between requests.</summary>
/// <summary>Copies everything read from <paramref name="inner"/> into <paramref name="sink"/> (a raw wire recorder).</summary>
internal sealed class TeeStream(Stream inner, MemoryStream sink) : Stream
{
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        int n = await inner.ReadAsync(buffer, ct);
        lock (sink) sink.Write(buffer.Span[..n]);
        return n;
    }
    public override Task<int> ReadAsync(byte[] b, int o, int c, CancellationToken ct) => ReadAsync(b.AsMemory(o, c), ct).AsTask();
    public override int Read(byte[] b, int o, int c) => ReadAsync(b, o, c, default).GetAwaiter().GetResult();
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> b, CancellationToken ct = default) => inner.WriteAsync(b, ct);
    public override void Write(byte[] b, int o, int c) => inner.Write(b, o, c);
    public override void Flush() => inner.Flush();
    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}

internal sealed class RequestReader(Stream s, ConcurrentQueue<string> log)
{
    private readonly List<byte> _buf = new();
    private readonly byte[] _tmp = new byte[65536];

    private async Task<bool> More()
    {
        int n = await s.ReadAsync(_tmp);
        if (n == 0) return false;
        _buf.AddRange(_tmp.AsSpan(0, n).ToArray());
        return true;
    }

    private int Find(string pat)
    {
        var p = Encoding.ASCII.GetBytes(pat);
        for (int i = 0; i + p.Length <= _buf.Count; i++)
        {
            int k = 0;
            while (k < p.Length && _buf[i + k] == p[k]) k++;
            if (k == p.Length) return i;
        }
        return -1;
    }

    private byte[] Take(int n)
    {
        var r = _buf.GetRange(0, n).ToArray();
        _buf.RemoveRange(0, n);
        return r;
    }

    public async Task<(string Head, byte[] Body)> ReadRequestAsync()
    {
        int end;
        while ((end = Find("\r\n\r\n")) < 0)
            if (!await More()) return ("", []);
        var head = Encoding.Latin1.GetString(Take(end + 4));
        log.Enqueue(head);
        var body = new List<byte>();
        var cl = head.Split("\r\n").FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase));
        if (cl is not null)
        {
            int len = int.Parse(cl[15..].Trim());
            while (_buf.Count < len) if (!await More()) break;
            body.AddRange(Take(Math.Min(len, _buf.Count)));
        }
        else if (head.Contains("Transfer-Encoding: chunked", StringComparison.OrdinalIgnoreCase))
        {
            while (true)
            {
                int le;
                while ((le = Find("\r\n")) < 0) if (!await More()) return (head, body.ToArray());
                int size = Convert.ToInt32(Encoding.ASCII.GetString(Take(le + 2)).Trim().Split(';')[0], 16);
                while (_buf.Count < size + 2) if (!await More()) return (head, body.ToArray());
                body.AddRange(Take(size));
                Take(2);
                if (size == 0) break;
            }
        }
        return (head, body.ToArray());
    }
}
