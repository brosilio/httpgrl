using System.Text;
using static Httpgrl.Tests.Client;

namespace Httpgrl.Tests;

/// <summary>set / if / break / map / add_header.</summary>
internal static class ScriptTests
{
    private static string Req(string path, string extra = "", string method = "GET") =>
        $"{method} {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n{extra}\r\n";

    public static void Register()
    {
        T.Add("set: variables, forward references and per-request values", async () =>
        {
            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0;
                  location /early { return 200 "[$greeting]"; }
                  location /set { set $greeting "hi $arg_name"; set $greeting "$greeting!"; return 200 "$greeting|$uri"; }
                } }
                """);
            T.Eq("[]", Body(await s.Raw(Req("/early"))));
            T.Eq("hi bob!|/set", Body(await s.Raw(Req("/set?name=bob"))));
            T.Eq("hi !|/set", Body(await s.Raw(Req("/set"))));
            var e = T.Throws<ConfigException>(() => TestServer.Start("http { server { listen 127.0.0.1:0;\n return 200 $nope; } }"));
            T.Contains("unknown variable \"$nope\"", e.Message);
            T.Eq(2, e.Where!.Value.Line);
            T.Contains("invalid variable name", T.Throws<ConfigException>(() => TestServer.Start("http { server { listen 127.0.0.1:0; set x 1; } }")).Message);
            T.Contains("twice", T.Throws<ConfigException>(() => TestServer.Start("http { server { listen 127.0.0.1:0; set $uri 1; } }")).Message);
        });

        T.Add("if: =, !=, truthiness, regexes with captures, case-insensitive and negated matches", async () =>
        {
            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0;
                  location / {
                    if ($request_method = POST) { return 405; }
                    if ($http_x_debug) { set $d "dbg"; }
                    if ($uri ~ "^/items/(\d+)$") { return 200 "item $1 $d"; }
                    if ( $arg_q !~* ^[a-z]*$ ) { return 400; }
                    if ($http_x_mode != "fast") { return 200 "slow $d"; }
                    return 200 "fast";
                  }
                } }
                """);
            T.Eq(405, Status(await s.Raw(Req("/", "Content-Length: 0\r\n", "POST"))));
            T.Eq("item 42 dbg", Body(await s.Raw(Req("/items/42", "X-Debug: yes\r\n"))));
            T.Eq("item 42 ", Body(await s.Raw(Req("/items/42", "X-Debug: 0\r\n")))); // "0" is false
            T.Eq("slow ", Body(await s.Raw(Req("/x?q=ABC"))));
            T.Eq(400, Status(await s.Raw(Req("/x?q=a1"))));
            T.Eq("fast", Body(await s.Raw(Req("/x", "X-Mode: fast\r\n"))));
        });

        T.Add("if/break: server script runs before the location's; break ends only its own block", async () =>
        {
            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0;
                  set $who server;
                  if ($arg_stop) { break; }
                  set $who "$who+more";
                  location / { set $loc yes; if ($loc) { break; } return 500; }
                  location /show { return 200 "$who"; }
                } }
                """);
            T.Eq("server+more", Body(await s.Raw(Req("/show"))));
            T.Eq("server", Body(await s.Raw(Req("/show?stop=1"))));
            T.True(Status(await s.Raw(Req("/"))) != 500); // break skipped the return; content phase ran
        });

        T.Add("if: only rewrite directives inside; file tests and bad syntax are config errors", () =>
        {
            string Err(string loc) => T.Throws<ConfigException>(() => TestServer.Start($$"""http { server { listen 127.0.0.1:0; location / { {{loc}} } } }""")).Message;
            T.Contains("not allowed in \"if\"", Err("if ($a) { proxy_pass http://127.0.0.1:1; }"));
            T.Contains("not allowed in \"if\"", Err("if ($uri) { add_header X y; }"));
            T.Contains("file tests", Err("if (-f $uri) { return 404; }"));
            T.Contains("parentheses", Err("if $uri { return 404; }"));
            T.Contains("unknown operator", Err("if ($uri ~~ x) { return 404; }"));
            T.Contains("must be a variable", Err("if (abc = x) { return 404; }"));
            return Task.CompletedTask;
        });

        T.Add("map: exact keys, regexes with captures, default, chaining, and a cycle that doesn't kill the server", async () =>
        {
            await using var s = TestServer.Start("""
                http {
                  map $http_user_agent $ua { default other; curl/8 curl; ~*^mozilla browser; "~^bot/(\d+)" "bot-$1"; \~tilde literal; }
                  map $ua $chain { default "c:$ua"; }
                  map $arg_x $loop1 { default $loop2; }
                  map $arg_x $loop2 { default $loop1; }
                  server { listen 127.0.0.1:0;
                    location / { return 200 "$ua $chain"; }
                    location /loop { return 200 "$loop1"; }
                  }
                }
                """);
            T.Eq("curl c:curl", Body(await s.Raw(Req("/", "User-Agent: curl/8\r\n"))));
            T.Eq("browser c:browser", Body(await s.Raw(Req("/", "User-Agent: MOZILLA/5.0\r\n"))));
            T.Eq("bot-7 c:bot-7", Body(await s.Raw(Req("/", "User-Agent: bot/7\r\n"))));
            T.Eq("literal c:literal", Body(await s.Raw(Req("/", "User-Agent: ~tilde\r\n"))));
            T.Eq("other c:other", Body(await s.Raw(Req("/"))));
            T.Eq(500, Status(await s.Raw(Req("/loop"))));
            T.Contains("cycle", s.LogText());
            T.Eq("other c:other", Body(await s.Raw(Req("/")))); // still serving

            string Err(string map) => T.Throws<ConfigException>(() => TestServer.Start($$"""http { map $uri $m { {{map}} } server { listen 127.0.0.1:0; } }""")).Message;
            T.Contains("duplicate key", Err("a 1; a 2;"));
            T.Contains("hostnames", Err("hostnames; a 1;"));
            T.Contains("invalid regex", Err("~( 1;"));
            T.Contains("duplicate default", Err("default 1; default 2;"));
        });

        T.Add("add_header: merges across levels, replaces existing headers, respects status unless always", async () =>
        {
            await using var up = new FakeUpstream(async (st, rd) =>
            {
                await rd.ReadRequestAsync();
                await st.WriteAsync("HTTP/1.1 200 OK\r\nX-Frame-Options: SAMEORIGIN\r\nX-Up: 1\r\nContent-Length: 2\r\nConnection: close\r\n\r\nup"u8.ToArray());
            });
            await using var s = TestServer.Start($$"""
                http {
                  add_header Strict-Transport-Security "max-age=63072000" always;
                  add_header X-Frame-Options DENY;
                  map $scheme $tls_only { https yes; }
                  server { listen 127.0.0.1:0;
                    add_header X-Server srv;
                    add_header X-Tls $tls_only;
                    location / { return 200 ok; }
                    location /inner { add_header X-Inner $uri; add_header X-Frame-Options ""; return 200 ok; }
                    location /missing { return 404; }
                    location /proxy { proxy_pass http://127.0.0.1:{{up.Port}}; }
                    location /multi { add_header Link "</a>; rel=preload"; add_header Link "</b>; rel=preload"; return 204; }
                  }
                }
                """);
            var root = await s.Raw(Req("/"));
            T.Eq("max-age=63072000", Header(root, "Strict-Transport-Security"));
            T.Eq("DENY", Header(root, "X-Frame-Options"));
            T.Eq("srv", Header(root, "X-Server"));
            T.Eq(null, Header(root, "X-Tls")); // empty map result: not sent

            var inner = await s.Raw(Req("/inner"));
            T.Eq("/inner", Header(inner, "X-Inner"));
            T.Eq("srv", Header(inner, "X-Server"));              // merged from the server level
            T.Eq("max-age=63072000", Header(inner, "Strict-Transport-Security"));
            T.Eq(null, Header(inner, "X-Frame-Options"));        // removed with an empty value

            var missing = await s.Raw(Req("/missing"));
            T.Eq(404, Status(missing));
            T.Eq("max-age=63072000", Header(missing, "Strict-Transport-Security")); // always
            T.Eq(null, Header(missing, "X-Frame-Options"));

            var proxied = await s.Raw(Req("/proxy"));
            T.Eq("up", Body(proxied));
            T.Eq("1", Header(proxied, "X-Up"));
            T.Eq(1, Count(proxied, "X-Frame-Options"));
            T.Eq("DENY", Header(proxied, "X-Frame-Options"));     // replaced, not duplicated

            T.Eq(2, Count(await s.Raw(Req("/multi")), "Link"));

            string Err(string d) => T.Throws<ConfigException>(() => TestServer.Start($$"""http { server { listen 127.0.0.1:0; {{d}} } }""")).Message;
            T.Contains("managed by the server", Err("add_header Content-Length 5;"));
            T.Contains("invalid header name", Err("add_header \"X Y\" 5;"));
            T.Contains("invalid parameter", Err("add_header X 5 sometimes;"));
        });

        T.Add("add_header: a variable carrying CR/LF never splits the response", async () =>
        {
            await using var s = TestServer.Start("""http { server { listen 127.0.0.1:0; add_header X-Path $uri always; location / { return 200 ok; } } }""");
            var r = await s.Raw(Req("/a%0d%0aSet-Cookie:%20pwned"));
            T.True(!r.Contains("\r\nSet-Cookie", StringComparison.OrdinalIgnoreCase));
            T.Eq(200, Status(r)); // the path is legal; the header is what's refused
            T.Eq(null, Header(r, "X-Path"));
            T.Contains("add_header value dropped", s.LogText());
        });
    }

    private static int Count(string resp, string name)
    {
        int end = resp.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        int n = 0;
        foreach (var line in resp[..end].Split("\r\n"))
            if (line.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase)) n++;
        return n;
    }
}
