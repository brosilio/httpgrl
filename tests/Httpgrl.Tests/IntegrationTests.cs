using System.Diagnostics;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static Httpgrl.Tests.Client;

namespace Httpgrl.Tests;

internal static class IntegrationTests
{
    private const string Base = """
        error_log stdout debug;
        http {
            include mime.types;
            default_type application/octet-stream;
            server {
                listen 127.0.0.1:0;
                root {DIR}/www;
                location /list/ { autoindex on; }
                location /listjson/ { autoindex on; autoindex_format json; alias {DIR}/www/list/; }
                location /img { alias {DIR}/www/images/; }
                location /spa/ { try_files $uri $uri/ /spa/index.html; }
                location /strict/ { try_files $uri =404; }
                location /named/ { try_files $uri @fallback; }
                location @fallback { root {DIR}/fallback; try_files /fb.txt =500; }
                location = /custom404.html { internal; }
                location /errs/ { error_page 404 /custom404.html; }
                location /errs2/ { error_page 404 =200 /custom404.html; }
                location ~ \.secret$ { internal; }
            }
        }
        """;

    private static void Populate(string dir)
    {
        var www = Path.Combine(dir, "www");
        Directory.CreateDirectory(Path.Combine(www, "list", "sub"));
        Directory.CreateDirectory(Path.Combine(www, "images"));
        Directory.CreateDirectory(Path.Combine(www, "spa"));
        Directory.CreateDirectory(Path.Combine(www, "dir"));
        Directory.CreateDirectory(Path.Combine(dir, "fallback"));
        File.WriteAllText(Path.Combine(www, "index.html"), "<h1>root index</h1>");
        File.WriteAllText(Path.Combine(www, "hello.txt"), "hello world");
        File.WriteAllText(Path.Combine(www, "custom404.html"), "custom not found");
        File.WriteAllText(Path.Combine(www, "x.secret"), "TOP SECRET");
        File.WriteAllText(Path.Combine(www, "list", "a.txt"), "a");
        File.WriteAllText(Path.Combine(www, "list", ".hidden"), "h");
        if (!OperatingSystem.IsWindows()) File.WriteAllText(Path.Combine(www, "list", "<script>x\".txt"), "x");
        File.WriteAllText(Path.Combine(www, "images", "cat.png"), "PNG");
        File.WriteAllText(Path.Combine(www, "spa", "index.html"), "spa shell");
        File.WriteAllText(Path.Combine(www, "imagessecret.txt"), "should not leak");
        File.WriteAllText(Path.Combine(dir, "fallback", "fb.txt"), "fallback body");
        File.WriteAllText(Path.Combine(dir, "mime.types"), "types { text/html html; text/plain txt; image/png png; }");
        File.WriteAllBytes(Path.Combine(www, "big.bin"), RandomNumberGenerator.GetBytes(3 << 20));
    }

    private static string Get(string path, string extra = "") => $"GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n{extra}\r\n";

    /// <summary>A TLS handshake offering only <paramref name="suite"/> (any, if null). Returns the negotiated suite, or null if refused.</summary>
    private static async Task<System.Net.Security.TlsCipherSuite?> Handshake(int port, System.Security.Authentication.SslProtocols protocol, System.Net.Security.TlsCipherSuite? suite)
    {
        using var tcp = new System.Net.Sockets.TcpClient();
        await tcp.ConnectAsync(System.Net.IPAddress.Loopback, port);
        using var ssl = new System.Net.Security.SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        var o = new System.Net.Security.SslClientAuthenticationOptions { TargetHost = "t.test", EnabledSslProtocols = protocol };
        if (suite is { } one && !OperatingSystem.IsWindows()) o.CipherSuitesPolicy = new System.Net.Security.CipherSuitesPolicy([one]);
        try
        {
            await ssl.AuthenticateAsClientAsync(o);
            return ssl.NegotiatedCipherSuite;
        }
        catch (Exception e) when (e is System.Security.Authentication.AuthenticationException or IOException) { return null; }
    }

    internal static bool HasOpenSsl()
    {
        try { using var p = Process.Start(new ProcessStartInfo("openssl", ["version"]) { RedirectStandardOutput = true })!; p.WaitForExit(); return p.ExitCode == 0; }
        catch (System.ComponentModel.Win32Exception) { return false; }
    }

    /// <summary>Run openssl with <paramref name="stdin"/> (then EOF); its stdout and stderr together.</summary>
    internal static async Task<string> OpenSsl(string[] args, string stdin)
    {
        var psi = new ProcessStartInfo("openssl") { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var o = p.StandardOutput.ReadToEndAsync();
        var e = p.StandardError.ReadToEndAsync();
        await p.StandardInput.WriteAsync(stdin);
        await Task.Delay(300); // let the response arrive before EOF closes the connection
        p.StandardInput.Close();
        using var cts = new CancellationTokenSource(15_000);
        await p.WaitForExitAsync(cts.Token);
        return await o + await e;
    }

    private static int Count(string hay, string needle)
    {
        int n = 0;
        for (int i = hay.IndexOf(needle, StringComparison.Ordinal); i >= 0; i = hay.IndexOf(needle, i + 1, StringComparison.Ordinal)) n++;
        return n;
    }

    public static void Register()
    {
        T.Add("security: regex SNI timeout refuses the TLS handshake", async () =>
        {
            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0 ssl; server_name "~^(?=a)((a+)+$|a+b$)";
                  ssl_certificate {DIR}/q.crt; ssl_certificate_key {DIR}/q.key; return 200 public; } }
                """, d => ProxyTests.MakeCert("aaaa", d, "q").Dispose());
            foreach (string host in new[] { "aaaa", new string('a', 60) + "b" })
            {
                using var tcp = new TcpClient();
                await tcp.ConnectAsync(System.Net.IPAddress.Loopback, s.Port);
                using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
                bool accepted = false;
                try { await ssl.AuthenticateAsClientAsync(host); accepted = true; }
                catch (Exception e) when (e is System.Security.Authentication.AuthenticationException or IOException) { }
                T.Eq(host == "aaaa", accepted);
            }
            T.NotContains("\"level\":\"error\"", s.LogText());
        });

        T.Add("security: regex Host timeout drops rather than selecting the default server", async () =>
        {
            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0; server_name "~^(?=a)((a+)+$|a+b$)"; return 200 public; } }
                """);
            T.Eq(200, Status(await s.Raw("GET / HTTP/1.1\r\nHost: aaaa\r\nConnection: close\r\n\r\n")));
            T.Eq("", await s.Raw("GET / HTTP/1.1\r\nHost: " + new string('a', 60) + "b\r\nConnection: close\r\n\r\n"));
            T.Contains("\"event\":\"routing_regex_timeout\"", s.LogText());
        });

        T.Add("security: regex location timeout fails closed", async () =>
        {
            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0;
                  location / { return 200 public; }
                  location ~ "^/(?=a)((a+)+$|a+!$)" { deny all; return 403; }
                } }
                """);
            using var client = new System.Net.Http.HttpClient();
            var normal = await client.GetAsync($"http://127.0.0.1:{s.Port}/aaaa");
            T.Eq(403, (int)normal.StatusCode);
            var attack = await client.GetAsync($"http://127.0.0.1:{s.Port}/" + new string('a', 4000) + "!");
            T.Eq(500, (int)attack.StatusCode);
        });


        T.Add("http: static file, HEAD, content type", async () =>
        {
            await using var s = TestServer.Start(Base, Populate);
            var r = await s.Raw(Get("/hello.txt"));
            T.Eq(200, Status(r));
            T.Eq("hello world", Body(r));
            T.Eq("text/plain", Header(r, "Content-Type"));
            T.Eq("11", Header(r, "Content-Length"));
            T.True(Header(r, "ETag") is not null && Header(r, "Date") is not null);
            r = await s.Raw($"HEAD /hello.txt HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
            T.Eq(200, Status(r));
            T.Eq("11", Header(r, "Content-Length"));
            T.Eq("", Body(r));
        });

        T.Add("http: large file is byte-exact", async () =>
        {
            await using var s = TestServer.Start(Base, Populate);
            using var http = new HttpClient();
            var bytes = await http.GetByteArrayAsync($"http://127.0.0.1:{s.Port}/big.bin");
            T.True(bytes.AsSpan().SequenceEqual(File.ReadAllBytes(Path.Combine(s.Dir, "www", "big.bin"))));
        });

        T.Add("http: conditional GET and ranges", async () =>
        {
            await using var s = TestServer.Start(Base, Populate);
            var r = await s.Raw(Get("/hello.txt"));
            var etag = Header(r, "ETag")!;
            var lm = Header(r, "Last-Modified")!;
            T.Eq(304, Status(await s.Raw(Get("/hello.txt", $"If-None-Match: {etag}\r\n"))));
            T.Eq(304, Status(await s.Raw(Get("/hello.txt", $"If-None-Match: \"x\", W/{etag}\r\n"))));
            T.Eq(200, Status(await s.Raw(Get("/hello.txt", "If-None-Match: \"nope\"\r\n"))));
            T.Eq(304, Status(await s.Raw(Get("/hello.txt", $"If-Modified-Since: {lm}\r\n"))));
            r = await s.Raw(Get("/hello.txt", "Range: bytes=6-\r\n"));
            T.Eq(206, Status(r));
            T.Eq("world", Body(r));
            T.Eq("bytes 6-10/11", Header(r, "Content-Range"));
            r = await s.Raw(Get("/hello.txt", "Range: bytes=50-\r\n"));
            T.Eq(416, Status(r));
            T.Eq("bytes */11", Header(r, "Content-Range"));
            T.Eq(200, Status(await s.Raw(Get("/hello.txt", "Range: bytes=0-1\r\nIf-Range: \"stale\"\r\n"))));
        });

        T.Add("http: index, directory redirect, autoindex", async () =>
        {
            await using var s = TestServer.Start(Base, Populate);
            var r = await s.Raw(Get("/"));
            T.Eq(200, Status(r));
            T.Eq("<h1>root index</h1>", Body(r));
            r = await s.Raw(Get("/dir?x=1"));
            T.Eq(301, Status(r));
            T.Eq("/dir/?x=1", Header(r, "Location"));
            T.Eq(403, Status(await s.Raw(Get("/dir/"))));
            T.Eq(404, Status(await s.Raw(Get("/missing/"))));
            r = await s.Raw(Get("/list/"));
            T.Eq(200, Status(r));
            T.Contains("<a href=\"./a.txt\">a.txt</a>", r);
            T.Contains("<a href=\"./sub/\">sub/</a>", r);
            T.NotContains(".hidden", r);
            if (!OperatingSystem.IsWindows())
            {
                T.NotContains("<script>", Body(r));
                T.Contains("&lt;script&gt;x&quot;.txt", r);
                T.Contains("href=\"./%3Cscript%3Ex%22.txt\"", r);
            }
            r = await s.Raw(Get("/listjson/"));
            T.Eq("application/json", Header(r, "Content-Type"));
            using var doc = System.Text.Json.JsonDocument.Parse(Dechunked(r));
            T.Eq("sub", doc.RootElement[0].GetProperty("name").GetString());
            T.Eq("directory", doc.RootElement[0].GetProperty("type").GetString());
        });

        T.Add("autoindex: a big directory is streamed in pieces, and arrives complete", async () =>
        {
            const int Files = 3000;
            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0; root {DIR}; location /big/ { autoindex on; }
                       location /bigjson/ { alias {DIR}/big/; autoindex on; autoindex_format json; } } }
                """, d =>
            {
                Directory.CreateDirectory(Path.Combine(d, "big"));
                for (int i = 0; i < Files; i++) File.WriteAllText(Path.Combine(d, "big", $"{i:D5}-" + new string('n', 100)), "");
            });
            var r = await s.Raw(Get("/bigjson/"));
            T.Eq("chunked", Header(r, "Transfer-Encoding"));
            using var doc = System.Text.Json.JsonDocument.Parse(Dechunked(r));
            T.Eq(Files, doc.RootElement.GetArrayLength());
            T.Eq("00000-" + new string('n', 100), doc.RootElement[0].GetProperty("name").GetString());
            var html = Dechunked(await s.Raw(Get("/big/")));
            T.Eq(Files, html.Split("<a href=\"./0", StringSplitOptions.None).Length - 1);
            T.True(html.EndsWith("</html>\r\n", StringComparison.Ordinal));
            T.Eq(200, Status(await s.Raw("HEAD /big/ HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")));
        });

        T.Add("security: traversal and alias off-by-slash", async () =>
        {
            await using var s = TestServer.Start(Base, Populate);
            T.Eq(400, Status(await s.Raw(Get("/../../etc/passwd"))));
            T.Eq(400, Status(await s.Raw(Get("/%2e%2e/%2e%2e/etc/passwd"))));
            T.Eq(400, Status(await s.Raw(Get("/a/..%2f..%2f..%2fetc/passwd"))));
            T.Eq("PNG", Body(await s.Raw(Get("/img/cat.png"))));
            // Classic nginx alias bug: "location /img { alias .../images/; }" + "/img../x" escapes the alias dir.
            var r = await s.Raw(Get("/img../imagessecret.txt"));
            T.Refused(r);
            T.NotContains("should not leak", r);
            T.Eq(404, Status(r));
            r = await s.Raw(Get("/x.secret"));
            T.Eq(404, Status(r));
            T.NotContains("TOP SECRET", r);
        });

        T.Add("security: a root or alias that begins with a variable can't be climbed out of", async () =>
        {
            // No constant leading directory to check against: the value itself is the boundary, and a value with dot
            // segments (or a relative one) maps nothing. $arg_d stands in for any variable the request can influence.
            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0;
                  location /r/ { root $arg_d; }
                  location ~ ^/a/(.*)$ { alias $arg_d/$1; }
                } }
                """, d =>
            {
                Directory.CreateDirectory(Path.Combine(d, "www", "r"));
                File.WriteAllText(Path.Combine(d, "www", "r", "ok.txt"), "fine");
                File.WriteAllText(Path.Combine(d, "secret.txt"), "TOP SECRET");
                Directory.CreateDirectory(Path.Combine(d, "r"));
                File.WriteAllText(Path.Combine(d, "r", "secret.txt"), "TOP SECRET");
            });
            var www = Path.Combine(s.Dir, "www");
            T.Eq("fine", Body(await s.Raw(Get($"/r/ok.txt?d={www}"))));
            foreach (var d in new[] { $"{www}/..", $"{www}/../www/..", "..", "www", $"{www}/./.." })
            {
                var r = await s.Raw(Get($"/r/secret.txt?d={d}"));
                T.Refused(r); // a real answer, not a hang or reset passing for "defended"
                T.NotContains("TOP SECRET", r);
                r = await s.Raw(Get($"/a/secret.txt?d={d}"));
                T.Refused(r);
                T.NotContains("TOP SECRET", r);
            }
            T.Eq("fine", Body(await s.Raw(Get($"/a/ok.txt?d={www}/r"))));
        });

        T.Add("security: catastrophic regexes (backreferences force backtracking) cost bounded time and fail closed, quietly", async () =>
        {
            // A backreference can't run on the non-backtracking engine, so these fall back to backtracking with a match
            // timeout. Input built to blow up (a long run that almost matches) must fail closed with 500, no
            // error-level log line per request (an attacker could flood the log), and the server keeps serving.
            const string evil = @"(a+)+\1b$";
            await using var s = TestServer.Start($$"""
                http {
                  map $uri $m { "~{{evil}}" hit; default miss; }
                  server { listen 127.0.0.1:0 default_server; server_name "~^(a+)+\1b$";
                    location ~ {{evil}} { return 200 "loc"; }
                    location ^~ /if/ { if ($uri ~ "{{evil}}") { return 200 "if"; } return 200 "m=$m"; }
                    location ^~ /rw/ { rewrite "{{evil}}" /x; return 200 "rw"; }
                    location / { return 200 "m=$m"; }
                  }
                }
                """);
            var payload = new string('a', 40) + "!";
            foreach (var path in new[] { "/" + payload, "/if/" + payload, "/rw/" + payload })
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                var r = await s.Raw($"GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", 10_000);
                T.True(sw.ElapsedMilliseconds < 3000);
                // Fails closed: a timed-out regex is neither a match nor a non-match (nginx answers 500 too).
                if (Status(r) != 500) throw new Exception($"{path}: {r}\n{s.LogText()}");
            }
            T.Eq(200, Status(await s.Raw(Get("/fine"))));
            var log = s.LogText();
            T.Contains("regex match timed out", log);
            T.NotContains("\"level\":\"error\"", log);
            T.NotContains("\"stack\"", log);
        });

        T.Add("security: $request_uri is origin-form, so an absolute-form target can't pick a redirect's host", async () =>
        {
            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0;
                  location /go/ { return 302 $request_uri; }
                  location / { return 200 "[$request_uri]"; }
                } }
                """);
            var r = await s.Raw("GET http://evil.example/go/x?y=1 HTTP/1.1\r\nHost: good.test\r\nConnection: close\r\n\r\n");
            T.Eq(302, Status(r));
            T.Eq("/go/x?y=1", Header(r, "Location"));
            T.Eq("[/]", Body(await s.Raw("GET http://evil.example HTTP/1.1\r\nHost: good.test\r\nConnection: close\r\n\r\n")));
            T.Eq("[/a/../b?q]", Body(await s.Raw(Get("/a/../b?q")))); // origin form: as received (nginx keeps it unnormalized too)
        });

        T.Add("security: an unread request body is never parsed as the next request", async () =>
        {
            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0; client_max_body_size 100;
                  location /evil { return 200 "EVIL"; }
                  location / { return 200 "ok $uri"; }
                } }
                """);
            const string hidden = "GET /evil HTTP/1.1\r\nHost: a\r\n\r\n";
            const string next = "GET /next HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
            // Content-Length body the handler never reads: drained, then the real next request.
            var r = await s.Raw($"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: {hidden.Length}\r\n\r\n{hidden}{next}");
            T.NotContains("EVIL", r);
            T.Contains("ok /next", r);
            // Chunked, same.
            r = await s.Raw($"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n{hidden.Length:x}\r\n{hidden}\r\n0\r\n\r\n{next}");
            T.NotContains("EVIL", r);
            T.Contains("ok /next", r);
            // The drain limit counts wire bytes, chunk framing included: 1-byte chunks are six bytes each on the wire.
            var tiny = string.Concat(Enumerable.Repeat("1\r\nx\r\n", 20_000)); // 20 kB of data, 120 kB read
            r = await s.Raw($"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n{tiny}0\r\n\r\n{next}", 10_000);
            T.True(r.StartsWith("HTTP/1.1 200", StringComparison.Ordinal) || r.Contains("<<RESET>>"), r[..Math.Min(r.Length, 200)]); // closing on unread bytes may reset
            T.NotContains("ok /next", r); // not drained: the connection closed instead
            var few = string.Concat(Enumerable.Repeat("1\r\nx\r\n", 2_000));
            r = await s.Raw($"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n{few}0\r\n\r\n{next}");
            T.Contains("ok /next", r);
            // Too big to accept (413): the server can't know where the body ends without reading it, so it closes.
            var big = new string('x', 200);
            r = await s.Raw($"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: {big.Length + hidden.Length}\r\n\r\n{big}{hidden}{next}");
            T.Eq(413, Status(r));
            T.NotContains("EVIL", r);
            // Expect: 100-continue that's never honored (answered early): the body may never come, so the connection closes.
            r = await s.Raw($"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: {hidden.Length}\r\nExpect: 100-continue\r\n\r\n{hidden}{next}");
            T.Eq(200, Status(r));
            T.Contains("ok /a", r);
            T.NotContains("EVIL", r);
        });

        T.Add("ssl_ciphers: AEAD-only by default; explicit lists are exact; OpenSSL expressions fall back with a warning", async () =>
        {
            if (OperatingSystem.IsWindows()) return; // SChannel: the OS chooses the suites
            static string Conf(string ciphers) => $$"""
                http { server { listen 127.0.0.1:0 ssl; server_name t.test;
                  ssl_certificate {DIR}/t.crt; ssl_certificate_key {DIR}/t.key; {{ciphers}}
                  return 200 "ok"; } }
                """;
            static void Populate(string d) => ProxyTests.MakeCert("t.test", d, "t");
            const System.Net.Security.TlsCipherSuite Cbc = System.Net.Security.TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                Gcm = System.Net.Security.TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                Chacha = System.Net.Security.TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;

            // Default: TLS 1.2 CBC (SSL Labs: weak) is refused; AEAD suites and TLS 1.3 work.
            await using (var s = TestServer.Start(Conf(""), Populate))
            {
                T.Eq(null, await Handshake(s.Port, System.Security.Authentication.SslProtocols.Tls12, Cbc));
                T.Eq(Gcm, await Handshake(s.Port, System.Security.Authentication.SslProtocols.Tls12, Gcm));
                T.Eq(Chacha, await Handshake(s.Port, System.Security.Authentication.SslProtocols.Tls12, Chacha));
                T.True(await Handshake(s.Port, System.Security.Authentication.SslProtocols.Tls13, null) is not null);
            }
            // An explicit list is exactly that list for TLS 1.2 (OpenSSL names here); TLS 1.3 keeps its own suites.
            await using (var s = TestServer.Start(Conf("ssl_ciphers ECDHE-ECDSA-AES128-SHA256;"), Populate))
            {
                T.Eq(Cbc, await Handshake(s.Port, System.Security.Authentication.SslProtocols.Tls12, Cbc));
                T.Eq(null, await Handshake(s.Port, System.Security.Authentication.SslProtocols.Tls12, Gcm));
                T.True(await Handshake(s.Port, System.Security.Authentication.SslProtocols.Tls13, null) is not null);
            }
            // IANA names work too.
            await using (var s = TestServer.Start(Conf("ssl_ciphers TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;"), Populate))
                T.Eq(Chacha, await Handshake(s.Port, System.Security.Authentication.SslProtocols.Tls12, Chacha));
            // nginx's default expression: not evaluable without OpenSSL's rule engine, so the safe default plus a warning.
            await using (var s = TestServer.Start(Conf("ssl_ciphers HIGH:!aNULL:!MD5;"), Populate))
            {
                T.Eq(null, await Handshake(s.Port, System.Security.Authentication.SslProtocols.Tls12, Cbc));
                T.Eq(Gcm, await Handshake(s.Port, System.Security.Authentication.SslProtocols.Tls12, Gcm));
                T.Contains("OpenSSL cipher expressions", s.LogText());
            }
            foreach (var (conf, msg) in new[]
            {
                ("ssl_ciphers ECDHE-RSA-NOPE-SHA256;", "unknown cipher suite"),
                ("ssl_ciphers TLS_RSA_WITH_RC4_128_SHA;", "isn't allowed"),
                ("ssl_ciphers TLS_RSA_WITH_NULL_SHA256;", "isn't allowed"),
                ("ssl_ciphers TLS_DH_anon_WITH_AES_128_GCM_SHA256;", "isn't allowed"),
                ("ssl_ciphers TLS_RSA_WITH_3DES_EDE_CBC_SHA;", "isn't allowed"),
            })
                T.Contains(msg, T.Throws<ConfigException>(() => TestServer.Start(Conf(conf), Populate).DisposeAsync().AsTask().GetAwaiter().GetResult()).Message);
        });

        T.Add("ssl_ciphers: a negotiated suite outside the list closes the connection (fail closed)", async () =>
        {
            if (OperatingSystem.IsWindows()) return;
            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0 ssl; server_name t.test;
                  ssl_certificate {DIR}/t.crt; ssl_certificate_key {DIR}/t.key; return 200 "ok"; } }
                """, d => ProxyTests.MakeCert("t.test", d, "t"));
            async Task<string> Request()
            {
                using var tcp = new System.Net.Sockets.TcpClient();
                await tcp.ConnectAsync(System.Net.IPAddress.Loopback, s.Port);
                using var ssl = new System.Net.Security.SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
                try
                {
                    await ssl.AuthenticateAsClientAsync(new System.Net.Security.SslClientAuthenticationOptions { TargetHost = "t.test", EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 });
                    await ssl.WriteAsync("GET / HTTP/1.1\r\nHost: t.test\r\nConnection: close\r\n\r\n"u8.ToArray());
                    using var cts = new CancellationTokenSource(5000);
                    return await new StreamReader(ssl, Encoding.Latin1).ReadToEndAsync(cts.Token);
                }
                catch (Exception e) when (e is System.Security.Authentication.AuthenticationException or IOException) { return ""; }
            }
            T.Eq(200, Status(await Request()));
            // As if the platform had negotiated a CBC suite despite the configured (AEAD-only) list.
            Httpgrl.Core.Http.Http1Session.NegotiatedSuiteForTests = _ => System.Net.Security.TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256;
            try { T.Eq("", await Request()); }
            finally { Httpgrl.Core.Http.Http1Session.NegotiatedSuiteForTests = null; }
            T.Contains("negotiated a cipher suite outside ssl_ciphers", s.LogText());
            T.Eq(200, Status(await Request()));
        });

        T.Add("tls: sessions resume (TLS 1.2 IDs, TLS 1.3 tickets) with the strict default suites still enforced", async () =>
        {
            // .NET caches its OpenSSL context, where resumable sessions live, only without a CipherSuitesPolicy. The
            // AEAD-only default is OpenSSL's process default instead (OpenSslDefaults), so both hold at once. This pins
            // that: if a runtime or OpenSSL update breaks it, resumption (or the suite check) fails here.
            if (!OperatingSystem.IsLinux()) return;
            if (!HasOpenSsl()) throw new Exception("this test needs the openssl command-line tool");
            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0 ssl; server_name t.test;
                  ssl_certificate {DIR}/t.crt; ssl_certificate_key {DIR}/t.key;
                  return 200 "ok"; } }
                """, d => ProxyTests.MakeCert("t.test", d, "t"));
            T.NotContains("session resumption unavailable", s.LogText());
            var addr = $"127.0.0.1:{s.Port}";
            // TLS 1.2: -reconnect makes five more connections offering the first one's session.
            var r12 = await OpenSsl(["s_client", "-connect", addr, "-servername", "t.test", "-tls1_2", "-reconnect"], "");
            T.True(Count(r12, "\nReused, TLSv1.2") >= 4);
            // TLS 1.3: a ticket saved from one connection resumes the next.
            var sess = Path.Combine(s.Dir, "sess.pem");
            await OpenSsl(["s_client", "-connect", addr, "-servername", "t.test", "-tls1_3", "-sess_out", sess], "GET / HTTP/1.1\r\nHost: t.test\r\nConnection: close\r\n\r\n");
            T.Contains("Reused, TLSv1.3", await OpenSsl(["s_client", "-connect", addr, "-servername", "t.test", "-tls1_3", "-sess_in", sess], ""));
            // And the default suites are still the strict ones.
            T.Eq(null, await Handshake(s.Port, System.Security.Authentication.SslProtocols.Tls12, System.Net.Security.TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256));
        });

        T.Add("security: FIFO in the web root neither hangs nor serves", async () =>
        {
            if (OperatingSystem.IsWindows()) return;
            await using var s = TestServer.Start(Base, d =>
            {
                Populate(d);
                using var p = Process.Start("mkfifo", Path.Combine(d, "www", "pipe"))!;
                p.WaitForExit();
            });
            var sw = Stopwatch.StartNew();
            T.Eq(403, Status(await s.Raw(Get("/pipe"), 3000)));
            T.True(sw.ElapsedMilliseconds < 1000);
        });

        T.Add("http: try_files, named location, error_page", async () =>
        {
            await using var s = TestServer.Start(Base, Populate);
            T.Eq("spa shell", Body(await s.Raw(Get("/spa/some/client/route"))));
            T.Eq(404, Status(await s.Raw(Get("/strict/nothing"))));
            T.Eq("fallback body", Body(await s.Raw(Get("/named/nothing"))));
            var r = await s.Raw(Get("/errs/nothing"));
            T.Eq(404, Status(r));
            T.Eq("custom not found", Body(r));
            r = await s.Raw(Get("/errs2/nothing"));
            T.Eq(200, Status(r));
            T.Eq(404, Status(await s.Raw(Get("/custom404.html"))));
            r = await s.Raw("POST /hello.txt HTTP/1.1\r\nHost: t\r\nConnection: close\r\nContent-Length: 3\r\n\r\nabc");
            T.Eq(405, Status(r));
            T.Eq("GET, HEAD", Header(r, "Allow"));
        });

        T.Add("http: Server header and error-page product name are off unless server_tokens on", async () =>
        {
            await using var s = TestServer.Start("""
                http {
                  server { listen 127.0.0.1:0; root {DIR}; location /on/ { server_tokens on; } }
                }
                """, d => { Directory.CreateDirectory(Path.Combine(d, "on")); File.WriteAllText(Path.Combine(d, "f.txt"), "f"); File.WriteAllText(Path.Combine(d, "on", "f.txt"), "f"); });
            var r = await s.Raw(Get("/f.txt"));
            T.Eq(null, Header(r, "Server"));
            r = await s.Raw(Get("/missing"));
            T.Eq(404, Status(r));
            T.Eq(null, Header(r, "Server"));
            T.NotContains("httpgrl", Body(r));
            r = await s.Raw(Get("/on/f.txt"));
            T.Eq("httpgrl/" + Httpgrl.Core.Http.ServerInfo.Version, Header(r, "Server"));
            T.Contains("<center>httpgrl</center>", Body(await s.Raw(Get("/on/missing"))));
        });

        T.Add("sockets: a port is shared only when every listener opts into reuseport", async () =>
        {
            if (OperatingSystem.IsWindows()) return;
            await using var a = TestServer.Start("http { server { listen 127.0.0.1:0 reuseport; root {DIR}; } }");
            int port = a.Port;
            // Same port, also reuseport: allowed (multi-process / zero-downtime restarts).
            await using var b = TestServer.Start($"http {{ server {{ listen 127.0.0.1:{port} reuseport; root {{DIR}}; }} }}");
            T.Eq(port, b.Port);
            // Without the flag the port is exclusive: a stray instance fails loudly instead of stealing traffic.
            var e = T.Throws<IOException>(() => TestServer.Start($"http {{ server {{ listen 127.0.0.1:{port}; root {{DIR}}; }} }}"));
            T.Contains("in use", e.Message);
        });

        T.Add("return: status, text, redirects, header-injection safe", async () =>
        {
            await using var s = TestServer.Start("""
                http { default_type text/plain; server { listen 127.0.0.1:0; root {DIR};
                    location /gone { return 410; }
                    location /hello { return 200 "hi $uri"; }
                    location /moved { return 301 https://example.test$request_uri; }
                    location /bare { return https://example.test/x; }
                    location /decoded { return 302 /to$uri; }
                    location /nf { error_page 404 /page.txt; return 404; }
                } }
                """, d => File.WriteAllText(Path.Combine(d, "page.txt"), "custom"));
            T.Eq(410, Status(await s.Raw(Get("/gone"))));
            var r = await s.Raw(Get("/hello/x"));
            T.Eq(200, Status(r));
            T.Eq("hi /hello/x", Body(r));
            T.Eq("text/plain", Header(r, "Content-Type"));
            r = await s.Raw(Get("/moved/a?b=c"));
            T.Eq(301, Status(r));
            T.Eq("https://example.test/moved/a?b=c", Header(r, "Location"));
            r = await s.Raw(Get("/bare"));
            T.Eq(302, Status(r));
            T.Eq("https://example.test/x", Header(r, "Location"));
            // %0d%0a would decode into $uri: control characters in a path are refused outright...
            r = await s.Raw(Get("/decoded%0d%0aSet-Cookie:%20pwned=1"));
            T.Eq(400, Status(r));
            T.Eq(null, Header(r, "Set-Cookie"));
            // ...and what does decode (spaces, non-ASCII) comes back out encoded in the Location header.
            r = await s.Raw(Get("/decoded%20%C3%A9"));
            T.Eq(302, Status(r));
            T.Eq("/to/decoded%20%C3%A9", Header(r, "Location"));
            r = await s.Raw(Get("/nf"));
            T.Eq(404, Status(r));
            T.Eq("custom", Body(r));
        });

        T.Add("error_page with an absolute URL: the Location is escaped, never a 500 or an error line", async () =>
        {
            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0; root {DIR};
                    error_page 404 https://x.test$uri;
                    location /perm/ { error_page 404 =301 https://x.test$uri; }
                } }
                """, d => Directory.CreateDirectory(Path.Combine(d, "perm")));
            var r = await s.Raw(Get("/%E6%97%A5%E6%9C%AC")); // non-Latin-1: used to throw in HeaderCollection (500 + stack trace)
            T.Eq(302, Status(r));
            T.Eq("https://x.test/%E6%97%A5%E6%9C%AC", Header(r, "Location"));
            r = await s.Raw(Get("/caf%C3%A9%20x")); // Latin-1 and space: used to go out raw
            T.Eq(302, Status(r));
            T.Eq("https://x.test/caf%C3%A9%20x", Header(r, "Location"));
            r = await s.Raw(Get("/%5Cevil"));
            T.Eq("https://x.test/%5Cevil", Header(r, "Location"));
            r = await s.Raw(Get("/perm/gone"));
            T.Eq(301, Status(r));
            T.Eq("https://x.test/perm/gone", Header(r, "Location"));
            T.NotContains("\"level\":\"error\"", s.LogText());
        });

        T.Add("static: the directory redirect escapes a query that came from config (internal redirect)", async () =>
        {
            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0; root {DIR};
                    location /go { try_files /nope "/d?q=日本 x"; }
                } }
                """, d => Directory.CreateDirectory(Path.Combine(d, "d")));
            var r = await s.Raw(Get("/go"));
            T.Eq(301, Status(r)); // used to be a 500: HeaderCollection refuses non-Latin-1
            T.Eq("/d/?q=%E6%97%A5%E6%9C%AC%20x", Header(r, "Location"));
            r = await s.Raw(Get("/d?a=b"));
            T.Eq("/d/?a=b", Header(r, "Location"));
        });

        T.Add("redirects built from $uri or captures are never protocol-relative and never carry a backslash", async () =>
        {
            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0; root {DIR};
                    location /a/ { rewrite ^/a/(.*)/$ /$1 permanent; }
                    location /b/ { rewrite ^/b(.*)/$ $1 redirect; }
                    location /c/ { return 302 $uri; }
                    location ~ ^/d(/.*)$ { return 302 /$1; }
                    location /cdn/ { return 302 //cdn.test$uri; }
                    location /rq { return 302 $request_uri; }
                } }
                """);
            async Task<string?> Loc(string path, int status)
            {
                var r = await s.Raw(Get(path));
                T.Eq(status, Status(r));
                return Header(r, "Location");
            }
            // The classic "strip the trailing slash" rule: /\evil.example is //evil.example to a browser.
            T.Eq("/%5Cevil.example", await Loc("/a/%5Cevil.example/", 301));
            T.Eq("/x/y", await Loc("/a/x/y/", 301));
            // A capture that supplies the leading slashes: collapsed to one, so the target stays on this host.
            T.Eq("/evil.example", await Loc("/b//evil.example/", 302));
            T.Eq("/evil.example", await Loc("/b/%2Fevil.example/", 302));
            T.Eq("/c/x", await Loc("/c/x", 302));
            T.Eq("/evil.example/", await Loc("/d//evil.example/", 302));
            // $request_uri is raw: GET //rq.example would be a redirect to the host rq.example.
            var rq = await s.Raw("GET //rq.example HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
            T.Eq(302, Status(rq));
            T.Eq("/rq.example", Header(rq, "Location"));
            // The admin wrote // themselves: left alone.
            T.Eq("//cdn.test/cdn/x", await Loc("/cdn/x", 302));
        });

        T.Add("return 444 and error_page =444 drop the connection without a byte", async () =>
        {
            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0; root {DIR};
                    error_page 400 =444;
                    location /drop { return 444; }
                    location /quiet/ { error_page 400 401 402 403 404 =444; }
                    location /idiom/ { error_page 404 = @drop; }
                    location @drop { return 444; }
                } }
                """, d => { Directory.CreateDirectory(Path.Combine(d, "quiet")); File.WriteAllText(Path.Combine(d, "quiet", "ok.txt"), "ok"); });
            static void Dropped(string r) => T.True(r is "" or "<<RESET>>");
            Dropped(await s.Raw(Get("/drop")));
            Dropped(await s.Raw(Get("/quiet/missing")));
            T.Eq("ok", Body(await s.Raw(Get("/quiet/ok.txt"))));
            Dropped(await s.Raw(Get("/idiom/missing")));
            Dropped(await s.Raw("GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n")); // malformed: server-level 400 =444
            T.Eq(404, Status(await s.Raw(Get("/other")))); // drops are opt-in per code
            T.Contains("\"status\":444", s.LogText());
        });

        T.Add("http: virtual hosts by Host header", async () =>
        {
            await using var s = TestServer.Start("""
                http {
                  server { listen 127.0.0.1:0; server_name a.test; root {DIR}/a; }
                  server { listen 127.0.0.1:0; server_name *.b.test; root {DIR}/b; }
                }
                """, d =>
            {
                Directory.CreateDirectory(Path.Combine(d, "a"));
                Directory.CreateDirectory(Path.Combine(d, "b"));
                File.WriteAllText(Path.Combine(d, "a", "w.txt"), "A");
                File.WriteAllText(Path.Combine(d, "b", "w.txt"), "B");
            });
            T.Eq("A", Body(await s.Raw("GET /w.txt HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n")));
            T.Eq("B", Body(await s.Raw("GET /w.txt HTTP/1.1\r\nHost: x.b.test:8080\r\nConnection: close\r\n\r\n")));
            T.Eq("A", Body(await s.Raw("GET /w.txt HTTP/1.1\r\nHost: other\r\nConnection: close\r\n\r\n")));
        });

        T.Add("http: keep-alive, pipelining, chunked body drained", async () =>
        {
            await using var s = TestServer.Start(Base, Populate);
            using var c = await Connect(s.Port);
            await c.SendAsync(Encoding.ASCII.GetBytes("GET /hello.txt HTTP/1.1\r\nHost: t\r\n\r\n"));
            T.Eq("hello world", Body(await ReadOne(c)));
            // Two pipelined requests in one segment, the first carrying a chunked body nobody reads.
            await c.SendAsync(Encoding.ASCII.GetBytes(
                "GET /hello.txt HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n" +
                "GET /index.html HTTP/1.1\r\nHost: t\r\n\r\n"));
            T.Eq("hello world", Body(await ReadOne(c)));
            T.Eq("<h1>root index</h1>", Body(await ReadOne(c)));
            // HTTP/1.0 defaults to close.
            var r = await s.Raw("GET /hello.txt HTTP/1.0\r\n\r\n");
            T.Eq("close", Header(r, "Connection"));
        });

        T.Add("limits: oversized URI and headers", async () =>
        {
            await using var s = TestServer.Start(Base.Replace("http {", "http {\n large_client_header_buffers 2 1k;"), Populate);
            T.Eq(414, Status(await s.Raw(Get("/" + new string('a', 2000)))));
            T.Eq(431, Status(await s.Raw(Get("/", "X-Big: " + new string('b', 1500) + "\r\n"))));
            var many = new StringBuilder();
            for (int i = 0; i < 101; i++) many.Append($"X-{i}: v\r\n");
            T.Eq(431, Status(await s.Raw(Get("/", many.ToString()))));

        });

        T.Add("dos: slow-loris header trickle is cut at client_header_timeout", async () =>
        {
            await using var s = TestServer.Start(Base.Replace("http {", "http {\n client_header_timeout 1s;"), Populate);
            using var c = await Connect(s.Port);
            var sw = Stopwatch.StartNew();
            try
            {
                // One byte every 50 ms: each read makes progress, but the head as a whole never completes in time.
                foreach (var ch in "GET / HTTP/1.1\r\nHost: t\r\nX-a: " + new string('a', 200))
                {
                    await c.SendAsync(new[] { (byte)ch });
                    await Task.Delay(50);
                }
            }
            catch (SocketException) { }
            var tail = await ReadToClose(c, 1000);
            T.NotContains("<<TIMEOUT>>", tail);
            T.True(sw.ElapsedMilliseconds < 3500);
            T.Contains("request header timeout", s.LogText());
        });

        T.Add("dos: idle connection without a request is cut", async () =>
        {
            await using var s = TestServer.Start(Base.Replace("http {", "http {\n client_header_timeout 1s;"), Populate);
            using var c = await Connect(s.Port);
            var sw = Stopwatch.StartNew();
            var r = await ReadToClose(c, 4000);
            T.NotContains("<<TIMEOUT>>", r);
            T.True(sw.ElapsedMilliseconds < 2500);
        });

        T.Add("dos: stalled request body is cut at client_body_timeout", async () =>
        {
            await using var s = TestServer.Start(Base.Replace("http {", "http {\n client_body_timeout 1s;"), Populate);
            using var c = await Connect(s.Port);
            await c.SendAsync(Encoding.ASCII.GetBytes("GET /hello.txt HTTP/1.1\r\nHost: t\r\nContent-Length: 1000\r\n\r\nabc"));
            var sw = Stopwatch.StartNew();
            var r = await ReadToClose(c, 5000);
            T.Eq(200, Status(r)); // response goes out; draining the unread body then times out
            T.NotContains("<<TIMEOUT>>", r);
            T.True(sw.ElapsedMilliseconds < 3000);
        });

        T.Add("dos: per-client connection cap", async () =>
        {
            await using var s = TestServer.Start(Base.Replace("http {", "events { connections_per_client 3; }\nhttp {"), Populate);
            var held = new List<Socket>();
            for (int i = 0; i < 3; i++) held.Add(await Connect(s.Port));
            await Task.Delay(100);
            // The refusal is a reset right after accept. It can land before the client's connect completes, in which
            // case the connect itself reports it.
            string r;
            try
            {
                using var extra = await Connect(s.Port);
                r = await ReadToClose(extra, 2000);
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionReset) { r = "<<RESET>>"; }
            T.True(r.Length == 0 || r.Contains("<<RESET>>"));
            foreach (var h in held) h.Dispose();
            // The slots free once the server notices the closes: soon, but not by a fixed time on a busy machine.
            int status = 0;
            for (long until = Environment.TickCount64 + 5000; status != 200 && Environment.TickCount64 < until;)
            {
                try { status = Status(await s.Raw(Get("/hello.txt"))); }
                catch (SocketException) { await Task.Delay(50); }
            }
            T.Eq(200, status);
        });

        T.Add("dos: full table evicts idle keep-alive connections", async () =>
        {
            await using var s = TestServer.Start(Base.Replace("http {", "events { worker_connections 16; connections_per_client 0; }\nhttp {"), Populate);
            var idle = new List<Socket>();
            for (int i = 0; i < 16; i++)
            {
                var c = await Connect(s.Port);
                await c.SendAsync(Encoding.ASCII.GetBytes("GET /hello.txt HTTP/1.1\r\nHost: t\r\n\r\n"));
                await ReadOne(c);
                idle.Add(c);
            }
            T.Eq(200, Status(await s.Raw(Get("/hello.txt"))));
            foreach (var c in idle) c.Dispose();
        });

        T.Add("api: upgrade hands over the raw connection", async () =>
        {
            await using var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0; location /ws { echo_upgrade; } } }
                """, null, [new TestModule()]);
            using var c = await Connect(s.Port);
            // "early" is pipelined behind the head: it must reach the module through the upgraded stream.
            await c.SendAsync(Encoding.ASCII.GetBytes("GET /ws HTTP/1.1\r\nHost: t\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\nearly"));
            var head = new byte[4096];
            var sb = new StringBuilder();
            while (!sb.ToString().Contains("\r\n\r\nearly", StringComparison.Ordinal))
            {
                int n = await c.ReceiveAsync(head, SocketFlags.None);
                if (n == 0) break;
                sb.Append(Encoding.ASCII.GetString(head, 0, n));
            }
            var text = sb.ToString();
            T.Eq(101, Status(text));
            T.Eq("echo", Header(text, "Upgrade"));
            T.Eq("Upgrade", Header(text, "Connection"));
            T.True(Header(text, "Transfer-Encoding") is null && Header(text, "Content-Length") is null);
            await c.SendAsync(Encoding.ASCII.GetBytes("ping"));
            int got = await c.ReceiveAsync(head, SocketFlags.None);
            T.Eq("ping", Encoding.ASCII.GetString(head, 0, got));
        });

        T.Add("http: request bodies: limits, chunked decoding, 100-continue", async () =>
        {
            await using var s = TestServer.Start("""
                http { client_max_body_size 1k; server { listen 127.0.0.1:0; location /body { echo_body; } } }
                """, null, [new TestModule()]);
            var r = await s.Raw("POST /body HTTP/1.1\r\nHost: t\r\nConnection: close\r\nContent-Length: 5\r\n\r\nhello");
            T.Eq("5:hello", Body(r));
            r = await s.Raw("POST /body HTTP/1.1\r\nHost: t\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n2\r\nde\r\n0\r\nTrailer: v\r\n\r\n");
            T.Eq("5:abcde", Body(r));
            T.Eq(413, Status(await s.Raw("POST /body HTTP/1.1\r\nHost: t\r\nConnection: close\r\nContent-Length: 2048\r\n\r\n")));
            T.Eq(413, Status(await s.Raw("POST /body HTTP/1.1\r\nHost: t\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n800\r\n" + new string('x', 2048) + "\r\n0\r\n\r\n")));
            // Chunk extensions are bounded per body, not just per line: "1;<4 KiB>" per data byte stays under 1k of data.
            var extLine = "1;" + new string('e', 4000) + "\r\nx\r\n";
            T.Eq(400, Status(await s.Raw("POST /body HTTP/1.1\r\nHost: t\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n" + string.Concat(Enumerable.Repeat(extLine, 3)) + "0\r\n\r\n")));
            r = await s.Raw("POST /body HTTP/1.1\r\nHost: t\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n" + extLine + extLine + "0\r\n\r\n"); // 8 KiB: still fine
            T.Eq("2:xx", Body(r));
            T.Eq(400, Status(await s.Raw("POST /body HTTP/1.1\r\nHost: t\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n")));
            T.Eq(400, Status(await s.Raw("POST /body HTTP/1.1\r\nHost: t\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXX0\r\n\r\n")));
            // Trailers are dropped but must be well-formed: a bare CR is where two parsers disagree about where the body ends.
            T.Eq(400, Status(await s.Raw("POST /body HTTP/1.1\r\nHost: t\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX: a\r\r\n\r\n")));
            T.Eq(400, Status(await s.Raw("POST /body HTTP/1.1\r\nHost: t\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nnocolon\r\n\r\n")));
            using var c = await Connect(s.Port);
            await c.SendAsync(Encoding.ASCII.GetBytes("POST /body HTTP/1.1\r\nHost: t\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n"));
            var buf = new byte[256];
            int n = await c.ReceiveAsync(buf, SocketFlags.None);
            T.Eq("HTTP/1.1 100 Continue\r\n\r\n", Encoding.ASCII.GetString(buf, 0, n));
            await c.SendAsync(Encoding.ASCII.GetBytes("ok"));
            T.Eq("2:ok", Body(await ReadOne(c)));
        });

        T.Add("disable_symlinks: symlinks below the checked prefix are refused, race-free; listings hide them", async () =>
        {
            if (OperatingSystem.IsWindows()) return;
            void Populate(string d)
            {
                var www = Path.Combine(d, "www");
                Directory.CreateDirectory(Path.Combine(www, "sub"));
                Directory.CreateDirectory(Path.Combine(d, "outside"));
                File.WriteAllText(Path.Combine(www, "real.txt"), "real");
                File.WriteAllText(Path.Combine(www, "sub", "in.txt"), "in");
                File.WriteAllText(Path.Combine(d, "outside", "secret.txt"), "secret");
                File.CreateSymbolicLink(Path.Combine(www, "link.txt"), Path.Combine(www, "real.txt"));
                File.CreateSymbolicLink(Path.Combine(www, "escape.txt"), Path.Combine(d, "outside", "secret.txt"));
                Directory.CreateSymbolicLink(Path.Combine(www, "linkdir"), Path.Combine(www, "sub"));
                Directory.CreateSymbolicLink(Path.Combine(d, "rootlink"), www);
            }
            // Default (as nginx): symlinks are followed, even out of the root.
            await using (var s = TestServer.Start("http { server { listen 127.0.0.1:0; root {DIR}/www; } }", Populate))
                T.Eq("secret", Body(await s.Raw(Get("/escape.txt"))));

            await using (var s = TestServer.Start("""
                http { server { listen 127.0.0.1:0; root {DIR}/www; disable_symlinks on;
                  location /try/ { try_files /link.txt /real.txt =404; }
                  location /idx/ { alias {DIR}/www/; autoindex on; autoindex_format json; }
                } }
                """, Populate))
            {
                T.Eq("real", Body(await s.Raw(Get("/real.txt"))));
                T.Eq("in", Body(await s.Raw(Get("/sub/in.txt"))));
                T.Eq(403, Status(await s.Raw(Get("/link.txt"))));
                T.Eq(403, Status(await s.Raw(Get("/escape.txt"))));
                T.Eq(403, Status(await s.Raw(Get("/linkdir/in.txt"))));
                T.Eq(404, Status(await s.Raw(Get("/real.txt/x"))));       // a real non-directory is still "not found"
                T.Eq(404, Status(await s.Raw(Get("/nope/x"))));
                T.Eq("real", Body(await s.Raw(Get("/try/x"))));            // the symlinked candidate doesn't exist for try_files
                var listing = Dechunked(await s.Raw(Get("/idx/")));
                T.Contains("real.txt", listing);
                T.True(!listing.Contains("link.txt") && !listing.Contains("escape.txt") && !listing.Contains("linkdir"), listing);
            }

            // A root reached through a symlink: "on" checks the whole path; from=$document_root trusts the root itself.
            await using (var s = TestServer.Start("http { server { listen 127.0.0.1:0; root {DIR}/rootlink; disable_symlinks on; } }", Populate))
                T.Eq(403, Status(await s.Raw(Get("/real.txt"))));
            await using (var s = TestServer.Start("http { server { listen 127.0.0.1:0; root {DIR}/rootlink; disable_symlinks on from=$document_root; } }", Populate))
            {
                T.Eq("real", Body(await s.Raw(Get("/real.txt"))));
                T.Eq(403, Status(await s.Raw(Get("/link.txt"))));
            }
            T.Contains("if_not_owner", T.Throws<ConfigException>(() => TestServer.Start("http { server { listen 127.0.0.1:0; disable_symlinks if_not_owner; } }")).Message);
        });

        T.Add("ssl_reject_handshake: no SNI or an unknown name gets no certificate; Host aimed at the default is refused", async () =>
        {
            const string Conf = """
                http {
                  server { listen 127.0.0.1:0 ssl default_server; ssl_reject_handshake on; error_page 421 =444; }
                  server { listen 127.0.0.1:0 ssl; server_name real.test; ssl_certificate {DIR}/r.crt; ssl_certificate_key {DIR}/r.key; return 200 "real"; }
                }
                """;
            await using var s = TestServer.Start(Conf, d => WriteCert(d, "r", "real.test"));
            async Task<(bool Handshake, string? Subject, string Response)> Try(string sni, string host)
            {
                using var c = await Connect(s.Port);
                await using var ssl = new SslStream(new NetworkStream(c, ownsSocket: false));
                X509Certificate? seen = null;
                try
                {
                    await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = sni, RemoteCertificateValidationCallback = (_, cert, _, _) => { seen = cert; return true; } });
                }
                catch (Exception e) when (e is System.Security.Authentication.AuthenticationException or IOException) { return (false, seen?.Subject, ""); }
                await ssl.WriteAsync(Encoding.ASCII.GetBytes($"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"));
                try { return (true, seen?.Subject, await new StreamReader(ssl, Encoding.ASCII).ReadToEndAsync()); }
                catch (IOException) { return (true, seen?.Subject, ""); }
            }
            var ok = await Try("real.test", "real.test");
            T.True(ok.Handshake);
            T.Eq("real", Body(ok.Response));
            var noSni = await Try("", "127.0.0.1");              // what a client connecting by IP sends: no SNI at all
            T.True(!noSni.Handshake);
            T.Eq(null, noSni.Subject);                           // no certificate, so no names, leak out
            T.True(!(await Try("other.test", "other.test")).Handshake);
            var aimed = await Try("real.test", "127.0.0.1");     // a real handshake, then Host aimed at the IP
            T.True(aimed.Handshake);
            T.Eq("", aimed.Response);                            // 421, dropped by error_page 421 =444

            // Without error_page: a plain 421 rather than whatever the default server's root would hold.
            await using var s2 = TestServer.Start(Conf.Replace(" error_page 421 =444;", ""), d => WriteCert(d, "r", "real.test"));
            using var c2 = await Connect(s2.Port);
            await using var ssl2 = new SslStream(new NetworkStream(c2, ownsSocket: false));
            await ssl2.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "real.test", RemoteCertificateValidationCallback = (_, _, _, _) => true });
            await ssl2.WriteAsync("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"u8.ToArray());
            T.Eq(421, Status(await new StreamReader(ssl2, Encoding.ASCII).ReadToEndAsync()));
        });

        T.Add("tls: handshake, SNI certificate selection, HTTP over TLS", async () =>
        {
            await using var s = TestServer.Start("""
                http {
                  server { listen 127.0.0.1:0 ssl; server_name one.test; ssl_certificate {DIR}/one.crt; ssl_certificate_key {DIR}/one.key; root {DIR}/one; }
                  server { listen 127.0.0.1:0 ssl; server_name two.test; ssl_certificate {DIR}/two.crt; ssl_certificate_key {DIR}/two.key; root {DIR}/two; }
                }
                """, d =>
            {
                foreach (var n in new[] { "one", "two" })
                {
                    WriteCert(d, n);
                    Directory.CreateDirectory(Path.Combine(d, n));
                    File.WriteAllText(Path.Combine(d, n, "i.txt"), n);
                }
            });
            foreach (var n in new[] { "one", "two" })
            {
                using var c = await Connect(s.Port);
                await using var ssl = new SslStream(new NetworkStream(c, ownsSocket: false));
                X509Certificate? seen = null;
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = n + ".test",
                    RemoteCertificateValidationCallback = (_, cert, _, _) => { seen = cert; return true; },
                });
                T.Contains("CN=" + n + ".test", seen!.Subject);
                await ssl.WriteAsync(Encoding.ASCII.GetBytes($"GET /i.txt HTTP/1.1\r\nHost: {n}.test\r\nConnection: close\r\n\r\n"));
                var resp = await new StreamReader(ssl, Encoding.ASCII).ReadToEndAsync();
                T.Eq(200, Status(resp));
                T.Eq(n, Body(resp));
            }
            // Plain HTTP on a TLS port gets nowhere.
            T.True(Status(await s.Raw(Get("/i.txt"), 3000)) == -1);
        });

        T.Add("logging: every line from a busy server is valid JSON", async () =>
        {
            await using var s = TestServer.Start(Base, Populate);
            await s.Raw(Get("/hello.txt", "User-Agent: a\"b\\cÿ\r\nReferer: x\r\n"));
            await s.Raw(Get("/nope"));
            await s.Raw("garbage\r\n\r\n");
            var lines = s.LogText().Split('\n', StringSplitOptions.RemoveEmptyEntries);
            T.True(lines.Length >= 4);
            foreach (var l in lines) using (System.Text.Json.JsonDocument.Parse(l)) { }
            T.Contains("\"msg\":\"access\"", string.Join('\n', lines));
        });
    }

    private static void WriteCert(string dir, string name) => WriteCert(dir, name, name + ".test");

    private static void WriteCert(string dir, string name, string dnsName)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=" + dnsName, key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(dnsName);
        req.CertificateExtensions.Add(san.Build());
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        File.WriteAllText(Path.Combine(dir, name + ".crt"), cert.ExportCertificatePem());
        File.WriteAllText(Path.Combine(dir, name + ".key"), key.ExportPkcs8PrivateKeyPem());
    }
}

/// <summary>Test-only module: exercises the exclusive-handler, body and upgrade APIs the proxy module will build on.</summary>
internal sealed class TestModule : IModule
{
    public string Name => "test";

    public void Register(IModuleRegistry r)
    {
        r.AddDirective(new()
        {
            Name = "echo_upgrade", Contexts = [ContextKind.Location],
            Handler = i => { var c = i.Conf<LocationHandlerConf>(); c.Handler = Handle; c.Owner = Name; },
        });
        r.AddDirective(new()
        {
            Name = "echo_body", Contexts = [ContextKind.Location],
            Handler = i => { var c = i.Conf<LocationHandlerConf>(); c.Handler = EchoBody; c.Owner = Name; },
        });
    }

    private static async ValueTask<HandlerResult> EchoBody(HttpContext ctx)
    {
        var ms = new MemoryStream();
        await ctx.Request.Body.CopyToAsync(ms);
        var body = Encoding.ASCII.GetBytes(ms.Length + ":" + Encoding.ASCII.GetString(ms.ToArray()));
        ctx.Response.ContentLength = body.Length;
        await ctx.Response.WriteAsync(body);
        return HandlerResult.Done;
    }

    private static async ValueTask<HandlerResult> Handle(HttpContext ctx)
    {
        if (ctx.Request.Headers.Get("Upgrade") != "echo") return HandlerResult.WithStatus(426);
        ctx.Response.Status = 101;
        ctx.Response.Headers.Set("Connection", "Upgrade");
        ctx.Response.Headers.Set("Upgrade", "echo");
        var stream = await ctx.UpgradeAsync(5000);
        var buf = new byte[1024];
        int n;
        while ((n = await stream.ReadAsync(buf)) > 0) await stream.WriteAsync(buf.AsMemory(0, n));
        return HandlerResult.Done;
    }
}
