using System.Text;
using Httpgrl.Core.Config;
using Httpgrl.Core.Http;
using Httpgrl.Core.Logging;
using Httpgrl.Core.Pipeline;
using Httpgrl.Modules.StaticFiles;

namespace Httpgrl.Tests;

internal static class UnitTests
{
    public static void Register()
    {
        T.Add("version: the reported version is semver, without build metadata", () =>
        {
            var v = Httpgrl.Core.Http.ServerInfo.Version;
            T.True(System.Text.RegularExpressions.Regex.IsMatch(v, @"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$"));
            T.Eq("0.2.0-rc.1", Httpgrl.Core.Http.ServerInfo.Semver("0.2.0-rc.1+3f2a9c1"));
            T.Eq("1.0.0", Httpgrl.Core.Http.ServerInfo.Semver("1.0.0"));
        });

        // ---------------- URI normalization ----------------
        T.Add("uri: dot segments and slashes", () =>
        {
            T.Eq("/b", N("/a/../b"));
            T.Eq("/a/b/", N("//a///b/"));
            T.Eq("/a/b/", N("/a/./b/."));
            T.Eq("/", N("/a/.."));
            T.Eq("/b", N("/a/%2e%2e/b"));
            T.Eq("/x y", N("/x%20y"));
            T.Eq("/a/b", N("/a%2fb"));
            T.Eq("/img..", N("/img.."));
        });
        T.Add("uri: rejects escapes above root, NUL, bad hex, bad utf8", () =>
        {
            T.Eq(null, N("/.."));
            T.Eq(null, N("/a/../.."));
            T.Eq(null, N("/%2e%2e/etc/passwd"));
            T.Eq(null, N("/a%00b"));
            T.Eq(null, N("/%zz"));
            T.Eq(null, N("/%f"));
            T.Eq(null, N("/%ff%fe"));
            T.Eq(null, N("relative"));
        });

        // ---------------- request parser ----------------
        T.Add("parser: valid request", () =>
        {
            var r = new RequestImpl();
            T.Eq(0, P("GET /x/../y?q=1 HTTP/1.1\r\nHost: Example.COM:8080\r\nUser-Agent: t\r\n\r\n", r));
            T.Eq("/y", r.PathValue);
            T.Eq("q=1", r.QueryValue);
            T.Eq("example.com", r.HostValue);
            T.True(ReferenceEquals(HttpMethods.Get, r.MethodValue));
            T.Eq("t", r.HeaderList.Get("user-agent"));
        });
        T.Add("parser: request smuggling vectors are rejected", () =>
        {
            T.Eq(400, P("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n"));
            T.Eq(501, P("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"));
            T.Eq(501, P("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"));
            T.Eq(400, P("POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n"));
            T.Eq(400, P("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n"));
            T.Eq(400, P("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3, 3\r\n\r\n"));
            T.Eq(400, P("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +3\r\n\r\n"));
            T.Eq(400, P("POST / HTTP/1.1\r\nHost: a\r\nContent-Length : 3\r\n\r\n"));
            T.Eq(400, P("GET / HTTP/1.1\r\nHost: a\r\nX: a\r\n b\r\n\r\n"));     // obs-fold
            T.Eq(400, P("GET / HTTP/1.1\r\nHost: a\nX: b\r\n\r\n"));             // bare LF
            T.Eq(400, P("GET / HTTP/1.1\r\nHost: a\r\nX: a\rb\r\n\r\n"));         // bare CR
            T.Eq(400, P("GET / HTTP/1.1\r\nHost: a\r\nX: a\0b\r\n\r\n"));        // NUL
            // RFC 9112 3.2: absolute form still needs a valid Host field on HTTP/1.1 (the target's authority wins).
            T.Eq(400, P("GET http://a.test/ HTTP/1.1\r\n\r\n"));
            T.Eq(400, P("GET http://a.test/ HTTP/1.1\r\nHost: a/b\r\n\r\n"));
            T.Eq(400, P("GET http://a.test/ HTTP/1.1\r\nHost:\r\n\r\n"));
            T.Eq(0, P("GET http://a.test/ HTTP/1.0\r\n\r\n"));
        });
        T.Add("parser: header names with underscores are ignored unless underscores_in_headers", () =>
        {
            // CGI-style backends map X_Client_Verify and X-Client-Verify to the same variable: never let one stand in for the other.
            var r = new RequestImpl();
            T.Eq(0, P("GET / HTTP/1.1\r\nHost: a\r\nX_Client_Verify: SUCCESS\r\nX-Ok: 1\r\n\r\n", r));
            T.Eq(null, r.Headers.Get("X_Client_Verify"));
            T.Eq("1", r.Headers.Get("X-Ok"));
            // An underscored framing header is ignored too, so it can't disagree with the real one.
            r = new RequestImpl();
            T.Eq(0, P("POST / HTTP/1.1\r\nHost: a\r\nContent_Length: 99\r\nContent-Length: 1\r\n\r\n", r));
            T.Eq(1L, r.ContentLengthValue);
            r = new RequestImpl();
            T.Eq(0, RequestParser.Parse(Encoding.Latin1.GetBytes("GET / HTTP/1.1\r\nHost: a\r\nX_Y: z\r\n\r\n"), r, new HeadLimits(8192, 32768, 100, underscores: true)));
            T.Eq("z", r.Headers.Get("X_Y"));
        });
        T.Add("parser: protocol and target validation", () =>
        {
            T.Eq(505, P("GET / HTTP/2.0\r\nHost: a\r\n\r\n"));
            T.Eq(400, P("GET / HTTP/1.1x\r\nHost: a\r\n\r\n"));
            T.Eq(400, P("GET  / HTTP/1.1\r\nHost: a\r\n\r\n"));
            T.Eq(400, P("GET / HTTP/1.1\r\n\r\n"));                               // missing Host
            T.Eq(400, P("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"));
            T.Eq(400, P("GET / HTTP/1.1\r\nHost: a/b\r\n\r\n"));
            T.Eq(400, P("GET / HTTP/1.1\r\nHost: ..\r\n\r\n"));
            T.Eq(400, P("GET /#frag HTTP/1.1\r\nHost: a\r\n\r\n"));
            T.Eq(400, P("GET * HTTP/1.1\r\nHost: a\r\n\r\n"));
            T.Eq(405, P("CONNECT a:443 HTTP/1.1\r\nHost: a\r\n\r\n"));
            T.Eq(417, P("GET / HTTP/1.1\r\nHost: a\r\nExpect: x\r\n\r\n"));
            T.Eq(0, P("GET / HTTP/1.0\r\n\r\n"));
            var r = new RequestImpl();
            T.Eq(0, P("GET http://Other.Host:81/p?x HTTP/1.1\r\nHost: a\r\n\r\n", r));
            T.Eq("other.host", r.HostValue);
            T.Eq("/p", r.PathValue);
        });
        T.Add("parser: host normalization", () =>
        {
            T.Eq("example.com", RequestParser.NormalizeHost("EXAMPLE.com."));
            T.Eq("[::1]", RequestParser.NormalizeHost("[::1]:80"));
            T.Eq(null, RequestParser.NormalizeHost("a..b"));
            T.Eq(null, RequestParser.NormalizeHost("a b"));
            T.Eq(null, RequestParser.NormalizeHost("a:x"));
            T.Eq(null, RequestParser.NormalizeHost("[::1"));
        });
        T.Add("parser: incomplete head limits", () =>
        {
            var lim = new HeadLimits(16, 64, 100);
            T.Eq(414, RequestParser.CheckIncomplete(Encoding.ASCII.GetBytes("GET /aaaaaaaaaaaaaaaaaaaaaaaa"), lim));
            T.Eq(0, RequestParser.CheckIncomplete(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nX"), lim));
            T.Eq(431, RequestParser.CheckIncomplete(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n" + new string('x', 64)), lim));
        });
        T.Add("chunk size parsing", () =>
        {
            T.Eq(26L, BodyStream.ParseChunkSize("1a"u8));
            T.Eq(26L, BodyStream.ParseChunkSize("1A;ext=val"u8));
            T.Eq(-1L, BodyStream.ParseChunkSize(""u8));
            T.Eq(-1L, BodyStream.ParseChunkSize("x"u8));
            T.Eq(-1L, BodyStream.ParseChunkSize("1 x"u8));
            T.Eq(-1L, BodyStream.ParseChunkSize("1000000000000000"u8)); // > 15 hex digits
        });
        T.Add("byte range parsing", () =>
        {
            T.Eq(StaticModule.RangeResult.Satisfiable, StaticModule.ParseRange("bytes=0-4", 10, out var o, out var c)); T.Eq(0L, o); T.Eq(5L, c);
            T.Eq(StaticModule.RangeResult.Satisfiable, StaticModule.ParseRange("bytes=-3", 10, out o, out c)); T.Eq(7L, o); T.Eq(3L, c);
            T.Eq(StaticModule.RangeResult.Satisfiable, StaticModule.ParseRange("bytes=5-", 10, out o, out c)); T.Eq(5L, o); T.Eq(5L, c);
            T.Eq(StaticModule.RangeResult.Satisfiable, StaticModule.ParseRange("bytes=5-99", 10, out o, out c)); T.Eq(5L, c);
            T.Eq(StaticModule.RangeResult.Unsatisfiable, StaticModule.ParseRange("bytes=10-", 10, out _, out _));
            T.Eq(StaticModule.RangeResult.Ignore, StaticModule.ParseRange("bytes=0-1,3-4", 10, out _, out _));
            T.Eq(StaticModule.RangeResult.Ignore, StaticModule.ParseRange("bytes=5-2", 10, out _, out _));
            T.Eq(StaticModule.RangeResult.Ignore, StaticModule.ParseRange("items=0-1", 10, out _, out _));
        });

        // ---------------- config ----------------
        T.Add("config: size/time values", () =>
        {
            T.True(ConfigValue.TryParseSize("8k", out var s) && s == 8192);
            T.True(ConfigValue.TryParseSize("1M", out s) && s == 1 << 20);
            T.True(!ConfigValue.TryParseSize("1x", out _));
            T.True(ConfigValue.TryParseMillis("30", out var ms) && ms == 30_000);
            T.True(ConfigValue.TryParseMillis("1m30s", out ms) && ms == 90_000);
            T.True(ConfigValue.TryParseMillis("250ms", out ms) && ms == 250);
            T.True(!ConfigValue.TryParseMillis("1m30", out _));
            T.True(!ConfigValue.TryParseMillis("s", out _));
        });
        T.Add("config: lexer quoting, escapes, comments, ${var}", () =>
        {
            var root = Parse("http { server { listen 127.0.0.1:0; location ~ \"\\.php$\" { root '/a b'; } # c\n location /x { try_files ${uri}.html =404; } } }");
            var server = root.Children[0].Children[0];
            var loc = server.Children[0];
            T.Eq("\\.php$", loc.Args[1]);
            T.Eq("${uri}.html", server.Children[1].Get<Httpgrl.Core.Modules.HttpCoreConf>().TryFiles!.Files[0].Raw);
        });
        T.Add("config: errors carry file:line", () =>
        {
            var e = T.Throws<ConfigException>(() => Parse("http {\n  server {\n    bogus on;\n  }\n}"));
            T.Contains("unknown directive \"bogus\"", e.Message);
            T.Eq(3, e.Where!.Value.Line);
            T.Contains("not allowed", T.Throws<ConfigException>(() => Parse("listen 80;")).Message);
            T.Contains("duplicate", T.Throws<ConfigException>(() => Parse("http { root /a; root /b; }")).Message);
            T.Contains("unexpected \"}\"", T.Throws<ConfigException>(() => Parse("http { root /a }")).Message);
            T.Contains("expecting", T.Throws<ConfigException>(() => Parse("http { root /a;")).Message);
            T.Contains("mutually exclusive", T.Throws<ConfigException>(() => Parse("http { server { location / { root /a; alias /b; } } }")).Message);
            T.Contains("insecure", T.Throws<ConfigException>(() => Parse("http { ssl_protocols TLSv1 TLSv1.2; }")).Message);
            T.Contains("unknown variable", T.Throws<ConfigException>(() => Parse("http { root /a/$nope; }")).Message);
            T.Contains("unterminated", T.Throws<ConfigException>(() => Parse("http { root \"/a; }")).Message);
            T.Contains("requires a block", T.Throws<ConfigException>(() => Parse("http;")).Message);
            T.Contains("cannot carry text", T.Throws<ConfigException>(() => Parse("http { server { return 444 x; } }")).Message);
            T.Contains("invalid return code", T.Throws<ConfigException>(() => Parse("http { server { return 999; } }")).Message);
            T.Contains("needs a URL", T.Throws<ConfigException>(() => Parse("http { server { return 301; } }")).Message);
            T.Contains("invalid code", T.Throws<ConfigException>(() => Parse("http { error_page 444 /x; }")).Message);
        });

        // ---------------- routing ----------------
        T.Add("routing: nginx location precedence", () =>
        {
            var srv = Server("""
                http { server { listen 127.0.0.1:0;
                    location / { }
                    location /images/ { }
                    location ^~ /static/ { }
                    location = /exact { }
                    location ~ \.(png|jpg)$ { }
                    location ~* \.GIF$ { }
                    location /api/ { location ~ /api/v[0-9]+/ { } location /api/admin/ { } }
                    location @named { }
                } }
                """);
            T.Eq("= /exact", Loc(srv, "/exact"));
            T.Eq("/", Loc(srv, "/exact/more"));
            T.Eq("~ \\.(png|jpg)$", Loc(srv, "/images/a.png"));     // regex beats plain prefix
            T.Eq("^~ /static/", Loc(srv, "/static/a.png"));         // ^~ stops regex search
            T.Eq("/images/", Loc(srv, "/images/a.txt"));
            T.Eq("~* \\.GIF$", Loc(srv, "/x/a.gif"));
            T.Eq("~ /api/v[0-9]+/", Loc(srv, "/api/v2/x"));          // nested regex
            T.Eq("/api/admin/", Loc(srv, "/api/admin/x"));          // nested longer prefix
            T.Eq("/api/", Loc(srv, "/api/x"));
            T.True(srv.Named.ContainsKey("@named"));
            T.Eq("~ \\.(png|jpg)$", Loc(srv, "/x/1.png"));
            T.Eq(1, srv.Find("/x/1.png", out var m).Def!.Regex!.GetGroupNumbers().Length - 1);
            T.Eq("png", m!.Groups[1].Value);
        });
        T.Add("routing: invalid nesting rejected", () =>
        {
            T.Contains("outside location", T.Throws<ConfigException>(() => Server("http { server { location /a/ { location /b/ { } } } }")).Message);
            T.Contains("exact location", T.Throws<ConfigException>(() => Server("http { server { location = /a { location /a { } } } }")).Message);
            T.Contains("duplicate location", T.Throws<ConfigException>(() => Server("http { server { location /a { } location ^~ /a { } } }")).Message);
        });
        T.Add("routing: server_name resolution", () =>
        {
            var root = Parse("""
                http {
                  server { listen 127.0.0.1:0; server_name _; }
                  server { listen 127.0.0.1:0; server_name example.com www.example.com; }
                  server { listen 127.0.0.1:0; server_name *.example.com; }
                  server { listen 127.0.0.1:0; server_name mail.*; }
                  server { listen 127.0.0.1:0; server_name ~^api\d+\.test$; }
                  server { listen 127.0.0.1:0 default_server; server_name dflt; }
                }
                """);
            var vh = RoutingBuilder.Build(root, Null)[0].Hosts;
            T.Eq("example.com", vh.Resolve("example.com").PrimaryName);
            T.Eq("example.com", vh.Resolve("www.example.com").PrimaryName);
            T.Eq(0, vh.Resolve("a.b.example.com").Names[0].IndexOf("*.example.com", StringComparison.Ordinal));
            T.Eq("mail.*", vh.Resolve("mail.org").Names[0]);
            T.Eq("~^api\\d+\\.test$", vh.Resolve("api7.test").Names[0]);
            T.Eq("dflt", vh.Resolve("unknown.org").PrimaryName);
            T.Eq("dflt", vh.Resolve(null).PrimaryName);
            T.Contains("conflicting \"reuseport\"", T.Throws<ConfigException>(() => RoutingBuilder.Build(Parse(
                "http { server { listen 127.0.0.1:1 reuseport; } server { listen 127.0.0.1:1; } }"), Null)).Message);
            T.Contains("duplicate default", T.Throws<ConfigException>(() => RoutingBuilder.Build(Parse(
                "http { server { listen 127.0.0.1:1 default_server; } server { listen 127.0.0.1:1 default_server; } }"), Null)).Message);
        });

        // ---------------- logger ----------------
        T.Add("logger: one well-formed JSON object per line, control chars escaped", () =>
        {
            var ms = new MemoryStream();
            using (var log = new JsonLogger(ms, LogLevel.Debug))
            {
                log.Info("a\nb", new LogField("k", "line1\r\nline2\u2028\"}"), new("n", 42L), new("d", double.NaN), new("b", true));
                log.Debug("x", new LogField("nul", "\0"));
            }
            var lines = Encoding.UTF8.GetString(ms.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
            T.Eq(2, lines.Length);
            foreach (var l in lines)
            {
                using var doc = System.Text.Json.JsonDocument.Parse(l);
                T.True(doc.RootElement.TryGetProperty("ts", out _));
            }
            using var d = System.Text.Json.JsonDocument.Parse(lines[0]);
            T.Eq("line1\r\nline2\u2028\"}", d.RootElement.GetProperty("k").GetString());
        });

        T.Add("logger: a stalled stdout holds a bounded number of bytes, and the drops are counted and reported", () =>
        {
            var gate = new ManualResetEventSlim(false);
            var sink = new GatedStream(gate);
            using (var log = new JsonLogger(sink, LogLevel.Info))
            {
                var big = new string('\u0001', 4000); // escapes to 6 bytes a char: the most a request can inflate a field
                for (int i = 0; i < 20_000; i++)
                    log.Info("access", new LogField("uri", big), new("ua", big), new("referer", big), new("host", big));
                T.True(log.QueuedBytes <= JsonLogger.MaxQueuedBytes, $"queued {log.QueuedBytes}");
                T.True(log.DroppedTotal > 0, "drops counted");
                gate.Set();
                for (int i = 0; i < 200 && log.QueuedBytes > 0; i++) Thread.Sleep(10);
                log.Info("after");
            }
            var text = Encoding.UTF8.GetString(sink.Written.ToArray());
            T.Contains("log lines dropped", text);
            foreach (var l in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                T.True(l.Length <= JsonLogger.MaxLine + 1, $"line of {l.Length} bytes");
                using var doc = System.Text.Json.JsonDocument.Parse(l);
            }
            T.Contains("\"truncated\":true", text);
        });

        T.Add("logger: after the output fails for good, lines are dropped instead of queued", () =>
        {
            var broken = new GatedStream(null) { Fail = true };
            using var log = new JsonLogger(broken, LogLevel.Info);
            log.Info("first");
            for (int i = 0; i < 200 && log.DroppedTotal == 0; i++) { Thread.Sleep(10); log.Info("more"); }
            T.True(log.DroppedTotal > 0);
            T.Eq(0L, log.QueuedBytes);
        });
    }

    private static readonly ILogger Null = new JsonLogger(Stream.Null, LogLevel.Error);

    /// <summary>An output that blocks until the gate opens (a stalled stdout), or fails every write.</summary>
    private sealed class GatedStream(ManualResetEventSlim? gate) : Stream
    {
        public readonly MemoryStream Written = new();
        public bool Fail;
        public override void Write(byte[] buffer, int offset, int count)
        {
            if (Fail) throw new IOException("broken pipe");
            gate?.Wait();
            lock (Written) Written.Write(buffer, offset, count);
        }
        public override void Flush() { }
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    private static string? N(string raw) => UriNormalizer.NormalizeRaw(Encoding.Latin1.GetBytes(raw));

    private static int P(string head, RequestImpl? r = null) =>
        RequestParser.Parse(Encoding.Latin1.GetBytes(head), r ?? new RequestImpl(), new HeadLimits(8192, 32768, 100));

    internal static ConfigScope Parse(string text)
    {
        var vars = new VariableRegistry();
        var reg = new DirectiveCollector(vars);
        new Httpgrl.Core.Modules.HttpCoreModule(Path.GetTempPath()).Register(reg);
        new Httpgrl.Core.Modules.SslModule(Path.GetTempPath()).Register(reg);
        foreach (var m in StaticFiles.Modules()) m.Register(reg);
        new Httpgrl.Modules.Rewrite.RewriteModule().Register(reg);
        var root = new ConfigParser(reg.Directives, vars).ParseText(text);
        vars.ResolvePending();
        root.MergeAndFreeze();
        return root;
    }

    private static ServerRt Server(string text) => RoutingBuilder.Build(Parse(text), Null)[0].Hosts.Default;

    private static string Loc(ServerRt s, string path) => s.Find(path, out _).Name;

    private sealed class DirectiveCollector(VariableRegistry vars) : IModuleRegistry
    {
        public readonly Dictionary<string, List<Directive>> Directives = new();
        public void AddDirective(Directive d)
        {
            if (!Directives.TryGetValue(d.Name, out var l)) Directives[d.Name] = l = new();
            l.Add(d);
        }
        public void AddVariable(string name, VariableGetter getter) => vars.Add(name, getter);
        public void AddVariablePrefix(string prefix, PrefixVariableGetter getter) => vars.AddPrefix(prefix, getter);
    }
}
