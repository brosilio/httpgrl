using System.Diagnostics;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Httpgrl.Core.Config;
using Httpgrl.Core.Hosting;
using Httpgrl.Core.Http;
using Httpgrl.Core.Logging;
using Httpgrl.Core.Modules;
using Httpgrl.Core.Pipeline;
using Httpgrl.Modules.Proxy;

namespace Httpgrl.Tests;

/// <summary>
/// Dependency-free mutation fuzzing of everything that parses untrusted (or semi-trusted) bytes. Each target states
/// which exceptions are legitimate rejections and which invariants an accepted input must satisfy; anything else is
/// a bug. Inputs derive from (seed, iteration) alone, so a failure reproduces exactly from the printed numbers.
///
/// The test suite runs a short fixed-seed pass of every target. Long runs:
///   dotnet run -c Release --project tests/Httpgrl.Tests -- --fuzz [target|all] [seconds] [seed]
/// </summary>
internal static partial class Fuzz
{
    /// <summary><c>Run</c> returns true when the parser accepted the input (reported, so a run that never gets past the first check is visible).</summary>
    /// <summary>A fuzz target. <paramref name="Serial"/>: it drives one shared, stateful fixture, so it runs on one thread (a lock would make the slow-input check time the queue, not the input).</summary>
    private sealed record Target(string Name, byte[][] Seeds, byte[][] Dict, Func<byte[], bool> Run, int MaxLen = 16 * 1024, bool Serial = false);

    public sealed class Finding(string message) : Exception(message);

    private static Target LogPrivacyTarget() => new("log-privacy", B("/x?token=secret", "/%3f/x", "/x#secret"), B("?", "#", "\r\n"), bytes =>
    {
        var input = Encoding.UTF8.GetString(bytes);
        var output = LogPrivacy.PathOnly(input);
        if (!input.StartsWith(output, StringComparison.Ordinal) || output.Contains('?') || output.Contains('#'))
            throw new Finding("log redaction retained a query/fragment or changed the path prefix");
        if (LogPrivacy.PathOnly(output) != output) throw new Finding("redaction is not idempotent");
        return true;
    });

    private static readonly Lazy<Target[]> All = new(() =>
    [
        LogPrivacyTarget(), RequestTarget(), UriTarget(), ChunkedTarget(), UpstreamTarget(), ConfigTarget(), CrlTarget(), AcceptEncodingTarget(), OcspTarget(), ProxyProtocolTarget(), TunnelHandshakeTarget(), PathMapTarget(), RangeTarget(), HostTarget(), RewriteTarget(), HpackTarget(), HuffmanTarget(), H2FramesTarget(), H2SessionTarget(),
        QuicVarIntTarget(), QuicPacketTarget(), QuicFramesTarget(), QuicTransportParametersTarget(), QuicConnectionTarget(), QuicClientHandshakeTarget(), QuicClientFramesTarget(), QpackTarget(), H3FramesTarget(), H3SessionTarget(),
    ]);

    public static void Register()
    {
        foreach (var name in new[] { "request", "uri", "chunked", "upstream", "config", "crl", "accept-encoding", "ocsp", "proxy-protocol", "tunnel-handshake", "path-map", "range", "host", "rewrite", "hpack", "huffman", "h2-frames", "h2-session", "quic-varint", "quic-packet", "quic-frames", "quic-tp", "quic-connection", "quic-client-handshake", "quic-client-frames", "qpack", "h3-frames", "h3-session" })
        {
            int iterations = name == "config" ? 3_000 : name == "h2-session" ? 2_000 : name is "quic-connection" or "quic-client-frames" ? 1_000 : name == "quic-client-handshake" ? 3_000 : name == "h3-session" ? 100 : 20_000;
            T.Add($"fuzz: {name} parser ({iterations} mutated inputs, fixed seed)", () =>
            {
                var t = Array.Find(All.Value, x => x.Name == name)!;
                var (failure, _, _) = Run(t, seed: 1, iterations, deadline: long.MaxValue, parallel: true);
                if (failure is not null) throw new Finding(failure);
            });
        }
    }

    /// <summary>Long-running mode. Exit code 1 on the first finding.</summary>
    public static int RunCli(string[] args)
    {
        string which = args.Length > 1 ? args[1] : "all";
        int seconds = args.Length > 2 ? int.Parse(args[2]) : 60;
        int seed = args.Length > 3 ? int.Parse(args[3]) : Environment.TickCount & 0x7fffffff;
        var targets = which == "all" ? All.Value : [Array.Find(All.Value, t => t.Name == which) ?? throw new ArgumentException($"unknown target \"{which}\"")];
        long perTarget = seconds * 1000L / targets.Length;
        foreach (var t in targets)
        {
            var (failure, done, accepted) = Run(t, seed, long.MaxValue, Environment.TickCount64 + perTarget, parallel: true);
            Console.WriteLine($"fuzz {t.Name}: {done} inputs ({100.0 * accepted / Math.Max(1, done):F1}% accepted), seed {seed}{(failure is null ? ", no findings" : "")}");
            if (failure is not null)
            {
                Console.WriteLine(failure);
                return 1;
            }
        }
        return 0;
    }

    private static (string? Failure, long Done, long Accepted) Run(Target t, int seed, long iterations, long deadline, bool parallel)
    {
        string? failure = null;
        long done = 0, accepted = 0, next = -1;
        void Worker()
        {
            while (Volatile.Read(ref failure) is null)
            {
                long i = Interlocked.Increment(ref next);
                if (i >= iterations || ((i & 63) == 0 && Environment.TickCount64 > deadline)) return;
                var input = Input(t, seed, i);
                var sw = Stopwatch.StartNew();
                try { if (t.Run(input)) Interlocked.Increment(ref accepted); }
                catch (Exception e)
                {
                    Interlocked.CompareExchange(ref failure, Report(t, seed, i, input, e), null);
                    return;
                }
                if (sw.ElapsedMilliseconds > 2000)
                {
                    Interlocked.CompareExchange(ref failure, Report(t, seed, i, input, new Finding($"slow input: {sw.ElapsedMilliseconds} ms")), null);
                    return;
                }
                Interlocked.Increment(ref done);
            }
        }
        int n = parallel && !t.Serial ? Math.Max(1, Environment.ProcessorCount) : 1;
        var threads = new Thread[n];
        for (int k = 0; k < n; k++) (threads[k] = new Thread(Worker, 16 << 20) { IsBackground = true }).Start();
        foreach (var th in threads) th.Join();
        return (failure, done, accepted);
    }

    private static string Report(Target t, int seed, long i, byte[] input, Exception e)
    {
        var shown = input.Length > 600 ? input[..600] : input;
        var sb = new StringBuilder();
        foreach (byte b in shown) sb.Append(b is >= 0x20 and < 0x7f and not (byte)'\\' ? (char)b : $"\\x{b:x2}");
        return $"[{t.Name}] seed {seed} iteration {i}: {e.GetType().Name}: {e.Message}\n  input ({input.Length} bytes): {sb}{(input.Length > 600 ? "..." : "")}\n  at {e.StackTrace?.Split('\n').FirstOrDefault()?.Trim()}";
    }

    // ---------------------------------------------------------------- mutation

    private static byte[] Input(Target t, int seed, long i)
    {
        var r = new Random(HashCode.Combine(seed, i, t.Name.Length));
        var data = new List<byte>(t.Seeds[r.Next(t.Seeds.Length)]);
        int ops = 1 + r.Next(r.Next(2) == 0 ? 3 : 12);
        for (int k = 0; k < ops; k++) Mutate(r, data, t);
        if (data.Count > t.MaxLen) data.RemoveRange(t.MaxLen, data.Count - t.MaxLen);
        return data.ToArray();
    }

    private static readonly byte[] Interesting = [0, (byte)'\r', (byte)'\n', (byte)' ', (byte)'\t', (byte)':', (byte)'%', (byte)';', (byte)'{', (byte)'}', (byte)'"', (byte)'\\', (byte)'/', (byte)'.', (byte)'0', (byte)'9', (byte)'f', 0x7f, 0x80, 0xc0, 0xff];

    private static void Mutate(Random r, List<byte> d, Target t)
    {
        int Pos() => d.Count == 0 ? 0 : r.Next(d.Count + 1);
        switch (r.Next(10))
        {
            case 0 when d.Count > 0: { int p = r.Next(d.Count); d[p] ^= (byte)(1 << r.Next(8)); break; }
            case 1 when d.Count > 0: d[r.Next(d.Count)] = Interesting[r.Next(Interesting.Length)]; break;
            case 2 or 3: d.InsertRange(Pos(), t.Dict[r.Next(t.Dict.Length)]); break;
            case 4 when d.Count > 0: { int p = r.Next(d.Count); d.RemoveRange(p, Math.Min(d.Count - p, 1 + r.Next(16))); break; }
            case 5 when d.Count > 0: { int p = r.Next(d.Count); int len = Math.Min(d.Count - p, 1 + r.Next(64)); d.InsertRange(Pos(), d.GetRange(p, len)); break; }
            case 6 when d.Count > 0: { int p = r.Next(d.Count); d.RemoveRange(p, Math.Min(d.Count - p, 1 + r.Next(8))); d.InsertRange(p, t.Dict[r.Next(t.Dict.Length)]); break; } // replace
            case 7 when d.Count > 0: { int p = r.Next(d.Count); d.RemoveRange(p, d.Count - p); break; } // truncate
            case 8: { var other = t.Seeds[r.Next(t.Seeds.Length)]; int p = r.Next(other.Length + 1); d.InsertRange(Pos(), other[p..]); break; } // splice
            default: d.Insert(Pos(), Interesting[r.Next(Interesting.Length)]); break;
        }
    }

    private static byte[][] B(params string[] s) => Array.ConvertAll(s, x => Encoding.Latin1.GetBytes(x));

    // ---------------------------------------------------------------- targets

    private static readonly HeadLimits Lim = new(8192, 32768, 100);

    /// <summary>The request head: framing, Host, target. A wrong "accept" here is request smuggling.</summary>
    private static Target RequestTarget() => new("request",
        B("GET / HTTP/1.1\r\nHost: a.test\r\n\r\n",
          "POST /up?x=1 HTTP/1.1\r\nHost: a.test:8080\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\n",
          "POST /c HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n",
          "GET /a/%2e%2e/b//c?q#f HTTP/1.0\r\n\r\n",
          "GET http://a.test/x HTTP/1.1\r\nHost: a.test\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n",
          "OPTIONS * HTTP/1.1\r\nHost: [::1]:80\r\n\r\n",
          "\r\nHEAD /caf%C3%A9 HTTP/1.1\r\nhost: A.Test\r\nX-A: 1\r\nX-B:\t2 \r\nCookie: a=b\r\n\r\n"),
        B("\r\n", "\n", "\r", " ", "\t", ":", ": ", "Content-Length: ", "Content-Length: 0\r\n", "Transfer-Encoding: chunked\r\n",
          "Transfer-Encoding: ", "chunked", "identity", "Host: ", "Host: x\r\n", "%", "%00", "%2e", "%2E%2e", "%2f", "%c0%af", "%ff", "/../",
          "/./", "//", "?", "#", "HTTP/1.1", "HTTP/1.0", "HTTP/2.0", "HTTP/1.10", "\0", "\x7f", "\xff", "99999999999999999999", "-1", "+5",
          "0x10", ",", "Connection: close\r\n", "Expect: 100-continue\r\n", "Upgrade: h2c\r\n", "X_A: 1\r\n", "_", "*", "@", "[::1]", ":8080", "a.test.", "GET ", "CONNECT "),
        data =>
        {
            using var inb = new InputBuffer(Math.Max(16, data.Length));
            data.CopyTo(inb.Buf, 0);
            inb.End = data.Length;
            int headLen = RequestParser.FindHeadEnd(inb);
            if (headLen < 0)
            {
                int inc = RequestParser.CheckIncomplete(inb.Data, Lim);
                if (inc != 0 && inc is < 400 or > 599) throw new Finding($"CheckIncomplete returned {inc}");
                return false;
            }
            if (headLen > data.Length) throw new Finding($"head length {headLen} > input {data.Length}");
            var req = new RequestImpl();
            int rc = RequestParser.Parse(data.AsSpan(0, headLen), req, Lim);
            if (rc != 0)
            {
                if (rc is < 400 or > 599) throw new Finding($"Parse returned {rc}");
                return false;
            }
            if (req.ContentLengthValue >= 0 && req.ChunkedValue) throw new Finding("accepted both Content-Length and chunked");
            if (req.ContentLengthValue < -1) throw new Finding($"negative Content-Length {req.ContentLengthValue}");
            if (req.ChunkedValue && req.VersionValue == HttpVersion.Http10) throw new Finding("chunked on HTTP/1.0");
            if (req.VersionValue == HttpVersion.Http11 && req.HostValue.Length == 0) throw new Finding("HTTP/1.1 without Host accepted");
            foreach (char c in req.HostValue)
                if (char.IsAsciiLetterUpper(c) || c is '\r' or '\n' or '\0' or ' ' or '/' or '\\' or '@') throw new Finding($"bad host \"{req.HostValue}\"");
            foreach (char c in req.MethodValue)
                if (c > 0x7f || !HttpChars.IsToken((byte)c)) throw new Finding($"bad method \"{req.MethodValue}\"");
            if (!(req.PathValue == "*" && req.MethodValue == HttpMethods.Options)) CheckPath(req.PathValue);
            foreach (char c in req.QueryValue)
                if (c is '\r' or '\n' or '\0' or ' ' or '#') throw new Finding($"bad query \"{req.QueryValue}\"");
            var h = req.Headers;
            for (int k = 0; k < h.Count; k++)
            {
                foreach (char c in h.ValueAt(k))
                    if (c is '\r' or '\n' or '\0') throw new Finding("control character in a header value");
                if (h.NameAt(k).Contains('_')) throw new Finding($"underscored header \"{h.NameAt(k)}\" kept");
            }
            if (req.VersionValue == HttpVersion.Http11 && h.Get("Host") is null) throw new Finding("HTTP/1.1 without a Host field accepted");
            return true;
        });

    private static void CheckPath(string p)
    {
        if (p.Length == 0 || p[0] != '/') throw new Finding($"path \"{p}\" not absolute");
        if (p.Contains("//", StringComparison.Ordinal)) throw new Finding($"path \"{p}\" has an empty segment");
        foreach (char c in p) if (c < ' ' || c == (char)0x7f) throw new Finding($"path contains control character 0x{(int)c:x2}");
        foreach (var seg in p.Split('/'))
            if (seg is "." or "..") throw new Finding($"path \"{p}\" has a dot segment");
        for (int k = 0; k < p.Length; k++)
            if (char.IsSurrogate(p[k]) && !(char.IsHighSurrogate(p[k]) && k + 1 < p.Length && char.IsLowSurrogate(p[++k])))
                throw new Finding("path has an unpaired surrogate");
    }

    private static Target UriTarget() => new("uri",
        B("/", "/a/b/../c", "/%2e%2e/x", "/a//b/./c/", "/caf%C3%A9/%F0%9F%98%80", "/a%2fb", "/x/..", "/%2E%2E%2F%2E%2E%2Fetc%2Fpasswd"),
        B("%", "%2e", "%2E", "%2f", "%5c", "%00", "%c0%ae", "%e0%80%ae", "%ff", "/", "..", ".", "//", "\\", "\0", "%%", "%2", "\xc3", "\xa9"),
        data =>
        {
            var p = UriNormalizer.NormalizeRaw(data);
            if (p is null) return false;
            CheckPath(p);
            if (UriNormalizer.NormalizeDecoded(p) is { } again && again != p) throw new Finding($"not stable: \"{p}\" -> \"{again}\"");
            return true;
        }, MaxLen: 4096);

    /// <summary>Chunked request bodies: the other half of smuggling safety.</summary>
    private static Target ChunkedTarget() => new("chunked",
        B("5\r\nhello\r\n0\r\n\r\n", "3;ext=1\r\nabc\r\n0\r\nTrailer: x\r\n\r\n", "a\r\n0123456789\r\n1\r\nx\r\n0\r\n\r\nGET / HTTP/1.1\r\n\r\n", "0\r\n\r\n",
          "1\r\n\r\r\nA\r\n0000000000\r\n0\r\n\r\n", "1\r\nx\r\n0\r\nX: a\r\r\n\r\n", "1;e\r\r\nx\r\n0\r\n\r\n"),
        B("\r\n", "\n", "\r", ";", "0", "f", "F", "ffffffffffffffff", "7fffffff", "-1", " ", "\t", "0x", "+1", "Trailer: v\r\n", "\0", "1\r\na\r\n"),
        data =>
        {
            using var sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            var conn = new Connection(1, sock, default);
            using var inb = new InputBuffer(64);
            var body = new BodyStream(conn, inb) { MaxSize = 1 << 20 };
            body.Reset(new MemoryStream(data), -1, chunked: true);
            var buf = new byte[512];
            long total = 0;
            try
            {
                int n;
                while ((n = body.ReadAsync(buf).AsTask().GetAwaiter().GetResult()) > 0)
                {
                    total += n;
                    if (total > data.Length) throw new Finding($"decoded {total} bytes from {data.Length}");
                }
            }
            catch (HttpBodyException e) when (e.Status is 400 or 413 or 431) { return false; }
            if (!body.IsComplete) throw new Finding("EOF reported without the terminating chunk");
            return true;
        }, MaxLen: 4096);

    /// <summary>Upstream response heads: a hostile backend must not be able to split or desync our response.</summary>
    private static Target UpstreamTarget() => new("upstream",
        B("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\n",
          "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
          "HTTP/1.0 302 Found\r\nLocation: /x\r\nConnection: keep-alive\r\n\r\n",
          "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: x-foo, close\r\nX-Foo: 1\r\n\r\n",
          "HTTP/1.1 304 Not Modified\r\nETag: \"a\"\r\n\r\n", "HTTP/1.1 204\r\n\r\n"),
        B("\r\n", "\n", "\r", " ", "\t", ":", "Content-Length: ", "Content-Length: 5\r\n", "Transfer-Encoding: chunked\r\n", "Transfer-Encoding: ",
          "chunked, gzip", "Connection: ", "close", "keep-alive", "HTTP/1.1 ", "HTTP/1.0 ", "HTTP/2 ", "999", "000", "100", "\0", "\x7f", "\xff",
          "99999999999999999999", "-1"),
        data =>
        {
            int end = data.AsSpan().IndexOf("\r\n\r\n"u8);
            if (end < 0) return false; // ReadAsync only ever hands over a complete head
            var r = new UpstreamResponse();
            try { r.Parse(data.AsSpan(0, end + 4), requestWasHead: (data.Length & 1) == 1); }
            catch (UpstreamException) { return false; }
            if (r.Status is < 100 or > 999) throw new Finding($"status {r.Status}");
            if (r.Framing == BodyFraming.Chunked && r.ContentLength >= 0) throw new Finding("chunked framing with a Content-Length");
            if (r.Framing == BodyFraming.UntilClose && r.KeepAlive) throw new Finding("close-delimited body on a kept-alive connection");
            foreach (var (name, value) in r.Headers)
            {
                foreach (char c in name)
                    if (c > 0x7f || !HttpChars.IsToken((byte)c)) throw new Finding($"bad header name \"{name}\"");
                foreach (char c in value)
                    if (c is '\r' or '\n' or '\0') throw new Finding("control character in an upstream header value");
            }
            return true;
        }, MaxLen: 8192);

    /// <summary>The config parser and every module's directive handlers: errors must be ConfigExceptions with a location, never crashes.</summary>
    private static Target ConfigTarget()
    {
        var seeds = new List<string>
        {
            File.Exists("conf/httpgrl.conf") ? File.ReadAllText("conf/httpgrl.conf").Replace("include", "#") : "http { server { listen 80; } }",
            """
            worker_shutdown_timeout 5s; reload_drain_timeout 1m; error_log stdout info;
            events { worker_connections 1024; connections_per_client 64; }
            http {
              map $http_user_agent $ua { default a; ~*bot b; "~^x(\d+)" "c$1"; }
              limit_req_zone $remote_net zone=r:64k rate=10r/s;
              limit_conn_zone $remote_net zone=c:64k;
              limit_req zone=r burst=5 nodelay; limit_conn c 10;
              add_header X-A "$ua" always;
              upstream app { server 127.0.0.1:9000 weight=2 max_fails=3; server 127.0.0.2:9000 backup; keepalive 8; }
              server {
                listen 127.0.0.1:8080 default_server reuseport backlog=128; server_name a.test *.b.test ~^c\d+$;
                root /srv; index index.html; autoindex on; error_page 404 /404.html; error_page 403 =444;
                set $x "y"; if ($request_method = POST) { return 405; } if ($uri ~ "^/i/(\d+)$") { set $id $1; }
                location / { try_files $uri $uri/ =404; }
                location = /exact { return 200 "ok $x"; }
                location ^~ /p/ { proxy_pass http://app/; proxy_set_header X-Id $id; proxy_read_timeout 30s; }
                location ~* \.(png|jpg)$ { expires_is_not_a_directive_so_mutations_must_handle_unknowns; }
                location @named { return 302 https://$host$request_uri; }
              }
            }
            """.Replace("expires_is_not_a_directive_so_mutations_must_handle_unknowns", "internal"),
        };
        var dict = B("{", "}", ";", "\"", "'", "\\", "$", "${", "#", "\n", " ", "(", ")", "~", "~*", "=", "^~", "@", "*", "location", "server",
            "http", "map", "if", "set", "return", "listen", "proxy_pass", "limit_req", "add_header", "error_page", "try_files", "alias",
            "zone=", "rate=", "burst=", "1r/s", "0", "-1", "99999999999999999999", "1k", "10m", "1s", "on", "off", "$uri", "$1", "$nope",
            "http://", "unix:", "[::]:80", "\0", "\xff", "default", "*.x", "~^a(", "{1000}");
        return new Target("config", seeds.ConvertAll(s => Encoding.UTF8.GetBytes(s)).ToArray(), dict, data =>
        {
            var text = Encoding.UTF8.GetString(data);
            if (text.Contains("include", StringComparison.Ordinal)) return false; // would read the real filesystem
            try { ParseAll(text); return true; }
            catch (ConfigException) { return false; }
        }, MaxLen: 4096);
    }

    private static readonly ILogger NullLog = new JsonLogger(Stream.Null, LogLevel.Error);

    /// <summary>Parse with every module's directives, resolve variables, merge, and compile routing. No I/O.</summary>
    private static void ParseAll(string text)
    {
        var vars = new VariableRegistry();
        var reg = new Collector(vars);
        IModule[] modules =
        [
            new HttpCoreModule(Path.GetTempPath()), new SslModule(Path.GetTempPath()), new AccessLogModule(),
            new Httpgrl.Modules.Rewrite.RewriteModule(), new Httpgrl.Modules.Rewrite.MapModule(), new Httpgrl.Modules.Headers.HeadersModule(),
            new Httpgrl.Modules.Limits.LimitReqModule(), new Httpgrl.Modules.Limits.LimitConnModule(), new ProxyModule(),
            .. Httpgrl.Modules.StaticFiles.StaticFiles.Modules(),
        ];
        foreach (var m in modules) m.Register(reg);
        var root = new ConfigParser(reg.Directives, vars).ParseText(text, "/fuzz/<inline>", "/fuzz-nonexistent");
        vars.ResolvePending();
        root.MergeAndFreeze();
        RoutingBuilder.Build(root, NullLog);
    }

    private sealed class Collector(VariableRegistry vars) : IModuleRegistry
    {
        public readonly Dictionary<string, List<Directive>> Directives = new(StringComparer.Ordinal);
        public void AddDirective(Directive d)
        {
            if (!Directives.TryGetValue(d.Name, out var l)) Directives[d.Name] = l = new();
            l.Add(d);
        }
        public void AddVariable(string name, VariableGetter getter) => vars.Add(name, getter);
        public void AddVariablePrefix(string prefix, PrefixVariableGetter getter) => vars.AddPrefix(prefix, getter);
    }

    /// <summary>Accept-Encoding negotiation: any header value yields a coding, never an exception; q=0 is always honoured.</summary>
    private static Target AcceptEncodingTarget() => new("accept-encoding",
        B("gzip, deflate, br", "br;q=0.5, gzip;q=0.9", "*;q=0.1, br;q=0", "identity", "gzip;q=0", "x-gzip, *"),
        B(",", ";", "q=", "q=0", "q=1", "q=0.001", "q=1.0001", "q=-1", "q=NaN", "q=1e3", " ", "\t", "*", "br", "gzip", "BR", "GZIP", "\0", "\xff"),
        data =>
        {
            var v = Encoding.Latin1.GetString(data);
            var c = AcceptEncoding.Choose(v, true, true);
            // Whatever the rest says, an explicit q=0 (exact, unambiguous form) for a coding is never overridden for it.
            if (c == ContentCoding.Brotli && v == "br;q=0") throw new Finding("br chosen despite q=0");
            if (c != ContentCoding.Identity && !AcceptEncoding.Accepts(v, c)) throw new Finding($"chose {c} but it isn't acceptable");
            return c != ContentCoding.Identity;
        }, MaxLen: 1024);

    /// <summary>PROXY protocol headers: what anyone who can reach a proxy_protocol listener can send.</summary>
    private static Target ProxyProtocolTarget()
    {
        byte[] Sig(byte cmd, byte fam, byte[] body) => [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, cmd, fam, (byte)(body.Length >> 8), (byte)body.Length, .. body];
        return new Target("proxy-protocol",
            [.. B("PROXY TCP4 203.0.113.7 198.51.100.1 4242 443\r\nGET / HTTP/1.1\r\n", "PROXY TCP6 2001:db8::1 ::2 1 65535\r\n", "PROXY UNKNOWN\r\n"),
             Sig(0x21, 0x11, [1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 1, 187]), Sig(0x21, 0x21, new byte[36]), Sig(0x20, 0x00, []), Sig(0x21, 0x31, new byte[216])],
            B("\r\n", " ", "PROXY ", "TCP4", "TCP6", "UNKNOWN", "0", "65535", "65536", "::", "1.2.3.4", "\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a", "\x21", "\x20", "\x11", "\x21\x21", "\xff\xff", "\x00\x00"),
            data =>
            {
                int r = Httpgrl.Core.Http.ProxyProtocol.TryParse(data, out var h);
                if (r > data.Length) throw new Finding($"consumed {r} of {data.Length} bytes");
                if (r <= 0) return false;
                if (data[0] == (byte)'P' && (r < 8 || data[r - 2] != '\r' || data[r - 1] != '\n')) throw new Finding("v1 header not ending in CRLF");
                if (r > Httpgrl.Core.Http.ProxyProtocol.V2Max) throw new Finding("header longer than the cap");
                if ((h.Source is null) != (h.Destination is null)) throw new Finding("half an address pair");
                if (h.Source is not null && h.Source.AddressFamily != h.Destination!.AddressFamily) throw new Finding("mixed address families");
                return true;
            }, MaxLen: 2048);
    }

    /// <summary>
    /// Request path (and request-influenced variable text) through root/alias to a filesystem path. Whatever the input,
    /// the result is null or inside the directory the configuration intends, checked independently of the mapper.
    /// Input: raw request path, then optionally '\x01' and the text a variable in the root/alias evaluates to.
    /// </summary>
    private static Target PathMapTarget()
    {
        static void Inside(string? result, string dir, string what)
        {
            if (result is null) return;
            var rel = Path.GetRelativePath(dir, result);
            if (rel == ".." || rel.StartsWith("../", StringComparison.Ordinal) || Path.IsPathRooted(rel))
                throw new Finding($"{what}: \"{result}\" is outside \"{dir}\"");
            foreach (var seg in result.Split('/')) if (seg is "." or "..") throw new Finding($"{what}: dot segment in \"{result}\"");
        }
        return new Target("path-map",
            B("/index.html", "/dl/a/b", "/dl../etc/passwd", "/x..", "/a/%2e%2e/b", "/dl/\x01/srv/www", "/p\x01/srv/www/../etc", "/q\x01..", "/%2e%2e%2f..%2fetc"),
            B("/", "..", ".", "%2e", "%2f", "%2e%2e", "dl", "dl/", "x", "\x01", "/srv", "/etc", "\0", "\\", "~", "%00", "//"),
            data =>
            {
                int sep = Array.IndexOf(data, (byte)1);
                var raw = sep < 0 ? data : data[..sep];
                var var_ = sep < 0 ? "" : Encoding.Latin1.GetString(data, sep + 1, data.Length - sep - 1);
                if (raw.Length == 0 || raw[0] != (byte)'/') return false;
                var uri = UriNormalizer.NormalizeRaw(raw);
                if (uri is null) return false;
                const string www = "/srv/www", files = "/srv/files", sites = "/srv/sites";
                Inside(HttpContextImpl.Map(uri, www, false, -1, www), www, "root");
                Inside(HttpContextImpl.Map(uri, files + "/", true, 4, files + "/"), files, "alias /dl/");
                Inside(HttpContextImpl.Map(uri, files, true, 3, files), files, "alias /dl (off-by-slash shape)");
                // location ~ ^/x(.*)$ { alias /srv/files/$1; }: the capture is a substring of the normalized path.
                if (uri.StartsWith("/x", StringComparison.Ordinal))
                    Inside(HttpContextImpl.Map(uri, files + "/" + uri[2..], true, -1, files), files, "regex alias");
                // root $var; (no constant part): never escape the value, and a value with dot segments maps nothing.
                var r = HttpContextImpl.Map(uri, var_, false, -1, null);
                if (r is not null)
                {
                    if (!Path.IsPathFullyQualified(var_)) throw new Finding($"relative root \"{var_}\" accepted");
                    Inside(r, Path.GetFullPath(var_), "root $var");
                }
                // root /srv/sites/$var;
                Inside(HttpContextImpl.Map(uri, sites + "/" + var_, false, -1, sites), sites, "root /srv/sites/$var");
                return true;
            }, MaxLen: 512);
    }

    /// <summary>Range header against files of a few sizes: a satisfiable range always lies inside the file.</summary>
    private static Target RangeTarget() => new("range",
        B("bytes=0-0", "bytes=-5", "bytes=5-", "bytes=1-2,3-4", "bytes=9223372036854775806-9223372036854775807", "BYTES = 3 - 9", "bytes=-0"),
        B("bytes=", "-", ",", " ", "\t", "0", "1", "9", "9223372036854775807", "9223372036854775808", "99999999999999999999", "+", "x", "="),
        data =>
        {
            var h = Encoding.Latin1.GetString(data);
            bool any = false;
            foreach (long len in new long[] { 0, 1, 10, 4096, long.MaxValue })
            {
                var r = Httpgrl.Modules.StaticFiles.StaticModule.ParseRange(h, len, out long off, out long count);
                if (r != Httpgrl.Modules.StaticFiles.StaticModule.RangeResult.Satisfiable) continue;
                any = true;
                if (off < 0 || count < 1 || off >= len || count > len - off) throw new Finding($"range [{off}, +{count}) outside a {len}-byte file");
            }
            return any;
        }, MaxLen: 256);

    /// <summary>Host header / SNI normalization: what comes out is a valid, lower-case, port-free name, and stable.</summary>
    private static Target HostTarget() => new("host",
        B("a.test", "A.Test:8080", "[::1]:80", "a.test.", "xn--bcher-kva.example", "a_b.test", "[]", "a..", "1.2.3.4"),
        B(".", "..", ":", "[", "]", "::", "-", "_", "A", "\0", " ", "/", "@", "%", "\xff", ":99999", ":", "0"),
        data =>
        {
            var h = RequestParser.NormalizeHost(Encoding.Latin1.GetString(data));
            if (h is null) return false;
            if (h.Length == 0) throw new Finding("empty host accepted");
            foreach (char c in h)
                if (!(char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c is '-' or '_' or '.' or '[' or ']' or ':')) throw new Finding($"bad character in \"{h}\"");
            if (h == "[]" ) throw new Finding("empty IPv6 literal accepted");
            if (!h.StartsWith('[') && (h.Contains(':') || h.Contains("..") || h.StartsWith('.') || h.EndsWith('.'))) throw new Finding($"malformed name \"{h}\"");
            if (RequestParser.NormalizeHost(h) != h) throw new Finding($"not stable: \"{h}\" -> \"{RequestParser.NormalizeHost(h)}\"");
            return true;
        }, MaxLen: 300);

    /// <summary>
    /// A rewrite result (literal text plus captures of the client's path) through to what the core keeps: a clean path,
    /// a query that can sit on a request line, and a Location value that can't split the response. Input: the
    /// replacement result, then optionally '\x01' and the original query.
    /// </summary>
    private static readonly ComplexValue VariableTemplate = new("$1", []), LiteralSlashesTemplate = new("//cdn.example$1", []);

    private static Target RewriteTarget() => new("rewrite",
        B("/new/path", "/a?x=1", "/a?", "/a?b=2\x01c=3", "/../../etc", "/x/%2e%2e/y", "http://evil/\r\nSet-Cookie: x", "/caf\u00e9?q=\u00e9 \t#f"),
        B("?", "&", "#", "/", "..", ".", "%", "%0d%0a", "\r", "\n", "\0", " ", "\t", "\x7f", "\xff", "\x01", "//", "\\"),
        data =>
        {
            int sep = Array.IndexOf(data, (byte)1);
            var target = Encoding.UTF8.GetString(sep < 0 ? data : data[..sep]);
            var orig = sep < 0 ? "" : Encoding.Latin1.GetString(data, sep + 1, data.Length - sep - 1);
            var loc = Redirects.Location(VariableTemplate, target);
            foreach (char c in loc) if (c is < (char)0x21 or > (char)0x7e or '\\') throw new Finding($"Location carries 0x{(int)c:x2}");
            if (loc.StartsWith("//", StringComparison.Ordinal)) throw new Finding($"variable-built Location is protocol-relative: \"{loc}\"");
            if (Redirects.Location(LiteralSlashesTemplate, target) != Redirects.Escape(target)) throw new Finding("a template written with // was changed");
            var (path, query) = Httpgrl.Modules.Rewrite.RewriteModule.SplitTarget(target, orig);
            if (path.Contains('?')) throw new Finding($"'?' left in path \"{path}\"");
            var q = HttpContextImpl.EscapeQuery(query);
            foreach (char c in q) if (c is <= ' ' or >= (char)0x7f or '#') throw new Finding($"query carries 0x{(int)c:x2}");
            var p = UriNormalizer.NormalizeDecoded(path);
            if (p is null) return false;
            CheckPath(p);
            return true;
        }, MaxLen: 1024);

    /// <summary>
    /// HPACK header blocks (HTTP/2's compressed headers, straight from the client). Whatever is accepted stays within the
    /// limits, and survives a round trip through our encoder unchanged.
    /// </summary>
    private static Target HpackTarget()
    {
        var seeds = Httpgrl.Tests.HpackVectors.All.Select(v => Convert.FromHexString(v.Hex)).ToArray();
        return new Target("hpack", seeds,
            B("\x80", "\x82", "\xbe", "\x40", "\x00", "\x10", "\x20", "\x3f\xe1\x1f", "\x7f", "\xff\xff\xff\xff\x0f", "\x81", "\x8f", "\x01a", "\x00\x00"),
            data =>
            {
                const int listMax = 16 << 10, tableMax = 4096;
                var d = new Httpgrl.HttpFields.HpackDecoder(tableMax, listMax);
                var got = new List<(byte[], byte[])>();
                long size = 0;
                try { d.Decode(data, (n, v) => { got.Add((n.ToArray(), v.ToArray())); size += n.Length + v.Length + 32; }); }
                catch (Httpgrl.HttpFields.HpackException) { return false; }
                if (d.TableSize > tableMax) throw new Finding($"dynamic table at {d.TableSize} bytes");
                if (size > listMax) throw new Finding($"emitted {size} bytes of fields");
                if (got.Count > 128) throw new Finding($"emitted {got.Count} fields");
                var buf = new byte[64];
                int len = 0;
                foreach (var (n, v) in got) Httpgrl.HttpFields.HpackEncoder.Encode(ref buf, ref len, Encoding.Latin1.GetString(n), Encoding.Latin1.GetString(v));
                var again = new List<(byte[], byte[])>();
                new Httpgrl.HttpFields.HpackDecoder(tableMax, 1 << 30, 1 << 20).Decode(buf.AsSpan(0, len), (n, v) => again.Add((n.ToArray(), v.ToArray())));
                if (again.Count != got.Count) throw new Finding("round trip changed the field count");
                for (int k = 0; k < got.Count; k++)
                    if (!again[k].Item1.AsSpan().SequenceEqual(got[k].Item1) || !again[k].Item2.AsSpan().SequenceEqual(got[k].Item2)) throw new Finding($"round trip changed field {k}");
                return true;
            }, MaxLen: 8192);
    }

    /// <summary>Huffman-coded strings: a decoded string re-encodes and decodes to itself; the output never outgrows its bound.</summary>
    private static Target HuffmanTarget() => new("huffman",
        [Convert.FromHexString("f1e3c2e5f23a6ba0ab90f4ff"), Convert.FromHexString("a8eb10649cbf"), Convert.FromHexString("25a849e95ba97d7f")],
        B("\xff", "\x00", "\xfe", "\x1f", "\xf8"),
        data =>
        {
            var dec = new byte[data.Length * 8 / 5 + 1];
            int n;
            try { n = Httpgrl.HttpFields.Huffman.Decode(data, dec); }
            catch (Httpgrl.HttpFields.HpackException) { return false; }
            var enc = new byte[Httpgrl.HttpFields.Huffman.EncodedLength(dec.AsSpan(0, n))];
            int e = Httpgrl.HttpFields.Huffman.Encode(dec.AsSpan(0, n), enc);
            var back = new byte[e * 8 / 5 + 1];
            int m = Httpgrl.HttpFields.Huffman.Decode(enc.AsSpan(0, e), back);
            if (!back.AsSpan(0, m).SequenceEqual(dec.AsSpan(0, n))) throw new Finding("encode/decode round trip differs");
            return true;
        }, MaxLen: 512);

    /// <summary>
    /// A stream of HTTP/2 frames: each read consumes exactly its header and declared length, stays within the frame size
    /// limit, and yields a payload inside the frame; anything else is a classified protocol error.
    /// </summary>
    private static Target H2FramesTarget()
    {
        static byte[] Fr(int type, int flags, int sid, params byte[] p)
        {
            var f = new byte[9 + p.Length];
            Httpgrl.Core.Http2.FrameWriter.Header(f, p.Length, (Httpgrl.Core.Http2.FrameType)type, (byte)flags, sid);
            p.CopyTo(f, 9);
            return f;
        }
        byte[][] seeds =
        [
            [.. Fr(4, 0, 0, 0, 3, 0, 0, 0, 100), .. Fr(8, 0, 0, 0, 1, 0, 0), .. Fr(1, 5, 1, 0x82, 0x86, 0x84), .. Fr(0, 1, 1, (byte)'x')],
            [.. Fr(0, 8, 3, 2, 1, 2, 0, 0), .. Fr(1, 0x24, 5, 0, 0, 0, 1, 16, 0x82), .. Fr(9, 4, 5, 0x84)],
            [.. Fr(6, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8), .. Fr(7, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0), .. Fr(3, 0, 1, 0, 0, 0, 8), .. Fr(2, 0, 3, 0, 0, 0, 1, 16)],
        ];
        return new Target("h2-frames", seeds,
            B("\x00\x00\x00", "\x00\x40\x01", "\xff\xff\xff", "\x00", "\x01", "\x04", "\x08", "\x09", "\x20", "\x25", "\x80\x00\x00\x01", "\x7f\xff\xff\xff", "\xff"),
            data =>
            {
                const int max = 16384;
                var buf = data.AsSpan();
                int frames = 0;
                while (buf.Length > 0)
                {
                    int n;
                    Httpgrl.Core.Http2.Frame f;
                    ReadOnlySpan<byte> p;
                    try { n = Httpgrl.Core.Http2.FrameReader.TryRead(buf, max, out f, out p); }
                    catch (Httpgrl.Core.Http2.H2Exception) { return frames > 0; }
                    if (n == 0) return frames > 0;
                    if (n != 9 + f.Length || n > buf.Length) throw new Finding($"consumed {n} for a {f.Length}-byte frame with {buf.Length} left");
                    if (f.Length > max) throw new Finding("frame over the size limit accepted");
                    if (p.Length > f.Length) throw new Finding("payload longer than its frame");
                    if (p.Length > 0 && !buf.Slice(9, f.Length).Overlaps(p)) throw new Finding("payload outside its frame");
                    if (f.StreamId < 0) throw new Finding("negative stream id");
                    frames++;
                    buf = buf[n..];
                }
                return true;
            }, MaxLen: 4096);
    }

    /// <summary>The remote's answer to a tunnel agent's Upgrade (what the agent reads before serving anything).</summary>
    private static Target TunnelHandshakeTarget() => new("tunnel-handshake",
        B("HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: httpgrl-tunnel\r\n\r\nGET / HTTP/1.1\r\n",
          "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n"),
        B("\r\n", "\r", "\n", ":", " ", "\t", "HTTP/1.1 ", "HTTP/1.0 ", "101", "200", "Upgrade", "Connection", "httpgrl-tunnel", "upgrade", "\x00", "\x7f"),
        data =>
        {
            int r = Httpgrl.Core.Modules.TunnelHandshake.Parse(data, out int status);
            if (r > data.Length) throw new Finding($"consumed {r} of {data.Length} bytes");
            if (r > Httpgrl.Core.Modules.TunnelHandshake.MaxHead) throw new Finding("head longer than the cap");
            if (r == 0 && data.Length >= Httpgrl.Core.Modules.TunnelHandshake.MaxHead) throw new Finding("wants more bytes past the cap");
            if (r <= 0) return false;
            if (status != 101 || !data.AsSpan().StartsWith("HTTP/1.1 101"u8)) throw new Finding("accepted something other than a 101");
            if (!data.AsSpan(0, r).EndsWith("\r\n\r\n"u8) || data.AsSpan(0, r - 2).IndexOf("\r\n\r\n"u8) >= 0) throw new Finding("head boundary is not the first empty line");
            var text = Encoding.Latin1.GetString(data, 0, r);
            if (!text.Contains("httpgrl-tunnel", StringComparison.OrdinalIgnoreCase)) throw new Finding("accepted without our Upgrade token");
            foreach (char c in text) if ((c < 0x20 && c is not ('\t' or '\r' or '\n')) || c == 0x7f) throw new Finding("control character in an accepted head");
            return true;
        }, MaxLen: 10_000);

    /// <summary>OCSP responses (what a responder, or a man in the middle on its plain-HTTP path, sends us to staple).</summary>
    private static Target OcspTarget()
    {
        var pki = new OcspPki("fuzz.test");
        var seeds = new List<byte[]> { pki.MakeResponse() };
        pki.Revoked = true; seeds.Add(pki.MakeResponse());
        pki.Revoked = false; pki.Delegated = true; seeds.Add(pki.MakeResponse());
        var leaf = pki.Leaf;
        var issuer = pki.Ca;
        return new Target("ocsp", seeds.ToArray(), B("\x30", "\x0a\x01\x00", "\x0a\x01\x06", "\xa0", "\xa1", "\xa2", "\x80\x00", "\x81", "\x82\x00", "\x04", "\x06", "\x18", "\x02", "\x01\x01\xff", "\x84\xff\xff\xff\xff"), data =>
        {
            var now = DateTime.UtcNow;
            var v = Httpgrl.Core.Modules.Ocsp.Verify(data, leaf, issuer, now, out _);
            if (v is null) return false;
            if (v.Status == Httpgrl.Core.Modules.OcspCertStatus.Unknown) throw new Finding("accepted status unknown");
            if (v.Expires <= now) throw new Finding("accepted an expired response");
            return true;
        }, MaxLen: 8192);
    }

    /// <summary>CRLs (DER). Only CryptographicException is a legitimate rejection.</summary>
    private static Target CrlTarget()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=fuzz ca", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        using var ca = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var empty = new CertificateRevocationListBuilder().Build(ca, BigInteger.One, DateTimeOffset.UtcNow.AddDays(1), HashAlgorithmName.SHA256);
        var b = new CertificateRevocationListBuilder();
        for (int k = 1; k < 6; k++) b.AddEntry(new byte[] { 0x01, (byte)k }, DateTimeOffset.UtcNow, X509RevocationReason.KeyCompromise);
        var full = b.Build(ca, new BigInteger(7), DateTimeOffset.UtcNow.AddDays(1), HashAlgorithmName.SHA256);
        return new Target("crl", [empty, full], B("\x30", "\x02", "\x04", "\x05\x00", "\x06", "\x17", "\x18", "\x80", "\x81", "\x82\xff\xff", "\x84\xff\xff\xff\xff", "\xa0", "\x01\x01\xff", "\x00"), data =>
        {
            try { Crl.Parse(data, "fuzz"); return true; }
            catch (CryptographicException) { return false; }
        }, MaxLen: 4096);
    }
}
