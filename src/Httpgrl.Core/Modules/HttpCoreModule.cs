using System.Runtime.InteropServices;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Httpgrl.Core.Http;

namespace Httpgrl.Core.Modules;

/// <summary>
/// main/events/http/server/location skeleton and the settings every request depends on
/// (cf. ngx_core_module, ngx_events_module, ngx_http_core_module).
/// </summary>
internal sealed class HttpCoreModule(string prefix) : IModule
{
    public string Name => "http_core";

    private static readonly string[] Ignored = ["user", "worker_processes", "worker_rlimit_nofile", "pid", "daemon", "master_process", "use", "multi_accept", "sendfile", "tcp_nopush", "tcp_nodelay", "aio", "log_format"];
    private readonly List<(string, SourceLocation)> _ignoredSeen = new();
    private static readonly ContextKind TypesKind = new("types");

    private static void DisableSymlinks(DirectiveInvocation i)
    {
        var c = i.Conf<HttpCoreConf>();
        switch (i.Args[0])
        {
            case "off":
                if (i.Args.Length > 1) throw i.Error("\"off\" takes no parameters");
                c.DisableSymlinks = false;
                c.DisableSymlinksFrom = null;
                return;
            case "on": break;
            case "if_not_owner": throw i.Error("\"if_not_owner\" is not supported (file ownership isn't available portably); use \"on\"");
            default: throw i.Error($"invalid value \"{i.Args[0]}\"; expected on or off");
        }
        if (OperatingSystem.IsWindows()) throw i.Error("not supported on Windows");
        if (!OperatingSystem.IsMacOS() && !OperatingSystem.IsFreeBSD()
            && !(OperatingSystem.IsLinux() && RuntimeInformation.ProcessArchitecture is Architecture.X64 or Architecture.Arm64))
            throw i.Error("not supported on this platform");
        string from = "";
        if (i.Args.Length == 2)
        {
            if (!i.Args[1].StartsWith("from=", StringComparison.Ordinal)) throw i.Error($"invalid parameter \"{i.Args[1]}\"");
            from = i.Args[1][5..];
            if (from != "$document_root" && !System.IO.Path.IsPathFullyQualified(from)) throw i.Error("from= must be $document_root or an absolute path");
        }
        c.DisableSymlinks = true;
        c.DisableSymlinksFrom = from;
    }

    public void Register(IModuleRegistry r)
    {
        var main = new[] { ContextKind.Main };
        var http = ContextKind.HttpAny;

        // ---- main / events ----
        r.AddDirective(new() { Name = "events", Contexts = main, Block = ContextKind.Events, Handler = _ => { } });
        r.AddDirective(new() { Name = "http", Contexts = main, Block = ContextKind.Http, Handler = _ => { } });
        r.AddDirective(new() { Name = "error_log", Contexts = main, MinArgs = 1, MaxArgs = 2, Handler = ErrorLog });
        r.AddDirective(new() { Name = "reload_drain_timeout", Contexts = main, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<MainConf>().ReloadDrainTimeout = i.Millis(0) });
        r.AddDirective(new() { Name = "worker_shutdown_timeout", Contexts = main, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<MainConf>().ShutdownTimeout = i.Millis(0) });
        r.AddDirective(new() { Name = "worker_connections", Contexts = [ContextKind.Events], MinArgs = 1, MaxArgs = 1, Handler = WorkerConnections });
        r.AddDirective(new() { Name = "connections_per_client", Contexts = [ContextKind.Events], MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<EventsConf>().ConnectionsPerClient = i.Int(0) });
        foreach (var name in Ignored)
            r.AddDirective(new() { Name = name, Contexts = [ContextKind.Main, ContextKind.Events, ContextKind.Http, ContextKind.Server, ContextKind.Location], MaxArgs = -1, Repeatable = true, Handler = i => _ignoredSeen.Add((i.Name, i.Source)) });

        // ---- http structure ----
        r.AddDirective(new() { Name = "server", Contexts = [ContextKind.Http], Block = ContextKind.Server, Repeatable = true, Handler = _ => { } });
        r.AddDirective(new() { Name = "location", Contexts = ContextKind.ServerAny, MinArgs = 1, MaxArgs = 2, Block = ContextKind.Location, Repeatable = true, Handler = Location });
        r.AddDirective(new() { Name = "listen", Contexts = [ContextKind.Server], MinArgs = 1, MaxArgs = -1, Repeatable = true, Handler = Listen });
        r.AddDirective(new() { Name = "server_name", Contexts = [ContextKind.Server], MinArgs = 1, MaxArgs = -1, Repeatable = true, Handler = ServerName });

        // ---- files ----
        r.AddDirective(new() { Name = "root", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = Root });
        r.AddDirective(new() { Name = "alias", Contexts = [ContextKind.Location], MinArgs = 1, MaxArgs = 1, Handler = Alias });
        r.AddDirective(new() { Name = "try_files", Contexts = ContextKind.ServerAny, MinArgs = 2, MaxArgs = -1, Handler = TryFiles });
        r.AddDirective(new() { Name = "error_page", Contexts = http, MinArgs = 2, MaxArgs = -1, Repeatable = true, Handler = ErrorPageDirective });
        r.AddDirective(new() { Name = "internal", Contexts = [ContextKind.Location], Handler = i => i.Conf<HttpCoreConf>().Internal = true });
        r.AddDirective(new() { Name = "types", Contexts = http, Block = TypesKind, RawBlock = true, Handler = Types });
        r.AddDirective(new() { Name = "default_type", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<HttpCoreConf>().DefaultType = i.Args[0] });

        // ---- limits & timeouts ----
        r.AddDirective(new() { Name = "keepalive_timeout", Contexts = http, MinArgs = 1, MaxArgs = 2, Handler = i => i.Conf<HttpCoreConf>().KeepaliveTimeout = i.Millis(0) });
        r.AddDirective(new() { Name = "keepalive_requests", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<HttpCoreConf>().KeepaliveRequests = i.Int(0) });
        r.AddDirective(new() { Name = "client_header_timeout", Contexts = [ContextKind.Http, ContextKind.Server], MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<HttpCoreConf>().ClientHeaderTimeout = Positive(i, i.Millis(0)) });
        r.AddDirective(new() { Name = "client_body_timeout", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<HttpCoreConf>().ClientBodyTimeout = Positive(i, i.Millis(0)) });
        r.AddDirective(new() { Name = "send_timeout", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<HttpCoreConf>().SendTimeout = Positive(i, i.Millis(0)) });
        r.AddDirective(new() { Name = "ssl_handshake_timeout", Contexts = [ContextKind.Http, ContextKind.Server], MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<HttpCoreConf>().SslHandshakeTimeout = Positive(i, i.Millis(0)) });
        r.AddDirective(new() { Name = "client_body_min_rate", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<HttpCoreConf>().BodyMinRate = (int)Math.Min(i.Size(0), int.MaxValue) });
        r.AddDirective(new() { Name = "send_min_rate", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<HttpCoreConf>().SendMinRate = (int)Math.Min(i.Size(0), int.MaxValue) });
        r.AddDirective(new() { Name = "client_max_body_size", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<HttpCoreConf>().ClientMaxBodySize = i.Size(0) });
        r.AddDirective(new() { Name = "large_client_header_buffers", Contexts = [ContextKind.Http, ContextKind.Server], MinArgs = 2, MaxArgs = 2, Handler = LargeHeaders });
        r.AddDirective(new() { Name = "disable_symlinks", Contexts = http, MinArgs = 1, MaxArgs = 2, Handler = DisableSymlinks });
        r.AddDirective(new() { Name = "underscores_in_headers", Contexts = [ContextKind.Http, ContextKind.Server], MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<HttpCoreConf>().UnderscoresInHeaders = i.Flag(0) });
        r.AddDirective(new() { Name = "server_tokens", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<HttpCoreConf>().ServerTokens = i.Flag(0) });

        RegisterVariables(r);
    }

    public void Configure(IModuleSetup setup)
    {
        foreach (var (name, src) in _ignoredSeen)
        {
            if (name.StartsWith("error_log ", StringComparison.Ordinal))
                setup.Log.Warn("error_log: logs go to stdout as JSON, not to this file (the level still applies)", new("path", name[10..]), new("at", src.ToString()));
            else setup.Log.Warn("directive ignored", new("directive", name), new("at", src.ToString()));
        }
        foreach (var server in setup.ScopesOf(ContextKind.Server))
        {
            var sc = server.Get<ServerConf>();
            if (sc.Listens.Count == 0)
                sc.Listens.Add(new ListenSpec(new IPEndPoint(IPAddress.Any, 80), true, false, false, 511, false, server.Source));
        }
    }

    private static int Positive(DirectiveInvocation i, int v) => v > 0 ? v : throw i.Error("must be positive");

    private void ErrorLog(DirectiveInvocation i)
    {
        // A file path (nginx's usual form) is accepted, but logs are single-line JSON on stdout regardless (the
        // journal or the container runtime collects them).
        if (i.Args[0] is not ("stdout" or "stderr")) _ignoredSeen.Add(("error_log " + i.Args[0], i.Source));
        if (i.Args.Length > 1)
        {
            i.Conf<MainConf>().LogLevel = i.Args[1] switch
            {
                "debug" => LogLevel.Debug,
                "info" or "notice" => LogLevel.Info,
                "warn" => LogLevel.Warn,
                "error" or "crit" or "alert" or "emerg" => LogLevel.Error,
                _ => throw i.Error($"invalid level \"{i.Args[1]}\""),
            };
        }
    }

    private static void WorkerConnections(DirectiveInvocation i)
    {
        int n = i.Int(0);
        if (n < 16 || n > 1_048_576) throw i.Error("must be between 16 and 1048576");
        i.Conf<EventsConf>().WorkerConnections = n;
    }

    private static void LargeHeaders(DirectiveInvocation i)
    {
        int n = i.Int(0);
        long size = i.Size(1);
        if (n < 1 || n > 64 || size < 1024 || size > 1 << 20) throw i.Error("invalid value");
        var c = i.Conf<HttpCoreConf>();
        c.LargeHeaderCount = n;
        c.LargeHeaderSize = (int)size;
    }

    // ---------------- location ----------------

    private static void Location(DirectiveInvocation i)
    {
        var def = i.Block!.Get<LocationDef>();
        string mod = i.Args.Length == 2 ? i.Args[0] : "";
        string pat = i.Args.Length == 2 ? i.Args[1] : i.Args[0];
        if (i.Args.Length == 1 && pat.Length > 1 && pat[0] == '=') { mod = "="; pat = pat[1..]; }
        def.Defined = true;
        def.Pattern = pat;
        switch (mod)
        {
            case "=": def.Kind = LocationKind.Exact; break;
            case "^~": def.Kind = LocationKind.PrefixNoRegex; break;
            case "~": def.Kind = LocationKind.Regex; def.Regex = CompileRegex(i, pat, false); break;
            case "~*": def.Kind = LocationKind.Regex; def.Regex = CompileRegex(i, pat, true); break;
            case "":
                if (pat.StartsWith('@'))
                {
                    if (i.Scope.Kind != ContextKind.Server) throw i.Error("named locations are only allowed at server level");
                    def.Kind = LocationKind.Named;
                }
                else def.Kind = LocationKind.Prefix;
                break;
            default: throw i.Error($"invalid location modifier \"{mod}\"");
        }
        if ((def.Kind is LocationKind.Exact or LocationKind.Prefix or LocationKind.PrefixNoRegex) && !pat.StartsWith('/'))
            throw i.Error($"location \"{pat}\" must start with \"/\"");
    }

    /// <summary>Linear-time engine when the pattern allows it; otherwise backtracking with a hard timeout.</summary>
    internal static Regex CompileRegex(DirectiveInvocation i, string pattern, bool ignoreCase)
    {
        var opts = RegexOptions.CultureInvariant | (ignoreCase ? RegexOptions.IgnoreCase : 0);
        try { return new Regex(pattern, opts | RegexOptions.NonBacktracking); }
        catch (NotSupportedException) { }
        catch (ArgumentException e) { throw i.Error($"invalid regex \"{pattern}\": {e.Message}"); }
        try { return new Regex(pattern, opts, TimeSpan.FromMilliseconds(50)); }
        catch (ArgumentException e) { throw i.Error($"invalid regex \"{pattern}\": {e.Message}"); }
    }

    // ---------------- listen / server_name ----------------

    private static void Listen(DirectiveInvocation i)
    {
        var a = i.Args[0];
        EndPoint ep;
        bool wildcard = false;
        if (a.StartsWith("unix:", StringComparison.Ordinal))
        {
            if (a.Length <= 5) throw i.Error("empty unix socket path");
            ep = new UnixDomainSocketEndPoint(a[5..]);
        }
        else if (a.StartsWith("tunnel:", StringComparison.Ordinal))
        {
            // Requests arrive over connections we dial out (see the "tunnel" block). Nothing is bound, and the inner
            // protocol is plain HTTP/1.1 inside the tunnel's TLS: none of the socket options apply.
            if (a.Length <= 7) throw i.Error("empty tunnel name");
            for (int k = 1; k < i.Args.Length; k++)
                if (i.Args[k] is not ("default_server" or "default")) throw i.Error($"parameter \"{i.Args[k]}\" doesn't apply to a tunnel");
            ep = new TunnelEndPoint(a[7..]);
        }
        else ep = ParseInet(i, a, out wildcard);

        bool ssl = false, def = false, reusePort = false, proxyProtocol = false;
        int backlog = 511;
        for (int k = 1; k < i.Args.Length; k++)
        {
            var o = i.Args[k];
            if (o == "ssl") ssl = true;
            else if (o is "default_server" or "default") def = true;
            else if (o.StartsWith("backlog=", StringComparison.Ordinal))
            {
                if (!int.TryParse(o.AsSpan(8), out backlog) || backlog < 1) throw i.Error($"invalid backlog \"{o}\"");
            }
            else if (o == "reuseport")
            {
                // Opt-in only: lets any same-user socket share this port and receive a slice of its connections.
                if (!(OperatingSystem.IsLinux() || OperatingSystem.IsMacOS() || OperatingSystem.IsFreeBSD())) throw i.Error("\"reuseport\" is not supported on this platform");
                if (ep is UnixDomainSocketEndPoint) throw i.Error("\"reuseport\" does not apply to unix sockets");
                reusePort = true;
            }
            else if (o == "proxy_protocol") proxyProtocol = true;
            else if (o is "deferred" or "http2" or "fastopen" || o.StartsWith("so_keepalive", StringComparison.Ordinal) || o.StartsWith("ipv6only", StringComparison.Ordinal))
                continue; // accepted for compatibility; no effect
            else throw i.Error($"invalid parameter \"{o}\"");
        }
        var sc = i.Conf<ServerConf>();
        var spec = new ListenSpec(ep, wildcard, ssl, def, backlog, reusePort, i.Source, proxyProtocol);
        foreach (var l in sc.Listens) if (l.Key == spec.Key) throw i.Error($"duplicate listen {spec.Key}");
        sc.Listens.Add(spec);
    }

    internal static IPEndPoint ParseInet(DirectiveInvocation i, string a, out bool wildcard)
    {
        string host;
        int port = 80;
        if (a.StartsWith('['))
        {
            int close = a.IndexOf(']');
            if (close < 0) throw i.Error($"invalid address \"{a}\"");
            host = a[1..close];
            var rest = a.AsSpan(close + 1);
            if (!rest.IsEmpty && (rest[0] != ':' || !int.TryParse(rest[1..], out port))) throw i.Error($"invalid port in \"{a}\"");
        }
        else if (int.TryParse(a, out var p)) { host = "*"; port = p; }
        else
        {
            int colon = a.LastIndexOf(':');
            host = colon < 0 ? a : a[..colon];
            if (colon >= 0 && !int.TryParse(a.AsSpan(colon + 1), out port)) throw i.Error($"invalid port in \"{a}\"");
        }
        if (port is < 0 or > 65535) throw i.Error($"invalid port in \"{a}\"");
        IPAddress addr;
        if (host is "*" or "") addr = IPAddress.Any;
        else if (host == "localhost") addr = IPAddress.Loopback;
        else if (!IPAddress.TryParse(host, out addr!)) throw i.Error($"host \"{host}\" must be an IP literal, \"*\" or \"localhost\"");
        wildcard = addr.Equals(IPAddress.Any) || addr.Equals(IPAddress.IPv6Any);
        return new IPEndPoint(addr, port);
    }

    private static void ServerName(DirectiveInvocation i)
    {
        var sc = i.Conf<ServerConf>();
        foreach (var n in i.Args)
        {
            if (n.StartsWith('~'))
            {
                _ = CompileRegex(i, n[1..], true);
                sc.Names.Add(n);
                continue;
            }
            if (n.Length > 0 && n != "_" && RequestParser.NormalizeHost(n.Replace("*", "x")) is null) throw i.Error($"invalid server name \"{n}\"");
            int stars = n.Count(c => c == '*');
            if (stars > 1 || (stars == 1 && !n.StartsWith("*.", StringComparison.Ordinal) && !n.EndsWith(".*", StringComparison.Ordinal)))
                throw i.Error($"invalid wildcard server name \"{n}\"");
            sc.Names.Add(n.ToLowerInvariant());
        }
    }

    // ---------------- files ----------------

    private void Root(DirectiveInvocation i)
    {
        var c = i.Conf<HttpCoreConf>();
        if (c.Alias is not null) throw i.Error("\"root\" and \"alias\" are mutually exclusive");
        c.Root = PathValue(i, i.Args[0], out c.RootBase);
    }

    private void Alias(DirectiveInvocation i)
    {
        var c = i.Conf<HttpCoreConf>();
        if (c.Root is not null) throw i.Error("\"root\" and \"alias\" are mutually exclusive");
        c.Alias = PathValue(i, i.Args[0], out c.AliasBase);
        c.AliasOwner = i.Scope;
    }

    /// <summary>Compile a root/alias value; relative constant paths resolve against the config directory.</summary>
    private ComplexValue PathValue(DirectiveInvocation i, string raw, out string? baseDir)
    {
        var v = i.Compile(raw);
        if (v.Constant is { } k)
        {
            var full = Path.GetFullPath(Path.IsPathRooted(k) ? k : Path.Combine(prefix, k));
            if (k.EndsWith('/') && !full.EndsWith(Path.DirectorySeparatorChar)) full += Path.DirectorySeparatorChar;
            baseDir = full;
            return new ComplexValue(full, [new(full, null)]);
        }
        // Variable path: containment is checked against its constant leading directory.
        int dollar = raw.IndexOf('$');
        int slash = raw.LastIndexOf('/', Math.Max(dollar - 1, 0));
        baseDir = slash > 0 ? Path.GetFullPath(Path.IsPathRooted(raw) ? raw[..slash] : Path.Combine(prefix, raw[..slash])) : null;
        return v;
    }

    private static void TryFiles(DirectiveInvocation i)
    {
        var files = new ComplexValue[i.Args.Length - 1];
        for (int k = 0; k < files.Length; k++) files[k] = i.Compile(i.Args[k]);
        var last = i.Args[^1];
        TryFilesSpec spec;
        if (last.StartsWith('='))
        {
            if (!int.TryParse(last.AsSpan(1), out var code) || code is < 100 or > 599) throw i.Error($"invalid code \"{last}\"");
            spec = new TryFilesSpec(files, null, code);
        }
        else spec = new TryFilesSpec(files, i.Compile(last), 0);
        i.Conf<HttpCoreConf>().TryFiles = spec;
    }

    private static void ErrorPageDirective(DirectiveInvocation i)
    {
        var c = i.Conf<HttpCoreConf>();
        // A block that declares its own error_page drops the inherited set (nginx semantics).
        c.ErrorPages ??= new Dictionary<int, ErrorPage>();
        int over = -1;
        int n = i.Args.Length - 1;
        ComplexValue? uri = null;
        if (i.Args[^1] == "=444")
        {
            // httpgrl shorthand: "error_page 400 403 =444;" closes the connection without a response.
            over = HandlerResult.DropStatus;
        }
        else uri = i.Compile(i.Args[^1]);
        if (uri is not null && i.Args[n - 1].StartsWith('='))
        {
            var o = i.Args[n - 1].AsSpan(1);
            over = o.IsEmpty ? 0 : int.TryParse(o, out var oc) && oc is >= 100 and <= 599 ? oc : throw i.Error($"invalid response code \"{i.Args[n - 1]}\"");
            n--;
        }
        if (n < 1) throw i.Error("no status codes");
        for (int k = 0; k < n; k++)
        {
            if (!int.TryParse(i.Args[k], out var code) || code is < 300 or > 599 || code == HandlerResult.DropStatus) throw i.Error($"invalid code \"{i.Args[k]}\"");
            c.ErrorPages[code] = new ErrorPage(uri, over);
        }
    }

    private static void Types(DirectiveInvocation i)
    {
        var c = i.Conf<HttpCoreConf>();
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var st in i.RawChildren!)
        {
            if (st.Args.Length == 0) throw new ConfigException($"no extensions for type \"{st.Name}\"", st.Source);
            foreach (var ext in st.Args) map[ext] = st.Name;
        }
        c.Types = map;
        c.TypesLookup = map.GetAlternateLookup<ReadOnlySpan<char>>();
    }

    internal static readonly Dictionary<string, string> BuiltinTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["html"] = "text/html", ["htm"] = "text/html", ["css"] = "text/css", ["js"] = "text/javascript",
        ["mjs"] = "text/javascript", ["json"] = "application/json", ["txt"] = "text/plain", ["xml"] = "text/xml",
        ["png"] = "image/png", ["jpg"] = "image/jpeg", ["jpeg"] = "image/jpeg", ["gif"] = "image/gif",
        ["svg"] = "image/svg+xml", ["ico"] = "image/x-icon", ["webp"] = "image/webp", ["avif"] = "image/avif",
        ["woff"] = "font/woff", ["woff2"] = "font/woff2", ["wasm"] = "application/wasm", ["pdf"] = "application/pdf",
        ["mp4"] = "video/mp4", ["webm"] = "video/webm", ["mp3"] = "audio/mpeg", ["zip"] = "application/zip",
    };
    internal static readonly Dictionary<string, string>.AlternateLookup<ReadOnlySpan<char>> BuiltinLookup = BuiltinTypes.GetAlternateLookup<ReadOnlySpan<char>>();

    // ---------------- variables ----------------

    private static void RegisterVariables(IModuleRegistry r)
    {
        r.AddVariable("dollar", _ => "$");
        r.AddVariable("uri", c => c.Request.Path);
        r.AddVariable("document_uri", c => c.Request.Path);
        r.AddVariable("request_uri", c => c.Request.RawTarget);
        r.AddVariable("args", c => c.Request.Query);
        r.AddVariable("query_string", c => c.Request.Query);
        r.AddVariable("is_args", c => c.Request.Query.Length > 0 ? "?" : "");
        r.AddVariable("request_method", c => c.Request.Method);
        r.AddVariable("server_protocol", c => c.Request.Version == HttpVersion.Http11 ? "HTTP/1.1" : "HTTP/1.0");
        r.AddVariable("scheme", c => c.Connection.IsTls ? "https" : "http");
        r.AddVariable("https", c => c.Connection.IsTls ? "on" : "");
        r.AddVariable("host", c => c.Request.Host.Length > 0 ? c.Request.Host : ((HttpContextImpl)c).ServerRt.PrimaryName);
        r.AddVariable("server_name", c => ((HttpContextImpl)c).ServerRt.PrimaryName);
        r.AddVariable("remote_addr", c => c.Connection.RemoteAddress);
        r.AddVariable("binary_remote_addr", c => c.Connection.Remote is System.Net.IPEndPoint ip ? System.Text.Encoding.Latin1.GetString(ip.Address.GetAddressBytes()) : "");
        r.AddVariable("remote_net", c => c.Connection.RemoteNet);
        r.AddVariable("proxy_protocol_addr", c => c.Connection.ProxySource?.Address.ToString());
        r.AddVariable("proxy_protocol_port", c => c.Connection.ProxySource?.Port.ToString(System.Globalization.CultureInfo.InvariantCulture));
        r.AddVariable("proxy_protocol_server_addr", c => c.Connection.ProxyDestination?.Address.ToString());
        r.AddVariable("proxy_protocol_server_port", c => c.Connection.ProxyDestination?.Port.ToString(System.Globalization.CultureInfo.InvariantCulture));
        r.AddVariable("remote_port", c => c.Connection.RemotePort.ToString(System.Globalization.CultureInfo.InvariantCulture));
        r.AddVariable("server_addr", c => c.Connection.LocalAddress);
        r.AddVariable("server_port", c => c.Connection.LocalPort.ToString(System.Globalization.CultureInfo.InvariantCulture));
        r.AddVariable("content_length", c => c.Request.Headers.Get("Content-Length"));
        r.AddVariable("content_type", c => c.Request.Headers.Get("Content-Type"));
        r.AddVariable("document_root", c => ((HttpContextImpl)c).DocumentRoot());
        r.AddVariable("request_filename", c => ((HttpContextImpl)c).MapPath(c.Request.Path));
        r.AddVariable("status", c => c.Response.Status.ToString(System.Globalization.CultureInfo.InvariantCulture));
        r.AddVariable("body_bytes_sent", c => c.Response.BodyBytesSent.ToString(System.Globalization.CultureInfo.InvariantCulture));
        r.AddVariable("request_time", c => c.Elapsed.TotalSeconds.ToString("0.000", System.Globalization.CultureInfo.InvariantCulture));
        r.AddVariable("request_id", c => c.Request.Id);
        r.AddVariable("connection", c => c.Connection.Id.ToString(System.Globalization.CultureInfo.InvariantCulture));
        r.AddVariable("connection_requests", c => c.Connection.Requests.ToString(System.Globalization.CultureInfo.InvariantCulture));
        r.AddVariable("msec", _ => (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0).ToString("0.000", System.Globalization.CultureInfo.InvariantCulture));
        r.AddVariable("time_iso8601", _ => DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:sszzz", System.Globalization.CultureInfo.InvariantCulture));
        r.AddVariablePrefix("http_", (c, s) => c.Request.Headers.Get(s.Replace('_', '-')));
        r.AddVariablePrefix("sent_http_", (c, s) => c.Response.Headers.Get(s.Replace('_', '-')));
        r.AddVariablePrefix("arg_", (c, s) => QueryArg(c.Request.Query, s));
        r.AddVariablePrefix("cookie_", (c, s) => Cookie(c.Request.Headers.Get("Cookie"), s));
    }

    internal static string? QueryArg(string query, string name)
    {
        foreach (var range in query.AsSpan().Split('&'))
        {
            var kv = query.AsSpan()[range];
            int eq = kv.IndexOf('=');
            var k = eq < 0 ? kv : kv[..eq];
            if (k.Equals(name, StringComparison.OrdinalIgnoreCase)) return eq < 0 ? "" : kv[(eq + 1)..].ToString();
        }
        return null;
    }

    internal static string? Cookie(string? header, string name)
    {
        if (header is null) return null;
        foreach (var range in header.AsSpan().Split(';'))
        {
            var kv = header.AsSpan()[range].Trim(' ');
            int eq = kv.IndexOf('=');
            if (eq > 0 && kv[..eq].SequenceEqual(name)) return kv[(eq + 1)..].ToString();
        }
        return null;
    }
}
