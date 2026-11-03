using System.Text.RegularExpressions;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Httpgrl.Modules.Proxy;

public sealed class ProxyConf : ScopeConfig<ProxyConf>
{
    // Location-only (not inherited).
    public string? Pass;
    public SourceLocation PassSource;
    public string[] LocationArgs = [];
    internal ProxyTarget? Target;
    /// <summary>
    /// proxy_pass with variables: everything after the scheme, evaluated per request and split at the first '/'
    /// (as nginx does). The authority must name an upstream block; a URI part replaces the request URI.
    /// </summary>
    internal ComplexValue? DynUrl;
    internal bool DynTls;
    internal Dictionary<string, ProxyTarget>? DynTargets;

    // Inherited.
    public List<(string Name, ComplexValue Value)>? SetHeaders; // a level that sets any replaces the inherited list
    public List<string>? HideHeaders;
    public int? HttpVersion, ConnectTimeout, SendTimeout, ReadTimeout, BufferSize, NextUpstreamTries;
    public bool? InterceptErrors, Upgrade, RawUri, SslVerify, SslServerName, BufferingOn;
    public long? Buffers;
    public bool Buffering => BufferingOn ?? true;
    /// <summary>proxy_buffers total, in memory (nginx: 8 × 4k|8k before spilling to disk; nothing spills here).</summary>
    public long BuffersTotal => Buffers ?? 64 * 1024;
    public string? SslName;
    public X509Certificate2Collection? SslTrusted;
    public SslProtocols? SslProtocols;
    /// <summary>proxy_redirect specs as written (null: "default"; empty: "off"). A level with any replaces the inherited list.</summary>
    internal List<RedirectSpec>? Redirects;
    internal RedirectRule[] RedirectRules = [];

    public int Version => HttpVersion ?? 11;
    public int ConnectTimeoutMs => ConnectTimeout ?? 10_000;
    public int SendTimeoutMs => SendTimeout ?? 60_000;
    public int ReadTimeoutMs => ReadTimeout ?? 60_000;
    public int HeaderBufferSize => BufferSize ?? 8192;
    public bool UpgradeEnabled => Upgrade ?? true;

    protected override void Inherit(ProxyConf p)
    {
        SetHeaders ??= p.SetHeaders;
        HideHeaders ??= p.HideHeaders;
        HttpVersion ??= p.HttpVersion;
        ConnectTimeout ??= p.ConnectTimeout;
        SendTimeout ??= p.SendTimeout;
        ReadTimeout ??= p.ReadTimeout;
        BufferSize ??= p.BufferSize;
        NextUpstreamTries ??= p.NextUpstreamTries;
        InterceptErrors ??= p.InterceptErrors;
        Upgrade ??= p.Upgrade;
        RawUri ??= p.RawUri;
        SslVerify ??= p.SslVerify;
        SslServerName ??= p.SslServerName;
        SslName ??= p.SslName;
        SslTrusted ??= p.SslTrusted;
        SslProtocols ??= p.SslProtocols;
        Redirects ??= p.Redirects;
        BufferingOn ??= p.BufferingOn;
        Buffers ??= p.Buffers;
    }
}

public sealed class UpstreamConf : ScopeConfig<UpstreamConf>
{
    public string Name = "";
    public readonly List<UpstreamServerSpec> Servers = new();
    public int? KeepAlive, KeepAliveTimeout, KeepAliveRequests;
    internal HealthCheckSpec? HealthCheck;
    protected override void Inherit(UpstreamConf parent) { }
}

public sealed record UpstreamServerSpec(string Address, int Weight, int MaxFails, int FailTimeoutMs, bool Backup, bool Down, SourceLocation Source, bool Resolve = false);

/// <summary>
/// Reverse proxy (cf. ngx_http_proxy_module + ngx_http_upstream). HTTP/1.x to upstreams over TCP, TLS or
/// unix sockets; keep-alive pooling; passive health checks; Upgrade/WebSocket tunnelling on by default.
/// </summary>
public sealed class ProxyModule : IModule, IDisposable
{
    private readonly Func<string, CancellationToken, Task<IPAddress[]>> _resolve;
    private int _resolveIntervalMs = 30_000;
    private DnsRefresher? _refresher;

    public ProxyModule() : this(null) { }

    /// <summary>Tests substitute the resolver; production uses the system's.</summary>
    internal ProxyModule(Func<string, CancellationToken, Task<IPAddress[]>>? resolver) =>
        _resolve = resolver ?? ((host, ct) => Dns.GetHostAddressesAsync(host, ct));

    public static readonly ContextKind Upstream = new("upstream");
    public string Name => "http_proxy";

    internal static readonly object UpstreamAddrKey = new(), UpstreamStatusKey = new();

    public void Register(IModuleRegistry r)
    {
        var http = ContextKind.HttpAny;
        var up = new[] { Upstream };

        r.AddDirective(new() { Name = "upstream", Contexts = [ContextKind.Http], MinArgs = 1, MaxArgs = 1, Block = Upstream, Repeatable = true, Handler = i => i.Block!.Get<UpstreamConf>().Name = i.Args[0] });
        r.AddDirective(new() { Name = "server", Contexts = up, MinArgs = 1, MaxArgs = -1, Repeatable = true, Handler = UpstreamServer });
        r.AddDirective(new() { Name = "health_check", Contexts = up, MaxArgs = -1, Handler = HealthCheck });
        r.AddDirective(new() { Name = "keepalive", Contexts = up, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<UpstreamConf>().KeepAlive = i.Int(0) });
        r.AddDirective(new() { Name = "keepalive_timeout", Contexts = up, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<UpstreamConf>().KeepAliveTimeout = i.Millis(0) });
        r.AddDirective(new() { Name = "keepalive_requests", Contexts = up, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<UpstreamConf>().KeepAliveRequests = i.Int(0) });

        r.AddDirective(new() { Name = "proxy_pass", Contexts = [ContextKind.Location], MinArgs = 1, MaxArgs = 1, Handler = Pass });
        r.AddDirective(new()
        {
            Name = "proxy_set_header", Contexts = http, MinArgs = 2, MaxArgs = 2, Repeatable = true,
            Handler = i =>
            {
                var c = i.Conf<ProxyConf>();
                var name = i.Args[0];
                foreach (char ch in name) if (!HttpChars.IsToken(ch)) throw i.Error($"invalid header name \"{name}\"");
                if (name.Equals("Connection", StringComparison.OrdinalIgnoreCase) || name.Equals("Upgrade", StringComparison.OrdinalIgnoreCase))
                    return; // managed by the module (keep-alive / upgrade); accepted for nginx-config compatibility
                (c.SetHeaders ??= new()).Add((name, i.Compile(i.Args[1])));
            },
        });
        r.AddDirective(new()
        {
            Name = "upstream_resolve_interval", Contexts = [ContextKind.Http], MinArgs = 1, MaxArgs = 1,
            Handler = i => _resolveIntervalMs = i.Args[0] == "off" ? 0 : i.Millis(0) is var ms && ms >= 100 ? ms : throw i.Error("must be at least 100ms, or off"),
        });
        r.AddDirective(new() { Name = "proxy_buffering", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<ProxyConf>().BufferingOn = i.Flag(0) });
        r.AddDirective(new()
        {
            Name = "proxy_buffers", Contexts = http, MinArgs = 2, MaxArgs = 2,
            Handler = i =>
            {
                int n = i.Int(0);
                long size = i.Size(1);
                long total = n * size;
                if (n < 1 || size < 1024 || total > 64L << 20) throw i.Error("expected a count and a size of at least 1k, at most 64m in total");
                i.Conf<ProxyConf>().Buffers = total;
            },
        });
        foreach (var n in new[] { "proxy_busy_buffers_size", "proxy_max_temp_file_size", "proxy_temp_file_write_size", "proxy_temp_path",
                                  "proxy_cache", "proxy_cache_bypass", "proxy_no_cache", "proxy_cache_valid", "proxy_cache_key", "proxy_cache_methods", "proxy_cache_lock" })
            r.AddDirective(new() { Name = n, Contexts = http, MaxArgs = -1, Repeatable = true, Handler = i => _ignoredSeen.Add((i.Name, i.Source)) });
        r.AddDirective(new() { Name = "proxy_cache_path", Contexts = [ContextKind.Http], MaxArgs = -1, Repeatable = true, Handler = i => _ignoredSeen.Add((i.Name, i.Source)) });
        r.AddDirective(new() { Name = "proxy_redirect", Contexts = http, MinArgs = 1, MaxArgs = 2, Repeatable = true, Handler = Redirect });
        r.AddDirective(new() { Name = "proxy_hide_header", Contexts = http, MinArgs = 1, MaxArgs = 1, Repeatable = true, Handler = i => (i.Conf<ProxyConf>().HideHeaders ??= new()).Add(i.Args[0]) });
        r.AddDirective(new()
        {
            Name = "proxy_http_version", Contexts = http, MinArgs = 1, MaxArgs = 1,
            Handler = i => i.Conf<ProxyConf>().HttpVersion = i.Args[0] switch { "1.0" => 10, "1.1" => 11, _ => throw i.Error("expected 1.0 or 1.1") },
        });
        r.AddDirective(new() { Name = "proxy_connect_timeout", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<ProxyConf>().ConnectTimeout = Positive(i, i.Millis(0)) });
        r.AddDirective(new() { Name = "proxy_send_timeout", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<ProxyConf>().SendTimeout = Positive(i, i.Millis(0)) });
        r.AddDirective(new() { Name = "proxy_read_timeout", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<ProxyConf>().ReadTimeout = Positive(i, i.Millis(0)) });
        r.AddDirective(new()
        {
            Name = "proxy_buffer_size", Contexts = http, MinArgs = 1, MaxArgs = 1,
            Handler = i => { long v = i.Size(0); i.Conf<ProxyConf>().BufferSize = v is >= 1024 and <= 1 << 20 ? (int)v : throw i.Error("must be between 1k and 1m"); },
        });
        r.AddDirective(new() { Name = "proxy_next_upstream_tries", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<ProxyConf>().NextUpstreamTries = i.Int(0) });
        r.AddDirective(new() { Name = "proxy_intercept_errors", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<ProxyConf>().InterceptErrors = i.Flag(0) });
        r.AddDirective(new() { Name = "proxy_upgrade", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<ProxyConf>().Upgrade = i.Flag(0) });
        r.AddDirective(new() { Name = "proxy_pass_raw_uri", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<ProxyConf>().RawUri = i.Flag(0) });
        r.AddDirective(new() { Name = "proxy_ssl_verify", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<ProxyConf>().SslVerify = i.Flag(0) });
        r.AddDirective(new() { Name = "proxy_ssl_server_name", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<ProxyConf>().SslServerName = i.Flag(0) });
        r.AddDirective(new() { Name = "proxy_ssl_name", Contexts = http, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<ProxyConf>().SslName = i.Args[0] });
        r.AddDirective(new()
        {
            Name = "proxy_ssl_trusted_certificate", Contexts = http, MinArgs = 1, MaxArgs = 1,
            Handler = i =>
            {
                var pem = Encoding.ASCII.GetString(i.ReadFile(i.Args[0], 4 << 20));
                var col = new X509Certificate2Collection();
                try { col.ImportFromPem(pem); }
                catch (System.Security.Cryptography.CryptographicException e) { throw i.Error($"invalid PEM: {e.Message}"); }
                if (col.Count == 0) throw i.Error("no certificates found");
                i.Conf<ProxyConf>().SslTrusted = col;
            },
        });
        r.AddDirective(new()
        {
            Name = "proxy_ssl_protocols", Contexts = http, MinArgs = 1, MaxArgs = -1,
            Handler = i =>
            {
                SslProtocols p = 0;
                foreach (var a in i.Args)
                    p |= a switch { "TLSv1.2" => System.Security.Authentication.SslProtocols.Tls12, "TLSv1.3" => System.Security.Authentication.SslProtocols.Tls13, _ => throw i.Error($"unsupported protocol \"{a}\"") };
                i.Conf<ProxyConf>().SslProtocols = p;
            },
        });

        r.AddVariable("proxy_host", c => ProxyHandler.CurrentTarget(c)?.HostHeader);
        r.AddVariable("proxy_port", c => ProxyHandler.CurrentTarget(c)?.Port.ToString(System.Globalization.CultureInfo.InvariantCulture));
        r.AddVariable("proxy_add_x_forwarded_for", c =>
        {
            var xff = c.Request.Headers.Get("X-Forwarded-For");
            return string.IsNullOrEmpty(xff) ? c.Connection.RemoteAddress : xff + ", " + c.Connection.RemoteAddress;
        });
        r.AddVariable("upstream_addr", c => c.Items.TryGetValue(UpstreamAddrKey, out var v) ? v as string : null);
        r.AddVariable("upstream_status", c => c.Items.TryGetValue(UpstreamStatusKey, out var v) ? v as string : null);
    }

    private static int Positive(DirectiveInvocation i, int v) => v > 0 ? v : throw i.Error("must be positive");

    private static void UpstreamServer(DirectiveInvocation i)
    {
        int weight = 1, maxFails = 1, failTimeout = 10_000;
        bool backup = false, down = false, resolve = false;
        for (int k = 1; k < i.Args.Length; k++)
        {
            var a = i.Args[k];
            if (a.StartsWith("weight=", StringComparison.Ordinal) && int.TryParse(a.AsSpan(7), out weight) && weight is >= 1 and <= 1000) continue;
            if (a.StartsWith("max_fails=", StringComparison.Ordinal) && int.TryParse(a.AsSpan(10), out maxFails) && maxFails >= 0) continue;
            if (a.StartsWith("fail_timeout=", StringComparison.Ordinal) && ConfigValue.TryParseMillis(a.AsSpan(13), out failTimeout)) continue;
            if (a == "backup") { backup = true; continue; }
            if (a == "down") { down = true; continue; }
            if (a == "resolve") { resolve = true; continue; }
            throw i.Error($"invalid parameter \"{a}\"");
        }
        i.Conf<UpstreamConf>().Servers.Add(new UpstreamServerSpec(i.Args[0], weight, maxFails, failTimeout, backup, down, i.Source, resolve));
    }

    private static void HealthCheck(DirectiveInvocation i)
    {
        string uri = "/";
        string? host = null;
        int interval = 5000, timeout = 2000, fails = 1, passes = 1, min = 200, max = 399;
        foreach (var a in i.Args)
        {
            int eq = a.IndexOf('=');
            if (eq <= 0) throw i.Error($"invalid parameter \"{a}\"");
            var (k, v) = (a[..eq], a[(eq + 1)..]);
            switch (k)
            {
                case "uri":
                    if (!v.StartsWith('/') || v.Any(c => c <= ' ' || c == 0x7f)) throw i.Error($"invalid uri \"{v}\"");
                    uri = v;
                    break;
                case "host":
                    if (v.Length == 0 || v.Any(c => c <= ' ' || c == 0x7f || c == '/')) throw i.Error($"invalid host \"{v}\"");
                    host = v;
                    break;
                case "interval": interval = ConfigValue.TryParseMillis(v, out var iv) && iv >= 100 ? iv : throw i.Error("interval must be at least 100ms"); break;
                case "timeout": timeout = ConfigValue.TryParseMillis(v, out var tv) && tv > 0 ? tv : throw i.Error("invalid timeout"); break;
                case "fails": fails = int.TryParse(v, out var f) && f is >= 1 and <= 100 ? f : throw i.Error("fails must be 1..100"); break;
                case "passes": passes = int.TryParse(v, out var p) && p is >= 1 and <= 100 ? p : throw i.Error("passes must be 1..100"); break;
                case "status":
                    var parts = v.Split('-');
                    if (parts.Length is < 1 or > 2 || !int.TryParse(parts[0], out min) || !int.TryParse(parts[^1], out max) || min is < 100 or > 599 || max < min || max > 599)
                        throw i.Error($"invalid status \"{v}\"; expected e.g. 200 or 200-399");
                    break;
                default: throw i.Error($"invalid parameter \"{a}\"");
            }
        }
        i.Conf<UpstreamConf>().HealthCheck = new HealthCheckSpec(uri, interval, timeout, fails, passes, min, max, host);
    }

    private static void Pass(DirectiveInvocation i)
    {
        var c = i.Conf<ProxyConf>();
        var url = i.Args[0];
        if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            throw i.Error($"invalid URL prefix in \"{url}\"");
        if (url.Contains('$'))
        {
            // Variables may pick an upstream block by name (and set the whole URI), never an arbitrary host: a
            // variable fed by the request would otherwise make this an open proxy to anything the server can reach.
            bool tls = url.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
            var rest = url[(tls ? 8 : 7)..];
            if (rest.Length == 0 || rest[0] == '/') throw i.Error("no host in proxy_pass");
            c.DynTls = tls;
            c.DynUrl = i.Compile(rest);
        }
        c.Pass = url;
        c.PassSource = i.Source;
        c.LocationArgs = [.. i.Scope.Args];
        var h = i.Conf<LocationHandlerConf>();
        if (h.Handler is not null) throw i.Error($"location already handled by \"{h.Owner}\"");
        h.Owner = "proxy_pass";
        h.Handler = ctx => ProxyHandler.HandleAsync(ctx, c);
    }

    private static void Redirect(DirectiveInvocation i)
    {
        var c = i.Conf<ProxyConf>();
        var list = c.Redirects ??= new();
        if (i.Args is ["off"] or ["default"])
        {
            bool off = i.Args[0] == "off";
            if (off ? list.Count > 0 : list.Exists(s => s.Off)) throw i.Error("\"off\" can't be combined with other proxy_redirect rules");
            list.Add(new RedirectSpec(off, !off, null, null, null));
            return;
        }
        if (i.Args.Length != 2) throw i.Error("expected \"proxy_redirect redirect replacement;\", \"default\" or \"off\"");
        if (list.Exists(s => s.Off)) throw i.Error("\"off\" can't be combined with other proxy_redirect rules");
        var pattern = i.Args[0];
        Regex? re = null;
        if (pattern.StartsWith('~'))
        {
            bool ci = pattern.StartsWith("~*", StringComparison.Ordinal);
            var p = pattern[(ci ? 2 : 1)..];
            var opts = RegexOptions.CultureInvariant | (ci ? RegexOptions.IgnoreCase : RegexOptions.None);
            try { re = new Regex(p, opts | RegexOptions.NonBacktracking); }
            catch (NotSupportedException) { re = new Regex(p, opts, TimeSpan.FromMilliseconds(50)); }
        }
        list.Add(new RedirectSpec(false, false, re is null ? pattern : null, re, i.Compile(i.Args[1])));
    }

    public void Configure(IModuleSetup setup)
    {
        foreach (var (name, src) in _ignoredSeen)
            setup.Log.Warn(name.StartsWith("proxy_cache", StringComparison.Ordinal) || name == "proxy_no_cache"
                ? "directive ignored: there's no proxy cache (responses are never cached)"
                : "directive ignored: proxy_buffering is memory-only here (nothing is written to disk)", new("directive", name), new("at", src.ToString()));
        var groups = new Dictionary<string, UpstreamGroup>(StringComparer.OrdinalIgnoreCase);
        foreach (var scope in setup.ScopesOf(Upstream))
        {
            var u = scope.Get<UpstreamConf>();
            if (u.Servers.Count == 0) throw new ConfigException($"no servers in upstream \"{u.Name}\"", scope.Source);
            if (groups.ContainsKey(u.Name)) throw new ConfigException($"duplicate upstream \"{u.Name}\"", scope.Source);
            var servers = new List<UpstreamServer>();
            var resolvable = new List<ResolvableSpec>();
            foreach (var s in u.Servers)
            {
                if (Hostname(s.Address, 80, s.Source) is { } hp)
                    resolvable.Add(new ResolvableSpec(s.Address, hp.Host, hp.Port, s.Weight, s.MaxFails, s.FailTimeoutMs, s.Backup, s.Down));
                foreach (var ep in Resolve(s.Address, 80, s.Source, allowMissing: s.Resolve, setup.Log))
                    servers.Add(new UpstreamServer(ep, s.Address, s.Weight, s.MaxFails, s.FailTimeoutMs, s.Backup, s.Down));
            }
            if (servers.Count == 0 && resolvable.Count == 0) throw new ConfigException($"no servers in upstream \"{u.Name}\"", scope.Source);
            groups[u.Name] = new UpstreamGroup(u.Name, servers, u.KeepAlive ?? 32, u.KeepAliveTimeout ?? 60_000, u.KeepAliveRequests ?? 1000, [.. resolvable]);
        }

        var implicitGroups = new Dictionary<string, UpstreamGroup>(StringComparer.OrdinalIgnoreCase);
        foreach (var loc in setup.ScopesOf(ContextKind.Location))
        {
            if (!loc.TryGet<ProxyConf>(out var pc) || pc.Pass is null) continue;
            if (pc.DynUrl is not null)
            {
                if (groups.Count == 0) throw new ConfigException("proxy_pass with variables needs upstream blocks to choose from", pc.PassSource);
                pc.DynTargets = new Dictionary<string, ProxyTarget>(StringComparer.OrdinalIgnoreCase);
                foreach (var name in groups.Keys)
                    pc.DynTargets[name] = BuildTarget(pc, groups, implicitGroups, setup.Log, (pc.DynTls ? "https://" : "http://") + name);
                pc.RedirectRules = pc.Redirects is null ? [] : RedirectRules(pc, setup); // no "default" mapping for a variable URL
                continue;
            }
            pc.Target = BuildTarget(pc, groups, implicitGroups, setup.Log);
            pc.RedirectRules = RedirectRules(pc, setup);
        }
        _groups.AddRange(groups.Values);
        _groups.AddRange(implicitGroups.Values);

        // Health checks probe with the scheme/TLS settings of the (first) location that proxies to the group.
        var checkers = new Dictionary<UpstreamGroup, HealthChecker>();
        foreach (var scope in setup.ScopesOf(Upstream))
        {
            var u = scope.Get<UpstreamConf>();
            if (u.HealthCheck is null) continue;
            var g = groups[u.Name];
            ProxyTarget? first = null;
            foreach (var loc in setup.ScopesOf(ContextKind.Location))
            {
                if (!loc.TryGet<ProxyConf>(out var pc)) continue;
                if (pc.Target is { } t && t.Group == g) { first = t; break; }
                if (pc.DynTargets?.Values.FirstOrDefault(x => x.Group == g) is { } d) { first = d; break; }
            }
            if (first is null) continue; // nobody proxies to it
            checkers[g] = new HealthChecker(g, u.HealthCheck, first, setup.Log);
        }
        _checkers.AddRange(checkers.Values);
        if (checkers.Count > 0)
            Enrich(setup, t => checkers.TryGetValue(t.Group, out var hc) ? t with { Health = hc } : t);
        if (_resolveIntervalMs > 0 && _groups.Exists(g => g.Resolvable.Length > 0))
        {
            _refresher = new DnsRefresher(_groups.FindAll(g => g.Resolvable.Length > 0), _resolveIntervalMs, _resolve, setup.Log);
            Enrich(setup, t => t.Group.Resolvable.Length > 0 ? t with { Dns = _refresher } : t);
        }
    }

    private readonly List<UpstreamGroup> _groups = new();
    private readonly List<HealthChecker> _checkers = new();
    private readonly List<(string, SourceLocation)> _ignoredSeen = new();

    /// <summary>Apply <paramref name="f"/> to every target of every location (fixed and variable ones).</summary>
    private static void Enrich(IModuleSetup setup, Func<ProxyTarget, ProxyTarget> f)
    {
        foreach (var loc in setup.ScopesOf(ContextKind.Location))
        {
            if (!loc.TryGet<ProxyConf>(out var pc)) continue;
            if (pc.Target is { } t) pc.Target = f(t);
            if (pc.DynTargets is { } d)
                foreach (var k in d.Keys.ToArray()) d[k] = f(d[k]);
        }
    }

    /// <summary>
    /// "default" maps the proxy_pass URL to the location's prefix (nginx): with
    /// <c>location /one/ { proxy_pass http://app:8080/two/; }</c>, <c>http://app:8080/two/x</c> becomes <c>/one/x</c>.
    /// It only applies to prefix and exact locations; a regex or named location has no prefix to map to.
    /// </summary>
    private static RedirectRule[] RedirectRules(ProxyConf c, IModuleSetup setup)
    {
        var specs = c.Redirects ?? [new RedirectSpec(false, true, null, null, null)];
        var rules = new List<RedirectRule>();
        foreach (var s in specs)
        {
            if (s.Off) return [];
            if (!s.Default) { rules.Add(new RedirectRule(s.Prefix, s.Regex, s.Replacement!)); continue; }
            var args = c.LocationArgs;
            string? prefix = args switch
            {
                [var p] when !p.StartsWith('@') => p,
                ["^~" or "=", var p] => p,
                _ => null,
            };
            if (prefix is null) continue;
            var t = c.Target!;
            var from = c.Pass!;
            if (t.UriPart is null) { from += "/"; prefix = "/"; }
            rules.Add(new RedirectRule(from, null, new ComplexValue(prefix, [new ComplexValue.Part(prefix, null)])));
        }
        return rules.ToArray();
    }

    /// <summary>The configuration was replaced (reload) and its last connection is gone: close pooled upstream connections.</summary>
    public void Dispose()
    {
        _refresher?.Stop();
        foreach (var c in _checkers) c.Stop();
        foreach (var g in _groups) g.Retire();
    }

    private ProxyTarget BuildTarget(ProxyConf c, Dictionary<string, UpstreamGroup> groups, Dictionary<string, UpstreamGroup> implicitGroups, ILogger log, string? urlOverride = null)
    {
        var url = urlOverride ?? c.Pass!;
        var src = c.PassSource;
        bool tls = url.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        var rest = url[(tls ? 8 : 7)..];
        string authority;
        string? uriPart;
        if (rest.StartsWith("unix:", StringComparison.Ordinal))
        {
            // nginx form: http://unix:/path/to.sock:/optional/uri
            int colon = rest.IndexOf(':', 5);
            authority = colon < 0 ? rest : rest[..colon];
            uriPart = colon < 0 || colon + 1 >= rest.Length ? null : rest[(colon + 1)..];
            if (authority.Length <= 5) throw new ConfigException("empty unix socket path in proxy_pass", src);
        }
        else
        {
            int slash = rest.IndexOf('/');
            authority = slash < 0 ? rest : rest[..slash];
            uriPart = slash < 0 ? null : rest[slash..];
            if (authority.Length == 0) throw new ConfigException("no host in proxy_pass", src);
        }
        if (uriPart is not null && (uriPart.Contains('?') || uriPart.Contains('#'))) throw new ConfigException("query or fragment in proxy_pass URI is not supported", src);

        // Which part of the request path the URI part replaces.
        var a = c.LocationArgs;
        string? prefix = a.Length switch
        {
            1 when a[0].StartsWith('@') => null,
            1 when a[0].StartsWith('=') && a[0].Length > 1 => a[0][1..],
            1 => a[0],
            2 when a[0] is "=" or "^~" => a[1],
            _ => null,
        };
        if (uriPart is not null && prefix is null)
            throw new ConfigException("proxy_pass cannot have a URI part in a regex or named location", src);

        int defPort = tls ? 443 : 80;
        UpstreamGroup? group;
        string host;
        int port;
        if (authority.StartsWith("unix:", StringComparison.Ordinal))
        {
            host = "localhost";
            port = 0;
            var key = (tls ? "s:" : "") + authority;
            if (!implicitGroups.TryGetValue(key, out group))
                implicitGroups[key] = group = new UpstreamGroup(authority, [new UpstreamServer(new UnixDomainSocketEndPoint(authority[5..]), authority, 1, 1, 10_000, false, false)], 32, 60_000, 1000);
        }
        else
        {
            SplitHostPort(authority, defPort, src, out host, out port, out bool explicitPort);
            if (!explicitPort && groups.TryGetValue(authority, out group)) { }
            else
            {
                var key = (tls ? "s:" : "") + host + ":" + port;
                if (!implicitGroups.TryGetValue(key, out group))
                {
                    var servers = new List<UpstreamServer>();
                    foreach (var ep in Resolve(authority, defPort, src, allowMissing: false, log)) servers.Add(new UpstreamServer(ep, authority, 1, 1, 10_000, false, false));
                    ResolvableSpec[] res = Hostname(authority, defPort, src) is { } hp ? [new ResolvableSpec(authority, hp.Host, hp.Port, 1, 1, 10_000, false, false)] : [];
                    implicitGroups[key] = group = new UpstreamGroup(authority, servers, 32, 60_000, 1000, res);
                }
            }
        }

        SslClientAuthenticationOptions? ssl = null;
        if (tls) ssl = BuildSsl(c, c.SslName ?? host);
        return new ProxyTarget(group!, tls, authority.StartsWith("unix:", StringComparison.Ordinal) ? "localhost" : authority, port, uriPart, prefix, ssl);
    }

    private static SslClientAuthenticationOptions BuildSsl(ProxyConf c, string name)
    {
        bool verify = c.SslVerify ?? true;
        bool sni = c.SslServerName ?? true;
        var trusted = c.SslTrusted;
        return new SslClientAuthenticationOptions
        {
            TargetHost = sni ? name : "",
            EnabledSslProtocols = c.SslProtocols ?? (SslProtocols.Tls12 | SslProtocols.Tls13),
            ApplicationProtocols = [SslApplicationProtocol.Http11],
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            AllowRenegotiation = false,
            RemoteCertificateValidationCallback = (_, cert, chain, errors) =>
            {
                if (!verify) return true;
                if (cert is null) return false;
                var leaf = cert as X509Certificate2 ?? new X509Certificate2(cert);
                // Without SNI the platform can't name-check; do it ourselves against proxy_ssl_name.
                if (!sni) errors &= ~SslPolicyErrors.RemoteCertificateNameMismatch;
                if (!sni && !leaf.MatchesHostname(name)) return false;
                if (trusted is null) return errors == SslPolicyErrors.None;
                if ((errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None) return false;
                using var ch = new X509Chain();
                ch.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                ch.ChainPolicy.CustomTrustStore.AddRange(trusted);
                ch.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                if (chain is not null)
                    foreach (var el in chain.ChainElements) ch.ChainPolicy.ExtraStore.Add(el.Certificate);
                return ch.Build(leaf);
            },
        };
    }

    private static void SplitHostPort(string authority, int defPort, SourceLocation src, out string host, out int port, out bool explicitPort)
    {
        port = defPort;
        explicitPort = false;
        if (authority.StartsWith('['))
        {
            int close = authority.IndexOf(']');
            if (close < 0) throw new ConfigException($"invalid host \"{authority}\"", src);
            host = authority[1..close];
            if (close + 1 < authority.Length)
            {
                if (authority[close + 1] != ':' || !int.TryParse(authority.AsSpan(close + 2), out port)) throw new ConfigException($"invalid port in \"{authority}\"", src);
                explicitPort = true;
            }
        }
        else
        {
            int colon = authority.LastIndexOf(':');
            host = colon < 0 ? authority : authority[..colon];
            if (colon >= 0)
            {
                if (!int.TryParse(authority.AsSpan(colon + 1), out port)) throw new ConfigException($"invalid port in \"{authority}\"", src);
                explicitPort = true;
            }
        }
        if (port is < 1 or > 65535) throw new ConfigException($"invalid port in \"{authority}\"", src);
        if (host.Length == 0) throw new ConfigException($"no host in \"{authority}\"", src);
    }

    /// <summary>Resolved once at load (like nginx without a resolver); every address becomes a peer.</summary>
    /// <summary>Host and port when <paramref name="address"/> names a host (not an IP literal or unix socket).</summary>
    private static (string Host, int Port)? Hostname(string address, int defPort, SourceLocation src)
    {
        if (address.StartsWith("unix:", StringComparison.Ordinal)) return null;
        SplitHostPort(address, defPort, src, out var host, out var port, out _);
        return IPAddress.TryParse(host, out _) ? null : (host, port);
    }

    /// <summary>Load-time resolution. <paramref name="allowMissing"/> ("resolve"): start without addresses and keep trying.</summary>
    private IEnumerable<EndPoint> Resolve(string address, int defPort, SourceLocation src, bool allowMissing, ILogger log)
    {
        if (address.StartsWith("unix:", StringComparison.Ordinal)) return [new UnixDomainSocketEndPoint(address[5..])];
        SplitHostPort(address, defPort, src, out var host, out var port, out _);
        if (IPAddress.TryParse(host, out var ip)) return [new IPEndPoint(ip, port)];
        IPAddress[] addrs;
        string? why = null;
        try { addrs = _resolve(host, CancellationToken.None).GetAwaiter().GetResult(); }
        catch (SocketException e) { addrs = []; why = e.Message; }
        if (addrs.Length == 0)
        {
            if (!allowMissing) throw new ConfigException($"host not found in upstream \"{address}\"{(why is null ? "" : ": " + why)}", src);
            log.Warn("upstream host not found; starting without it and retrying", new("host", host), new("at", src.ToString()));
            return [];
        }
        return Array.ConvertAll(addrs, a => (EndPoint)new IPEndPoint(a, port));
    }
}

internal sealed record RedirectSpec(bool Off, bool Default, string? Prefix, Regex? Regex, ComplexValue? Replacement);
internal sealed record RedirectRule(string? Prefix, Regex? Regex, ComplexValue Replacement);

internal sealed record ProxyTarget(UpstreamGroup Group, bool Tls, string HostHeader, int Port, string? UriPart, string? LocationPrefix, SslClientAuthenticationOptions? Ssl)
{
    public DnsRefresher? Dns { get; init; }
    public HealthChecker? Health { get; init; }
}
