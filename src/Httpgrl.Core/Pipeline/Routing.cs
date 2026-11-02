using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Httpgrl.Core.Modules;

namespace Httpgrl.Core.Pipeline;

internal static class PathCmp
{
    /// <summary>Location matching must agree with the filesystem, or "/SECRET" would dodge "location /secret".</summary>
    public static readonly StringComparison Mode = OperatingSystem.IsLinux() || OperatingSystem.IsFreeBSD() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
    public static readonly StringComparer Comparer = Mode == StringComparison.Ordinal ? StringComparer.Ordinal : StringComparer.OrdinalIgnoreCase;
}

internal sealed class LocationRt(IConfigScope scope, LocationDef? def, string name)
{
    public readonly IConfigScope Scope = scope;
    /// <summary>Null for the implicit server-level location.</summary>
    public readonly LocationDef? Def = def;
    public readonly string Name = name;
    public readonly HttpCoreConf Core = scope.Get<HttpCoreConf>();
    public readonly HttpHandler? Exclusive = scope.Get<LocationHandlerConf>().Handler;
    public LocationTree? Children;
    /// <summary>Pattern length the alias replaces (from the declaring location), or -1 for regex/whole replacement.</summary>
    public int AliasPrefixLength = -1;
}

internal sealed class LocationTree
{
    private readonly Dictionary<string, LocationRt> _exact = new(PathCmp.Comparer);
    private readonly List<LocationRt> _prefix = new();
    private readonly List<LocationRt> _regex = new();

    public bool IsEmpty => _exact.Count == 0 && _prefix.Count == 0 && _regex.Count == 0;

    public void Add(LocationRt loc)
    {
        var d = loc.Def!;
        switch (d.Kind)
        {
            case LocationKind.Exact:
                if (!_exact.TryAdd(d.Pattern, loc)) throw new ConfigException($"duplicate location \"= {d.Pattern}\"", loc.Scope.Source);
                break;
            case LocationKind.Prefix or LocationKind.PrefixNoRegex:
                foreach (var p in _prefix)
                    if (string.Equals(p.Def!.Pattern, d.Pattern, PathCmp.Mode)) throw new ConfigException($"duplicate location \"{d.Pattern}\"", loc.Scope.Source);
                _prefix.Add(loc);
                _prefix.Sort((a, b) => b.Def!.Pattern.Length.CompareTo(a.Def!.Pattern.Length));
                break;
            case LocationKind.Regex:
                _regex.Add(loc);
                break;
        }
    }

    /// <summary>nginx order: exact; longest prefix (stop if ^~); first matching regex; else the longest prefix.</summary>
    public LocationRt? Find(string path, out Match? match, out bool final)
    {
        match = null;
        final = true;
        if (_exact.TryGetValue(path, out var exact)) return exact;

        LocationRt? best = null;
        var prefixes = _prefix;
        for (int i = 0; i < prefixes.Count; i++)
        {
            if (path.StartsWith(prefixes[i].Def!.Pattern, PathCmp.Mode)) { best = prefixes[i]; break; }
        }
        if (best is not null)
        {
            if (best.Children is { } kids)
            {
                var inner = kids.Find(path, out var im, out var innerFinal);
                if (inner is not null)
                {
                    if (innerFinal) { match = im; return inner; }
                    best = inner;
                }
            }
            if (best.Def!.Kind == LocationKind.PrefixNoRegex) return best;
        }

        var regexes = _regex;
        for (int i = 0; i < regexes.Count; i++)
        {
            Match m;
            try { m = regexes[i].Def!.Regex!.Match(path); }
            catch (RegexMatchTimeoutException) { continue; }
            if (!m.Success) continue;
            match = m;
            var r = regexes[i];
            if (r.Children is { } kids)
            {
                var inner = kids.Find(path, out var im, out _);
                if (inner is not null) { if (im is not null) match = im; return inner; }
            }
            return r;
        }
        final = false;
        return best;
    }
}

internal sealed class ServerRt
{
    public readonly IConfigScope Scope;
    public readonly LocationRt Root;
    public readonly Dictionary<string, LocationRt> Named = new(StringComparer.Ordinal);
    public readonly string[] Names;
    public readonly string PrimaryName;
    public readonly SslServerAuthenticationOptions? Tls;
    public readonly ClientAuth? ClientAuth;

    public ServerRt(IConfigScope scope)
    {
        Scope = scope;
        Root = new LocationRt(scope, null, "(server)");
        Names = scope.Get<ServerConf>().Names.ToArray();
        PrimaryName = Array.Find(Names, n => !n.StartsWith('~') && !n.Contains('*')) ?? "";
        Tls = scope.Get<SslConf>().Options;
        ClientAuth = scope.Get<SslConf>().ClientAuth;
    }

    public LocationRt Find(string path, out Match? match)
    {
        match = null;
        return Root.Children?.Find(path, out match, out _) ?? Root;
    }
}

internal sealed class VirtualHosts
{
    private readonly Dictionary<string, ServerRt> _exact = new(StringComparer.Ordinal);
    private readonly List<(string Suffix, ServerRt S)> _leading = new();   // "*.example.com" -> ".example.com"
    private readonly List<(string Prefix, ServerRt S)> _trailing = new();  // "www.example.*" -> "www.example."
    private readonly List<(Regex R, ServerRt S)> _regex = new();
    public ServerRt Default { get; private set; } = null!;
    public readonly List<ServerRt> Servers = new();

    public void Add(ServerRt s, bool isDefault, SourceLocation src, ILogger log)
    {
        if (Servers.Contains(s)) return;
        Servers.Add(s);
        if (isDefault)
        {
            if (_explicitDefault) throw new ConfigException("duplicate default server", src);
            Default = s;
            _explicitDefault = true;
        }
        else Default ??= s;

        foreach (var name in s.Names)
        {
            if (name.Length == 0 || name == "_") continue;
            if (name[0] == '~') { _regex.Add((new Regex(name[1..], RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(50)), s)); continue; }
            if (name.StartsWith("*.", StringComparison.Ordinal)) _leading.Add((name[1..], s));
            else if (name.EndsWith(".*", StringComparison.Ordinal)) _trailing.Add((name[..^1], s));
            else if (name[0] == '.') { TryExact(name[1..], s, log, src); _leading.Add((name, s)); }
            else TryExact(name, s, log, src);
        }
        _leading.Sort((a, b) => b.Suffix.Length.CompareTo(a.Suffix.Length));
        _trailing.Sort((a, b) => b.Prefix.Length.CompareTo(a.Prefix.Length));
    }

    private bool _explicitDefault;

    private void TryExact(string name, ServerRt s, ILogger log, SourceLocation src)
    {
        if (!_exact.TryAdd(name, s)) log.Warn("conflicting server name, ignored", new("name", name), new("at", src.ToString()));
    }

    public ServerRt Resolve(string? host)
    {
        if (string.IsNullOrEmpty(host)) return Default;
        if (_exact.TryGetValue(host, out var s)) return s;
        foreach (var (suffix, srv) in _leading)
            if (host.Length > suffix.Length && host.EndsWith(suffix, StringComparison.Ordinal)) return srv;
        foreach (var (prefix, srv) in _trailing)
            if (host.Length > prefix.Length && host.StartsWith(prefix, StringComparison.Ordinal)) return srv;
        foreach (var (re, srv) in _regex)
        {
            try { if (re.IsMatch(host)) return srv; }
            catch (RegexMatchTimeoutException) { }
        }
        return Default;
    }
}

/// <summary>One bound socket and the virtual hosts reachable through it.</summary>
internal sealed class ListenBinding(EndPoint endPoint, bool ssl, int backlog, bool reusePort)
{
    public readonly EndPoint EndPoint = endPoint;
    public readonly bool Ssl = ssl;
    public readonly int Backlog = backlog;
    public readonly bool ReusePort = reusePort;
    public VirtualHosts Hosts = new();
    /// <summary>When bound to a wildcard address: servers listening on specific local addresses of the same port.</summary>
    public Dictionary<IPAddress, VirtualHosts>? ByAddress;

    public VirtualHosts For(EndPoint? local)
    {
        if (ByAddress is not null && local is IPEndPoint ip)
        {
            var a = ip.Address.IsIPv4MappedToIPv6 ? ip.Address.MapToIPv4() : ip.Address;
            if (ByAddress.TryGetValue(a, out var vh)) return vh;
        }
        return Hosts;
    }

    public override string ToString() => EndPoint switch
    {
        IPEndPoint ip when ip.AddressFamily == AddressFamily.InterNetworkV6 => $"[{ip.Address}]:{ip.Port}",
        _ => EndPoint.ToString() ?? "",
    };
}

internal static class RoutingBuilder
{
    public static List<ListenBinding> Build(IConfigScope root, ILogger log)
    {
        var http = root.Children.FirstOrDefault(c => c.Kind == ContextKind.Http)
            ?? throw new ConfigException("no \"http\" block", root.Source);

        var groups = new Dictionary<string, (ListenSpec Spec, VirtualHosts Hosts)>();
        foreach (var scope in http.Children)
        {
            if (scope.Kind != ContextKind.Server) continue;
            var srv = new ServerRt(scope);
            var tree = BuildTree(srv, scope, null);
            if (tree is not null) srv.Root.Children = tree;
            foreach (var l in scope.Get<ServerConf>().Listens)
            {
                if (!groups.TryGetValue(l.Key, out var g))
                {
                    g = (l, new VirtualHosts());
                    groups[l.Key] = g;
                }
                else if (g.Spec.Ssl != l.Ssl) throw new ConfigException($"conflicting \"ssl\" parameter for {l.Key}", l.Source);
                else if (g.Spec.ReusePort != l.ReusePort) throw new ConfigException($"conflicting \"reuseport\" parameter for {l.Key}", l.Source);
                g.Hosts.Add(srv, l.DefaultServer, l.Source, log);
            }
        }
        if (groups.Count == 0) throw new ConfigException("no \"server\" blocks in \"http\"", http.Source);

        // Bind wildcard addresses once; specific addresses on the same port/family become sub-tables.
        var bindings = new List<ListenBinding>();
        var wild = new Dictionary<(AddressFamily, int), ListenBinding>();
        foreach (var (spec, hosts) in groups.Values)
        {
            if (spec.EndPoint is IPEndPoint ip && spec.IsWildcard)
            {
                var b = new ListenBinding(spec.EndPoint, spec.Ssl, spec.Backlog, spec.ReusePort) { Hosts = hosts };
                wild[(ip.AddressFamily, ip.Port)] = b;
                bindings.Add(b);
            }
        }
        foreach (var (spec, hosts) in groups.Values)
        {
            if (spec.IsWildcard) continue;
            if (spec.EndPoint is IPEndPoint ip && ip.Port != 0 && wild.TryGetValue((ip.AddressFamily, ip.Port), out var w))
            {
                if (w.Ssl != spec.Ssl) throw new ConfigException($"conflicting \"ssl\" parameter for port {ip.Port}", spec.Source);
                if (w.ReusePort != spec.ReusePort) throw new ConfigException($"conflicting \"reuseport\" parameter for port {ip.Port}", spec.Source);
                (w.ByAddress ??= new())[ip.Address] = hosts;
                continue;
            }
            bindings.Add(new ListenBinding(spec.EndPoint, spec.Ssl, spec.Backlog, spec.ReusePort) { Hosts = hosts });
        }
        return bindings;
    }

    private static LocationTree? BuildTree(ServerRt srv, IConfigScope parent, LocationRt? parentLoc)
    {
        LocationTree? tree = null;
        foreach (var child in parent.Children)
        {
            if (child.Kind != ContextKind.Location) continue;
            var def = child.Get<LocationDef>();
            var loc = new LocationRt(child, def, Describe(def));
            if (def.Kind == LocationKind.Named)
            {
                if (!srv.Named.TryAdd(def.Pattern, loc)) throw new ConfigException($"duplicate location \"{def.Pattern}\"", child.Source);
            }
            else
            {
                if (parentLoc?.Def is { } pd)
                {
                    if (pd.Kind == LocationKind.Exact) throw new ConfigException($"location \"{def.Pattern}\" cannot be inside the exact location \"{pd.Pattern}\"", child.Source);
                    if (pd.Kind is LocationKind.Prefix or LocationKind.PrefixNoRegex && def.Kind != LocationKind.Regex && !def.Pattern.StartsWith(pd.Pattern, PathCmp.Mode))
                        throw new ConfigException($"location \"{def.Pattern}\" is outside location \"{pd.Pattern}\"", child.Source);
                }
                (tree ??= new LocationTree()).Add(loc);
            }
            ResolveAlias(loc);
            var kids = BuildTree(srv, child, loc);
            if (kids is not null) loc.Children = kids;
        }
        return tree;
    }

    private static void ResolveAlias(LocationRt loc)
    {
        var core = loc.Core;
        if (core.Alias is null) return;
        var owner = core.AliasOwner?.Get<LocationDef>();
        if (owner is null) return;
        if (owner.Kind == LocationKind.Named) throw new ConfigException("\"alias\" is not allowed in named locations", loc.Scope.Source);
        loc.AliasPrefixLength = owner.Kind == LocationKind.Regex ? -1 : owner.Pattern.Length;
    }

    private static string Describe(LocationDef d) => d.Kind switch
    {
        LocationKind.Exact => "= " + d.Pattern,
        LocationKind.PrefixNoRegex => "^~ " + d.Pattern,
        LocationKind.Regex => (d.Regex!.Options.HasFlag(RegexOptions.IgnoreCase) ? "~* " : "~ ") + d.Pattern,
        _ => d.Pattern,
    };
}
