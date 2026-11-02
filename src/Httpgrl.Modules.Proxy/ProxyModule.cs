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

    // Inherited.
    public List<(string Name, ComplexValue Value)>? SetHeaders; // a level that sets any replaces the inherited list
    public List<string>? HideHeaders;
    public int? HttpVersion, ConnectTimeout, SendTimeout, ReadTimeout, BufferSize, NextUpstreamTries;
    public bool? InterceptErrors, Upgrade, RawUri, SslVerify, SslServerName;
    public string? SslName;
    public X509Certificate2Collection? SslTrusted;
    public SslProtocols? SslProtocols;

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
    }
}

public sealed class UpstreamConf : ScopeConfig<UpstreamConf>
{
    public string Name = "";
    public readonly List<UpstreamServerSpec> Servers = new();
    public int? KeepAlive, KeepAliveTimeout, KeepAliveRequests;
    protected override void Inherit(UpstreamConf parent) { }
}

public sealed record UpstreamServerSpec(string Address, int Weight, int MaxFails, int FailTimeoutMs, bool Backup, bool Down, SourceLocation Source);

/// <summary>
/// Reverse proxy (cf. ngx_http_proxy_module + ngx_http_upstream). HTTP/1.x to upstreams over TCP, TLS or
/// unix sockets; keep-alive pooling; passive health checks; Upgrade/WebSocket tunnelling on by default.
/// </summary>
public sealed class ProxyModule : IModule, IDisposable
{
    public static readonly ContextKind Upstream = new("upstream");
    public string Name => "http_proxy";

    internal static readonly object UpstreamAddrKey = new(), UpstreamStatusKey = new();

    public void Register(IModuleRegistry r)
    {
        var http = ContextKind.HttpAny;
        var up = new[] { Upstream };

        r.AddDirective(new() { Name = "upstream", Contexts = [ContextKind.Http], MinArgs = 1, MaxArgs = 1, Block = Upstream, Repeatable = true, Handler = i => i.Block!.Get<UpstreamConf>().Name = i.Args[0] });
        r.AddDirective(new() { Name = "server", Contexts = up, MinArgs = 1, MaxArgs = -1, Repeatable = true, Handler = UpstreamServer });
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

        r.AddVariable("proxy_host", c => c.Config<ProxyConf>().Target?.HostHeader);
        r.AddVariable("proxy_port", c => c.Config<ProxyConf>().Target?.Port.ToString(System.Globalization.CultureInfo.InvariantCulture));
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
        bool backup = false, down = false;
        for (int k = 1; k < i.Args.Length; k++)
        {
            var a = i.Args[k];
            if (a.StartsWith("weight=", StringComparison.Ordinal) && int.TryParse(a.AsSpan(7), out weight) && weight is >= 1 and <= 1000) continue;
            if (a.StartsWith("max_fails=", StringComparison.Ordinal) && int.TryParse(a.AsSpan(10), out maxFails) && maxFails >= 0) continue;
            if (a.StartsWith("fail_timeout=", StringComparison.Ordinal) && ConfigValue.TryParseMillis(a.AsSpan(13), out failTimeout)) continue;
            if (a == "backup") { backup = true; continue; }
            if (a == "down") { down = true; continue; }
            throw i.Error($"invalid parameter \"{a}\"");
        }
        i.Conf<UpstreamConf>().Servers.Add(new UpstreamServerSpec(i.Args[0], weight, maxFails, failTimeout, backup, down, i.Source));
    }

    private static void Pass(DirectiveInvocation i)
    {
        var c = i.Conf<ProxyConf>();
        var url = i.Args[0];
        if (url.Contains('$')) throw i.Error("variables in proxy_pass are not supported");
        if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            throw i.Error($"invalid URL prefix in \"{url}\"");
        c.Pass = url;
        c.PassSource = i.Source;
        c.LocationArgs = [.. i.Scope.Args];
        var h = i.Conf<LocationHandlerConf>();
        if (h.Handler is not null) throw i.Error($"location already handled by \"{h.Owner}\"");
        h.Owner = "proxy_pass";
        h.Handler = ctx => ProxyHandler.HandleAsync(ctx, c);
    }

    public void Configure(IModuleSetup setup)
    {
        var groups = new Dictionary<string, UpstreamGroup>(StringComparer.OrdinalIgnoreCase);
        foreach (var scope in setup.ScopesOf(Upstream))
        {
            var u = scope.Get<UpstreamConf>();
            if (u.Servers.Count == 0) throw new ConfigException($"no servers in upstream \"{u.Name}\"", scope.Source);
            if (groups.ContainsKey(u.Name)) throw new ConfigException($"duplicate upstream \"{u.Name}\"", scope.Source);
            var servers = new List<UpstreamServer>();
            foreach (var s in u.Servers)
                foreach (var ep in Resolve(s.Address, 80, s.Source))
                    servers.Add(new UpstreamServer(ep, s.Address, s.Weight, s.MaxFails, s.FailTimeoutMs, s.Backup, s.Down));
            groups[u.Name] = new UpstreamGroup(u.Name, servers, u.KeepAlive ?? 32, u.KeepAliveTimeout ?? 60_000, u.KeepAliveRequests ?? 1000);
        }

        var implicitGroups = new Dictionary<string, UpstreamGroup>(StringComparer.OrdinalIgnoreCase);
        foreach (var loc in setup.ScopesOf(ContextKind.Location))
        {
            if (!loc.TryGet<ProxyConf>(out var pc) || pc.Pass is null) continue;
            pc.Target = BuildTarget(pc, groups, implicitGroups);
        }
        _groups.AddRange(groups.Values);
        _groups.AddRange(implicitGroups.Values);
    }

    private readonly List<UpstreamGroup> _groups = new();

    /// <summary>The configuration was replaced (reload) and its last connection is gone: close pooled upstream connections.</summary>
    public void Dispose()
    {
        foreach (var g in _groups) g.Retire();
    }

    private static ProxyTarget BuildTarget(ProxyConf c, Dictionary<string, UpstreamGroup> groups, Dictionary<string, UpstreamGroup> implicitGroups)
    {
        var url = c.Pass!;
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
                    foreach (var ep in Resolve(authority, defPort, src)) servers.Add(new UpstreamServer(ep, authority, 1, 1, 10_000, false, false));
                    implicitGroups[key] = group = new UpstreamGroup(authority, servers, 32, 60_000, 1000);
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
    private static IEnumerable<EndPoint> Resolve(string address, int defPort, SourceLocation src)
    {
        if (address.StartsWith("unix:", StringComparison.Ordinal)) return [new UnixDomainSocketEndPoint(address[5..])];
        SplitHostPort(address, defPort, src, out var host, out var port, out _);
        if (IPAddress.TryParse(host, out var ip)) return [new IPEndPoint(ip, port)];
        IPAddress[] addrs;
        try { addrs = Dns.GetHostAddresses(host); }
        catch (SocketException e) { throw new ConfigException($"host not found in upstream \"{address}\": {e.Message}", src); }
        if (addrs.Length == 0) throw new ConfigException($"host not found in upstream \"{address}\"", src);
        return Array.ConvertAll(addrs, a => (EndPoint)new IPEndPoint(a, port));
    }
}

internal sealed record ProxyTarget(UpstreamGroup Group, bool Tls, string HostHeader, int Port, string? UriPart, string? LocationPrefix, SslClientAuthenticationOptions? Ssl);
