using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Httpgrl.Core.Http;

namespace Httpgrl.Core.Modules;

/// <summary>The address of a <c>listen tunnel:NAME</c>: connections are dialed out to a remote httpgrl, not accepted.</summary>
internal sealed class TunnelEndPoint(string name) : EndPoint
{
    public string Name { get; } = name;
    public override string ToString() => "tunnel:" + Name;
}

/// <summary>A <c>tunnel NAME { }</c> block, validated and with its certificates loaded.</summary>
internal sealed class TunnelSpec
{
    public required string Name { get; init; }
    public required string Host { get; init; }
    public required int Port { get; init; }
    public required string Uri { get; init; }
    /// <summary>TLS name of the remote (SNI, verification) and the Host header of the handshake request.</summary>
    public required string ServerName { get; init; }
    /// <summary>Idle connections kept parked at the remote.</summary>
    public required int Pool { get; init; }
    /// <summary>Connections in total (parked and serving).</summary>
    public required int Max { get; init; }
    /// <summary>How long an idle tunnel connection may wait for a request before we close it ourselves.</summary>
    public required int IdleTimeoutMs { get; init; }
    public required int ConnectTimeoutMs { get; init; }
    public required SslClientAuthenticationOptions Ssl { get; init; }
    /// <summary>Everything a connection's identity depends on: equal across a reload means existing connections stay valid.</summary>
    public required string Identity { get; init; }
    public SourceLocation Source { get; init; }
}

internal sealed class TunnelConf : ScopeConfig<TunnelConf>
{
    public string Name = "";
    public string? Connect, Uri, ServerName, Certificate, CertificateKey, Trusted;
    public int? Pool, Max, IdleTimeout, ConnectTimeout;
    internal TunnelSpec? Spec;
    protected override void Inherit(TunnelConf parent) { }
}

/// <summary>
/// The agent side of a reverse tunnel. A <c>tunnel</c> block says where the remote is and how to authenticate to it;
/// <c>listen tunnel:NAME</c> puts servers behind it. Connections are dialed out (mTLS), turned around with an Upgrade
/// handshake, and from then on carry requests from the remote to us, served like any accepted connection.
/// </summary>
internal sealed class TunnelModule(string prefix) : IModule
{
    public const string DefaultUri = "/.well-known/httpgrl-tunnel";
    public const string Protocol = "httpgrl-tunnel";
    public static readonly ContextKind Kind = new("tunnel");

    public string Name => "http_tunnel";

    public void Register(IModuleRegistry r)
    {
        var t = new[] { Kind };
        r.AddDirective(new()
        {
            Name = "tunnel", Contexts = [ContextKind.Http], MinArgs = 1, MaxArgs = 1, Block = Kind, Repeatable = true,
            Handler = i =>
            {
                var n = i.Args[0];
                if (n.Length == 0 || !n.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.')) throw i.Error($"invalid tunnel name \"{n}\"");
                i.Block!.Get<TunnelConf>().Name = n;
            },
        });
        r.AddDirective(new() { Name = "connect", Contexts = t, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<TunnelConf>().Connect = i.Args[0] });
        r.AddDirective(new()
        {
            Name = "uri", Contexts = t, MinArgs = 1, MaxArgs = 1,
            Handler = i => i.Conf<TunnelConf>().Uri = i.Args[0].StartsWith('/') && !i.Args[0].Any(c => c <= ' ' || c >= 0x7f || c == '#') ? i.Args[0] : throw i.Error("expected an absolute path"),
        });
        r.AddDirective(new()
        {
            Name = "server_name", Contexts = t, MinArgs = 1, MaxArgs = 1,
            Handler = i => i.Conf<TunnelConf>().ServerName = RequestParser.NormalizeHost(i.Args[0]) ?? throw i.Error($"invalid name \"{i.Args[0]}\""),
        });
        r.AddDirective(new() { Name = "pool", Contexts = t, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<TunnelConf>().Pool = i.Int(0) is var v and >= 1 and <= 256 ? v : throw i.Error("must be 1..256") });
        r.AddDirective(new() { Name = "max", Contexts = t, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<TunnelConf>().Max = i.Int(0) is var v and >= 1 and <= 4096 ? v : throw i.Error("must be 1..4096") });
        r.AddDirective(new() { Name = "idle_timeout", Contexts = t, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<TunnelConf>().IdleTimeout = i.Millis(0) is var v and >= 1000 ? v : throw i.Error("must be at least 1s") });
        r.AddDirective(new() { Name = "connect_timeout", Contexts = t, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<TunnelConf>().ConnectTimeout = i.Millis(0) is var v and > 0 ? v : throw i.Error("must be positive") });
        r.AddDirective(new() { Name = "certificate", Contexts = t, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<TunnelConf>().Certificate = i.Args[0] });
        r.AddDirective(new() { Name = "certificate_key", Contexts = t, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<TunnelConf>().CertificateKey = i.Args[0] });
        r.AddDirective(new() { Name = "trusted_certificate", Contexts = t, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<TunnelConf>().Trusted = i.Args[0] });
    }

    public void Configure(IModuleSetup setup)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var scope in setup.ScopesOf(Kind))
        {
            var c = scope.Get<TunnelConf>();
            if (!names.Add(c.Name)) throw new ConfigException($"duplicate tunnel \"{c.Name}\"", scope.Source);
            c.Spec = Build(c, scope.Source);
        }
        // A tunnel nobody listens on dials nothing; one that's listened on but undefined is caught by routing.
    }

    private TunnelSpec Build(TunnelConf c, SourceLocation src)
    {
        if (c.Connect is null) throw new ConfigException($"tunnel \"{c.Name}\": no \"connect\"", src);
        var (host, port) = SplitHostPort(c.Connect, src);
        if (c.Certificate is null || c.CertificateKey is null)
            throw new ConfigException($"tunnel \"{c.Name}\": no \"certificate\"/\"certificate_key\" (the remote only accepts agents it can authenticate)", src);
        var certPath = Path.GetFullPath(c.Certificate, prefix);
        var keyPath = Path.GetFullPath(c.CertificateKey, prefix);
        X509Certificate2 leaf;
        X509Certificate2Collection chain;
        try { (leaf, chain) = SslModule.LoadCertificate(certPath, keyPath); }
        catch (Exception e) when (e is CryptographicException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            throw new ConfigException($"tunnel \"{c.Name}\": cannot load certificate \"{certPath}\": {e.Message}", src);
        }

        X509Certificate2Collection? trusted = null;
        string? trustedPath = c.Trusted is null ? null : Path.GetFullPath(c.Trusted, prefix);
        if (trustedPath is not null)
        {
            trusted = new X509Certificate2Collection();
            try { trusted.ImportFromPemFile(trustedPath); }
            catch (Exception e) when (e is CryptographicException or IOException or UnauthorizedAccessException or ArgumentException)
            {
                throw new ConfigException($"tunnel \"{c.Name}\": cannot read \"{trustedPath}\": {e.Message}", src);
            }
            if (trusted.Count == 0) throw new ConfigException($"tunnel \"{c.Name}\": no certificates in \"{trustedPath}\"", src);
        }

        var name = c.ServerName ?? (IPAddress.TryParse(host, out _) ? null : RequestParser.NormalizeHost(host))
            ?? throw new ConfigException($"tunnel \"{c.Name}\": \"connect\" is an IP address; set \"server_name\" to the name the remote's certificate is for", src);
        int pool = c.Pool ?? 4, max = c.Max ?? 64;
        if (max < pool) throw new ConfigException($"tunnel \"{c.Name}\": \"max\" is smaller than \"pool\"", src);

        var ssl = new SslClientAuthenticationOptions
        {
            TargetHost = name,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            ApplicationProtocols = [SslApplicationProtocol.Http11],
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            AllowRenegotiation = false,
            ClientCertificateContext = SslStreamCertificateContext.Create(leaf, chain, offline: true),
            RemoteCertificateValidationCallback = (_, cert, ch, errors) => Verify(cert, ch, errors, trusted),
        };
        var identity = string.Join('|', host, port, c.Uri ?? DefaultUri, name, leaf.Thumbprint,
            string.Join(',', chain.Select(x => x.Thumbprint)), trusted is null ? "system" : string.Join(',', trusted.Select(x => x.Thumbprint)));
        return new TunnelSpec
        {
            Name = c.Name, Host = host, Port = port, Uri = c.Uri ?? DefaultUri, ServerName = name,
            Pool = pool, Max = max, IdleTimeoutMs = c.IdleTimeout ?? 300_000, ConnectTimeoutMs = c.ConnectTimeout ?? 10_000,
            Ssl = ssl, Identity = identity, Source = src,
        };
    }

    /// <summary>The remote is verified like any upstream: system roots by default, or only the configured bundle.</summary>
    private static bool Verify(X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors, X509Certificate2Collection? trusted)
    {
        if (cert is null) return false;
        if (trusted is null) return errors == SslPolicyErrors.None;
        if ((errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None) return false;
        var leaf = cert as X509Certificate2 ?? new X509Certificate2(cert);
        using var ch = new X509Chain();
        ch.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        ch.ChainPolicy.CustomTrustStore.AddRange(trusted);
        ch.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        if (chain is not null)
            foreach (var el in chain.ChainElements) ch.ChainPolicy.ExtraStore.Add(el.Certificate);
        return ch.Build(leaf);
    }

    private static (string Host, int Port) SplitHostPort(string a, SourceLocation src)
    {
        string host;
        int port = 443;
        if (a.StartsWith('['))
        {
            int close = a.IndexOf(']');
            if (close < 0) throw new ConfigException($"invalid address \"{a}\"", src);
            host = a[1..close];
            var rest = a.AsSpan(close + 1);
            if (!rest.IsEmpty && (rest[0] != ':' || !int.TryParse(rest[1..], out port))) throw new ConfigException($"invalid port in \"{a}\"", src);
        }
        else
        {
            int colon = a.LastIndexOf(':');
            host = colon < 0 ? a : a[..colon];
            if (colon >= 0 && !int.TryParse(a.AsSpan(colon + 1), out port)) throw new ConfigException($"invalid port in \"{a}\"", src);
        }
        if (port is < 1 or > 65535) throw new ConfigException($"invalid port in \"{a}\"", src);
        if (host.Length == 0 || (!IPAddress.TryParse(host, out _) && RequestParser.NormalizeHost(host) is null)) throw new ConfigException($"invalid host in \"{a}\"", src);
        return (host, port);
    }
}

/// <summary>The response to the agent's Upgrade request. Untrusted bytes from the network: parsed strictly.</summary>
internal static class TunnelHandshake
{
    public const int MaxHead = 8192;

    /// <summary>
    /// The handshake request. Nothing in it comes from a client: the URI and name are validated config values.
    /// </summary>
    public static byte[] Request(TunnelSpec s) => System.Text.Encoding.ASCII.GetBytes(
        $"GET {s.Uri} HTTP/1.1\r\nHost: {s.ServerName}\r\nConnection: Upgrade\r\nUpgrade: {TunnelModule.Protocol}\r\nUser-Agent: httpgrl-tunnel\r\n\r\n");

    /// <summary>
    /// Length of a complete head (through the empty line), 0 if more bytes are needed, -1 if it's malformed or isn't a
    /// switch to our protocol. <paramref name="status"/> is the status code once the status line is complete, else 0.
    /// </summary>
    public static int Parse(ReadOnlySpan<byte> buf, out int status)
    {
        status = 0;
        int end = buf.IndexOf("\r\n\r\n"u8);
        int eol = buf.IndexOf("\r\n"u8);
        if (eol < 0) return buf.Length >= MaxHead || !"HTTP/1.1 "u8.StartsWith(buf[..Math.Min(buf.Length, 9)]) ? -1 : 0;
        var line = buf[..eol];
        if (line.Length < 12 || !line.StartsWith("HTTP/1.1 "u8) || !IsDigit(line[9]) || !IsDigit(line[10]) || !IsDigit(line[11]) || (line.Length > 12 && line[12] != ' '))
            return -1;
        status = (line[9] - '0') * 100 + (line[10] - '0') * 10 + (line[11] - '0');
        foreach (byte b in line[12..]) if ((b < 0x20 && b != '\t') || b == 0x7F) return -1;
        if (end < 0) return buf.Length >= MaxHead ? -1 : 0;
        if (end + 4 > MaxHead) return -1;
        if (status != 101) return -1;

        bool upgrade = false, connection = false;
        int pos = eol + 2;
        while (pos < end + 2)
        {
            int nl = buf[pos..].IndexOf("\r\n"u8);
            var h = buf.Slice(pos, nl);
            pos += nl + 2;
            if (h.IndexOf((byte)'\r') >= 0 || h.IndexOf((byte)'\n') >= 0) return -1;
            int colon = h.IndexOf((byte)':');
            if (colon <= 0) return -1;
            foreach (byte b in h[..colon]) if (!HttpChars.IsToken(b)) return -1;
            var v = h[(colon + 1)..];
            foreach (byte b in v) if ((b < 0x20 && b != '\t') || b == 0x7F) return -1;
            v = v.Trim(" \t"u8);
            var name = h[..colon];
            if (System.Text.Ascii.EqualsIgnoreCase(name, "Upgrade"u8)) upgrade = System.Text.Ascii.EqualsIgnoreCase(v, "httpgrl-tunnel"u8);
            else if (System.Text.Ascii.EqualsIgnoreCase(name, "Connection"u8)) connection = System.Text.Ascii.EqualsIgnoreCase(v, "upgrade"u8);
        }
        // A 101 for some other protocol (a WebSocket endpoint at the same URI) is not the remote agreeing to tunnel.
        return upgrade && connection ? end + 4 : -1;
    }

    private static bool IsDigit(byte b) => (uint)(b - '0') <= 9;
}
