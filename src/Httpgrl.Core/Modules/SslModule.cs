using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Httpgrl.Core.Modules;

public sealed class SslConf : ScopeConfig<SslConf>
{
    public string? Certificate, CertificateKey;
    public SourceLocation CertificateSource;
    public SslProtocols? Protocols;
    /// <summary>Built in Configure for every server that listens with ssl.</summary>
    public SslServerAuthenticationOptions? Options;

    protected override void Inherit(SslConf p)
    {
        if (Certificate is null) { Certificate = p.Certificate; CertificateKey = p.CertificateKey; CertificateSource = p.CertificateSource; }
        Protocols ??= p.Protocols;
    }
}

/// <summary>TLS termination via the platform stack (SslStream). PEM certificate chains, TLS 1.2/1.3 only.</summary>
internal sealed class SslModule : IModule
{
    public string Name => "http_ssl";

    private static readonly string[] Ignored = ["ssl_ciphers", "ssl_prefer_server_ciphers", "ssl_session_cache", "ssl_session_timeout", "ssl_session_tickets", "ssl_dhparam", "ssl_ecdh_curve", "ssl_stapling", "ssl_stapling_verify"];
    private readonly List<(string, SourceLocation)> _ignoredSeen = new();

    public void Register(IModuleRegistry r)
    {
        var ctx = new[] { ContextKind.Http, ContextKind.Server };
        r.AddDirective(new() { Name = "ssl_certificate", Contexts = ctx, MinArgs = 1, MaxArgs = 1, Handler = i => { var c = i.Conf<SslConf>(); c.Certificate = i.Args[0]; c.CertificateSource = i.Source; } });
        r.AddDirective(new() { Name = "ssl_certificate_key", Contexts = ctx, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<SslConf>().CertificateKey = i.Args[0] });
        r.AddDirective(new() { Name = "ssl_protocols", Contexts = ctx, MinArgs = 1, MaxArgs = -1, Handler = Protocols });
        foreach (var n in Ignored)
            r.AddDirective(new() { Name = n, Contexts = ctx, MaxArgs = -1, Handler = i => _ignoredSeen.Add((i.Name, i.Source)) });
    }

    private static void Protocols(DirectiveInvocation i)
    {
        SslProtocols p = 0;
        foreach (var a in i.Args)
        {
            p |= a switch
            {
                "TLSv1.2" => SslProtocols.Tls12,
                "TLSv1.3" => SslProtocols.Tls13,
                "SSLv2" or "SSLv3" or "TLSv1" or "TLSv1.1" => throw i.Error($"\"{a}\" is insecure and not supported"),
                _ => throw i.Error($"unknown protocol \"{a}\""),
            };
        }
        i.Conf<SslConf>().Protocols = p;
    }

    public void Configure(IModuleSetup setup)
    {
        foreach (var (name, src) in _ignoredSeen)
            setup.Log.Warn("directive ignored; the platform TLS stack defaults apply", new("directive", name), new("at", src.ToString()));

        var cache = new Dictionary<(string, string), SslStreamCertificateContext>();
        foreach (var server in setup.ScopesOf(ContextKind.Server))
        {
            var sc = server.Get<ServerConf>();
            var ssl = server.Get<SslConf>();
            bool needs = sc.Listens.Exists(l => l.Ssl);
            if (!needs) continue;
            if (ssl.Certificate is null || ssl.CertificateKey is null)
                throw new ConfigException("no \"ssl_certificate\"/\"ssl_certificate_key\" defined for a server with \"listen ... ssl\"", server.Source);
            var root = Path.GetDirectoryName(server.Source.File) ?? "";
            var cert = Path.GetFullPath(ssl.Certificate, root);
            var key = Path.GetFullPath(ssl.CertificateKey, root);
            if (!cache.TryGetValue((cert, key), out var context))
            {
                try { context = Load(cert, key); }
                catch (Exception e) when (e is CryptographicException or IOException or UnauthorizedAccessException or ArgumentException)
                {
                    throw new ConfigException($"cannot load certificate \"{cert}\" / key \"{key}\": {e.Message}", ssl.CertificateSource);
                }
                cache[(cert, key)] = context;
            }
            ssl.Options = new SslServerAuthenticationOptions
            {
                ServerCertificateContext = context,
                EnabledSslProtocols = ssl.Protocols ?? (SslProtocols.Tls12 | SslProtocols.Tls13),
                ApplicationProtocols = [SslApplicationProtocol.Http11],
                ClientCertificateRequired = false,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                AllowRenegotiation = false,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
            };
        }
    }

    internal static SslStreamCertificateContext Load(string certPath, string keyPath)
    {
        var leaf = X509Certificate2.CreateFromPemFile(certPath, keyPath);
        if (OperatingSystem.IsWindows())
        {
            // SChannel cannot use ephemeral PEM keys; round-trip through PKCS#12.
            var pfx = leaf.Export(X509ContentType.Pkcs12);
            leaf.Dispose();
            leaf = X509CertificateLoader.LoadPkcs12(pfx, null);
        }
        var all = new X509Certificate2Collection();
        all.ImportFromPemFile(certPath);
        var chain = new X509Certificate2Collection();
        foreach (var c in all)
            if (!c.RawDataMemory.Span.SequenceEqual(leaf.RawDataMemory.Span)) chain.Add(c);
        return SslStreamCertificateContext.Create(leaf, chain, offline: true);
    }
}
