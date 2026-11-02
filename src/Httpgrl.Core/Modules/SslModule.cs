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
    public VerifyClient? Verify;
    public string? ClientCa;
    public SourceLocation ClientCaSource;
    public int? VerifyDepth;
    public string? Crl;
    public SourceLocation CrlSource;
    /// <summary>Built in Configure for every server that listens with ssl.</summary>
    public SslServerAuthenticationOptions? Options;
    /// <summary>Built in Configure when ssl_verify_client is not off; shared by servers with identical settings.</summary>
    public ClientAuth? ClientAuth;

    protected override void Inherit(SslConf p)
    {
        if (Certificate is null) { Certificate = p.Certificate; CertificateKey = p.CertificateKey; CertificateSource = p.CertificateSource; }
        Protocols ??= p.Protocols;
        Verify ??= p.Verify;
        if (ClientCa is null) { ClientCa = p.ClientCa; ClientCaSource = p.ClientCaSource; }
        VerifyDepth ??= p.VerifyDepth;
        if (Crl is null) { Crl = p.Crl; CrlSource = p.CrlSource; }
    }
}

public enum VerifyClient : byte { Off, On, Optional, OptionalNoCa }

/// <summary>
/// Client certificate verification (ssl_verify_client). Chains are built only against the configured CA bundle:
/// no system roots, no revocation fetches, no AIA downloads (a client-supplied URL must never make us connect out),
/// and the leaf must allow TLS client authentication.
/// </summary>
public sealed class ClientAuth
{
    private static readonly Oid ClientAuthEku = new("1.3.6.1.5.5.7.3.2");

    public readonly VerifyClient Mode;
    public readonly int Depth;
    public readonly X509ChainPolicy Policy;
    /// <summary>The CA names sent in the CertificateRequest so clients can pick the right certificate.</summary>
    public readonly SslCertificateTrust? Trust;
    /// <summary>ssl_crl: revocation is checked for every certificate of the chain below the trust anchor.</summary>
    public readonly CrlSet? Crls;

    public ClientAuth(VerifyClient mode, X509Certificate2Collection? cas, int depth, CrlSet? crls = null)
    {
        Mode = mode;
        Depth = depth;
        Crls = crls;
        Policy = new X509ChainPolicy
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck,
            DisableCertificateDownloads = true,
            VerificationFlags = X509VerificationFlags.NoFlag,
        };
        Policy.ApplicationPolicy.Add(ClientAuthEku);
        if (cas is not null)
        {
            Policy.CustomTrustStore.AddRange(cas);
            // SChannel can't send a trust list built from a collection; elsewhere clients get the CA names.
            Trust = SslCertificateTrust.CreateForX509Collection(cas, sendTrustInHandshake: !OperatingSystem.IsWindows());
        }
    }

    /// <summary>The <c>$ssl_client_verify</c> verdict and whether the handshake may proceed.</summary>
    public (string Verdict, bool Accept) Evaluate(X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors)
    {
        if (cert is null) return ("NONE", Mode != VerifyClient.On);
        // Name checks are meaningless for client certificates.
        errors &= ~SslPolicyErrors.RemoteCertificateNameMismatch;
        errors &= ~SslPolicyErrors.RemoteCertificateNotAvailable;
        string? failure = null;
        bool caOnly = true;
        if (chain is null || errors != SslPolicyErrors.None)
        {
            failure = Describe(chain, out caOnly);
        }
        else if (chain.ChainElements.Count - 1 > Depth)
        {
            failure = "certificate chain too long";
            caOnly = false;
        }
        else if (Crls?.Check(chain.ChainElements, DateTime.UtcNow) is { } revocation)
        {
            failure = revocation;
            caOnly = false;
        }
        if (failure is null) return ("SUCCESS", true);
        // optional_no_ca tolerates an unknown issuer only; expired, malformed or wrong-purpose certificates still fail.
        return ("FAILED:" + failure, Mode == VerifyClient.OptionalNoCa && caOnly);
    }

    /// <summary>Verify with our policy outside the handshake callback (e.g. a resumed session).</summary>
    public (string Verdict, bool Accept) Evaluate(X509Certificate2? cert)
    {
        if (cert is null) return Evaluate(null, null, SslPolicyErrors.RemoteCertificateNotAvailable);
        using var chain = new X509Chain { ChainPolicy = Policy.Clone() };
        bool ok = chain.Build(cert);
        return Evaluate(cert, chain, ok ? SslPolicyErrors.None : SslPolicyErrors.RemoteCertificateChainErrors);
    }

    private const X509ChainStatusFlags CaFlags = X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.PartialChain;

    private static string Describe(X509Chain? chain, out bool caOnly)
    {
        caOnly = true;
        if (chain is null) { caOnly = false; return "no chain"; }
        X509ChainStatusFlags all = 0;
        foreach (var st in chain.ChainStatus) all |= st.Status;
        if (all == 0) { caOnly = false; return "verification failed"; }
        caOnly = (all & ~CaFlags) == 0;
        // Stable, short reasons (the platform's status text differs across OSes).
        if ((all & X509ChainStatusFlags.NotTimeValid) != 0) return "certificate expired or not yet valid";
        if ((all & X509ChainStatusFlags.NotValidForUsage) != 0) return "certificate not valid for client authentication";
        if ((all & X509ChainStatusFlags.NotSignatureValid) != 0) return "bad signature";
        if ((all & X509ChainStatusFlags.UntrustedRoot) != 0) return "untrusted issuer";
        if ((all & X509ChainStatusFlags.PartialChain) != 0) return "unable to get issuer certificate";
        return all.ToString();
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
        r.AddDirective(new() { Name = "ssl_verify_client", Contexts = ctx, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<SslConf>().Verify = i.Args[0] switch
        {
            "off" => VerifyClient.Off,
            "on" => VerifyClient.On,
            "optional" => VerifyClient.Optional,
            "optional_no_ca" => VerifyClient.OptionalNoCa,
            var a => throw i.Error($"invalid value \"{a}\"; expected on, off, optional or optional_no_ca"),
        } });
        r.AddDirective(new() { Name = "ssl_client_certificate", Contexts = ctx, MinArgs = 1, MaxArgs = 1, Handler = i => { var c = i.Conf<SslConf>(); c.ClientCa = i.Args[0]; c.ClientCaSource = i.Source; } });
        r.AddDirective(new() { Name = "ssl_verify_depth", Contexts = ctx, MinArgs = 1, MaxArgs = 1, Handler = i =>
        {
            int d = i.Int(0);
            if (d is < 0 or > 100) throw i.Error("ssl_verify_depth must be between 0 and 100");
            i.Conf<SslConf>().VerifyDepth = d;
        } });
        // Accepting these silently would claim a revocation check that doesn't happen.
        r.AddDirective(new() { Name = "ssl_crl", Contexts = ctx, MinArgs = 1, MaxArgs = 1, Handler = i => { var c = i.Conf<SslConf>(); c.Crl = i.Args[0]; c.CrlSource = i.Source; } });
        foreach (var n in new[] { "ssl_ocsp", "ssl_ocsp_responder", "ssl_trusted_certificate" })
            r.AddDirective(new() { Name = n, Contexts = ctx, MaxArgs = -1, Handler = i => throw i.Error($"\"{i.Name}\" is not supported") });

        r.AddVariable("ssl_protocol", c => c.Connection.TlsProtocol);
        r.AddVariable("ssl_server_name", c => c.Connection.TlsServerName);
        r.AddVariable("ssl_client_verify", c => c.Connection.IsTls ? c.Connection.ClientVerify ?? "NONE" : null);
        r.AddVariable("ssl_client_s_dn", c => c.Connection.ClientCertificate?.SubjectName.Name);
        r.AddVariable("ssl_client_i_dn", c => c.Connection.ClientCertificate?.IssuerName.Name);
        r.AddVariable("ssl_client_serial", c => c.Connection.ClientCertificate?.SerialNumber);
        r.AddVariable("ssl_client_fingerprint", c => c.Connection.ClientCertificate is { } cert
            ? Convert.ToHexStringLower(SHA256.HashData(cert.RawDataMemory.Span)) : null);
        r.AddVariable("ssl_client_escaped_cert", c => c.Connection.ClientCertificate is { } cert
            ? Uri.EscapeDataString(PemEncoding.WriteString("CERTIFICATE", cert.RawDataMemory.Span) + "\n") : null);
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

        var cache = new Dictionary<(string, string, string?), SslStreamCertificateContext>();
        var auths = new Dictionary<(VerifyClient, string?, int, string?), ClientAuth>();
        var crlSets = new Dictionary<string, CrlSet>();
        var caBundles = new Dictionary<string, X509Certificate2Collection>();
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

            ClientAuth? auth = null;
            var mode = ssl.Verify ?? VerifyClient.Off;
            if (mode != VerifyClient.Off)
            {
                string? ca = ssl.ClientCa is null ? null : Path.GetFullPath(ssl.ClientCa, root);
                if (ca is null && mode != VerifyClient.OptionalNoCa)
                    throw new ConfigException($"no \"ssl_client_certificate\" for \"ssl_verify_client {(mode == VerifyClient.On ? "on" : "optional")}\"", server.Source);
                int depth = ssl.VerifyDepth ?? 1;
                string? crlPath = ssl.Crl is null ? null : Path.GetFullPath(ssl.Crl, root);
                if (!auths.TryGetValue((mode, ca, depth, crlPath), out auth))
                {
                    X509Certificate2Collection? cas = null;
                    if (ca is not null && !caBundles.TryGetValue(ca, out cas))
                    {
                        cas = new X509Certificate2Collection();
                        try { cas.ImportFromPemFile(ca); }
                        catch (Exception e) when (e is CryptographicException or IOException or UnauthorizedAccessException or ArgumentException)
                        {
                            throw new ConfigException($"cannot load client CA bundle \"{ca}\": {e.Message}", ssl.ClientCaSource);
                        }
                        if (cas.Count == 0) throw new ConfigException($"no certificates in client CA bundle \"{ca}\"", ssl.ClientCaSource);
                        caBundles[ca] = cas;
                    }
                    CrlSet? crls = null;
                    if (crlPath is not null && !crlSets.TryGetValue(crlPath, out crls))
                        crlSets[crlPath] = crls = LoadCrls(crlPath, cas, ssl.CrlSource, setup.Log);
                    auths[(mode, ca, depth, crlPath)] = auth = new ClientAuth(mode, cas, depth, crls);
                }
            }
            ssl.ClientAuth = auth;

            // The trust list travels inside the certificate context, so a context is per (cert, key, CA bundle).
            string? trustKey = auth?.Trust is null ? null : ssl.ClientCa;
            if (!cache.TryGetValue((cert, key, trustKey), out var context))
            {
                try { context = Load(cert, key, auth?.Trust); }
                catch (Exception e) when (e is CryptographicException or IOException or UnauthorizedAccessException or ArgumentException)
                {
                    throw new ConfigException($"cannot load certificate \"{cert}\" / key \"{key}\": {e.Message}", ssl.CertificateSource);
                }
                cache[(cert, key, trustKey)] = context;
            }
            ssl.Options = new SslServerAuthenticationOptions
            {
                ServerCertificateContext = context,
                EnabledSslProtocols = ssl.Protocols ?? (SslProtocols.Tls12 | SslProtocols.Tls13),
                ApplicationProtocols = [SslApplicationProtocol.Http11],
                ClientCertificateRequired = auth is not null,
                CertificateChainPolicy = auth?.Policy,
                // A resumed session carries only the client's leaf certificate, so intermediates can't be re-chained,
                // and resumption across servers with different policies is a needless risk: always do the full check.
                AllowTlsResume = auth is null,
                RemoteCertificateValidationCallback = auth is null ? null : (sender, c, chain, errors) =>
                {
                    var (verdict, accept) = auth.Evaluate(c, chain, errors);
                    if (sender is ClientAuthSslStream s) s.Verdict = verdict;
                    return accept;
                },
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                AllowRenegotiation = false,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
            };
        }
    }

    /// <summary>
    /// Parse and pre-check a CRL file. A CRL naming a CA from the bundle must be signed by it (a forged or corrupt
    /// CRL fails the load, not a handshake later). CRLs from intermediates are checked against the intermediate
    /// the client presents.
    /// </summary>
    private static CrlSet LoadCrls(string path, X509Certificate2Collection? cas, SourceLocation src, ILogger log)
    {
        List<Crl> crls;
        try { crls = Crl.LoadFile(path); }
        catch (Exception e) when (e is CryptographicException or IOException or UnauthorizedAccessException or FormatException)
        {
            throw new ConfigException($"cannot load CRL file \"{path}\": {e.Message}", src);
        }
        var now = DateTime.UtcNow;
        foreach (var c in crls)
        {
            bool named = false, signed = false;
            foreach (var ca in cas ?? [])
            {
                if (!ca.SubjectName.RawData.AsSpan().SequenceEqual(c.IssuerName)) continue;
                named = true;
                signed |= c.IsSignedBy(ca);
            }
            var issuer = new X500DistinguishedName(c.IssuerName).Name;
            if (named && !signed) throw new ConfigException($"CRL for \"{issuer}\" in \"{path}\" is not signed by that CA", src);
            if (c.NextUpdate is { } next && next < now)
                log.Warn("CRL has expired; certificates it covers will be rejected until it's replaced", new("issuer", issuer), new("next_update", next.ToString("O")));
        }
        return new CrlSet(crls);
    }

    internal static SslStreamCertificateContext Load(string certPath, string keyPath, SslCertificateTrust? trust = null)
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
        return SslStreamCertificateContext.Create(leaf, chain, offline: true, trust);
    }
}

/// <summary>An SslStream that records the client certificate verdict from the (shared) validation callback.</summary>
internal sealed class ClientAuthSslStream(Stream inner) : SslStream(inner, leaveInnerStreamOpen: false)
{
    public string? Verdict;
}
