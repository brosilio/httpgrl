using System.Net.Security;

namespace Httpgrl.Core.Modules;

/// <summary>
/// TLS cipher suites for servers: the default policy (AEAD only) and <c>ssl_ciphers</c> lists. As in nginx, the list
/// governs TLS 1.2; TLS 1.3 keeps its own (all-AEAD) suites unless the list names TLS 1.3 suites itself.
/// </summary>
internal static class Ciphers
{
    private static readonly TlsCipherSuite[] Tls13 =
    [
        TlsCipherSuite.TLS_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_AES_128_GCM_SHA256,
    ];

    /// <summary>
    /// TLS 1.2 by default: forward-secret key exchange (ECDHE) and an AEAD cipher. No CBC (SSL Labs rates it weak:
    /// padding-oracle history, MAC-then-encrypt), no static RSA key exchange, no SHA-1 MACs.
    /// </summary>
    private static readonly TlsCipherSuite[] Tls12Default =
    [
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ];

    /// <summary>OpenSSL's names for the suites people put in nginx configs (IANA names are accepted as they are).</summary>
    private static readonly Dictionary<string, TlsCipherSuite> OpenSslNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["ECDHE-ECDSA-AES128-GCM-SHA256"] = TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ["ECDHE-RSA-AES128-GCM-SHA256"] = TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ["ECDHE-ECDSA-AES256-GCM-SHA384"] = TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ["ECDHE-RSA-AES256-GCM-SHA384"] = TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ["ECDHE-ECDSA-CHACHA20-POLY1305"] = TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        ["ECDHE-RSA-CHACHA20-POLY1305"] = TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ["DHE-RSA-AES128-GCM-SHA256"] = TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        ["DHE-RSA-AES256-GCM-SHA384"] = TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        ["DHE-RSA-CHACHA20-POLY1305"] = TlsCipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ["ECDHE-ECDSA-AES128-SHA256"] = TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        ["ECDHE-RSA-AES128-SHA256"] = TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        ["ECDHE-ECDSA-AES256-SHA384"] = TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        ["ECDHE-RSA-AES256-SHA384"] = TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        ["ECDHE-ECDSA-AES128-SHA"] = TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        ["ECDHE-RSA-AES128-SHA"] = TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        ["ECDHE-ECDSA-AES256-SHA"] = TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        ["ECDHE-RSA-AES256-SHA"] = TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        ["DHE-RSA-AES128-SHA256"] = TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
        ["DHE-RSA-AES256-SHA256"] = TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
        ["AES128-GCM-SHA256"] = TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
        ["AES256-GCM-SHA384"] = TlsCipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
        ["AES128-SHA256"] = TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
        ["AES256-SHA256"] = TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
        ["AES128-SHA"] = TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        ["AES256-SHA"] = TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
        ["TLS_AES_128_GCM_SHA256"] = TlsCipherSuite.TLS_AES_128_GCM_SHA256,
        ["TLS_AES_256_GCM_SHA384"] = TlsCipherSuite.TLS_AES_256_GCM_SHA384,
        ["TLS_CHACHA20_POLY1305_SHA256"] = TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
    };

    private static readonly Lazy<Dictionary<string, TlsCipherSuite>> IanaNames = new(() =>
    {
        var d = new Dictionary<string, TlsCipherSuite>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in Enum.GetValues<TlsCipherSuite>()) d.TryAdd(s.ToString(), s);
        return d;
    });

    public static IReadOnlyList<TlsCipherSuite> DefaultSuites => [.. Tls13, .. Tls12Default];

    /// <summary>
    /// The policy for an <c>ssl_ciphers</c> value (null: the AEAD-only default), as an opaque object for
    /// <see cref="Apply"/>. Null on Windows, whose TLS stack (SChannel) can't be given a suite list per server.
    /// </summary>
    public static object? Resolve(string? spec, SourceLocation src, Action<string> warn)
    {
        if (OperatingSystem.IsWindows())
        {
            if (spec is not null) throw new ConfigException("ssl_ciphers: this platform's TLS stack doesn't allow choosing cipher suites", src);
            return null;
        }
        if (spec is null) return new CipherSuitesPolicy([.. Tls13, .. Tls12Default]);
        var (suites, warning) = Parse(spec, src);
        if (warning is not null) warn(warning);
        return new CipherSuitesPolicy(suites);
    }

    public static void Apply(SslServerAuthenticationOptions o, object? policy)
    {
        if (!OperatingSystem.IsWindows() && policy is CipherSuitesPolicy p) o.CipherSuitesPolicy = p;
    }

    /// <summary>
    /// An <c>ssl_ciphers</c> value. Explicit suite names give exactly those suites (in order); an OpenSSL cipher
    /// expression ("HIGH:!aNULL:!MD5", nginx's default) can't be evaluated without OpenSSL's rule engine, so it
    /// yields the default and a warning. Throws <see cref="ConfigException"/> on unknown or broken suites.
    /// </summary>
    public static (List<TlsCipherSuite> Suites, string? Warning) Parse(string spec, SourceLocation src)
    {
        var tokens = spec.Split([':', ' ', ','], StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0) throw new ConfigException("ssl_ciphers: empty list", src);
        var list = new List<TlsCipherSuite>();
        foreach (var t in tokens)
        {
            if (Lookup(t) is { } s) { if (!list.Contains(s)) list.Add(s); continue; }
            if (IsExpression(t))
                return ([.. Tls13, .. Tls12Default], $"OpenSSL cipher expressions (\"{t}\") aren't supported; using the default AEAD-only suites. List suites by name to choose them.");
            throw new ConfigException($"ssl_ciphers: unknown cipher suite \"{t}\"", src);
        }
        foreach (var s in list)
        {
            var n = s.ToString();
            if (n.Contains("_NULL_") || n.EndsWith("_NULL", StringComparison.Ordinal) || n.Contains("_anon_") || n.Contains("EXPORT")
                || n.Contains("RC4") || n.Contains("_DES") || n.Contains("3DES") || n.EndsWith("_MD5", StringComparison.Ordinal))
                throw new ConfigException($"ssl_ciphers: \"{n}\" is broken (no encryption, no authentication, or a cipher/MAC that's been broken) and isn't allowed", src);
        }
        // nginx semantics: ssl_ciphers is about TLS 1.2. Without TLS 1.3 suites of its own, keep TLS 1.3's.
        if (!list.Exists(s => Array.IndexOf(Tls13, s) >= 0)) list.InsertRange(0, Tls13);
        return (list, null);
    }

    private static TlsCipherSuite? Lookup(string name) =>
        OpenSslNames.TryGetValue(name, out var s) ? s
        : name.StartsWith("TLS_", StringComparison.OrdinalIgnoreCase) && IanaNames.Value.TryGetValue(name, out s) ? s
        : null;

    /// <summary>OpenSSL's cipher-string syntax: operators, or keywords/aliases rather than suite names.</summary>
    private static bool IsExpression(string t) =>
        t[0] is '!' or '+' or '-' or '@' || t.Contains('+') || t.Contains('=') || (!t.Contains('-') && !t.Contains('_'));
}
