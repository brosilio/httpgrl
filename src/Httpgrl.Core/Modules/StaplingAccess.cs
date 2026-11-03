using System.Net.Security;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;

namespace Httpgrl.Core.Modules;

/// <summary>
/// Access to SslStreamCertificateContext internals so that OCSP stapling is driven by us: the platform staples
/// whatever response we hand it and never fetches on its own. UnsafeAccessor binds at compile time without
/// reflection (AOT-safe), and a native AOT binary embeds the runtime, so these internals can't change under a built
/// binary; a runtime upgrade that renames them fails <see cref="SelfTest"/> in CI, not in production.
/// </summary>
internal static class StaplingAccess
{
    [UnsafeAccessor(UnsafeAccessorKind.StaticMethod, Name = "Create")]
    private static extern SslStreamCertificateContext CreateCore(SslStreamCertificateContext? self, X509Certificate2 target, X509Certificate2Collection? additionalCertificates, bool offline, SslCertificateTrust? trust, bool noOcspFetch);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_staplingForbidden")]
    private static extern ref bool StaplingForbidden(SslStreamCertificateContext c);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_ocspResponse")]
    private static extern ref byte[]? OcspResponse(SslStreamCertificateContext c);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_ocspExpiration")]
    private static extern ref DateTimeOffset OcspExpiration(SslStreamCertificateContext c);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_nextDownload")]
    private static extern ref DateTimeOffset NextDownload(SslStreamCertificateContext c);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_ocspUrls")]
    private static extern ref List<string>? OcspUrls(SslStreamCertificateContext c);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "get_SyncObject")]
    private static extern object SyncObject(SslStreamCertificateContext c);

    /// <summary>
    /// A context that staples exactly what <see cref="Set"/> gives it and never contacts a responder itself
    /// (System.Net.Security, SslStreamCertificateContext.Linux.cs, .NET 10):
    /// - created with noOcspFetch, so creation doesn't start a download (AddRootCertificate);
    /// - then stapling re-allowed (noOcspFetch also disables stapling: GetOcspResponseAsync returns null);
    /// - _ocspUrls non-null, because OcspStaplingAvailable gates installing OpenSSL's status callback;
    /// - expiration and next-download pinned to MaxValue: those two are the only triggers for its own downloads;
    /// - the response itself is ours to set or clear; we handle expiry.
    /// The one remaining way the platform fetches is SslStream duplicating a context whose chain has already expired
    /// (SslStream.Protocol.cs, AcquireCredentialsHandle), i.e. a server presenting an expired certificate.
    /// </summary>
    public static SslStreamCertificateContext Create(X509Certificate2 leaf, X509Certificate2Collection chain, SslCertificateTrust? trust)
    {
        var c = CreateCore(null, leaf, chain, offline: true, trust, noOcspFetch: true);
        lock (SyncObject(c))
        {
            StaplingForbidden(c) = false;
            OcspUrls(c) = ["http://stapling-is-driven-by-httpgrl.invalid/"];
            OcspExpiration(c) = DateTimeOffset.MaxValue;
            NextDownload(c) = DateTimeOffset.MaxValue;
            OcspResponse(c) = null;
        }
        return c;
    }

    /// <summary>Staple <paramref name="response"/> (DER, already verified) from now on; null to staple nothing.</summary>
    public static void Set(SslStreamCertificateContext c, byte[]? response)
    {
        lock (SyncObject(c)) OcspResponse(c) = response;
    }

    /// <summary>Whether the accessors bind on this runtime (they throw MissingMemberException if not).</summary>
    public static string? SelfTest(X509Certificate2 leaf)
    {
        try
        {
            var c = Create(leaf, [], null);
            Set(c, null);
            return null;
        }
        catch (Exception e) when (e is MissingMemberException or MissingMethodException or MissingFieldException)
        {
            return e.Message;
        }
    }
}
