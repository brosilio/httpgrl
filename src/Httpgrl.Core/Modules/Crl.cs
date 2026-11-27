using System.Collections.Concurrent;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Httpgrl.Core.Modules;

/// <summary>
/// A parsed X.509 v2 CRL (RFC 5280 5.1). Full CRLs only: delta and indirect CRLs, and anything with a critical
/// extension we don't understand, are refused at load rather than half-applied. The signature is checked against
/// the actual issuing certificate of the chain being verified (cached per issuer), so a CRL can't be forged by
/// naming a CA it wasn't signed by.
/// </summary>
public sealed class Crl
{
    public readonly byte[] IssuerName;
    public readonly byte[]? AuthorityKeyId;
    public readonly DateTime ThisUpdate;
    public readonly DateTime? NextUpdate;
    /// <summary>IssuingDistributionPoint scope: the CRL covers only end-entity, or only CA, certificates.</summary>
    public readonly bool OnlyUser, OnlyCa;
    public readonly string Source;
    private readonly HashSet<string> _revoked;
    private readonly ReadOnlyMemory<byte> _tbs;
    private readonly byte[] _signature;
    private readonly string _sigOid;
    private readonly ConcurrentDictionary<string, bool> _verified = new(StringComparer.Ordinal);

    private Crl(string source, byte[] issuer, byte[]? aki, DateTime thisUpdate, DateTime? nextUpdate, bool onlyUser, bool onlyCa,
        HashSet<string> revoked, ReadOnlyMemory<byte> tbs, byte[] signature, string sigOid)
    {
        Source = source;
        IssuerName = issuer;
        AuthorityKeyId = aki;
        ThisUpdate = thisUpdate;
        NextUpdate = nextUpdate;
        OnlyUser = onlyUser;
        OnlyCa = onlyCa;
        _revoked = revoked;
        _tbs = tbs;
        _signature = signature;
        _sigOid = sigOid;
    }

    public int Count => _revoked.Count;

    public bool IsRevoked(X509Certificate2 cert) => _revoked.Contains(Convert.ToHexString(cert.SerialNumberBytes.Span));

    /// <summary>Whether this CRL is signed by <paramref name="issuer"/>'s key.</summary>
    public bool IsSignedBy(X509Certificate2 issuer) => _verified.GetOrAdd(issuer.Thumbprint, _ => VerifySignature(issuer));

    private bool VerifySignature(X509Certificate2 issuer)
    {
        var data = _tbs.Span;
        switch (_sigOid)
        {
            case "1.2.840.10045.4.3.2" or "1.2.840.10045.4.3.3" or "1.2.840.10045.4.3.4":
            {
                using var key = issuer.GetECDsaPublicKey();
                return key is not null && key.VerifyData(data, _signature, Hash(_sigOid), DSASignatureFormat.Rfc3279DerSequence);
            }
            case "1.2.840.113549.1.1.11" or "1.2.840.113549.1.1.12" or "1.2.840.113549.1.1.13":
            {
                using var key = issuer.GetRSAPublicKey();
                return key is not null && key.VerifyData(data, _signature, Hash(_sigOid), RSASignaturePadding.Pkcs1);
            }
            default: return false;
        }
    }

    private static HashAlgorithmName Hash(string oid) => oid switch
    {
        "1.2.840.10045.4.3.2" or "1.2.840.113549.1.1.11" => HashAlgorithmName.SHA256,
        "1.2.840.10045.4.3.3" or "1.2.840.113549.1.1.12" => HashAlgorithmName.SHA384,
        "1.2.840.10045.4.3.4" or "1.2.840.113549.1.1.13" => HashAlgorithmName.SHA512,
        _ => throw new CryptographicException($"unsupported CRL signature algorithm {oid}"),
    };

    private static bool Supported(string oid) => oid is "1.2.840.10045.4.3.2" or "1.2.840.10045.4.3.3" or "1.2.840.10045.4.3.4"
        or "1.2.840.113549.1.1.11" or "1.2.840.113549.1.1.12" or "1.2.840.113549.1.1.13";

    /// <summary>All CRLs in a file: PEM ("X509 CRL" blocks) or a single DER CRL.</summary>
    public static List<Crl> LoadFile(string path)
    {
        var bytes = File.ReadAllBytes(path);
        var list = new List<Crl>();
        var text = System.Text.Encoding.ASCII.GetString(bytes);
        if (text.Contains("-----BEGIN", StringComparison.Ordinal))
        {
            ReadOnlySpan<char> rest = text;
            while (PemEncoding.TryFind(rest, out var f))
            {
                if (rest[f.Label].SequenceEqual("X509 CRL"))
                    list.Add(Parse(Convert.FromBase64String(rest[f.Base64Data].ToString()), path));
                rest = rest[f.Location.End..];
            }
        }
        else list.Add(Parse(bytes, path));
        if (list.Count == 0) throw new CryptographicException("no CRLs found");
        return list;
    }

    public static Crl Parse(byte[] der, string source)
    {
        try { return ParseCore(der, source); }
        catch (AsnContentException e) { throw new CryptographicException("malformed CRL: " + e.Message, e); }
    }

    private static readonly Asn1Tag Ctx0 = new(TagClass.ContextSpecific, 0);

    private static Crl ParseCore(byte[] der, string source)
    {
        var top = new AsnReader(der, AsnEncodingRules.DER);
        var outer = top.ReadSequence();
        top.ThrowIfNotEmpty();
        var tbsEncoded = outer.ReadEncodedValue();
        string sigOid = ReadAlgorithm(outer);
        var signature = outer.ReadBitString(out int unused);
        if (unused != 0) throw new CryptographicException("malformed CRL signature");
        outer.ThrowIfNotEmpty();
        if (!Supported(sigOid)) throw new CryptographicException($"unsupported CRL signature algorithm {sigOid}");

        var tbs = new AsnReader(tbsEncoded, AsnEncodingRules.DER).ReadSequence();
        if (tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Integer))
        {
            if (!tbs.TryReadInt32(out int version) || version != 1) throw new CryptographicException("unsupported CRL version");
        }
        if (ReadAlgorithm(tbs) != sigOid) throw new CryptographicException("CRL signature algorithms disagree");
        var issuer = tbs.ReadEncodedValue().ToArray();
        var thisUpdate = ReadTime(tbs);
        DateTime? nextUpdate = null;
        if (tbs.HasData && IsTime(tbs.PeekTag())) nextUpdate = ReadTime(tbs);

        var revoked = new HashSet<string>(StringComparer.Ordinal);
        if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
        {
            var entries = tbs.ReadSequence();
            while (entries.HasData)
            {
                var e = entries.ReadSequence();
                var serial = e.ReadIntegerBytes();
                ReadTime(e);
                if (e.HasData)
                {
                    foreach (var (oid, critical, _) in ReadExtensions(e.ReadSequence()))
                    {
                        // reasonCode and invalidityDate are informational. certificateIssuer means an indirect CRL.
                        if (critical && oid is not ("2.5.29.21" or "2.5.29.24"))
                            throw new CryptographicException(oid == "2.5.29.29" ? "indirect CRLs are not supported" : $"unsupported critical CRL entry extension {oid}");
                    }
                }
                e.ThrowIfNotEmpty();
                revoked.Add(Convert.ToHexString(serial.Span));
            }
        }

        byte[]? aki = null;
        bool onlyUser = false, onlyCa = false;
        if (tbs.HasData)
        {
            var wrapper = tbs.ReadSequence(Ctx0);
            foreach (var (oid, critical, value) in ReadExtensions(wrapper.ReadSequence()))
            {
                switch (oid)
                {
                    case "2.5.29.35": aki = ReadAuthorityKeyId(value); break;
                    case "2.5.29.20": break; // cRLNumber
                    case "2.5.29.27": throw new CryptographicException("delta CRLs are not supported");
                    case "2.5.29.28": (onlyUser, onlyCa) = ReadIssuingDistributionPoint(value); break;
                    default:
                        if (critical) throw new CryptographicException($"unsupported critical CRL extension {oid}");
                        break;
                }
            }
            wrapper.ThrowIfNotEmpty();
        }
        tbs.ThrowIfNotEmpty();
        return new Crl(source, issuer, aki, thisUpdate, nextUpdate, onlyUser, onlyCa, revoked, tbsEncoded, signature, sigOid);
    }

    private static string ReadAlgorithm(AsnReader r)
    {
        var alg = r.ReadSequence();
        var oid = alg.ReadObjectIdentifier();
        // Before the parameters: an algorithm we don't verify (RSASSA-PSS carries a parameter SEQUENCE) would otherwise
        // read as a "malformed CRL", which sends an admin looking for file corruption.
        if (!Supported(oid))
            throw new CryptographicException($"unsupported CRL signature algorithm {(oid == "1.2.840.113549.1.1.10" ? "RSASSA-PSS" : oid)}");
        if (alg.HasData) alg.ReadNull(); // RSA algorithms carry NULL parameters; ECDSA none
        alg.ThrowIfNotEmpty();
        return oid;
    }

    private static bool IsTime(Asn1Tag t) => t.HasSameClassAndValue(Asn1Tag.UtcTime) || t.HasSameClassAndValue(Asn1Tag.GeneralizedTime);

    private static DateTime ReadTime(AsnReader r) =>
        (r.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime) ? r.ReadUtcTime() : r.ReadGeneralizedTime()).UtcDateTime;

    private static IEnumerable<(string Oid, bool Critical, byte[] Value)> ReadExtensions(AsnReader seq)
    {
        var list = new List<(string, bool, byte[])>();
        while (seq.HasData)
        {
            var ext = seq.ReadSequence();
            var oid = ext.ReadObjectIdentifier();
            bool critical = ext.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean) && ext.ReadBoolean();
            var value = ext.ReadOctetString();
            ext.ThrowIfNotEmpty();
            list.Add((oid, critical, value));
        }
        return list;
    }

    private static byte[]? ReadAuthorityKeyId(byte[] value)
    {
        var seq = new AsnReader(value, AsnEncodingRules.DER).ReadSequence();
        return seq.HasData && seq.PeekTag().HasSameClassAndValue(Ctx0) ? seq.ReadOctetString(Ctx0) : null;
    }

    /// <summary>Only a distribution point name and the user/CA scope flags are understood; anything else narrows scope in ways we'd ignore.</summary>
    private static (bool OnlyUser, bool OnlyCa) ReadIssuingDistributionPoint(byte[] value)
    {
        var seq = new AsnReader(value, AsnEncodingRules.DER).ReadSequence();
        bool user = false, ca = false;
        while (seq.HasData)
        {
            var tag = seq.PeekTag();
            if (tag.TagClass != TagClass.ContextSpecific) throw new CryptographicException("malformed issuing distribution point");
            switch (tag.TagValue)
            {
                case 0: seq.ReadEncodedValue(); break;
                case 1: user = seq.ReadBoolean(new Asn1Tag(TagClass.ContextSpecific, 1)); break;
                case 2: ca = seq.ReadBoolean(new Asn1Tag(TagClass.ContextSpecific, 2)); break;
                case 4: throw new CryptographicException("indirect CRLs are not supported");
                default: throw new CryptographicException("CRLs limited to some revocation reasons or attribute certificates are not supported");
            }
        }
        return (user, ca);
    }
}

/// <summary>The CRLs from one ssl_crl file, indexed by issuer name.</summary>
public sealed class CrlSet
{
    private readonly Dictionary<string, List<Crl>> _byIssuer = new(StringComparer.Ordinal);

    public CrlSet(IEnumerable<Crl> crls)
    {
        foreach (var c in crls)
        {
            var key = Convert.ToHexString(c.IssuerName);
            if (!_byIssuer.TryGetValue(key, out var list)) _byIssuer[key] = list = new List<Crl>(1);
            list.Add(c);
        }
    }

    public IEnumerable<Crl> All => _byIssuer.Values.SelectMany(l => l);

    /// <summary>
    /// Check every certificate of a verified chain below its trust anchor (OpenSSL's CRL_CHECK_ALL): each needs a
    /// current CRL signed by its issuer that doesn't list it. Returns the failure reason, or null.
    /// </summary>
    public string? Check(X509ChainElementCollection chain, DateTime now)
    {
        for (int i = 0; i + 1 < chain.Count; i++)
        {
            var cert = chain[i].Certificate;
            var issuer = chain[i + 1].Certificate;
            bool isCa = i > 0;
            Crl? best = null;
            if (_byIssuer.TryGetValue(Convert.ToHexString(issuer.SubjectName.RawData), out var list))
            {
                var ski = SubjectKeyId(issuer);
                foreach (var c in list)
                {
                    if ((c.OnlyUser && isCa) || (c.OnlyCa && !isCa)) continue;
                    if (c.AuthorityKeyId is not null && ski is not null && !c.AuthorityKeyId.AsSpan().SequenceEqual(ski)) continue;
                    if (!c.IsSignedBy(issuer)) continue;
                    if (best is null || c.ThisUpdate > best.ThisUpdate) best = c;
                }
            }
            if (best is null) return list is null ? "unable to get certificate CRL" : "CRL signature failure";
            if (now < best.ThisUpdate) return "CRL is not yet valid";
            if (best.NextUpdate is { } next && now > next) return "CRL has expired";
            if (best.IsRevoked(cert)) return "certificate revoked";
        }
        return null;
    }

    private static byte[]? SubjectKeyId(X509Certificate2 cert)
    {
        foreach (var e in cert.Extensions)
            if (e is X509SubjectKeyIdentifierExtension ski) return ski.SubjectKeyIdentifierBytes.ToArray();
        return null;
    }
}
