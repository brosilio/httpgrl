using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Httpgrl.Tests;

/// <summary>
/// A throwaway CA plus a minimal OCSP responder (RFC 6960) on loopback: it answers every request for the CertID it was
/// asked about, signed by the CA, with "good" (or "revoked"). The server certificate's AIA points at it, so the
/// platform's OCSP fetch for stapling never leaves the machine.
/// </summary>
internal sealed class OcspPki : IAsyncDisposable
{
    public readonly X509Certificate2 Ca, Leaf;
    public readonly string LeafKeyPem;
    public int Requests => Volatile.Read(ref _requests);
    public TimeSpan Validity = TimeSpan.FromDays(3);
    /// <summary>Sign with a responder certificate the CA issued (with or without the OCSP-signing EKU), included in the response.</summary>
    public bool Delegated, DelegatedWithoutEku;
    public string Url => $"http://127.0.0.1:{_responder.Port}/";
    private bool _badSignature;
    public bool BadSignature { get => Volatile.Read(ref _badSignature); set => Volatile.Write(ref _badSignature, value); }
    private bool _revoked, _fail;
    public bool Revoked { get => Volatile.Read(ref _revoked); set => Volatile.Write(ref _revoked, value); }
    public bool Fail { get => Volatile.Read(ref _fail); set => Volatile.Write(ref _fail, value); }
    private int _requests;
    private readonly FakeUpstream _responder;

    public OcspPki(string dnsName, string? responderUrl = null)
    {
        int port = 0;
        _responder = new FakeUpstream(async (st, rd) =>
        {
            var (head, body) = await rd.ReadRequestAsync();
            if (head.Length == 0) return;
            Interlocked.Increment(ref _requests);
            byte[] reply;
            try { reply = Fail ? [0x30, 0x03, 0x0a, 0x01, 0x02] /* internalError */ : Respond(head, body); }
            catch (Exception) { reply = [0x30, 0x03, 0x0a, 0x01, 0x01]; } // malformedRequest
            await st.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: {reply.Length}\r\nConnection: close\r\n\r\n"));
            await st.WriteAsync(reply);
        });
        port = _responder.Port;

        var now = DateTimeOffset.UtcNow;
        using (var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var req = new CertificateRequest("CN=ocsp test ca", caKey, HashAlgorithmName.SHA256);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
            Ca = req.CreateSelfSigned(now.AddDays(-2), now.AddDays(30));
        }
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var lr = new CertificateRequest("CN=" + dnsName, key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(dnsName);
        lr.CertificateExtensions.Add(san.Build());
        lr.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        lr.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
        lr.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension([responderUrl ?? $"http://127.0.0.1:{port}/"], null));
        var serial = RandomNumberGenerator.GetBytes(12);
        serial[0] &= 0x7f;
        Leaf = lr.Create(Ca, now.AddDays(-1), now.AddDays(20), serial);
        LeafKeyPem = key.ExportPkcs8PrivateKeyPem();
    }

    /// <summary>Leaf then CA, as an nginx-style ssl_certificate file.</summary>
    public void WriteFiles(string dir, string name)
    {
        File.WriteAllText(Path.Combine(dir, name + ".crt"), Leaf.ExportCertificatePem() + "\n" + Ca.ExportCertificatePem() + "\n");
        File.WriteAllText(Path.Combine(dir, name + ".key"), LeafKeyPem);
    }

    private byte[] Respond(string head, byte[] body)
    {
        byte[] der;
        if (head.StartsWith("POST", StringComparison.Ordinal)) der = body;
        else
        {
            var path = head.Split(' ')[1].TrimStart('/');
            der = Convert.FromBase64String(Uri.UnescapeDataString(path));
        }
        // OCSPRequest -> tbsRequest -> requestList -> first Request -> reqCert (CertID), echoed back verbatim.
        var tbs = new AsnReader(der, AsnEncodingRules.DER).ReadSequence().ReadSequence();
        if (tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0, true))) tbs.ReadEncodedValue(); // version
        if (tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1, true))) tbs.ReadEncodedValue(); // requestorName
        var certId = tbs.ReadSequence().ReadSequence().ReadEncodedValue();
        return BuildResponse(certId.Span);
    }

    /// <summary>A signed OCSP response for <see cref="Leaf"/> (SHA-1 CertID, as most clients and servers request).</summary>
    public byte[] MakeResponse()
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence()) { w.WriteObjectIdentifier("1.3.14.3.2.26"); w.WriteNull(); }
            w.WriteOctetString(SHA1.HashData(Ca.SubjectName.RawData));
            w.WriteOctetString(SHA1.HashData(Ca.PublicKey.EncodedKeyValue.RawData));
            w.WriteInteger(Leaf.SerialNumberBytes.Span);
        }
        return BuildResponse(w.Encode());
    }

    private X509Certificate2? _delegate;

    private X509Certificate2 Delegate()
    {
        if (_delegate is not null) return _delegate;
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var r = new CertificateRequest("CN=ocsp responder", key, HashAlgorithmName.SHA256);
        r.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        if (!DelegatedWithoutEku) r.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.9") }, false));
        var serial = RandomNumberGenerator.GetBytes(8);
        serial[0] &= 0x7f;
        using var cert = r.Create(Ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(10), serial);
        return _delegate = cert.CopyWithPrivateKey(key);
    }

    private byte[] BuildResponse(ReadOnlySpan<byte> certId) => Sign(ResponseData(certId));

    /// <summary>The ResponseData (the signed part) for <see cref="Leaf"/>, for fuzzing what's inside the signature.</summary>
    public byte[] MakeResponseData()
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence()) { w.WriteObjectIdentifier("1.3.14.3.2.26"); w.WriteNull(); }
            w.WriteOctetString(SHA1.HashData(Ca.SubjectName.RawData));
            w.WriteOctetString(SHA1.HashData(Ca.PublicKey.EncodedKeyValue.RawData));
            w.WriteInteger(Leaf.SerialNumberBytes.Span);
        }
        return ResponseData(w.Encode());
    }

    private byte[] ResponseData(ReadOnlySpan<byte> certId)
    {
        var now = DateTime.UtcNow;
        bool delegated = Delegated || DelegatedWithoutEku;
        var signerCert = delegated ? Delegate() : Ca;
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence()) // ResponseData
        {
            using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2, true))) // responderID byKey
                w.WriteOctetString(SHA1.HashData(signerCert.PublicKey.EncodedKeyValue.RawData));
            w.WriteGeneralizedTime(now, omitFractionalSeconds: true);
            using (w.PushSequence()) // responses
            using (w.PushSequence()) // SingleResponse
            {
                w.WriteEncodedValue(certId);
                if (Revoked)
                {
                    using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true))) // revoked
                        w.WriteGeneralizedTime(now.AddHours(-1), omitFractionalSeconds: true);
                }
                else w.WriteNull(new Asn1Tag(TagClass.ContextSpecific, 0)); // good
                w.WriteGeneralizedTime(now.AddMinutes(-5), omitFractionalSeconds: true); // thisUpdate
                using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    w.WriteGeneralizedTime(now.Add(Validity), omitFractionalSeconds: true); // nextUpdate
            }
        }
        return w.Encode();
    }

    /// <summary>Sign any ResponseData bytes (valid or not) as the configured signer and wrap them in an OCSPResponse.</summary>
    public byte[] Sign(byte[] tbsData)
    {
        bool delegated = Delegated || DelegatedWithoutEku;
        var signerCert = delegated ? Delegate() : Ca;
        using var caKey = BadSignature ? ECDsa.Create(ECCurve.NamedCurves.nistP256) : signerCert.GetECDsaPrivateKey()!;
        var sig = caKey.SignData(tbsData, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var basic = new AsnWriter(AsnEncodingRules.DER);
        using (basic.PushSequence())
        {
            basic.WriteEncodedValue(tbsData);
            using (basic.PushSequence()) basic.WriteObjectIdentifier("1.2.840.10045.4.3.2"); // ecdsa-with-SHA256
            basic.WriteBitString(sig);
            if (delegated)
            {
                using (basic.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                using (basic.PushSequence())
                    basic.WriteEncodedValue(signerCert.RawData);
            }
        }
        var resp = new AsnWriter(AsnEncodingRules.DER);
        using (resp.PushSequence())
        {
            resp.WriteEnumeratedValue(OcspStatus.Successful);
            using (resp.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            using (resp.PushSequence())
            {
                resp.WriteObjectIdentifier("1.3.6.1.5.5.7.48.1.1"); // id-pkix-ocsp-basic
                resp.WriteOctetString(basic.Encode());
            }
        }
        return resp.Encode();
    }

    private enum OcspStatus { Successful = 0 }

    public async ValueTask DisposeAsync() => await _responder.DisposeAsync();
}
