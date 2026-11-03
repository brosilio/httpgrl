using System.Formats.Asn1;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Httpgrl.Core.Modules;

internal enum OcspCertStatus : byte { Good, Revoked, Unknown }

/// <summary>A verified OCSP response for one certificate, ready to staple.</summary>
internal sealed record OcspVerified(byte[] Der, OcspCertStatus Status, DateTime ThisUpdate, DateTime Expires);

/// <summary>
/// OCSP (RFC 6960) for stapling: building the request, and verifying a response before we hand it to clients.
/// The platform's own fetcher is bypassed (see <see cref="StaplingAccess"/>), so verification is ours: a response is
/// only stapled if it is a successful basic response, about this certificate, signed by its issuer or by a responder
/// certificate the issuer delegated OCSP signing to, consistent with its responder ID, and within its validity.
/// Parsing never throws: anything malformed is a failure reason.
/// </summary>
internal static class Ocsp
{
    private const string Sha1 = "1.3.14.3.2.26", Sha256 = "2.16.840.1.101.3.4.2.1", Sha384 = "2.16.840.1.101.3.4.2.2", Sha512 = "2.16.840.1.101.3.4.2.3";
    private const string OcspSigning = "1.3.6.1.5.5.7.3.9", BasicResponse = "1.3.6.1.5.5.7.48.1.1";
    private static readonly TimeSpan Skew = TimeSpan.FromMinutes(5);
    /// <summary>A response without nextUpdate is "current" only; we treat it as good for this long.</summary>
    private static readonly TimeSpan NoNextUpdateValidity = TimeSpan.FromHours(1);
    public const int MaxResponseBytes = 64 * 1024;

    /// <summary>DER OCSPRequest for <paramref name="leaf"/>: one SHA-1 CertID, no nonce (RFC 5019, cache-friendly).</summary>
    public static byte[] BuildRequest(X509Certificate2 leaf, X509Certificate2 issuer)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())          // OCSPRequest
        using (w.PushSequence())          // TBSRequest
        using (w.PushSequence())          // requestList
        using (w.PushSequence())          // Request
        using (w.PushSequence())          // CertID
        {
            using (w.PushSequence()) { w.WriteObjectIdentifier(Sha1); w.WriteNull(); }
            w.WriteOctetString(SHA1.HashData(issuer.SubjectName.RawData));
            w.WriteOctetString(SHA1.HashData(issuer.PublicKey.EncodedKeyValue.RawData));
            w.WriteInteger(leaf.SerialNumberBytes.Span);
        }
        return w.Encode();
    }

    /// <summary>Verify <paramref name="der"/> as a stapleable response for <paramref name="leaf"/>. Returns null and a reason on failure.</summary>
    public static OcspVerified? Verify(byte[] der, X509Certificate2 leaf, X509Certificate2 issuer, DateTime now, out string? failure)
    {
        try { return VerifyCore(der, leaf, issuer, now, out failure); }
        catch (Exception e) when (e is AsnContentException or CryptographicException or ArgumentException or FormatException or OverflowException)
        {
            failure = "malformed response: " + e.Message;
            return null;
        }
    }

    private static readonly Asn1Tag C0 = new(TagClass.ContextSpecific, 0, true), C1 = new(TagClass.ContextSpecific, 1, true), C2 = new(TagClass.ContextSpecific, 2, true);

    private static OcspVerified? VerifyCore(byte[] der, X509Certificate2 leaf, X509Certificate2 issuer, DateTime now, out string? failure)
    {
        failure = null;
        if (der.Length > MaxResponseBytes) { failure = "response too large"; return null; }

        // OCSPResponse
        var top = new AsnReader(der, AsnEncodingRules.DER);
        var resp = top.ReadSequence();
        top.ThrowIfNotEmpty();
        var status = resp.ReadEnumeratedBytes();
        if (status.Length != 1 || status.Span[0] != 0) { failure = $"responder status {(status.Length == 1 ? status.Span[0] : -1)} (not successful)"; return null; }
        var bytesWrap = resp.ReadSequence(C0);
        var responseBytes = bytesWrap.ReadSequence();
        if (responseBytes.ReadObjectIdentifier() != BasicResponse) { failure = "not a basic OCSP response"; return null; }
        var basicDer = responseBytes.ReadOctetString();
        responseBytes.ThrowIfNotEmpty();
        bytesWrap.ThrowIfNotEmpty();
        resp.ThrowIfNotEmpty();

        // BasicOCSPResponse
        var basicTop = new AsnReader(basicDer, AsnEncodingRules.DER);
        var basic = basicTop.ReadSequence();
        basicTop.ThrowIfNotEmpty();
        var tbsDer = basic.ReadEncodedValue();
        var algSeq = basic.ReadSequence();
        var sigAlg = algSeq.ReadObjectIdentifier();
        if (algSeq.HasData) algSeq.ReadNull();
        algSeq.ThrowIfNotEmpty();
        var signature = basic.ReadBitString(out int unused);
        if (unused != 0) { failure = "malformed signature"; return null; }
        var included = new List<X509Certificate2>();
        if (basic.HasData)
        {
            var certsWrap = basic.ReadSequence(C0);
            var certs = certsWrap.ReadSequence();
            while (certs.HasData)
            {
                included.Add(X509CertificateLoader.LoadCertificate(certs.ReadEncodedValue().Span));
                if (included.Count > 8) { failure = "too many certificates in response"; return null; }
            }
            certsWrap.ThrowIfNotEmpty();
        }
        basic.ThrowIfNotEmpty();

        // ResponseData
        var tbs = new AsnReader(tbsDer, AsnEncodingRules.DER).ReadSequence();
        if (tbs.PeekTag().HasSameClassAndValue(C0))
        {
            var v = tbs.ReadSequence(C0);
            if (!v.TryReadInt32(out int version) || version != 0) { failure = "unsupported response version"; return null; }
        }
        byte[]? responderName = null, responderKeyHash = null;
        var rid = tbs.PeekTag();
        if (rid.HasSameClassAndValue(C1)) responderName = tbs.ReadSequence(C1).ReadEncodedValue().ToArray();
        else if (rid.HasSameClassAndValue(C2)) responderKeyHash = tbs.ReadSequence(C2).ReadOctetString();
        else { failure = "malformed responder ID"; return null; }
        tbs.ReadGeneralizedTime(); // producedAt
        var responses = tbs.ReadSequence();
        if (tbs.HasData)
        {
            foreach (var (_, critical) in ReadExtensions(tbs.ReadSequence(C1)))
                if (critical) { failure = "unsupported critical response extension"; return null; }
        }
        tbs.ThrowIfNotEmpty();

        // The single response about our certificate.
        OcspCertStatus? certStatus = null;
        DateTime thisUpdate = default;
        DateTime? nextUpdate = null;
        while (responses.HasData)
        {
            var single = responses.ReadSequence();
            var certId = single.ReadSequence();
            bool ours = CertIdMatches(certId, leaf, issuer);
            var st = single.PeekTag();
            OcspCertStatus s;
            if (st.TagClass == TagClass.ContextSpecific && st.TagValue == 0) { single.ReadNull(new Asn1Tag(TagClass.ContextSpecific, 0)); s = OcspCertStatus.Good; }
            else if (st.TagClass == TagClass.ContextSpecific && st.TagValue == 1) { single.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)); s = OcspCertStatus.Revoked; }
            else if (st.TagClass == TagClass.ContextSpecific && st.TagValue == 2) { single.ReadNull(new Asn1Tag(TagClass.ContextSpecific, 2)); s = OcspCertStatus.Unknown; }
            else { failure = "malformed certificate status"; return null; }
            var tu = single.ReadGeneralizedTime().UtcDateTime;
            DateTime? nu = null;
            if (single.HasData && single.PeekTag().HasSameClassAndValue(C0)) nu = single.ReadSequence(C0).ReadGeneralizedTime().UtcDateTime;
            if (single.HasData)
            {
                foreach (var (_, critical) in ReadExtensions(single.ReadSequence(C1)))
                    if (critical) { failure = "unsupported critical single-response extension"; return null; }
            }
            single.ThrowIfNotEmpty();
            if (!ours || certStatus is not null) continue;
            certStatus = s;
            thisUpdate = tu;
            nextUpdate = nu;
        }
        if (certStatus is null) { failure = "response is not about this certificate"; return null; }

        // Who signed it: the issuer, or a responder certificate the issuer delegated OCSP signing to (RFC 6960 4.2.2.2).
        var signer = ResolveSigner(issuer, included, responderName, responderKeyHash, now, out failure);
        if (signer is null) return null;
        if (!SignatureValid(signer, sigAlg, tbsDer.Span, signature)) { failure = "bad signature"; return null; }

        if (thisUpdate > now + Skew) { failure = "response is not yet valid (thisUpdate in the future)"; return null; }
        var expires = nextUpdate ?? thisUpdate + NoNextUpdateValidity;
        if (expires <= now) { failure = "response has expired"; return null; }
        if (certStatus == OcspCertStatus.Unknown) { failure = "responder doesn't know this certificate (status unknown)"; return null; }
        return new OcspVerified(der, certStatus.Value, thisUpdate, expires);
    }

    private static bool CertIdMatches(AsnReader certId, X509Certificate2 leaf, X509Certificate2 issuer)
    {
        var alg = certId.ReadSequence();
        var oid = alg.ReadObjectIdentifier();
        var nameHash = certId.ReadOctetString();
        var keyHash = certId.ReadOctetString();
        var serial = certId.ReadIntegerBytes();
        certId.ThrowIfNotEmpty();
        HashAlgorithmName? h = oid switch { Sha1 => HashAlgorithmName.SHA1, Sha256 => HashAlgorithmName.SHA256, Sha384 => HashAlgorithmName.SHA384, Sha512 => HashAlgorithmName.SHA512, _ => null };
        if (h is null) return false;
        return serial.Span.SequenceEqual(leaf.SerialNumberBytes.Span)
            && nameHash.AsSpan().SequenceEqual(Hash(h.Value, issuer.SubjectName.RawData))
            && keyHash.AsSpan().SequenceEqual(Hash(h.Value, issuer.PublicKey.EncodedKeyValue.RawData));
    }

    private static byte[] Hash(HashAlgorithmName h, byte[] data) =>
        h == HashAlgorithmName.SHA1 ? SHA1.HashData(data) : h == HashAlgorithmName.SHA256 ? SHA256.HashData(data) : h == HashAlgorithmName.SHA384 ? SHA384.HashData(data) : SHA512.HashData(data);

    private static X509Certificate2? ResolveSigner(X509Certificate2 issuer, List<X509Certificate2> included, byte[]? responderName, byte[]? responderKeyHash, DateTime now, out string? failure)
    {
        failure = null;
        if (Identifies(issuer, responderName, responderKeyHash)) return issuer;
        foreach (var c in included)
        {
            if (!Identifies(c, responderName, responderKeyHash)) continue;
            // A delegated responder: issued (signed) directly by our issuer, for OCSP signing, currently valid.
            bool ocspEku = false;
            foreach (var e in c.Extensions)
                if (e is X509EnhancedKeyUsageExtension eku)
                    foreach (var o in eku.EnhancedKeyUsages) if (o.Value == OcspSigning) ocspEku = true;
            if (!ocspEku) { failure = "responder certificate isn't authorized for OCSP signing"; return null; }
            if (now < c.NotBefore.ToUniversalTime() || now > c.NotAfter.ToUniversalTime()) { failure = "responder certificate is not valid now"; return null; }
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(issuer);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // id-pkix-ocsp-nocheck is the norm for responder certs
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.VerificationTime = now;
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(OcspSigning));
            if (!chain.Build(c) || chain.ChainElements.Count != 2 || !chain.ChainElements[1].Certificate.RawDataMemory.Span.SequenceEqual(issuer.RawDataMemory.Span))
            {
                failure = "responder certificate isn't issued by the certificate's issuer";
                return null;
            }
            return c;
        }
        failure = "response is signed by neither the issuer nor a delegated responder";
        return null;
    }

    private static bool Identifies(X509Certificate2 c, byte[]? name, byte[]? keyHash) =>
        name is not null ? c.SubjectName.RawData.AsSpan().SequenceEqual(name) : SHA1.HashData(c.PublicKey.EncodedKeyValue.RawData).AsSpan().SequenceEqual(keyHash);

    private static bool SignatureValid(X509Certificate2 signer, string alg, ReadOnlySpan<byte> data, byte[] sig)
    {
        switch (alg)
        {
            case "1.2.840.10045.4.3.2" or "1.2.840.10045.4.3.3" or "1.2.840.10045.4.3.4":
            {
                using var k = signer.GetECDsaPublicKey();
                var h = alg[^1] == '2' ? HashAlgorithmName.SHA256 : alg[^1] == '3' ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA512;
                return k is not null && k.VerifyData(data, sig, h, DSASignatureFormat.Rfc3279DerSequence);
            }
            case "1.2.840.113549.1.1.11" or "1.2.840.113549.1.1.12" or "1.2.840.113549.1.1.13" or "1.2.840.113549.1.1.5":
            {
                using var k = signer.GetRSAPublicKey();
                var h = alg switch
                {
                    "1.2.840.113549.1.1.11" => HashAlgorithmName.SHA256,
                    "1.2.840.113549.1.1.12" => HashAlgorithmName.SHA384,
                    "1.2.840.113549.1.1.13" => HashAlgorithmName.SHA512,
                    _ => HashAlgorithmName.SHA1, // still common for OCSP responses; forging one needs a chosen-prefix collision on responder-made data
                };
                return k is not null && k.VerifyData(data, sig, h, RSASignaturePadding.Pkcs1);
            }
            default: return false;
        }
    }

    private static List<(string Oid, bool Critical)> ReadExtensions(AsnReader wrapper)
    {
        var list = new List<(string, bool)>();
        var seq = wrapper.ReadSequence();
        while (seq.HasData)
        {
            var e = seq.ReadSequence();
            var oid = e.ReadObjectIdentifier();
            bool critical = e.HasData && e.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean) && e.ReadBoolean();
            e.ReadOctetString();
            e.ThrowIfNotEmpty();
            list.Add((oid, critical));
        }
        wrapper.ThrowIfNotEmpty();
        return list;
    }
}

/// <summary>Stapling state that survives a reload (keyed by certificate), so reloading doesn't refetch or drop the staple.</summary>
internal sealed class StapleState
{
    public volatile OcspVerified? Current;
    public DateTime NextFetch;
    public int Failures;
    /// <summary>
    /// Held for a fetch and the state update after it. During a reload drain the old configuration's stapler and the
    /// new one share this state; the gate keeps them to one fetch between them (the second sees the new NextFetch).
    /// </summary>
    public readonly SemaphoreSlim FetchGate = new(1, 1);
}

/// <summary>
/// Drives stapling for one certificate context: fetch on first use, refresh hourly, back off 5 minutes after a failure
/// (nginx's schedule), keep stapling a valid response through an outage, drop it the moment it expires. Never more
/// than one fetch in flight, across reloads too (<see cref="StapleState.FetchGate"/>); nothing a client does can
/// trigger extra fetches. With ssl_stapling_file the response is
/// fixed and nothing is fetched.
/// </summary>
internal sealed class OcspStapler
{
    public static readonly TimeSpan Refresh = TimeSpan.FromHours(1), FailureBackoff = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan FetchTimeout = TimeSpan.FromSeconds(15);

    private readonly SslStreamCertificateContext _ctx;
    private readonly X509Certificate2 _leaf, _issuer;
    private readonly string[] _urls;
    private readonly StapleState _state;
    private readonly ILogger _log;
    private readonly bool _fixed;
    private int _started;
    private readonly CancellationTokenSource _stop = new();
    private static readonly System.Net.Http.HttpClient Http = new(new System.Net.Http.SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        ConnectTimeout = TimeSpan.FromSeconds(10),
        MaxResponseHeadersLength = 16,
    }) { Timeout = FetchTimeout, MaxResponseContentBufferSize = Ocsp.MaxResponseBytes };

    public OcspStapler(SslStreamCertificateContext ctx, X509Certificate2 leaf, X509Certificate2 issuer, string[] urls, StapleState state, ILogger log, OcspVerified? fixedResponse)
    {
        _ctx = ctx;
        _leaf = leaf;
        _issuer = issuer;
        _urls = urls;
        _state = state;
        _log = log;
        _fixed = fixedResponse is not null;
        if (fixedResponse is not null) _state.Current = fixedResponse;
        Apply(DateTime.UtcNow);
    }

    /// <summary>Called for every handshake that uses this certificate. Cheap: starts the refresher once, drops an expired staple.</summary>
    public void OnHandshake()
    {
        if (_state.Current is { } cur && cur.Expires <= DateTime.UtcNow) Apply(DateTime.UtcNow);
        if (_fixed || Volatile.Read(ref _started) != 0 || Interlocked.Exchange(ref _started, 1) != 0) return;
        _ = Task.Run(LoopAsync);
    }

    /// <summary>Hand the platform the current response if it's still valid, else nothing.</summary>
    private void Apply(DateTime now)
    {
        var cur = _state.Current;
        StaplingAccess.Set(_ctx, cur is not null && cur.Expires > now ? cur.Der : null);
    }

    private async Task LoopAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            var now = DateTime.UtcNow;
            if (now >= _state.NextFetch)
            {
                try { await _state.FetchGate.WaitAsync(_stop.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                try { if (DateTime.UtcNow >= _state.NextFetch) await FetchAsync().ConfigureAwait(false); }
                finally { _state.FetchGate.Release(); }
            }
            now = DateTime.UtcNow;
            Apply(now);
            // Wake for the next fetch, or when the current response expires, whichever is first.
            var wake = _state.NextFetch;
            if (_state.Current is { } cur && cur.Expires > now && cur.Expires < wake) wake = cur.Expires;
            var delay = wake - now;
            if (delay < TimeSpan.FromSeconds(1)) delay = TimeSpan.FromSeconds(1);
            try { await Task.Delay(delay, _stop.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
        }
    }

    private async Task FetchAsync()
    {
        var request = Ocsp.BuildRequest(_leaf, _issuer);
        string? lastError = null;
        foreach (var url in _urls)
        {
            try
            {
                using var msg = BuildHttpRequest(url, request);
                using var resp = await Http.SendAsync(msg, _stop.Token).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode) { lastError = $"HTTP {(int)resp.StatusCode} from {url}"; continue; }
                var der = await resp.Content.ReadAsByteArrayAsync(_stop.Token).ConfigureAwait(false);
                var v = Ocsp.Verify(der, _leaf, _issuer, DateTime.UtcNow, out var why);
                if (v is null) { lastError = $"{why} ({url})"; continue; }
                Accept(v, url);
                return;
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { return; }
            catch (Exception e) when (e is System.Net.Http.HttpRequestException or TaskCanceledException or IOException)
            {
                lastError = $"{(e is TaskCanceledException ? "timed out" : e.Message)} ({url})";
            }
        }
        _state.Failures++;
        _state.NextFetch = DateTime.UtcNow + FailureBackoff;
        var cur = _state.Current;
        _log.Warn(cur is not null && cur.Expires > DateTime.UtcNow
                ? "OCSP refresh failed; still stapling the previous response until it expires"
                : "OCSP fetch failed; not stapling",
            new("certificate", _leaf.Subject), new("error", lastError), new("retry_in_s", (long)FailureBackoff.TotalSeconds),
            new("expires", cur?.Expires.ToString("O")));
    }

    private void Accept(OcspVerified v, string url)
    {
        bool recovered = _state.Failures > 0 || _state.Current is null;
        _state.Current = v;
        _state.Failures = 0;
        var next = DateTime.UtcNow + Refresh;
        if (v.Expires - TimeSpan.FromMinutes(1) < next) next = v.Expires - TimeSpan.FromMinutes(1); // refresh before it lapses
        _state.NextFetch = next > DateTime.UtcNow ? next : DateTime.UtcNow + TimeSpan.FromMinutes(1);
        if (v.Status == OcspCertStatus.Revoked)
            _log.Warn("OCSP: the responder says this certificate is REVOKED; stapling that, so clients will reject it", new("certificate", _leaf.Subject), new("responder", url));
        else if (recovered)
            _log.Info("OCSP response stapled", new("certificate", _leaf.Subject), new("responder", url), new("expires", v.Expires.ToString("O")));
    }

    /// <summary>RFC 5019: GET with the base64 request in the path when it's short, POST otherwise.</summary>
    private static System.Net.Http.HttpRequestMessage BuildHttpRequest(string url, byte[] request)
    {
        var b64 = Uri.EscapeDataString(Convert.ToBase64String(request));
        if (url.Length + b64.Length < 255)
            return new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, url.TrimEnd('/') + "/" + b64);
        var m = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Post, url) { Content = new System.Net.Http.ByteArrayContent(request) };
        m.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/ocsp-request");
        return m;
    }

    public void Stop()
    {
        try { _stop.Cancel(); } catch (ObjectDisposedException) { }
    }
}
