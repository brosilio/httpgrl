using System.Text;
using Httpgrl.Core.Http;

namespace Httpgrl.Core.Http2;

/// <summary>
/// Builds a request from a decoded HTTP/2 field block (RFC 9113 8.2, 8.3), as strictly as RequestParser does HTTP/1.1:
/// lower-case names only, pseudo-fields first, each once, only the request ones, no connection-specific fields,
/// <c>:authority</c> and <c>Host</c> agreeing, one valid <c>content-length</c>, and the same path, host and value rules.
/// A malformed request is a stream error (PROTOCOL_ERROR); a refusal with a status (431, 405) is answered normally.
/// </summary>
internal sealed class RequestHead(bool underscores, HttpVersion version = HttpVersion.Http20)
{
    private RequestImpl _req = null!;
    private string? _method, _scheme, _path, _authority, _protocol;
    private bool _regular, _malformed;
    private string? _why;
    private int _status;
    private List<string>? _cookies;

    /// <summary>Why the request was malformed (for the log), once <see cref="Finish"/> returned -1.</summary>
    public string? Why => _why;

    public void Begin(RequestImpl req)
    {
        _req = req;
        _method = _scheme = _path = _authority = _protocol = null;
        _regular = _malformed = false;
        _why = null;
        _status = 0;
        _cookies?.Clear();
    }

    private void Malformed(string why)
    {
        if (_malformed) return;
        _malformed = true;
        _why = why;
    }

    /// <summary>The field handler for <see cref="HpackDecoder.Decode"/>. Keeps going after an error, so HPACK stays in step.</summary>
    public void OnField(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value)
    {
        if (_malformed) return;
        if (name.IsEmpty) { Malformed("empty field name"); return; }
        // RFC 9113 8.2.1 only forbids NUL, CR and LF; we apply HTTP/1.1's field-value rule (no CTL but HTAB, no DEL), so
        // what h2/h3 accept is what the HTTP/1.1 parser would, and an HTTP/1.1 upstream never sees bytes it would refuse.
        foreach (byte b in value)
            if ((b < 0x20 && b != '\t') || b == 0x7F) { Malformed("control character in a field value"); return; }
        if (value.Length > 0 && (value[0] is (byte)' ' or (byte)'\t' || value[^1] is (byte)' ' or (byte)'\t')) { Malformed("whitespace around a field value"); return; }

        if (name[0] == ':')
        {
            if (_regular) { Malformed("pseudo-field after a regular field"); return; }
            var v = Encoding.Latin1.GetString(value);
            if (name.SequenceEqual(":method"u8)) Set(ref _method, v, ":method");
            else if (name.SequenceEqual(":scheme"u8)) Set(ref _scheme, v, ":scheme");
            else if (name.SequenceEqual(":path"u8)) Set(ref _path, v, ":path");
            else if (name.SequenceEqual(":authority"u8)) Set(ref _authority, v, ":authority");
            else if (name.SequenceEqual(":protocol"u8)) Set(ref _protocol, v, ":protocol"); // extended CONNECT (RFC 8441)
            else Malformed("unknown or response pseudo-field");
            return;
        }
        _regular = true;
        foreach (byte b in name)
        {
            if (b is >= (byte)'A' and <= (byte)'Z') { Malformed("upper-case field name"); return; }
            if (!HttpChars.IsToken(b)) { Malformed("invalid field name"); return; }
        }
        // Connection-specific fields have no meaning in HTTP/2 (8.2.2); TE only as "trailers".
        if (name.SequenceEqual("connection"u8) || name.SequenceEqual("proxy-connection"u8) || name.SequenceEqual("keep-alive"u8)
            || name.SequenceEqual("transfer-encoding"u8) || name.SequenceEqual("upgrade"u8))
        { Malformed("connection-specific field"); return; }
        if (name.SequenceEqual("te"u8) && !value.SequenceEqual("trailers"u8)) { Malformed("TE other than trailers"); return; }
        if (!underscores && name.IndexOf((byte)'_') >= 0) return; // ignored, as in HTTP/1.1 (CGI header folding)
        // Cookies may arrive split into crumbs (8.2.3): rejoin them, for HTTP/1.1 semantics downstream.
        if (name.SequenceEqual("cookie"u8)) { (_cookies ??= new()).Add(Encoding.Latin1.GetString(value)); return; }
        _req.HeaderList.AddUnchecked(RequestParser.InternHeaderName(name), value.IsEmpty ? "" : Encoding.Latin1.GetString(value));
    }

    private void Set(ref string? slot, string value, string what)
    {
        if (slot is not null) Malformed("duplicate " + what);
        else slot = value;
    }

    /// <summary>
    /// Complete the request. <paramref name="endStream"/>: the HEADERS frame ended the stream (no body follows).
    /// 0: a valid request; -1: malformed (stream PROTOCOL_ERROR, see <see cref="Why"/>); otherwise a status to answer.
    /// </summary>
    public int Finish(bool endStream)
    {
        if (_malformed) return -1;
        var req = _req;
        if (_cookies is { Count: > 0 }) req.HeaderList.AddUnchecked("Cookie", string.Join("; ", _cookies));
        if (_method is null) { Malformed("no :method"); return -1; }
        var method = Encoding.ASCII.GetBytes(_method);
        if (method.Length is 0 or > 32) { Malformed("invalid :method"); return -1; }
        foreach (byte b in method) if (!HttpChars.IsToken(b)) { Malformed("invalid :method"); return -1; }
        req.MethodValue = RequestParser.InternMethod(method);
        req.VersionValue = version; // HTTP/3 (RFC 9114 4.3) has the same rules for its fields

        bool websocket = false;
        if (ReferenceEquals(req.MethodValue, HttpMethods.Connect))
        {
            // Plain CONNECT (a TCP tunnel) is refused, as on HTTP/1.1.
            if (_protocol is null) return 405;
            // Extended CONNECT (RFC 8441): a tunnel for :protocol over this stream. It needs :scheme and :path like any
            // request, can't end with its HEADERS, and carries no request body.
            if (endStream) { Malformed("extended CONNECT with END_STREAM"); return -1; }
            if (req.HeaderList.Contains("Content-Length")) { Malformed("content-length on CONNECT"); return -1; }
            if (!_protocol.Equals("websocket", StringComparison.OrdinalIgnoreCase)) return 501; // nothing else is tunnelled (h2c least of all)
            websocket = true;
        }
        else if (_protocol is not null) { Malformed(":protocol outside CONNECT"); return -1; }
        // We only speak HTTP/2 over TLS: the scheme is https.
        if (_scheme != "https") { Malformed(_scheme is null ? "no :scheme" : ":scheme isn't https"); return -1; }
        if (string.IsNullOrEmpty(_path)) { Malformed("no :path"); return -1; }

        // :path is origin-form, or "*" for OPTIONS; the same rules and normalization as an HTTP/1.1 target.
        var target = Encoding.Latin1.GetBytes(_path);
        foreach (byte b in target) if (b <= 0x20 || b == 0x7F) { Malformed("invalid :path"); return -1; }
        req.RawTargetValue = req.RequestUriValue = _path;
        if (_path == "*")
        {
            if (!ReferenceEquals(req.MethodValue, HttpMethods.Options)) { Malformed("* outside OPTIONS"); return -1; }
            req.PathValue = "*";
            req.QueryValue = "";
        }
        else
        {
            if (target[0] != '/' || target.AsSpan().IndexOf((byte)'#') >= 0) { Malformed("invalid :path"); return -1; }
            int q = target.AsSpan().IndexOf((byte)'?');
            var path = UriNormalizer.NormalizeRaw(q < 0 ? target : target.AsSpan(0, q));
            if (path is null) { Malformed("invalid :path"); return -1; }
            req.PathValue = path;
            req.QueryValue = q < 0 ? "" : _path[(q + 1)..];
        }

        // Host: :authority (8.3.1), else a Host field; both present must agree.
        var headers = req.HeaderList;
        if (headers.CountOf("Host") > 1) { Malformed("duplicate host"); return -1; }
        var hostField = headers.Get("Host");
        var authority = _authority is { Length: > 0 } ? _authority : null;
        if (authority is not null && authority.Contains('@')) { Malformed("userinfo in :authority"); return -1; }
        var host = authority ?? hostField;
        if (host is null) { Malformed("no :authority or host"); return -1; }
        var normalized = RequestParser.NormalizeHost(host);
        if (normalized is null) { Malformed("invalid :authority"); return -1; }
        if (authority is not null && hostField is not null && RequestParser.NormalizeHost(hostField) != normalized) { Malformed(":authority and host disagree"); return -1; }
        req.HostValue = normalized;
        if (hostField is null) headers.AddUnchecked("Host", authority!); // modules and upstreams see a Host, as on HTTP/1.1

        // Framing: DATA frames carry the body; content-length, if any, is one valid number and must match them.
        int cl = headers.CountOf("Content-Length");
        if (cl > 1) { Malformed("duplicate content-length"); return -1; }
        if (cl == 1)
        {
            var v = headers.Get("Content-Length")!;
            if (v.Length is 0 or > 18) { Malformed("invalid content-length"); return -1; }
            long n = 0;
            foreach (char c in v)
            {
                if ((uint)(c - '0') > 9) { Malformed("invalid content-length"); return -1; }
                n = n * 10 + (c - '0');
            }
            if (endStream && n != 0) { Malformed("content-length without a body"); return -1; }
            req.ContentLengthValue = n;
        }
        else if (!endStream && !websocket) req.ChunkedValue = true; // a body of unknown length: HTTP/1.1's chunked, as far as anyone downstream knows
        if (websocket)
        {
            // Modules see what an HTTP/1.1 client would have sent: GET with Upgrade, so WebSocket handling (the proxy's
            // tunnelling) works unchanged. The key is ours; HTTP/2 has none, and an HTTP/1.1 upstream needs one.
            req.MethodValue = HttpMethods.Get;
            req.ExtendedConnect = true;
            req.ConnUpgrade = true;
            headers.AddUnchecked("Upgrade", "websocket");
            headers.AddUnchecked("Connection", "Upgrade");
            if (!headers.Contains("Sec-WebSocket-Key"))
            {
                Span<byte> key = stackalloc byte[16];
                System.Security.Cryptography.RandomNumberGenerator.Fill(key);
                headers.AddUnchecked("Sec-WebSocket-Key", Convert.ToBase64String(key));
            }
        }
        var expect = headers.Get("Expect");
        if (expect is not null && !expect.Equals("100-continue", StringComparison.OrdinalIgnoreCase)) return 417;
        return _status;
    }

    /// <summary>Trailers (a HEADERS frame ending the stream): checked like any field, then dropped, as on HTTP/1.1.</summary>
    public static string? CheckTrailer(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value)
    {
        if (name.IsEmpty || name[0] == ':') return "pseudo-field in trailers";
        foreach (byte b in name) if (b is >= (byte)'A' and <= (byte)'Z' || !HttpChars.IsToken(b)) return "invalid trailer name";
        foreach (byte b in value) if (b is 0 or (byte)'\r' or (byte)'\n') return "CR, LF or NUL in a trailer";
        return null;
    }
}
