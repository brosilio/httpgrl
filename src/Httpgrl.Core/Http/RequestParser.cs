using System.Text;

namespace Httpgrl.Core.Http;

internal readonly struct HeadLimits(int lineMax, int totalMax, int maxHeaders)
{
    public readonly int LineMax = lineMax;
    public readonly int TotalMax = totalMax;
    public readonly int MaxHeaders = maxHeaders;
}

/// <summary>
/// HTTP/1.x request-head parser. Strict by design: CRLF only, no obs-fold, no whitespace before ':',
/// single Content-Length, Transfer-Encoding exactly "chunked" and never alongside Content-Length.
/// Anything a proxy in front or behind could interpret differently is rejected.
/// </summary>
internal static class RequestParser
{
    private static ReadOnlySpan<byte> HeadEnd => "\r\n\r\n"u8;

    /// <summary>Length of the head including the blank line, or -1 if not yet complete.</summary>
    public static int FindHeadEnd(InputBuffer inb)
    {
        int from = Math.Max(inb.Start, inb.Scan - 3);
        int i = inb.Buf.AsSpan(from, inb.End - from).IndexOf(HeadEnd);
        if (i < 0) { inb.Scan = inb.End; return -1; }
        return from + i + 4 - inb.Start;
    }

    /// <summary>Status to answer an incomplete head that has hit a limit, or 0 to keep reading.</summary>
    public static int CheckIncomplete(ReadOnlySpan<byte> data, in HeadLimits lim)
    {
        int nl = data.IndexOf((byte)'\n');
        if (nl < 0) return data.Length >= lim.LineMax ? 414 : (data.Length >= lim.TotalMax ? 431 : 0);
        return data.Length >= lim.TotalMax ? 431 : 0;
    }

    /// <summary>Parse and validate a complete head into <paramref name="req"/>. Returns 0 or an HTTP error status.</summary>
    public static int Parse(ReadOnlySpan<byte> head, RequestImpl req, in HeadLimits lim)
    {
        // ---- request line ----
        int eol = head.IndexOf((byte)'\n');
        if (eol < 1 || head[eol - 1] != (byte)'\r') return 400;
        var line = head[..(eol - 1)];
        if (line.Length > lim.LineMax) return 414;

        int sp1 = line.IndexOf((byte)' ');
        if (sp1 <= 0 || sp1 > 32) return 400;
        var method = line[..sp1];
        foreach (byte b in method) if (!HttpChars.IsToken(b)) return 400;

        var rest = line[(sp1 + 1)..];
        int sp2 = rest.IndexOf((byte)' ');
        if (sp2 <= 0) return 400;
        var target = rest[..sp2];
        var version = rest[(sp2 + 1)..];
        foreach (byte b in target) if (b <= 0x20 || b == 0x7F) return 400;

        if (version.SequenceEqual("HTTP/1.1"u8)) req.VersionValue = HttpVersion.Http11;
        else if (version.SequenceEqual("HTTP/1.0"u8)) req.VersionValue = HttpVersion.Http10;
        else if (version.Length == 8 && version.StartsWith("HTTP/"u8) && char.IsAsciiDigit((char)version[5]) && version[6] == '.' && char.IsAsciiDigit((char)version[7])) return 505;
        else return 400;

        req.MethodValue = InternMethod(method);
        req.RawTargetValue = Encoding.Latin1.GetString(target);

        // ---- header fields ----
        var headers = req.HeaderList;
        int pos = eol + 1;
        while (true)
        {
            if (pos >= head.Length) return 400;
            int nl = head[pos..].IndexOf((byte)'\n');
            if (nl < 1 || head[pos + nl - 1] != (byte)'\r') return 400;
            var h = head.Slice(pos, nl - 1);
            pos += nl + 1;
            if (h.IsEmpty) break;
            if (h.Length > lim.LineMax) return 431;
            if (headers.Count >= lim.MaxHeaders) return 431;

            int colon = h.IndexOf((byte)':');
            if (colon <= 0) return 400; // also rejects obs-fold (leading SP/HTAB is not a tchar)
            var name = h[..colon];
            foreach (byte b in name) if (!HttpChars.IsToken(b)) return 400;
            var value = h[(colon + 1)..];
            int s = 0, e = value.Length;
            while (s < e && (value[s] == ' ' || value[s] == '\t')) s++;
            while (e > s && (value[e - 1] == ' ' || value[e - 1] == '\t')) e--;
            value = value[s..e];
            foreach (byte b in value) if ((b < 0x20 && b != '\t') || b == 0x7F) return 400;
            headers.AddUnchecked(InternHeaderName(name), value.IsEmpty ? "" : Encoding.Latin1.GetString(value));
        }

        return Validate(req, target);
    }

    private static int Validate(RequestImpl req, ReadOnlySpan<byte> target)
    {
        var headers = req.HeaderList;

        // ---- request target ----
        ReadOnlySpan<byte> pathAndQuery;
        string? uriHost = null;
        if (target[0] == '/') pathAndQuery = target;
        else if (target.Length == 1 && target[0] == '*')
        {
            if (!ReferenceEquals(req.MethodValue, HttpMethods.Options)) return 400;
            pathAndQuery = "*"u8;
        }
        else if (ReferenceEquals(req.MethodValue, HttpMethods.Connect)) return 405;
        else
        {
            int schemeLen = StartsWithIgnoreCase(target, "http://"u8) ? 7 : StartsWithIgnoreCase(target, "https://"u8) ? 8 : 0;
            if (schemeLen == 0) return 400;
            var afterScheme = target[schemeLen..];
            int slash = afterScheme.IndexOfAny((byte)'/', (byte)'?');
            var authority = slash < 0 ? afterScheme : afterScheme[..slash];
            if (authority.IsEmpty || authority.IndexOf((byte)'@') >= 0) return 400;
            uriHost = Encoding.Latin1.GetString(authority);
            pathAndQuery = slash < 0 ? "/"u8 : afterScheme[slash..];
            if (pathAndQuery[0] == '?') return 400;
        }
        if (pathAndQuery.IndexOf((byte)'#') >= 0) return 400;

        if (pathAndQuery.Length == 1 && pathAndQuery[0] == '*')
        {
            req.PathValue = "*";
            req.QueryValue = "";
        }
        else
        {
            int q = pathAndQuery.IndexOf((byte)'?');
            var rawPath = q < 0 ? pathAndQuery : pathAndQuery[..q];
            req.QueryValue = q < 0 ? "" : Encoding.Latin1.GetString(pathAndQuery[(q + 1)..]);
            var path = UriNormalizer.NormalizeRaw(rawPath);
            if (path is null) return 400;
            req.PathValue = path;
        }

        // ---- Host ----
        int hostCount = headers.CountOf("Host");
        if (hostCount > 1) return 400;
        string? host = uriHost ?? headers.Get("Host");
        if (host is null)
        {
            if (req.VersionValue == HttpVersion.Http11) return 400;
            req.HostValue = "";
        }
        else
        {
            var h = NormalizeHost(host);
            if (h is null) return 400;
            req.HostValue = h;
        }

        // ---- framing ----
        int clCount = headers.CountOf("Content-Length");
        int teCount = headers.CountOf("Transfer-Encoding");
        if (teCount > 0)
        {
            if (clCount > 0 || req.VersionValue == HttpVersion.Http10) return 400;
            if (teCount > 1) return 501;
            if (!headers.Get("Transfer-Encoding")!.Equals("chunked", StringComparison.OrdinalIgnoreCase)) return 501;
            req.ChunkedValue = true;
        }
        else if (clCount > 0)
        {
            if (clCount > 1) return 400;
            var v = headers.Get("Content-Length")!;
            if (v.Length is 0 or > 18) return 400;
            long n = 0;
            foreach (char c in v)
            {
                if ((uint)(c - '0') > 9) return 400;
                n = n * 10 + (c - '0');
            }
            req.ContentLengthValue = n;
        }

        // ---- Connection / Expect ----
        for (int i = 0; i < headers.Count; i++)
        {
            if (!headers.NameAt(i).Equals("Connection", StringComparison.OrdinalIgnoreCase)) continue;
            foreach (var tokRange in headers.ValueAt(i).AsSpan().Split(','))
            {
                var tok = headers.ValueAt(i).AsSpan()[tokRange].Trim(" \t");
                if (tok.Equals("close", StringComparison.OrdinalIgnoreCase)) req.ConnClose = true;
                else if (tok.Equals("keep-alive", StringComparison.OrdinalIgnoreCase)) req.ConnKeepAlive = true;
                else if (tok.Equals("upgrade", StringComparison.OrdinalIgnoreCase)) req.ConnUpgrade = true;
            }
        }
        var expect = headers.Get("Expect");
        if (expect is not null)
        {
            if (!expect.Equals("100-continue", StringComparison.OrdinalIgnoreCase)) return 417;
            if (req.VersionValue == HttpVersion.Http11) req.ExpectContinue = true;
        }
        return 0;
    }

    /// <summary>
    /// Lower-case, validate and strip the port (cf. ngx_http_validate_host). Returns null if invalid.
    /// </summary>
    internal static string? NormalizeHost(string host)
    {
        if (host.Length is 0 or > 255) return null;
        int end = host.Length;
        if (host[0] == '[')
        {
            int close = host.IndexOf(']');
            if (close < 0) return null;
            for (int i = 1; i < close; i++)
            {
                char c = host[i];
                if (!(char.IsAsciiHexDigit(c) || c is ':' or '.')) return null;
            }
            if (close + 1 < host.Length && !ValidPort(host.AsSpan(close + 1))) return null;
            return host[..(close + 1)].ToLowerInvariant();
        }
        int colon = host.IndexOf(':');
        if (colon >= 0)
        {
            if (!ValidPort(host.AsSpan(colon))) return null;
            end = colon;
        }
        if (end > 0 && host[end - 1] == '.') end--;
        if (end == 0) return null;
        bool needLower = false;
        char prev = '\0';
        for (int i = 0; i < end; i++)
        {
            char c = host[i];
            if (c == '.')
            {
                if (prev == '.' || i == 0) return null;
            }
            else if (char.IsAsciiLetterUpper(c)) needLower = true;
            else if (!(char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c is '-' or '_')) return null;
            prev = c;
        }
        var r = end == host.Length ? host : host[..end];
        return needLower ? r.ToLowerInvariant() : r;
    }

    private static bool ValidPort(ReadOnlySpan<char> s)
    {
        // s starts with ':'
        if (s.Length < 2 || s.Length > 6 || s[0] != ':') return false;
        foreach (char c in s[1..]) if (!char.IsAsciiDigit(c)) return false;
        return true;
    }

    private static bool StartsWithIgnoreCase(ReadOnlySpan<byte> s, ReadOnlySpan<byte> lowerPrefix)
    {
        if (s.Length < lowerPrefix.Length) return false;
        for (int i = 0; i < lowerPrefix.Length; i++)
            if ((s[i] | 0x20) != lowerPrefix[i] && s[i] != lowerPrefix[i]) return false;
        return true;
    }

    private static string InternMethod(ReadOnlySpan<byte> m)
    {
        switch (m.Length)
        {
            case 3:
                if (m.SequenceEqual("GET"u8)) return HttpMethods.Get;
                if (m.SequenceEqual("PUT"u8)) return HttpMethods.Put;
                break;
            case 4:
                if (m.SequenceEqual("HEAD"u8)) return HttpMethods.Head;
                if (m.SequenceEqual("POST"u8)) return HttpMethods.Post;
                break;
            case 5:
                if (m.SequenceEqual("PATCH"u8)) return HttpMethods.Patch;
                if (m.SequenceEqual("TRACE"u8)) return HttpMethods.Trace;
                break;
            case 6:
                if (m.SequenceEqual("DELETE"u8)) return HttpMethods.Delete;
                break;
            case 7:
                if (m.SequenceEqual("OPTIONS"u8)) return HttpMethods.Options;
                if (m.SequenceEqual("CONNECT"u8)) return HttpMethods.Connect;
                break;
        }
        return Encoding.ASCII.GetString(m);
    }

    private static readonly string[] KnownHeaders =
    [
        "Host", "Connection", "User-Agent", "Accept", "Accept-Encoding", "Accept-Language", "Accept-Charset",
        "Content-Length", "Content-Type", "Transfer-Encoding", "Cookie", "Referer", "Origin", "Upgrade",
        "Authorization", "Cache-Control", "Pragma", "Range", "If-Range", "If-Modified-Since", "If-None-Match",
        "If-Match", "If-Unmodified-Since", "Expect", "TE", "Keep-Alive", "X-Forwarded-For", "X-Forwarded-Proto",
        "X-Forwarded-Host", "X-Real-IP", "X-Requested-With", "DNT", "Upgrade-Insecure-Requests",
        "Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Extensions", "Sec-WebSocket-Protocol",
        "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User", "Priority",
    ];
    private static readonly byte[][] KnownHeaderBytes = Array.ConvertAll(KnownHeaders, Encoding.ASCII.GetBytes);

    private static string InternHeaderName(ReadOnlySpan<byte> name)
    {
        var known = KnownHeaderBytes;
        for (int i = 0; i < known.Length; i++)
            if (known[i].Length == name.Length && Ascii.EqualsIgnoreCase(name, known[i])) return KnownHeaders[i];
        return Encoding.ASCII.GetString(name);
    }
}
