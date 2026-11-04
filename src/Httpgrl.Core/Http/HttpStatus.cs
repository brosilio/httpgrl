using System.Text;

namespace Httpgrl.Core.Http;

internal static class HttpStatus
{
    private static readonly byte[][] Lines = BuildLines();
    private static readonly byte[]?[] Bodies = new byte[600][];
    private static readonly byte[]?[] BodiesWithName = new byte[600][];

    public static string Reason(int code) => code switch
    {
        100 => "Continue", 101 => "Switching Protocols",
        200 => "OK", 201 => "Created", 202 => "Accepted", 204 => "No Content", 206 => "Partial Content",
        301 => "Moved Permanently", 302 => "Found", 303 => "See Other", 304 => "Not Modified",
        307 => "Temporary Redirect", 308 => "Permanent Redirect",
        400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden", 404 => "Not Found",
        405 => "Method Not Allowed", 406 => "Not Acceptable", 408 => "Request Timeout", 409 => "Conflict",
        410 => "Gone", 411 => "Length Required", 412 => "Precondition Failed", 413 => "Content Too Large",
        414 => "URI Too Long", 415 => "Unsupported Media Type", 416 => "Range Not Satisfiable",
        417 => "Expectation Failed", 421 => "Misdirected Request", 426 => "Upgrade Required",
        429 => "Too Many Requests", 431 => "Request Header Fields Too Large",
        500 => "Internal Server Error", 501 => "Not Implemented", 502 => "Bad Gateway",
        503 => "Service Unavailable", 504 => "Gateway Timeout", 505 => "HTTP Version Not Supported",
        _ => "",
    };

    /// <summary>"HTTP/1.1 404 Not Found\r\n", precomputed for 100..599.</summary>
    public static ReadOnlySpan<byte> StatusLine(int code) => Lines[code - 100];

    private static byte[][] BuildLines()
    {
        var a = new byte[500][];
        for (int c = 100; c < 600; c++) a[c - 100] = Encoding.ASCII.GetBytes($"HTTP/1.1 {c} {Reason(c)}\r\n");
        return a;
    }

    /// <summary>The default nginx-style HTML body for an error/redirect status. The product footer follows server_tokens.</summary>
    public static byte[] DefaultBody(int code, bool withName)
    {
        var cache = withName ? BodiesWithName : Bodies;
        var b = Volatile.Read(ref cache[code]);
        if (b is not null) return b;
        var text = $"{code} {Reason(code)}".TrimEnd();
        var footer = withName ? "<hr><center>httpgrl</center>\r\n" : "";
        b = Encoding.ASCII.GetBytes(
            $"<html>\r\n<head><title>{text}</title></head>\r\n<body>\r\n<center><h1>{text}</h1></center>\r\n{footer}</body>\r\n</html>\r\n");
        Volatile.Write(ref cache[code], b);
        return b;
    }

    public static bool HasNoBody(int code) => code < 200 || code == 204 || code == 304;

    private static readonly string[] Codes = Enumerable.Range(0, 500).Select(i => (i + 100).ToString(System.Globalization.CultureInfo.InvariantCulture)).ToArray();
    /// <summary>"200", "404", ...: the :status value (HTTP/2, HTTP/3).</summary>
    public static string Code(int code) => Codes[code - 100];

    /// <summary>Errors after which the connection state is untrustworthy.</summary>
    public static bool ForcesClose(int code) => code is 400 or 408 or 413 or 414 or 431 or 500 or 501 or 505;
}

/// <summary>Cached IMF-fixdate, refreshed by the sweeper once per second.</summary>
internal static class HttpDate
{
    private static byte[] s_header = Build(DateTime.UtcNow);
    private static string s_value = DateTime.UtcNow.ToString("r");
    private static long s_second;

    /// <summary>"Date: Sun, 06 Nov 1994 08:49:37 GMT\r\n"</summary>
    public static ReadOnlySpan<byte> Header => Volatile.Read(ref s_header);
    /// <summary>"Sun, 06 Nov 1994 08:49:37 GMT"</summary>
    public static string Value => Volatile.Read(ref s_value);

    public static void Tick()
    {
        var now = DateTime.UtcNow;
        long sec = now.Ticks / TimeSpan.TicksPerSecond;
        if (sec == s_second) return;
        s_second = sec;
        Volatile.Write(ref s_header, Build(now));
        Volatile.Write(ref s_value, now.ToString("r"));
    }

    private static byte[] Build(DateTime t) => Encoding.ASCII.GetBytes("Date: " + t.ToString("r") + "\r\n");

    public static string Format(DateTime utc) => utc.ToString("r");

    public static bool TryParse(string s, out DateTime utc)
    {
        // IMF-fixdate only (RFC 9110 recipients MUST accept it; the obsolete forms are not worth the parser).
        return DateTime.TryParseExact(s, "r", System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out utc);
    }
}
