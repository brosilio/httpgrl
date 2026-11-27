using System.Text;

namespace Httpgrl;

/// <summary>
/// Builds <c>Location</c> header values from evaluated config templates. Every module (and the core's error_page)
/// that redirects to a URL built from variables goes through here, so the rules live in one place.
/// </summary>
public static class Redirects
{
    /// <summary>
    /// Percent-encode the UTF-8 bytes of <paramref name="url"/> that may not appear raw in a header URL: controls,
    /// space, DEL, non-ASCII, and '\' (browsers treat '\' as '/', so <c>/\host</c> would be a protocol-relative URL).
    /// Variables like <c>$uri</c> are percent-decoded and may hold any of these. Existing '%' escapes are kept.
    /// </summary>
    public static string Escape(string url)
    {
        bool clean = true;
        foreach (char c in url)
            if (!IsKept(c)) { clean = false; break; }
        if (clean) return url;
        var sb = new StringBuilder(url.Length + 16);
        foreach (byte b in Encoding.UTF8.GetBytes(url))
        {
            if (IsKept((char)b)) sb.Append((char)b);
            else sb.Append('%').Append("0123456789ABCDEF"[b >> 4]).Append("0123456789ABCDEF"[b & 15]);
        }
        return sb.ToString();
    }

    /// <summary>
    /// The <c>Location</c> value for a redirect whose target is the template <paramref name="template"/> evaluated to
    /// <paramref name="evaluated"/>: <see cref="Escape"/>d, and never protocol-relative unless the template's own text
    /// starts with <c>//</c>. A capture or <c>$uri</c> that supplies the leading slashes (<c>rewrite ^(.*)/$ $1</c> on
    /// <c>//evil.example/</c>) would otherwise send the client to another host; the leading slashes collapse to one.
    /// </summary>
    public static string Location(ComplexValue template, string evaluated)
    {
        var v = Escape(evaluated);
        if (v.StartsWith("//", StringComparison.Ordinal) && !template.Raw.StartsWith("//", StringComparison.Ordinal))
            v = v.TrimStart('/').Insert(0, "/");
        return v;
    }

    private static bool IsKept(char c) => c is >= (char)0x21 and <= (char)0x7E and not '\\';
}
