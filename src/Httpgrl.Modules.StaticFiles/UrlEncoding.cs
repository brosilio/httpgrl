using System.Text;

namespace Httpgrl.Modules.StaticFiles;

internal static class UrlEncoding
{
    /// <summary>Percent-encode a decoded path for use in a Location header or href. Keeps unreserved chars and '/'.</summary>
    public static string EscapePath(string path)
    {
        bool clean = true;
        foreach (char c in path)
            if (!IsKept(c)) { clean = false; break; }
        if (clean) return path;
        var bytes = Encoding.UTF8.GetBytes(path);
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes)
        {
            if (b < 0x80 && IsKept((char)b)) sb.Append((char)b);
            else sb.Append('%').Append("0123456789ABCDEF"[b >> 4]).Append("0123456789ABCDEF"[b & 15]);
        }
        return sb.ToString();
    }

    private static bool IsKept(char c) => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~' or '/';

    public static void HtmlEscape(StringBuilder sb, ReadOnlySpan<char> s)
    {
        foreach (char c in s)
        {
            switch (c)
            {
                case '&': sb.Append("&amp;"); break;
                case '<': sb.Append("&lt;"); break;
                case '>': sb.Append("&gt;"); break;
                case '"': sb.Append("&quot;"); break;
                case '\'': sb.Append("&#39;"); break;
                default: sb.Append(c < 0x20 ? '?' : c); break;
            }
        }
    }
}
