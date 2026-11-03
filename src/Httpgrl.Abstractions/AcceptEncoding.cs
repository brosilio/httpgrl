namespace Httpgrl;

public enum ContentCoding : byte { Identity, Gzip, Brotli }

/// <summary>Accept-Encoding negotiation (RFC 9110 12.5.3), shared by on-the-fly and precompressed serving.</summary>
public static class AcceptEncoding
{
    /// <summary>
    /// The coding to use among those allowed: codings with q=0 are refused; "*" stands for any coding not listed;
    /// brotli wins a tie, otherwise the higher q wins. Garbage yields Identity, never an error.
    /// </summary>
    public static ContentCoding Choose(string? acceptEncoding, bool gzip, bool brotli)
    {
        Parse(acceptEncoding, out double gz, out double br);
        if (!gzip) gz = 0;
        if (!brotli) br = 0;
        if (br > 0 && br >= gz) return ContentCoding.Brotli;
        if (gz > 0) return ContentCoding.Gzip;
        return ContentCoding.Identity;
    }

    /// <summary>Whether <paramref name="coding"/> is acceptable at all (q &gt; 0).</summary>
    public static bool Accepts(string? acceptEncoding, ContentCoding coding)
    {
        Parse(acceptEncoding, out double gz, out double br);
        return coding switch { ContentCoding.Gzip => gz > 0, ContentCoding.Brotli => br > 0, _ => true };
    }

    private static void Parse(string? acceptEncoding, out double gz, out double br)
    {
        gz = br = 0;
        if (string.IsNullOrEmpty(acceptEncoding)) return;
        double g = -1, b = -1, star = -1;
        var s = acceptEncoding.AsSpan();
        foreach (var r in s.Split(','))
        {
            var item = s[r].Trim();
            if (item.IsEmpty) continue;
            double q = 1;
            int semi = item.IndexOf(';');
            var name = (semi < 0 ? item : item[..semi]).Trim();
            if (semi >= 0)
            {
                var p = item[(semi + 1)..].Trim();
                if (p.Length < 2 || (p[0] | 0x20) != 'q' || p[1] != '=' || !double.TryParse(p[2..], System.Globalization.NumberStyles.AllowDecimalPoint, System.Globalization.CultureInfo.InvariantCulture, out q) || q is < 0 or > 1)
                    continue; // malformed: ignore this item
            }
            if (name.Equals("gzip", StringComparison.OrdinalIgnoreCase) || name.Equals("x-gzip", StringComparison.OrdinalIgnoreCase)) g = Math.Max(g, q);
            else if (name.Equals("br", StringComparison.OrdinalIgnoreCase)) b = Math.Max(b, q);
            else if (name.SequenceEqual("*")) star = Math.Max(star, q);
        }
        gz = g < 0 ? Math.Max(star, 0) : g;
        br = b < 0 ? Math.Max(star, 0) : b;
    }

    /// <summary>Add "Accept-Encoding" to a Vary header, merging with what's there.</summary>
    public static void AddVary(HeaderCollection h)
    {
        var v = h.Get("Vary");
        if (v is null) { h.Set("Vary", "Accept-Encoding"); return; }
        foreach (var r in v.AsSpan().Split(','))
        {
            var tok = v.AsSpan()[r].Trim();
            if (tok.Equals("Accept-Encoding", StringComparison.OrdinalIgnoreCase) || tok.SequenceEqual("*")) return;
        }
        h.Set("Vary", v + ", Accept-Encoding");
    }
}
