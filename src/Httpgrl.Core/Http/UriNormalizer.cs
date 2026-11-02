using System.Text;
using System.Text.Unicode;

namespace Httpgrl.Core.Http;

/// <summary>
/// Turns a raw origin-form path into the canonical decoded path every module works on:
/// percent-decoded, dot-segments resolved, duplicate slashes merged. Anything ambiguous is rejected.
/// </summary>
internal static class UriNormalizer
{
    public const int MaxPath = 8192;

    /// <summary>Decode and normalize a raw path (no query). Returns null if invalid.</summary>
    public static string? NormalizeRaw(ReadOnlySpan<byte> raw)
    {
        if (raw.IsEmpty || raw[0] != (byte)'/' || raw.Length > MaxPath) return null;
        Span<byte> buf = raw.Length <= 1024 ? stackalloc byte[raw.Length] : new byte[raw.Length];
        int n = 0;
        for (int i = 0; i < raw.Length; i++)
        {
            byte b = raw[i];
            if (b == (byte)'%')
            {
                if (i + 2 >= raw.Length) return null;
                int hi = Hex(raw[i + 1]), lo = Hex(raw[i + 2]);
                if ((hi | lo) < 0) return null;
                b = (byte)((hi << 4) | lo);
                i += 2;
            }
            if (b == 0) return null;
            buf[n++] = b;
        }
        n = Resolve(buf[..n]);
        if (n < 0) return null;
        var path = buf[..n];
        if (!Utf8.IsValid(path)) return null;
        return Encoding.UTF8.GetString(path);
    }

    /// <summary>Normalize an already-decoded path (internal redirect targets). Returns null if invalid.</summary>
    public static string? NormalizeDecoded(string path)
    {
        if (path.Length == 0 || path[0] != '/' || path.Contains('\0')) return null;
        if (!NeedsResolve(path)) return path;
        int max = Encoding.UTF8.GetMaxByteCount(path.Length);
        Span<byte> buf = max <= 2048 ? stackalloc byte[max] : new byte[max];
        int len = Encoding.UTF8.GetBytes(path, buf);
        int n = Resolve(buf[..len]);
        return n < 0 ? null : Encoding.UTF8.GetString(buf[..n]);
    }

    private static bool NeedsResolve(string p)
    {
        for (int i = 0; i < p.Length; i++)
        {
            if (p[i] != '/') continue;
            if (i + 1 < p.Length && (p[i + 1] == '/' || p[i + 1] == '.')) return true;
        }
        return false;
    }

    /// <summary>In-place RFC 3986 remove_dot_segments + slash merging. Returns new length, or -1 if the path escapes the root.</summary>
    internal static int Resolve(Span<byte> p)
    {
        int w = 0, r = 0, len = p.Length;
        while (r < len)
        {
            // p[r] == '/' here.
            int s = r + 1;
            int e = s;
            while (e < len && p[e] != (byte)'/') e++;
            int segLen = e - s;
            if (segLen == 0)
            {
                if (e == len) p[w++] = (byte)'/'; // trailing slash
            }
            else if (segLen == 1 && p[s] == (byte)'.')
            {
                if (e == len) p[w++] = (byte)'/';
            }
            else if (segLen == 2 && p[s] == (byte)'.' && p[s + 1] == (byte)'.')
            {
                if (w == 0) return -1;
                w--;
                while (w > 0 && p[w] != (byte)'/') w--;
                if (e == len) p[w++] = (byte)'/';
            }
            else
            {
                p[w++] = (byte)'/';
                p.Slice(s, segLen).CopyTo(p[w..]);
                w += segLen;
            }
            r = e;
        }
        if (w == 0) p[w++] = (byte)'/';
        return w;
    }

    private static int Hex(byte c)
    {
        if ((uint)(c - '0') <= 9) return c - '0';
        c |= 0x20;
        if ((uint)(c - 'a') <= 5) return c - 'a' + 10;
        return -1;
    }
}
