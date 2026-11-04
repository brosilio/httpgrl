using System.Text;
using Httpgrl.Core.Http2;

namespace Httpgrl.Core.Http3;

internal sealed class QpackException(string message, bool limit = false) : Exception(message)
{
    /// <summary>A size limit was exceeded (answer 431), as opposed to a malformed section (QPACK_DECOMPRESSION_FAILED).</summary>
    public bool Limit { get; } = limit;
}

/// <summary>
/// QPACK field section decoding (RFC 9204) with a dynamic table capacity of zero, which is what we advertise: static
/// references and literals only. Any dynamic-table reference, or a non-zero Required Insert Count, is
/// QPACK_DECOMPRESSION_FAILED (4.5.1, 2.2.3). With no table there's no state across streams: nothing to block on,
/// nothing to desynchronize. Sizes are bounded as in HPACK: the decoded section, field count, string lengths.
/// </summary>
internal sealed class QpackDecoder(int maxFieldSectionSize, int maxFields = 128)
{
    private byte[] _scratch = new byte[256];

    private static readonly (byte[] Name, byte[] Value)[] Static =
        Array.ConvertAll(QpackStaticTable.Entries, e => (Encoding.ASCII.GetBytes(e.Name), Encoding.ASCII.GetBytes(e.Value)));

    /// <summary>Decode one field section (a HEADERS frame's payload). Throws <see cref="QpackException"/>.</summary>
    public void Decode(ReadOnlySpan<byte> section, HpackFieldHandler onField)
    {
        int pos = 0;
        if (section.IsEmpty) throw new QpackException("empty field section");
        // Encoded Field Section Prefix: Required Insert Count (8-bit prefix), then Delta Base (sign + 7-bit prefix).
        int ric = ReadInt(section, ref pos, 8);
        if (ric != 0) throw new QpackException("a dynamic table reference (Required Insert Count > 0) with capacity 0");
        if (pos >= section.Length) throw new QpackException("truncated prefix");
        ReadInt(section, ref pos, 7); // Delta Base: meaningless without a table, but it must parse
        long size = 0;
        int fields = 0;
        string? over = null;
        while (pos < section.Length)
        {
            byte b = section[pos];
            if ((b & 0x80) != 0)
            {
                // Indexed field line: 1 T index(6).
                if ((b & 0x40) == 0) throw new QpackException("dynamic table reference");
                var (n, v) = Lookup(ReadInt(section, ref pos, 6));
                Emit(n, v, ref size, ref fields, ref over, onField);
            }
            else if ((b & 0xC0) == 0x40)
            {
                // Literal with name reference: 01 N T index(4), then the value.
                if ((b & 0x10) == 0) throw new QpackException("dynamic table name reference");
                var name = Lookup(ReadInt(section, ref pos, 4)).Name;
                bool huge = false;
                var value = ReadString(section, ref pos, 7, ref huge);
                if (huge) over ??= "field too large";
                else Emit(name, value, ref size, ref fields, ref over, onField);
            }
            else if ((b & 0xE0) == 0x20)
            {
                // Literal with literal name: 001 N H len(3) name, then the value.
                bool huge = false;
                var name = ReadString(section, ref pos, 3, ref huge).ToArray();
                var value = ReadString(section, ref pos, 7, ref huge);
                if (huge) over ??= "field too large";
                else Emit(name, value, ref size, ref fields, ref over, onField);
            }
            else throw new QpackException("post-base (dynamic table) reference"); // 0001xxxx and 0000xxxx
        }
        // A limit breach decodes the section to the end first (nothing to keep in step, but the answer is a 431 for
        // this request, not a connection error).
        if (over is not null) throw new QpackException(over, limit: true);
    }

    private void Emit(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value, ref long size, ref int fields, ref string? over, HpackFieldHandler onField)
    {
        if (over is not null) return;
        size += name.Length + value.Length + 32; // RFC 9114 4.2.2 accounting (as HTTP/2's)
        if (size > maxFieldSectionSize) { over = "field section too large"; return; }
        if (++fields > maxFields) { over = "too many fields"; return; }
        onField(name, value);
    }

    private static (byte[] Name, byte[] Value) Lookup(int index) =>
        index < Static.Length ? Static[index] : throw new QpackException("static index beyond the table");

    private static int ReadInt(ReadOnlySpan<byte> s, ref int pos, int prefix)
    {
        if (pos >= s.Length) throw new QpackException("truncated integer");
        try { return HpackDecoder.ReadInt(s, ref pos, prefix); }
        catch (HpackException e) { throw new QpackException(e.Message); }
    }

    /// <summary>
    /// A string literal whose length has a <paramref name="prefix"/>-bit prefix, the Huffman flag just above it.
    /// Longer than the section limit: <paramref name="huge"/>, and skipped.
    /// </summary>
    private ReadOnlySpan<byte> ReadString(ReadOnlySpan<byte> s, ref int pos, int prefix, ref bool huge)
    {
        if (pos >= s.Length) throw new QpackException("truncated string");
        bool huffman = (s[pos] & (1 << prefix)) != 0;
        int len = ReadInt(s, ref pos, prefix);
        if (len > s.Length - pos) throw new QpackException("string longer than the section");
        var raw = s.Slice(pos, len);
        pos += len;
        if (!huffman)
        {
            if (len > maxFieldSectionSize) { huge = true; return default; }
            return raw;
        }
        int most = (int)Math.Min(int.MaxValue, (long)len * 8 / 5 + 1);
        if (_scratch.Length < most) _scratch = new byte[Math.Max(most, _scratch.Length * 2)];
        int n;
        try { n = Huffman.Decode(raw, _scratch.AsSpan(0, most)); }
        catch (HpackException e) { throw new QpackException(e.Message); }
        if (n > maxFieldSectionSize) { huge = true; return default; }
        return _scratch.AsSpan(0, n);
    }
}

/// <summary>
/// QPACK encoding for responses: stateless, like our HPACK encoder. A section prefix of zero (no dynamic table), then
/// static references where the table has the field, literals otherwise, Huffman when it's shorter.
/// </summary>
internal static class QpackEncoder
{
    private static readonly Dictionary<string, int> Names = BuildNames();
    private static readonly Dictionary<(string, string), int> Pairs = BuildPairs();

    private static Dictionary<string, int> BuildNames()
    {
        var d = new Dictionary<string, int>(StringComparer.Ordinal);
        for (int i = 0; i < QpackStaticTable.Entries.Length; i++) d.TryAdd(QpackStaticTable.Entries[i].Name, i);
        return d;
    }

    private static Dictionary<(string, string), int> BuildPairs()
    {
        var d = new Dictionary<(string, string), int>();
        for (int i = 0; i < QpackStaticTable.Entries.Length; i++) d.TryAdd(QpackStaticTable.Entries[i], i);
        return d;
    }

    /// <summary>The section prefix (Required Insert Count 0, Delta Base 0): every section starts with it.</summary>
    public static void Begin(ref byte[] buf, ref int len)
    {
        Ensure(ref buf, len, 2);
        buf[len++] = 0;
        buf[len++] = 0;
    }

    /// <summary>Append one field. <paramref name="name"/> must already be lower-case.</summary>
    public static void Encode(ref byte[] buf, ref int len, string name, string value)
    {
        if (Pairs.TryGetValue((name, value), out int full))
        {
            Ensure(ref buf, len, 8);
            HpackEncoder.WriteInt(buf, ref len, 0xC0, 6, full); // 1 T=1 index
            return;
        }
        Ensure(ref buf, len, 16 + name.Length + value.Length);
        if (Names.TryGetValue(name, out int ni)) HpackEncoder.WriteInt(buf, ref len, 0x50, 4, ni); // 01 N=0 T=1 index
        else WriteString(ref buf, ref len, name, 0x20, 3); // 001 N=0 H len(3)
        WriteString(ref buf, ref len, value, 0x00, 7);
    }

    private static void WriteString(ref byte[] buf, ref int len, string s, byte flags, int prefix)
    {
        Span<byte> raw = s.Length <= 512 ? stackalloc byte[s.Length] : new byte[s.Length];
        for (int i = 0; i < s.Length; i++) raw[i] = (byte)s[i];
        int h = Huffman.EncodedLength(raw);
        if (h < raw.Length)
        {
            Ensure(ref buf, len, 8 + h);
            HpackEncoder.WriteInt(buf, ref len, (byte)(flags | (1 << prefix)), prefix, h);
            len += Huffman.Encode(raw, buf.AsSpan(len));
        }
        else
        {
            Ensure(ref buf, len, 8 + raw.Length);
            HpackEncoder.WriteInt(buf, ref len, flags, prefix, raw.Length);
            raw.CopyTo(buf.AsSpan(len));
            len += raw.Length;
        }
    }

    private static void Ensure(ref byte[] buf, int len, int more)
    {
        if (buf.Length - len >= more) return;
        Array.Resize(ref buf, Math.Max(buf.Length * 2, len + more));
    }
}
