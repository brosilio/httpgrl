using System.Buffers;

namespace Httpgrl.Core.Http2;

/// <summary>A header block that violates HPACK (a COMPRESSION_ERROR) or our limits (decoded size, field count).</summary>
internal sealed class HpackException(string message, bool limit = false) : Exception(message)
{
    /// <summary>A limit, not a protocol violation: the request is refused (431) rather than the connection killed.</summary>
    public bool Limit { get; } = limit;
}

/// <summary>The Huffman code of RFC 7541 (canonical, so decodable from code lengths alone).</summary>
internal static class Huffman
{
    private const int MaxLen = 30;
    // Canonical decoding: per code length, the first code and where its symbols start in Sorted.
    private static readonly uint[] FirstCode = new uint[MaxLen + 2];
    private static readonly int[] Count = new int[MaxLen + 2];
    private static readonly int[] Offset = new int[MaxLen + 2];
    private static readonly ushort[] Sorted = new ushort[257];

    static Huffman()
    {
        var len = HpackTables.HuffmanLength;
        for (int s = 0; s < 257; s++) Count[len[s]]++;
        int off = 0;
        uint code = 0;
        for (int l = 1; l <= MaxLen; l++)
        {
            Offset[l] = off;
            FirstCode[l] = code;
            off += Count[l];
            code = (code + (uint)Count[l]) << 1;
        }
        var fill = new int[MaxLen + 2];
        for (int s = 0; s < 257; s++) Sorted[Offset[len[s]] + fill[len[s]]++] = (ushort)s; // symbols ascend within a length
    }

    public static int EncodedLength(ReadOnlySpan<byte> s)
    {
        long bits = 0;
        foreach (byte b in s) bits += HpackTables.HuffmanLength[b];
        return (int)((bits + 7) >> 3);
    }

    /// <summary>Encode into <paramref name="dest"/> (sized by <see cref="EncodedLength"/>); pads with ones (an EOS prefix).</summary>
    public static int Encode(ReadOnlySpan<byte> s, Span<byte> dest)
    {
        ulong acc = 0;
        int bits = 0, n = 0;
        foreach (byte b in s)
        {
            int l = HpackTables.HuffmanLength[b];
            acc = (acc << l) | HpackTables.HuffmanCode[b];
            bits += l;
            while (bits >= 8)
            {
                bits -= 8;
                dest[n++] = (byte)(acc >> bits);
            }
        }
        if (bits > 0) dest[n++] = (byte)((acc << (8 - bits)) | (0xFFu >> bits));
        return n;
    }

    /// <summary>
    /// Decode into <paramref name="dest"/>. Throws on the EOS symbol, on padding longer than 7 bits or not all ones
    /// (RFC 7541 5.2), and when the output would exceed <paramref name="dest"/>.
    /// </summary>
    public static int Decode(ReadOnlySpan<byte> src, Span<byte> dest)
    {
        ulong acc = 0;
        int bits = 0, n = 0, i = 0;
        while (true)
        {
            while (bits <= 56 && i < src.Length) { acc = (acc << 8) | src[i++]; bits += 8; }
            if (bits == 0) return n;
            // Find the shortest code length whose prefix falls within that length's range.
            int l = 5;
            int sym = -1;
            for (; l <= MaxLen && l <= bits; l++)
            {
                uint code = (uint)(acc >> (bits - l)) & (uint)((1UL << l) - 1);
                uint d = code - FirstCode[l];
                if (Count[l] > 0 && code >= FirstCode[l] && d < (uint)Count[l]) { sym = Sorted[Offset[l] + (int)d]; break; }
            }
            if (sym < 0)
            {
                // Out of input: what's left must be padding, the most significant bits of EOS (all ones), at most 7 bits.
                if (i < src.Length || bits > 7) throw new HpackException("invalid Huffman code");
                ulong mask = (1UL << bits) - 1;
                if ((acc & mask) != mask) throw new HpackException("invalid Huffman padding");
                return n;
            }
            if (sym == 256) throw new HpackException("Huffman-encoded EOS");
            if (n == dest.Length) throw new HpackException("Huffman string too long", limit: true);
            dest[n++] = (byte)sym;
            bits -= l;
        }
    }
}

/// <summary>
/// HPACK decoder for one connection (RFC 7541): the dynamic table, integer and string decoding, and the limits that keep
/// a hostile header block bounded: total decoded size and field count per block, the table capped at the size we
/// advertised, string lengths checked against what's left before anything is allocated.
/// </summary>
internal sealed class HpackDecoder(int maxTableSize, int maxHeaderListSize, int maxFields = 128)
{
    private readonly int _maxTableSize = maxTableSize;
    private readonly List<(byte[] Name, byte[] Value)> _table = new(); // newest first
    private int _tableSize;
    private int _tableLimit = maxTableSize; // current limit, lowered (or raised up to the advertised size) by size updates
    private byte[] _scratch = new byte[256];

    public int TableSize => _tableSize;

    /// <summary>
    /// Decode one complete header block, handing each field to <paramref name="onField"/> (name, value; spans valid only
    /// during the call). Throws <see cref="HpackException"/>.
    /// </summary>
    public void Decode(ReadOnlySpan<byte> block, HpackFieldHandler onField)
    {
        int pos = 0, fields = 0;
        long listSize = 0;
        bool sawField = false;
        // A limit breach must not stop decoding halfway: the dynamic table would be left half-updated and every later
        // block on the connection misread. So the block is decoded to the end (table kept exact, nothing more emitted)
        // and the breach reported afterwards, for the caller to refuse just this request.
        _overLimit = null;
        while (pos < block.Length)
        {
            byte b = block[pos];
            if ((b & 0x80) != 0)
            {
                int index = ReadInt(block, ref pos, 7);
                var (n, v) = Lookup(index);
                Emit(n, v, ref listSize, ref fields, onField);
                sawField = true;
            }
            else if ((b & 0xE0) == 0x20)
            {
                // Dynamic table size update: only at the start of a block, never above what we advertised.
                if (sawField) throw new HpackException("table size update after a field");
                int size = ReadInt(block, ref pos, 5);
                if (size > _maxTableSize) throw new HpackException("table size update above the advertised limit");
                _tableLimit = size;
                Evict(0);
            }
            else
            {
                bool index = (b & 0xC0) == 0x40;
                int prefix = index ? 6 : 4;
                int nameIndex = ReadInt(block, ref pos, prefix);
                byte[] name;
                bool huge = false;
                if (nameIndex == 0) name = ReadString(block, ref pos, maxHeaderListSize, ref huge).ToArray();
                else name = Lookup(nameIndex).Name;
                var value = ReadString(block, ref pos, maxHeaderListSize, ref huge);
                if (huge) _overLimit ??= "header field too large";
                else Emit(name, value, ref listSize, ref fields, onField);
                // An oversized entry is larger than any table we allow, so inserting it empties the table (RFC 7541 4.4).
                if (index) { if (huge) { _table.Clear(); _tableSize = 0; } else Insert(name, value.ToArray()); }
                sawField = true;
            }
        }
        if (_overLimit is { } why) throw new HpackException(why, limit: true);
    }

    private string? _overLimit;

    private void Emit(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value, ref long listSize, ref int fields, HpackFieldHandler onField)
    {
        if (_overLimit is not null) return;
        listSize += name.Length + value.Length + 32; // RFC 9113 SETTINGS_MAX_HEADER_LIST_SIZE accounting
        if (listSize > maxHeaderListSize) { _overLimit = "header list too large"; return; }
        if (++fields > maxFields) { _overLimit = "too many header fields"; return; }
        onField(name, value);
    }

    private (byte[] Name, byte[] Value) Lookup(int index)
    {
        if (index <= 0) throw new HpackException("index 0");
        if (index <= HpackTables.Static.Length)
        {
            var (n, v) = StaticBytes[index - 1];
            return (n, v);
        }
        int d = index - HpackTables.Static.Length - 1;
        if (d >= _table.Count) throw new HpackException("index beyond the dynamic table");
        return _table[d];
    }

    private static readonly (byte[] Name, byte[] Value)[] StaticBytes =
        Array.ConvertAll(HpackTables.Static, e => (System.Text.Encoding.ASCII.GetBytes(e.Name), System.Text.Encoding.ASCII.GetBytes(e.Value)));

    private void Insert(byte[] name, byte[] value)
    {
        int size = name.Length + value.Length + 32;
        if (size > _tableLimit) { _table.Clear(); _tableSize = 0; return; } // RFC 7541 4.4: an entry too big empties the table
        Evict(size);
        _table.Insert(0, (name, value));
        _tableSize += size;
    }

    private void Evict(int room)
    {
        while (_tableSize + room > _tableLimit && _table.Count > 0)
        {
            var (n, v) = _table[^1];
            _table.RemoveAt(_table.Count - 1);
            _tableSize -= n.Length + v.Length + 32;
        }
    }

    /// <summary>An N-bit prefix integer (RFC 7541 5.1), capped far below overflow.</summary>
    internal static int ReadInt(ReadOnlySpan<byte> s, ref int pos, int prefix)
    {
        int max = (1 << prefix) - 1;
        int v = s[pos++] & max;
        if (v < max) return v;
        int shift = 0;
        while (true)
        {
            if (pos >= s.Length) throw new HpackException("truncated integer");
            byte b = s[pos++];
            if (shift > 21) throw new HpackException("integer too large");
            v += (b & 0x7F) << shift;
            shift += 7;
            if ((b & 0x80) == 0) return v;
        }
    }

    /// <summary>
    /// A string literal (RFC 7541 5.2). The span is valid until the next read. Longer than <paramref name="limit"/>: empty,
    /// with <paramref name="huge"/> set (its bytes are skipped; it's too big for any table we allow).
    /// </summary>
    private ReadOnlySpan<byte> ReadString(ReadOnlySpan<byte> s, ref int pos, int limit, ref bool huge)
    {
        if (pos >= s.Length) throw new HpackException("truncated string");
        bool huffman = (s[pos] & 0x80) != 0;
        int len = ReadInt(s, ref pos, 7);
        if (len > s.Length - pos) throw new HpackException("string longer than the block");
        var raw = s.Slice(pos, len);
        pos += len;
        if (!huffman)
        {
            if (len > limit) { huge = true; return default; }
            return raw;
        }
        // A Huffman code is at least 5 bits, so the output is at most len * 8 / 5 bytes (bounded by the block, which the
        // session bounds).
        int most = (int)Math.Min(int.MaxValue, (long)len * 8 / 5 + 1);
        if (_scratch.Length < most) _scratch = new byte[Math.Max(most, _scratch.Length * 2)];
        int n = Huffman.Decode(raw, _scratch.AsSpan(0, most));
        if (n > limit) { huge = true; return default; }
        return _scratch.AsSpan(0, n);
    }
}

internal delegate void HpackFieldHandler(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value);

/// <summary>
/// HPACK encoder for responses. Stateless by design: static-table references and literals, never the dynamic table, so
/// there's no state to desynchronize and nothing for a client to probe (no compression oracle across responses).
/// </summary>
internal static class HpackEncoder
{
    private static readonly Dictionary<string, int> StaticNames = BuildNames();
    private static readonly Dictionary<(string, string), int> StaticPairs = BuildPairs();

    private static Dictionary<string, int> BuildNames()
    {
        var d = new Dictionary<string, int>(StringComparer.Ordinal);
        for (int i = 0; i < HpackTables.Static.Length; i++) d.TryAdd(HpackTables.Static[i].Name, i + 1);
        return d;
    }

    private static Dictionary<(string, string), int> BuildPairs()
    {
        var d = new Dictionary<(string, string), int>();
        for (int i = 0; i < HpackTables.Static.Length; i++)
            if (HpackTables.Static[i].Value.Length > 0) d.TryAdd(HpackTables.Static[i], i + 1);
        return d;
    }

    /// <summary>Append one field. <paramref name="name"/> must already be lower-case. Grows <paramref name="buf"/> as needed.</summary>
    public static void Encode(ref byte[] buf, ref int len, string name, string value)
    {
        if (StaticPairs.TryGetValue((name, value), out int full))
        {
            Ensure(ref buf, len, 8);
            WriteInt(buf, ref len, 0x80, 7, full);
            return;
        }
        Ensure(ref buf, len, 16 + name.Length + value.Length);
        // Literal without indexing (0000xxxx), with a static name reference when there is one.
        if (StaticNames.TryGetValue(name, out int ni)) WriteInt(buf, ref len, 0x00, 4, ni);
        else
        {
            buf[len++] = 0x00;
            WriteString(ref buf, ref len, name);
        }
        WriteString(ref buf, ref len, value);
    }

    private static void WriteString(ref byte[] buf, ref int len, string s)
    {
        Span<byte> raw = s.Length <= 512 ? stackalloc byte[s.Length] : new byte[s.Length];
        for (int i = 0; i < s.Length; i++) raw[i] = (byte)s[i]; // HeaderCollection guarantees Latin-1
        int h = Huffman.EncodedLength(raw);
        if (h < raw.Length)
        {
            Ensure(ref buf, len, 8 + h);
            WriteInt(buf, ref len, 0x80, 7, h);
            len += Huffman.Encode(raw, buf.AsSpan(len));
        }
        else
        {
            Ensure(ref buf, len, 8 + raw.Length);
            WriteInt(buf, ref len, 0x00, 7, raw.Length);
            raw.CopyTo(buf.AsSpan(len));
            len += raw.Length;
        }
    }

    internal static void WriteInt(byte[] buf, ref int len, byte flags, int prefix, int v)
    {
        int max = (1 << prefix) - 1;
        if (v < max) { buf[len++] = (byte)(flags | v); return; }
        buf[len++] = (byte)(flags | max);
        v -= max;
        while (v >= 0x80) { buf[len++] = (byte)(v | 0x80); v >>= 7; }
        buf[len++] = (byte)v;
    }

    private static void Ensure(ref byte[] buf, int len, int more)
    {
        if (buf.Length - len >= more) return;
        Array.Resize(ref buf, Math.Max(buf.Length * 2, len + more));
    }
}
