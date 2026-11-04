using System.Text;
using Httpgrl.Core.Http2;

namespace Httpgrl.Tests;

/// <summary>HTTP/2 building blocks: HPACK (RFC 7541) for now.</summary>
internal static class Http2Tests
{
    private static List<(string, string)> Decode(HpackDecoder d, byte[] block)
    {
        var got = new List<(string, string)>();
        d.Decode(block, (n, v) => got.Add((Encoding.Latin1.GetString(n), Encoding.Latin1.GetString(v))));
        return got;
    }

    public static void Register()
    {
        T.Add("hpack: RFC 7541 Appendix C examples decode, with the dynamic table evolving as specified", () =>
        {
            HpackDecoder? d = null;
            foreach (var (sec, hex, fields, size) in HpackVectors.All)
            {
                // C.3 and C.4 each start a fresh connection with a 4096-byte table; C.5 and C.6 with 256 bytes.
                if (sec.EndsWith(".1", StringComparison.Ordinal)) d = new HpackDecoder(sec.StartsWith("C.5", StringComparison.Ordinal) || sec.StartsWith("C.6", StringComparison.Ordinal) ? 256 : 4096, 1 << 16);
                var got = Decode(d!, Convert.FromHexString(hex));
                T.Eq(string.Join("\n", fields.Select(f => f.Item1 + ": " + f.Item2)), string.Join("\n", got.Select(f => f.Item1 + ": " + f.Item2)));
                T.Eq(size, d!.TableSize);
            }
        });

        T.Add("hpack: the encoder's output decodes back to the same fields (static names, literals, Huffman)", () =>
        {
            var rnd = new Random(11);
            string[] names = [":status", "content-type", "content-length", "x-custom", "set-cookie", "cache-control", "date", "vary", "x-éé"];
            for (int round = 0; round < 500; round++)
            {
                var fields = new List<(string, string)>();
                int n = rnd.Next(1, 12);
                for (int k = 0; k < n; k++)
                {
                    var name = names[rnd.Next(names.Length)];
                    var chars = new char[rnd.Next(0, 80)];
                    for (int c = 0; c < chars.Length; c++) chars[c] = (char)(rnd.Next(4) == 0 ? rnd.Next(0x20, 0x100) : rnd.Next('a', 'z' + 1));
                    fields.Add((name, name == ":status" ? "200" : new string(chars)));
                }
                var buf = new byte[16];
                int len = 0;
                foreach (var (fn, fv) in fields) HpackEncoder.Encode(ref buf, ref len, fn, fv);
                var got = Decode(new HpackDecoder(4096, 1 << 20), buf[..len]);
                T.Eq(string.Join("|", fields), string.Join("|", got));
            }
        });

        T.Add("hpack: hostile header blocks are refused within their limits", () =>
        {
            static void Bad(string what, byte[] block, bool limit, int tableMax = 4096, int listMax = 16 << 10)
            {
                var e = T.Throws<HpackException>(() => new HpackDecoder(tableMax, listMax).Decode(block, (_, _) => { }));
                if (e.Limit != limit) throw new Exception($"{what}: expected limit={limit}, got {e.Limit} ({e.Message})");
            }
            // HPACK bomb: one 4000-byte entry in the table, then referenced over and over (one byte each).
            var bomb = new List<byte> { 0x40, 0x01, (byte)'x' };
            bomb.AddRange([0x7F, 0xA1, 0x1E]); // value length: 127 + 0x21 + (0x1E << 7) = 4000 (7-bit prefix, then continuation bytes)
            bomb.AddRange(Enumerable.Repeat((byte)'a', 4000));
            bomb.AddRange(Enumerable.Repeat((byte)0xBE, 100)); // indexed: dynamic entry 62
            Bad("bomb", [.. bomb], limit: true);
            // Table size updates: above what we advertised, or after a field.
            Bad("size update too big", [0x3F, 0xE2, 0x1F], limit: false); // 31 + 0x62 + (0x1F << 7) = 4097
            Bad("size update after a field", [0x82, 0x20], limit: false);
            // Indexes: 0, and past the (empty) dynamic table.
            Bad("index 0", [0x80], limit: false);
            Bad("index past the table", [0xBE], limit: false);
            // An integer that would overflow.
            Bad("integer overflow", [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F], limit: false);
            Bad("truncated integer", [0xFF, 0xFF], limit: false);
            // A string longer than the block.
            Bad("string past the end", [0x00, 0x05, (byte)'a'], limit: false);
            // Huffman: EOS, padding longer than 7 bits, padding that isn't all ones.
            Bad("Huffman EOS", [0x00, 0x81, 0xFF, 0x84, 0xFF, 0xFF, 0xFF, 0xFC], limit: false);
            Bad("Huffman long padding", [0x00, 0x81, 0x1F, 0x82, 0x1F, 0xFF], limit: false);   // "a" then a whole byte of ones
            Bad("Huffman zero padding", [0x00, 0x81, 0x1F, 0x81, 0x00], limit: false);
            // Field count and list size.
            Bad("too many fields", [.. Enumerable.Repeat((byte)0x82, 200)], limit: true);
            Bad("list too large", [.. Enumerable.Repeat((byte)0x82, 100)], limit: true, listMax: 1000);
            // The table never grows past the advertised size, however much is inserted.
            var d = new HpackDecoder(256, 1 << 20);
            var many = new List<byte>();
            for (int k = 0; k < 50; k++) many.AddRange([0x40, 0x01, (byte)('a' + k % 26), 0x0A, .. "0123456789"u8.ToArray()]);
            d.Decode([.. many], (_, _) => { });
            T.True(d.TableSize <= 256);
        });

        T.Add("hpack: Huffman round-trips every byte value", () =>
        {
            var all = new byte[256];
            for (int i = 0; i < 256; i++) all[i] = (byte)i;
            var enc = new byte[Huffman.EncodedLength(all)];
            T.Eq(enc.Length, Huffman.Encode(all, enc));
            var dec = new byte[512];
            int n = Huffman.Decode(enc, dec);
            T.True(dec.AsSpan(0, n).SequenceEqual(all));
        });
    }
}
