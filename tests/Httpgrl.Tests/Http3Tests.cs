using System.Text;
using Httpgrl.Core.Http3;

namespace Httpgrl.Tests;

/// <summary>HTTP/3 building blocks: QPACK (RFC 9204, static table only) and frames (RFC 9114 7).</summary>
internal static class Http3Tests
{
    private static List<(string, string)> Decode(byte[] section, int max = 16 << 10)
    {
        var got = new List<(string, string)>();
        new QpackDecoder(max).Decode(section, (n, v) => got.Add((Encoding.Latin1.GetString(n), Encoding.Latin1.GetString(v))));
        return got;
    }

    private static QpackException Fails(byte[] section, int max = 16 << 10)
    {
        try { Decode(section, max); }
        catch (QpackException e) { return e; }
        throw new Exception("accepted");
    }

    public static void Register()
    {
        T.Add("qpack: RFC 9204 B.1 decodes; encoder output decodes back, with static pairs, name references, literals and Huffman", () =>
        {
            var b1 = Convert.FromHexString("0000510b2f696e6465782e68746d6c");
            T.Eq(":path=/index.html", string.Join(";", Decode(b1).Select(f => f.Item1 + "=" + f.Item2)));

            (string, string)[] fields = [(":status", "200"), (":status", "418"), ("content-type", "text/html; charset=utf-8"),
                ("x-custom-header", "some value"), ("cache-control", "no-cache"), ("set-cookie", new string('a', 300)), ("x-empty", "")];
            var buf = new byte[16];
            int len = 0;
            QpackEncoder.Begin(ref buf, ref len);
            foreach (var (n, v) in fields) QpackEncoder.Encode(ref buf, ref len, n, v);
            T.Eq(string.Join("|", fields), string.Join("|", Decode(buf[..len])));
            // A full static match is one byte: ":status 200" is static index 25.
            var one = new byte[4];
            int l1 = 0;
            QpackEncoder.Encode(ref one, ref l1, ":status", "200");
            T.Eq(1, l1);
            T.Eq(0xC0 | 25, (int)one[0]);
        });

        T.Add("qpack: dynamic table references, a non-zero insert count, truncation and size limits are refused", () =>
        {
            T.True(!Fails(Convert.FromHexString("0381" + "10")).Limit);   // Required Insert Count > 0 (B.2's first section)
            T.True(!Fails(Convert.FromHexString("0000" + "80")).Limit);   // indexed, dynamic (T=0)
            T.True(!Fails(Convert.FromHexString("0000" + "10")).Limit);   // indexed post-base
            T.True(!Fails(Convert.FromHexString("0000" + "4103616263")).Limit); // name reference, dynamic (T=0)
            T.True(!Fails(Convert.FromHexString("0000" + "00")).Limit);   // literal with post-base name reference
            T.True(!Fails(Convert.FromHexString("0000" + "ff64")).Limit); // static index 63 + 100: beyond the table
            T.True(!Fails(Convert.FromHexString("0000" + "510b2f69")).Limit); // string longer than the section
            T.True(!Fails([]).Limit);
            // Over the section size limit: a limit (431 for this request), decoded to the end first.
            var big = new byte[16];
            int len = 0;
            QpackEncoder.Begin(ref big, ref len);
            QpackEncoder.Encode(ref big, ref len, "x-big", new string('z', 5000));
            T.True(Fails(big[..len], max: 1000).Limit);
            // Too many fields.
            var many = new byte[16];
            len = 0;
            QpackEncoder.Begin(ref many, ref len);
            for (int i = 0; i < 200; i++) QpackEncoder.Encode(ref many, ref len, ":status", "200");
            T.True(Fails(many[..len]).Limit);
        });

        T.Add("h3 frames: split reads, empty and unknown frames, HTTP/2 types, oversized payloads, SETTINGS rules", () =>
        {
            var frames = new List<string>();
            var data = new List<byte>();
            void OnFrame(ulong t, ReadOnlySpan<byte> p) => frames.Add($"{t}:{Convert.ToHexStringLower(p)}");
            void OnData(ReadOnlySpan<byte> d) { frames.Add("data"); data.AddRange(d.ToArray()); }
            // HEADERS(3 bytes), an unknown reserved type (0x21) with 5 bytes, DATA(4), empty DATA, SETTINGS.
            var stream = Convert.FromHexString("0103aabbcc" + "2105" + "0102030405" + "000474657374" + "0000" + "04020601");
            var r = new H3FrameReader(1024);
            foreach (byte b in stream) r.Feed([b], OnFrame, OnData); // one byte at a time
            T.True(r.AtBoundary);
            T.Eq("test", Encoding.ASCII.GetString(data.ToArray()));
            T.True(frames.Contains("1:aabbcc") && frames.Contains("4:0601") && !frames.Exists(f => f.StartsWith("33:")));

            H3Error Bad(string hex, int max = 1024)
            {
                try { new H3FrameReader(max).Feed(Convert.FromHexString(hex), OnFrame, OnData); }
                catch (H3Exception e) { return e.Code; }
                throw new Exception("accepted");
            }
            T.Eq(H3Error.FrameUnexpected, Bad("0200")); // HTTP/2's PRIORITY
            T.Eq(H3Error.FrameUnexpected, Bad("0900")); // HTTP/2's CONTINUATION
            T.Eq(H3Error.ExcessiveLoad, Bad("01" + "4401", max: 1000)); // HEADERS of 1025 bytes, over the limit
            // An unknown frame of any size is skipped, never stored.
            var skip = new H3FrameReader(16);
            skip.Feed(Convert.FromHexString("21" + "80100000"), OnFrame, OnData); // 1 MiB of nothing
            T.True(!skip.AtBoundary);

            T.Eq(2, H3FrameWriter.ParseSettings(Convert.FromHexString("0600" + "0801")).Count);
            H3Error S(string hex)
            {
                try { H3FrameWriter.ParseSettings(Convert.FromHexString(hex)); }
                catch (H3Exception e) { return e.Code; }
                throw new Exception("accepted");
            }
            T.Eq(H3Error.SettingsError, S("0600" + "0601"));  // duplicate
            T.Eq(H3Error.SettingsError, S("0200"));            // HTTP/2's ENABLE_PUSH
            T.Eq(H3Error.FrameError, S("06"));                 // truncated
            T.Eq(2, H3FrameWriter.ParseSettings(Convert.FromHexString("2105" + "0600")).Count); // unknown (grease) ids pass; callers ignore them
        });
    }
}
