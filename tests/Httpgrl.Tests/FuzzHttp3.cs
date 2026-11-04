using System.Text;
using Httpgrl.Core.Http3;

namespace Httpgrl.Tests;

internal static partial class Fuzz
{
    /// <summary>QPACK sections: only QpackException escapes; what decodes re-encodes (statelessly) to the same fields.</summary>
    private static Target QpackTarget()
    {
        var buf = new byte[64];
        int len = 0;
        QpackEncoder.Begin(ref buf, ref len);
        foreach (var (n, v) in new[] { (":method", "GET"), (":path", "/index.html"), (":authority", "example.com"), ("x-thing", "value"), ("accept", "*/*") })
            QpackEncoder.Encode(ref buf, ref len, n, v);
        return new Target("qpack", [buf[..len], Convert.FromHexString("0000510b2f696e6465782e68746d6c"), Convert.FromHexString("0000d1d7")],
            B("\x00", "\x80", "\xc0", "\xd1", "\x50", "\x51", "\x20", "\x28", "\x10", "\x7f", "\xff", "\x3f"),
            data =>
            {
                var fields = new List<(string, string)>();
                try { new QpackDecoder(4096).Decode(data, (n, v) => fields.Add((Encoding.Latin1.GetString(n), Encoding.Latin1.GetString(v)))); }
                catch (QpackException) { return false; }
                var b = new byte[64];
                int l = 0;
                QpackEncoder.Begin(ref b, ref l);
                foreach (var (n, v) in fields) QpackEncoder.Encode(ref b, ref l, n, v);
                var back = new List<(string, string)>();
                new QpackDecoder(1 << 20).Decode(b[..l], (n, v) => back.Add((Encoding.Latin1.GetString(n), Encoding.Latin1.GetString(v))));
                if (!fields.SequenceEqual(back)) throw new Finding("fields don't round-trip through the encoder");
                return true;
            }, MaxLen: 2048);
    }

    /// <summary>
    /// HTTP/3 frame streams fed whole and in random pieces: only H3Exception escapes; both ways give the same frames
    /// and DATA; buffered payloads never exceed the limit.
    /// </summary>
    private static Target H3FramesTarget() => new("h3-frames",
        [Convert.FromHexString("0103aabbcc2105010203040500047465737400000402060101"), Convert.FromHexString("04040600080107020102")],
        B("\x00", "\x01", "\x04", "\x07", "\x0d", "\x21", "\x40\x00", "\x80\x00\x00\x00", "\xc0", "\x02", "\x09", "\x3f"),
        data =>
        {
            string Run(Func<int, int> chunk)
            {
                var sb = new StringBuilder();
                var r = new H3FrameReader(512);
                try
                {
                    int at = 0;
                    while (at < data.Length)
                    {
                        int n = Math.Min(chunk(at), data.Length - at);
                        r.Feed(data.AsSpan(at, n), (t, p) =>
                        {
                            if (p.Length > 512) throw new Finding("payload over the limit buffered");
                            sb.Append($"F{t}:{Convert.ToHexString(p)};");
                        }, d => sb.Append(Convert.ToHexString(d))); // DATA pieces join up, however they were split
                        at += n;
                    }
                }
                catch (H3Exception e) { sb.Append("E" + e.Code); }
                return sb.ToString();
            }
            string whole = Run(_ => data.Length);
            var rng = new Random(data.Length);
            string pieces = Run(_ => 1 + rng.Next(5));
            if (whole != pieces) throw new Finding($"split reads differ: {whole} vs {pieces}");
            return !whole.Contains('E');
        }, MaxLen: 1024);
}
