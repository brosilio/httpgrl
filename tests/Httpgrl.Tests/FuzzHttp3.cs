using Httpgrl.Quic;
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

internal static partial class Fuzz
{
    private static TestServer? _h3Server;
    private static H3Client? _h3Client;
    private static int _h3Inputs;

    /// <summary>
    /// A live HTTP/3 server fed arbitrary bytes on new streams of one connection: the first input byte picks a request
    /// stream (with or without FIN) or a unidirectional stream. The server must never log an error, never close with
    /// H3_INTERNAL_ERROR, keep serving real requests (checked on a fresh connection now and then), and not hang.
    /// </summary>
    private static Target H3SessionTarget()
    {
        byte[] Req(params (string, string)[] f) => H3Client.Headers(f);
        (string, string)[] get = [(":method", "GET"), (":scheme", "https"), (":authority", "h3.test"), (":path", "/")];
        byte[][] seeds =
        [
            [0, .. Req(get)],
            [0, .. Req((":method", "POST"), (":scheme", "https"), (":authority", "h3.test"), (":path", "/up"), ("content-length", "4")), .. H3Client.Frame(0, "abcd"u8)],
            [1, .. Req(get), .. H3Client.Frame(0, "x"u8)],
            [2, 0x00, .. H3FrameWriter.Settings((6, 100))],
            [2, 0x02, 0x20],
            [2, 0x03, 0x41],
            [0, .. Req(get), .. Req(("trailer-x", "1"))],
            [0, .. Req((":method", "CONNECT"), (":protocol", "websocket"), (":scheme", "https"), (":authority", "h3.test"), (":path", "/"))],
        ];
        return new Target("h3-session", seeds,
            B("\x00", "\x01", "\x02", "\x04", "\x07", "\x21", "\x40\x00", "\x80", "\xc0", "\xd1", "\x51", "\x5f", "\x00\x00"),
            RunH3Session, MaxLen: 1024, Serial: true);
    }

    private static bool RunH3Session(byte[] data)
    {
        if (QuicTls.Unavailable is not null || data.Length == 0) return false;
        if (_h3Server is null)
        {
            _h3Server = TestServer.Start("""
                http { server { listen 127.0.0.1:0 quic; listen 127.0.0.1:0 ssl; server_name h3.test; http3 on; client_body_timeout 2s;
                  ssl_certificate {DIR}/h3.crt; ssl_certificate_key {DIR}/h3.key; root {DIR}/www;
                  location /up { return 200 "ok"; } } }
                """, d =>
            {
                ProxyTests.MakeCert("h3.test", d, "h3").Dispose();
                Directory.CreateDirectory(Path.Combine(d, "www"));
                File.WriteAllText(Path.Combine(d, "www", "index.html"), "hello");
            });
        }
        var s = _h3Server;
        if (_h3Client is null || _h3Client.C.IsClosed || _h3Client.C.IsDraining)
        {
            var old = _h3Client;
            if (old is not null && old.C.ClosedByPeer && old.C.CloseCode == QuicError.ApplicationError && old.C.ApplicationCloseCode == 0x102)
                throw new Finding("the server closed with H3_INTERNAL_ERROR: " + old.C.CloseReason);
            old?.Dispose();
            _h3Client = new H3Client(s.QuicEndPoint, Path.Combine(s.Dir, "h3.crt"));
            if (!_h3Client.Connect()) throw new Finding("handshake failed: " + _h3Client.C.CloseReason);
        }
        var c = _h3Client;
        var body = data.AsSpan(1).ToArray();
        try
        {
            switch (data[0] % 3)
            {
                // A request stream: until it's answered or reset (or the connection closes), at most 150 ms.
                case 0: c.Wait(c.SendRaw(body, fin: true), 150); break;
                case 1: c.Wait(c.SendRaw(body, fin: false), 150); break;
                // A unidirectional stream gets no answer; give the server a moment to object to it.
                default: c.SendUni(body); c.Udp.Run(() => { c.Pump(); return c.C.IsClosed; }, 30); break;
            }
        }
        catch (Exception e) when (e.Message == "no stream credit") { c.C.Close(0, "", QuicEndpoint.Now()); return false; }
        if (++_h3Inputs % 64 == 0)
        {
            if (s.LogNow().Contains("\"level\":\"error\"", StringComparison.Ordinal)) throw new Finding("an error was logged:\n" + s.LogNow());
            using var probe = new H3Client(s.QuicEndPoint, Path.Combine(s.Dir, "h3.crt"));
            if (!probe.Connect() || probe.Get("/index.html").Text != "hello") throw new Finding("the server stopped serving");
        }
        return !c.C.IsClosed;
    }
}
