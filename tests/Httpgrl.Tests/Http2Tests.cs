using System.Text;
using Httpgrl.Core.Http2;

namespace Httpgrl.Tests;

/// <summary>HTTP/2 building blocks: frames (RFC 9113) and HPACK (RFC 7541).</summary>
internal static class Http2Tests
{
    private static List<(string, string)> Decode(HpackDecoder d, byte[] block)
    {
        var got = new List<(string, string)>();
        d.Decode(block, (n, v) => got.Add((Encoding.Latin1.GetString(n), Encoding.Latin1.GetString(v))));
        return got;
    }

    private static byte[] F(FrameType type, byte flags, int sid, params byte[] payload)
    {
        var f = new byte[FrameReader.HeaderSize + payload.Length];
        FrameWriter.Header(f, payload.Length, type, flags, sid);
        payload.CopyTo(f, FrameReader.HeaderSize);
        return f;
    }

    private static void BadFrame(string what, byte[] frame, H2Error code, bool connection, int maxFrame = 16384)
    {
        H2Exception e;
        try { FrameReader.TryRead(frame, maxFrame, out _, out _); throw new Exception($"{what}: accepted"); }
        catch (H2Exception x) { e = x; }
        if (e.Code != code || e.IsConnectionError != connection)
            throw new Exception($"{what}: expected {code} ({(connection ? "connection" : "stream")}), got {e.Code} ({(e.IsConnectionError ? "connection" : "stream")}): {e.Message}");
    }

    /// <summary>Run fields through RequestHead: the result code, the request, and why if malformed.</summary>
    private static (int Code, Httpgrl.Core.Http.RequestImpl Req, string? Why) Head(bool endStream, params (string, string)[] fields)
    {
        var req = new Httpgrl.Core.Http.RequestImpl();
        var h = new RequestHead(underscores: false);
        h.Begin(req);
        foreach (var (n, v) in fields) h.OnField(Encoding.Latin1.GetBytes(n), Encoding.Latin1.GetBytes(v));
        int code = h.Finish(endStream);
        return (code, req, h.Why);
    }

    private static readonly (string, string)[] Base = [(":method", "GET"), (":scheme", "https"), (":path", "/a/../b?x=1"), (":authority", "Example.TEST:443")];

    public static void Register()
    {
        T.Add("h2 request head: a valid request maps onto HTTP/1.1 semantics", () =>
        {
            var (code, req, _) = Head(true, [.. Base, ("accept", "*/*"), ("cookie", "a=1"), ("cookie", "b=2"), ("x_hidden", "1")]);
            T.Eq(0, code);
            T.Eq(HttpMethods.Get, req.MethodValue);
            T.Eq("/b", req.PathValue);
            T.Eq("x=1", req.QueryValue);
            T.Eq("example.test", req.HostValue);
            T.Eq("a=1; b=2", req.Headers.Get("Cookie"));       // crumbs rejoined (RFC 9113 8.2.3)
            T.Eq("Example.TEST:443", req.Headers.Get("Host"));  // a Host for modules and upstreams
            T.Eq(null, req.Headers.Get("x_hidden"));            // underscores ignored, as on HTTP/1.1
            T.Eq(HttpVersion.Http20, req.VersionValue);
            T.True(!req.HasBody);
            // A body without content-length is "unknown length" (chunked, to HTTP/1.1 eyes); with one, that length.
            T.True(Head(false, Base).Req.ChunkedValue);
            var withLen = Head(false, [.. Base, ("content-length", "5")]).Req;
            T.Eq(5L, withLen.ContentLengthValue);
            T.True(!withLen.ChunkedValue);
        });

        T.Add("h2 request head: malformed requests are stream errors, refusals are statuses", () =>
        {
            void Bad(string what, bool end, params (string, string)[] f)
            {
                var (code, _, why) = Head(end, f);
                if (code != -1) throw new Exception($"{what}: expected malformed, got {code}");
                if (why is null) throw new Exception($"{what}: no reason");
            }
            Bad("upper-case name", true, [.. Base, ("Accept", "x")]);
            Bad("pseudo after regular", true, [(":method", "GET"), ("accept", "x"), (":scheme", "https"), (":path", "/"), (":authority", "a")]);
            Bad("duplicate :path", true, [.. Base, (":path", "/x")]);
            Bad("unknown pseudo", true, [.. Base, (":nonsense", "1")]);
            Bad("response pseudo", true, [.. Base, (":status", "200")]);
            Bad("no :method", true, [(":scheme", "https"), (":path", "/"), (":authority", "a")]);
            Bad("no :path", true, [(":method", "GET"), (":scheme", "https"), (":authority", "a")]);
            Bad("http scheme", true, [(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "a")]);
            Bad("connection", true, [.. Base, ("connection", "close")]);
            Bad("transfer-encoding", true, [.. Base, ("transfer-encoding", "chunked")]);
            Bad("upgrade", true, [.. Base, ("upgrade", "websocket")]);
            Bad("keep-alive", true, [.. Base, ("keep-alive", "1")]);
            Bad("te gzip", true, [.. Base, ("te", "gzip")]);
            Bad("CR in value", true, [.. Base, ("x", "a\rb")]);
            Bad("NUL in value", true, [.. Base, ("x", "a\0b")]);
            Bad("leading space", true, [.. Base, ("x", " a")]);
            Bad("authority disagrees with host", true, [.. Base, ("host", "other.test")]);
            Bad("two hosts", true, [(":method", "GET"), (":scheme", "https"), (":path", "/"), ("host", "a"), ("host", "b")]);
            Bad("userinfo", true, [(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "u@a")]);
            Bad("no host at all", true, [(":method", "GET"), (":scheme", "https"), (":path", "/")]);
            Bad("two content-lengths", false, [.. Base, ("content-length", "1"), ("content-length", "1")]);
            Bad("content-length +1", false, [.. Base, ("content-length", "+1")]);
            Bad("content-length with END_STREAM", true, [.. Base, ("content-length", "3")]);
            Bad("path escaping root", true, [(":method", "GET"), (":scheme", "https"), (":path", "/../x"), (":authority", "a")]);
            Bad("path with NUL", true, [(":method", "GET"), (":scheme", "https"), (":path", "/%00"), (":authority", "a")]);
            Bad("asterisk outside OPTIONS", true, [(":method", "GET"), (":scheme", "https"), (":path", "*"), (":authority", "a")]);
            Bad("absolute :path", true, [(":method", "GET"), (":scheme", "https"), (":path", "http://evil/x"), (":authority", "a")]);
            Bad(":protocol outside CONNECT", true, [.. Base, (":protocol", "websocket")]);
            T.Eq(405, Head(true, [(":method", "CONNECT"), (":authority", "a:443")]).Code);
            T.Eq(417, Head(true, [.. Base, ("expect", "nonsense")]).Code);
            T.Eq(0, Head(true, [(":method", "OPTIONS"), (":scheme", "https"), (":path", "*"), (":authority", "a")]).Code);
            T.Eq(0, Head(true, [.. Base, ("te", "trailers")]).Code);
        });


        T.Add("h2 frames: framing, padding and priority fields", () =>
        {
            var data = F(FrameType.Data, FrameFlags.Padded, 1, 2, (byte)'h', (byte)'i', 0, 0);
            T.Eq(0, FrameReader.TryRead(data.AsSpan(0, 8), 16384, out _, out _));              // header incomplete
            T.Eq(0, FrameReader.TryRead(data.AsSpan(0, data.Length - 1), 16384, out _, out _)); // payload incomplete
            T.Eq(data.Length, FrameReader.TryRead(data, 16384, out var f, out var p));
            T.Eq(FrameType.Data, f.Type);
            T.Eq(5, f.Length); // padding counts against flow control
            T.Eq("hi", Encoding.ASCII.GetString(p));
            // HEADERS with PRIORITY: 5 bytes of dependency and weight are stripped.
            var h = F(FrameType.Headers, FrameFlags.Priority | FrameFlags.EndHeaders, 3, 0, 0, 0, 1, 16, 0x82);
            FrameReader.TryRead(h, 16384, out _, out p);
            T.Eq(1, p.Length);
            // The reserved bit of the stream ID is ignored; unknown types pass through for the caller to skip.
            var r = F(FrameType.Data, 0, 1, (byte)'x');
            r[5] |= 0x80;
            FrameReader.TryRead(r, 16384, out f, out _);
            T.Eq(1, f.StreamId);
            FrameReader.TryRead(F((FrameType)0xEE, 0, 7, 1, 2, 3), 16384, out f, out p);
            T.Eq((FrameType)0xEE, f.Type);
            T.Eq(3, p.Length);
        });

        T.Add("h2 frames: every malformed frame is the right error, at the right scope", () =>
        {
            BadFrame("oversized", F(FrameType.Data, 0, 1, new byte[16385]), H2Error.FrameSizeError, true);
            BadFrame("oversized unknown type", F((FrameType)0xEE, 0, 1, new byte[100]), H2Error.FrameSizeError, true, maxFrame: 99);
            BadFrame("DATA on 0", F(FrameType.Data, 0, 0, 1), H2Error.ProtocolError, true);
            BadFrame("DATA padding = payload", F(FrameType.Data, FrameFlags.Padded, 1, 3, 0, 0), H2Error.ProtocolError, true);
            BadFrame("DATA pad length missing", F(FrameType.Data, FrameFlags.Padded, 1), H2Error.FrameSizeError, true);
            BadFrame("HEADERS on 0", F(FrameType.Headers, FrameFlags.EndHeaders, 0, 0x82), H2Error.ProtocolError, true);
            BadFrame("HEADERS short priority", F(FrameType.Headers, FrameFlags.Priority, 1, 0, 0), H2Error.FrameSizeError, true);
            BadFrame("HEADERS depends on itself", F(FrameType.Headers, FrameFlags.Priority, 5, 0, 0, 0, 5, 16), H2Error.ProtocolError, true);
            BadFrame("PRIORITY wrong size", F(FrameType.Priority, 0, 3, 0, 0, 0, 1), H2Error.FrameSizeError, false);
            BadFrame("PRIORITY on itself", F(FrameType.Priority, 0, 3, 0, 0, 0, 3, 16), H2Error.ProtocolError, false);
            BadFrame("PRIORITY on 0", F(FrameType.Priority, 0, 0, 0, 0, 0, 1, 16), H2Error.ProtocolError, true);
            BadFrame("RST_STREAM wrong size", F(FrameType.RstStream, 0, 1, 0, 0, 0), H2Error.FrameSizeError, true);
            BadFrame("RST_STREAM on 0", F(FrameType.RstStream, 0, 0, 0, 0, 0, 8), H2Error.ProtocolError, true);
            BadFrame("SETTINGS on a stream", F(FrameType.Settings, 0, 1), H2Error.ProtocolError, true);
            BadFrame("SETTINGS ACK with payload", F(FrameType.Settings, FrameFlags.Ack, 0, 0, 1, 0, 0, 0, 0), H2Error.FrameSizeError, true);
            BadFrame("SETTINGS odd length", F(FrameType.Settings, 0, 0, 0, 1, 0), H2Error.FrameSizeError, true);
            BadFrame("ENABLE_PUSH 2", F(FrameType.Settings, 0, 0, 0, 2, 0, 0, 0, 2), H2Error.ProtocolError, true);
            BadFrame("INITIAL_WINDOW_SIZE 2^31", F(FrameType.Settings, 0, 0, 0, 4, 0x80, 0, 0, 0), H2Error.FlowControlError, true);
            BadFrame("MAX_FRAME_SIZE too small", F(FrameType.Settings, 0, 0, 0, 5, 0, 0, 0x3F, 0xFF), H2Error.ProtocolError, true);
            BadFrame("MAX_FRAME_SIZE too big", F(FrameType.Settings, 0, 0, 0, 5, 0x01, 0, 0, 0), H2Error.ProtocolError, true);
            BadFrame("PUSH_PROMISE from a client", F(FrameType.PushPromise, FrameFlags.EndHeaders, 1, 0, 0, 0, 2), H2Error.ProtocolError, true);
            BadFrame("PING wrong size", F(FrameType.Ping, 0, 0, 1, 2, 3), H2Error.FrameSizeError, true);
            BadFrame("PING on a stream", F(FrameType.Ping, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0), H2Error.ProtocolError, true);
            BadFrame("GOAWAY short", F(FrameType.GoAway, 0, 0, 0, 0, 0, 0), H2Error.FrameSizeError, true);
            BadFrame("WINDOW_UPDATE wrong size", F(FrameType.WindowUpdate, 0, 1, 0, 0, 1), H2Error.FrameSizeError, true);
            BadFrame("WINDOW_UPDATE 0 on a stream", F(FrameType.WindowUpdate, 0, 1, 0, 0, 0, 0), H2Error.ProtocolError, false);
            BadFrame("WINDOW_UPDATE 0 on the connection", F(FrameType.WindowUpdate, 0, 0, 0, 0, 0, 0), H2Error.ProtocolError, true);
            BadFrame("CONTINUATION on 0", F(FrameType.Continuation, FrameFlags.EndHeaders, 0, 0x82), H2Error.ProtocolError, true);
            // Unknown settings are ignored, not errors (RFC 9113 6.5.2).
            T.Eq(15, FrameReader.TryRead(F(FrameType.Settings, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF), 16384, out _, out _));
        });


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
