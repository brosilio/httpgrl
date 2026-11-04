using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using Httpgrl.Core.Http2;

namespace Httpgrl.Tests;

/// <summary>HTTP/2 end to end: a real client for behaviour, a raw frame client for the attacks.</summary>
internal static class Http2SessionTests
{
    private static string Conf(string server = "", string http = "") => $$"""
        http { {{http}}
          server { listen 127.0.0.1:0 ssl; server_name h2.test; http2 on;
            ssl_certificate {DIR}/h2.crt; ssl_certificate_key {DIR}/h2.key; root {DIR}/www;
            {{server}} } }
        """;

    private static void Populate(string d)
    {
        ProxyTests.MakeCert("h2.test", d, "h2");
        Directory.CreateDirectory(Path.Combine(d, "www"));
        File.WriteAllText(Path.Combine(d, "www", "index.html"), "hello");
        var big = new byte[1 << 20];
        new Random(3).NextBytes(big);
        File.WriteAllBytes(Path.Combine(d, "www", "big"), big);
    }

    private static HttpClient Client(bool exact = true)
    {
        var h = new SocketsHttpHandler { SslOptions = { RemoteCertificateValidationCallback = (_, _, _, _) => true, TargetHost = "h2.test" } };
        return new HttpClient(h)
        {
            DefaultRequestVersion = exact ? System.Net.HttpVersion.Version20 : System.Net.HttpVersion.Version11,
            DefaultVersionPolicy = exact ? HttpVersionPolicy.RequestVersionExact : HttpVersionPolicy.RequestVersionOrHigher,
            Timeout = TimeSpan.FromSeconds(20),
        };
    }

    public static void Register()
    {
        T.Add("http2: files, HEAD, errors and many concurrent streams on one connection", async () =>
        {
            await using var s = TestServer.Start(Conf(), Populate);
            using var c = Client();
            var u = $"https://127.0.0.1:{s.Port}";
            var r = await c.GetAsync(u + "/index.html");
            T.Eq(System.Net.HttpVersion.Version20, r.Version);
            T.Eq("hello", await r.Content.ReadAsStringAsync());
            var big = await c.GetByteArrayAsync(u + "/big"); // well past every flow-control window
            T.True(big.AsSpan().SequenceEqual(File.ReadAllBytes(Path.Combine(s.Dir, "www", "big"))));
            T.Eq(404, (int)(await c.GetAsync(u + "/nope")).StatusCode);
            var head = await c.SendAsync(new HttpRequestMessage(HttpMethod.Head, u + "/big"));
            T.Eq(1L << 20, head.Content.Headers.ContentLength ?? -1);
            var all = await Task.WhenAll(Enumerable.Range(0, 300).Select(_ => c.GetStringAsync(u + "/index.html")));
            T.True(all.All(x => x == "hello"));
            var log = s.LogText();
            T.Contains("\"proto\":\"HTTP/2.0\"", log);
            T.NotContains("\"level\":\"error\"", log);
        });

        T.Add("http2: off unless asked for (ALPN offers only http/1.1)", async () =>
        {
            await using var s = TestServer.Start(Conf().Replace("http2 on;", ""), Populate);
            using var c = Client(exact: false);
            var r = await c.GetAsync($"https://127.0.0.1:{s.Port}/index.html");
            T.Eq(System.Net.HttpVersion.Version11, r.Version);
        });

        T.Add("http2: nginx's \"listen ... http2\" warns that it doesn't enable HTTP/2 (http2 on does)", async () =>
        {
            await using (var s = TestServer.Start(Conf().Replace("http2 on;", "").Replace("listen 127.0.0.1:0 ssl;", "listen 127.0.0.1:0 ssl http2;"), Populate))
                T.Contains("enable HTTP/2; add", s.LogText());
            await using (var s = TestServer.Start(Conf().Replace("listen 127.0.0.1:0 ssl;", "listen 127.0.0.1:0 ssl http2;"), Populate))
                T.NotContains("enable HTTP/2; add", s.LogText());
        });

        T.Add("http2: WebSockets over HTTP/2 (RFC 8441) reach an HTTP/1.1 WebSocket backend through the proxy", async () =>
        {
            await using var ws = FakeUpstream.WebSocketEcho();
            await using var s = TestServer.Start(Conf($"location /ws/ {{ proxy_pass http://127.0.0.1:{ws.Port}; }}"), Populate);
            using var handler = new SocketsHttpHandler { SslOptions = { RemoteCertificateValidationCallback = (_, _, _, _) => true, TargetHost = "h2.test" } };
            using var invoker = new HttpMessageInvoker(handler);
            using var c = new System.Net.WebSockets.ClientWebSocket();
            c.Options.HttpVersion = System.Net.HttpVersion.Version20;
            c.Options.HttpVersionPolicy = HttpVersionPolicy.RequestVersionExact; // no quiet fallback to HTTP/1.1
            await c.ConnectAsync(new Uri($"wss://127.0.0.1:{s.Port}/ws/chat"), invoker, CancellationToken.None);
            var buf = new byte[1 << 16];
            foreach (var msg in new[] { "hello over h2", new string('x', 40_000) })
            {
                await c.SendAsync(Encoding.UTF8.GetBytes(msg), System.Net.WebSockets.WebSocketMessageType.Text, true, default);
                var got = new MemoryStream();
                System.Net.WebSockets.ValueWebSocketReceiveResult r;
                do { r = await c.ReceiveAsync(buf.AsMemory(), default); got.Write(buf, 0, r.Count); } while (!r.EndOfMessage);
                T.Eq(msg, Encoding.UTF8.GetString(got.ToArray()));
            }
            await c.SendAsync(new byte[] { 0, 1, 2, 255 }, System.Net.WebSockets.WebSocketMessageType.Binary, true, default);
            var b = await c.ReceiveAsync(buf.AsMemory(), default);
            T.True(buf.AsSpan(0, b.Count).SequenceEqual(new byte[] { 0, 1, 2, 255 }));
            await c.CloseAsync(System.Net.WebSockets.WebSocketCloseStatus.NormalClosure, "bye", default);
            T.Eq(System.Net.WebSockets.WebSocketState.Closed, c.State);
            T.Contains("\"proto\":\"HTTP/2.0\"", s.LogText());
        });

        T.Add("http2: extended CONNECT is advertised, and only WebSockets are tunnelled", async () =>
        {
            await using var s = TestServer.Start(Conf(), Populate);
            await using var h = await RawH2.ConnectAsync(s.Port);
            T.Eq(1u, await h.ReadSettingAsync(SettingId.EnableConnectProtocol));
            (string, string)[] Connect(string protocol) => [(":method", "CONNECT"), (":protocol", protocol), (":scheme", "https"), (":path", "/ws"), (":authority", "h2.test"), ("sec-websocket-version", "13")];
            await h.SendHeadersAsync(1, false, Connect("h2c"));
            T.Eq("501", await h.ReadStatusAsync(1));
            await h.SendHeadersAsync(3, false, Connect("something-else"));
            T.Eq("501", await h.ReadStatusAsync(3));
            await h.SendHeadersAsync(5, false, (":method", "CONNECT"), (":authority", "h2.test:443")); // plain CONNECT
            T.Eq("405", await h.ReadStatusAsync(5));
            await h.SendHeadersAsync(7, true, Connect("websocket")); // END_STREAM: malformed
            T.Eq(H2Error.ProtocolError, (await h.ReadResetOrHeadersAsync(7)).Code);
            await h.SendHeadersAsync(9, true, (":method", "GET"), (":protocol", "websocket"), (":scheme", "https"), (":path", "/"), (":authority", "h2.test"));
            T.Eq(H2Error.ProtocolError, (await h.ReadResetOrHeadersAsync(9)).Code);
            // No WebSocket handler at a plain location: an ordinary answer, and the connection carries on.
            await h.SendHeadersAsync(11, false, Connect("websocket"));
            T.True(await h.ReadStatusAsync(11) is "404" or "405" or "400");
        });

        T.Add("http2: a WebSocket over HTTP/2 idles out at proxy_read_timeout, counted both ways", async () =>
        {
            await using var ws = FakeUpstream.WebSocketEcho();
            await using var s = TestServer.Start(Conf($"location /ws/ {{ proxy_pass http://127.0.0.1:{ws.Port}; proxy_read_timeout 1s; }}"), Populate);
            using var handler = new SocketsHttpHandler { SslOptions = { RemoteCertificateValidationCallback = (_, _, _, _) => true } };
            using var invoker = new HttpMessageInvoker(handler);
            using var c = new System.Net.WebSockets.ClientWebSocket();
            c.Options.HttpVersion = System.Net.HttpVersion.Version20;
            c.Options.HttpVersionPolicy = HttpVersionPolicy.RequestVersionExact;
            c.Options.KeepAliveInterval = TimeSpan.Zero;
            await c.ConnectAsync(new Uri($"wss://127.0.0.1:{s.Port}/ws/idle"), invoker, CancellationToken.None);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var buf = new byte[256];
            try { await c.ReceiveAsync(buf.AsMemory(), new CancellationTokenSource(8000).Token); }
            catch (Exception e) when (e is System.Net.WebSockets.WebSocketException or IOException or OperationCanceledException) { }
            T.True(sw.ElapsedMilliseconds < 5000);
        });

        T.Add("http2: request bodies reach an upstream, and upstream responses stream back", async () =>
        {
            await using var up = FakeUpstream.Echo();
            await using var s = TestServer.Start(Conf($"location /up/ {{ proxy_pass http://127.0.0.1:{up.Port}; }}"), Populate);
            using var c = Client();
            var body = new byte[300_000]; // more than a stream window: the upload must wait for WINDOW_UPDATEs
            new Random(5).NextBytes(body);
            var r = await c.PostAsync($"https://127.0.0.1:{s.Port}/up/x", new ByteArrayContent(body));
            var echo = await r.Content.ReadAsByteArrayAsync();
            T.Eq(200, (int)r.StatusCode);
            T.True(echo.AsSpan().EndsWith(body));
            T.Contains("Host: 127.0.0.1", Encoding.Latin1.GetString(echo, 0, 400));
        });

        T.Add("http2: malformed requests reset their stream, the connection carries on", async () =>
        {
            await using var s = TestServer.Start(Conf(), Populate);
            await using var h = await RawH2.ConnectAsync(s.Port);
            await h.SendHeadersAsync(1, true, (":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "h2.test"), ("Upper", "x"));
            var (rst, code) = await h.ReadResetOrHeadersAsync(1);
            T.True(rst);
            T.Eq(H2Error.ProtocolError, code);
            await h.SendHeadersAsync(3, true, (":method", "GET"), (":scheme", "https"), (":path", "/index.html"), (":authority", "h2.test"));
            T.Eq("200", await h.ReadStatusAsync(3));
        });

        T.Add("http2: an HPACK bomb gets a 431, not the connection's memory", async () =>
        {
            await using var s = TestServer.Start(Conf(), Populate);
            await using var h = await RawH2.ConnectAsync(s.Port);
            // One 4000-byte entry into the table, then 200 one-byte references to it: about 800 KB decoded.
            var block = new List<byte>();
            byte[] baseBlock = H(("" + ":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "h2.test"));
            block.AddRange(baseBlock);
            block.AddRange([0x40, 0x01, (byte)'x', 0x7F, 0xA1, 0x1E]);
            block.AddRange(Enumerable.Repeat((byte)'a', 4000));
            block.AddRange(Enumerable.Repeat((byte)0xBE, 200));
            await h.SendRawHeadersAsync(1, true, [.. block]);
            T.Eq("431", await h.ReadStatusAsync(1));
            await h.SendHeadersAsync(3, true, (":method", "GET"), (":scheme", "https"), (":path", "/index.html"), (":authority", "h2.test"));
            T.Eq("200", await h.ReadStatusAsync(3)); // the table stayed in step
        });

        T.Add("http2: rapid reset is cut off (CVE-2023-44487)", async () =>
        {
            await using var s = TestServer.Start(Conf(), Populate);
            await using var h = await RawH2.ConnectAsync(s.Port);
            for (int id = 1; id < 4000; id += 2)
            {
                await h.SendHeadersAsync(id, true, (":method", "GET"), (":scheme", "https"), (":path", "/big"), (":authority", "h2.test"));
                await h.SendAsync(FrameWriter.RstStream(id, H2Error.Cancel));
                if (h.Closed) break;
            }
            T.Eq(H2Error.EnhanceYourCalm, await h.ReadGoAwayAsync());
            T.Contains("too many streams reset, refused or malformed", s.LogText()); // this defence, not the control-frame budget
        });

        T.Add("http2: CONTINUATION floods and control-frame floods end the connection", async () =>
        {
            await using var s = TestServer.Start(Conf(), Populate);
            await using (var h = await RawH2.ConnectAsync(s.Port))
            {
                await h.SendRawHeadersAsync(1, true, H((":method", "GET")), endHeaders: false);
                for (int k = 0; k < 100 && !h.Closed; k++) await h.SendAsync(RawH2.Frame(FrameType.Continuation, 0, 1));
                T.Eq(H2Error.EnhanceYourCalm, await h.ReadGoAwayAsync());
                T.Contains("header block in too many fragments", s.LogText());
            }
            await using (var h = await RawH2.ConnectAsync(s.Port))
            {
                for (int k = 0; k < 3000 && !h.Closed; k++) await h.SendAsync(FrameWriter.Ping(new byte[8], ack: false));
                T.Eq(H2Error.EnhanceYourCalm, await h.ReadGoAwayAsync());
                T.Contains("too many control frames", s.LogText());
            }
        });

        T.Add("http2: flow-control and priority frames aren't charged as a flood (busy clients send thousands)", async () =>
        {
            await using var s = TestServer.Start(Conf(), Populate);
            await using var h = await RawH2.ConnectAsync(s.Port);
            for (int k = 0; k < 5000 && !h.Closed; k++)
            {
                await h.SendAsync(FrameWriter.WindowUpdate(0, 1));
                await h.SendAsync(RawH2.Frame(FrameType.Priority, 0, 3, 0, 0, 0, 0, 16)); // on an idle stream: legal
            }
            await h.SendHeadersAsync(1, true, (":method", "GET"), (":scheme", "https"), (":path", "/index.html"), (":authority", "h2.test"));
            T.Eq("200", await h.ReadStatusAsync(1));
            T.NotContains("too many control frames", s.LogText());
        });

        T.Add("http2: a reload drains in two steps (GOAWAY, PING, final GOAWAY): requests already sent are answered, then a clean close", async () =>
        {
            await using var s = TestServer.Start(Conf(), Populate);
            await using var h = await RawH2.ConnectAsync(s.Port);
            (string, string)[] Get(string p) => [(":method", "GET"), (":scheme", "https"), (":path", p), (":authority", "h2.test")];
            await h.SendHeadersAsync(1, true, Get("/index.html"));
            T.Eq("200", await h.ReadStatusAsync(1));
            T.True(await s.Reload(Conf()));

            // Step one: a GOAWAY that refuses nothing yet, and a PING.
            int? firstLast = null;
            byte[]? ping = null;
            while (ping is null && await h.NextFrameAsync() is { } x)
            {
                if (x.F.Type == FrameType.GoAway) firstLast = BinaryPrimitives.ReadInt32BigEndian(x.P) & int.MaxValue;
                if (x.F.Type == FrameType.Ping && !x.F.Has(FrameFlags.Ack)) ping = x.P;
            }
            T.Eq(int.MaxValue, firstLast ?? 0);
            T.True(ping is not null);
            // A request the client sent before it saw the GOAWAY: still served.
            await h.SendHeadersAsync(3, true, Get("/index.html"));
            await h.SendAsync(FrameWriter.Ping(ping!, ack: true));

            // Step two: the final GOAWAY names stream 3; 3 is answered; anything later is ignored (the client retries it).
            int? finalLast = null;
            string? status3 = null;
            bool sent5 = false, any5 = false;
            var trace = new StringBuilder();
            while (await h.NextFrameAsync() is { } x)
            {
                trace.Append($"{x.F.Type}/{x.F.StreamId}/{x.F.Flags} ");
                if (x.F.Type == FrameType.GoAway)
                {
                    finalLast = BinaryPrimitives.ReadInt32BigEndian(x.P) & int.MaxValue;
                    T.Eq(H2Error.NoError, (H2Error)BinaryPrimitives.ReadUInt32BigEndian(x.P.AsSpan(4)));
                    if (!sent5) { sent5 = true; await h.SendHeadersAsync(5, true, Get("/index.html")); }
                }
                if (x.F.Type == FrameType.Headers && x.F.StreamId == 3) status3 = h.LastStatus;
                if (x.F.StreamId == 5) any5 = true;
            }
            if (finalLast != 3) throw new Exception($"final GOAWAY {finalLast?.ToString() ?? "missing"}; frames after the PING ack: {trace}closed={h.Closed} clean={h.ClosedCleanly}\n{s.LogText()}");
            T.Eq("200", status3);
            T.True(!any5);
            T.True(h.ClosedCleanly);
            T.NotContains("\"level\":\"error\"", s.LogText());
        });

        T.Add("http2: keepalive_requests winds connections down under load without failing a request (and without crashing TLS)", async () =>
        {
            // Every few requests a connection drains (GOAWAY, PING, final GOAWAY, FIN) while streams are in flight and
            // the reader has a read pending: the close must not race the SslStream (it once corrupted OpenSSL's memory).
            await using var s = TestServer.Start(Conf("keepalive_requests 7;"), Populate);
            using var c = Client();
            var u = $"https://127.0.0.1:{s.Port}";
            int ok = 0;
            await Task.WhenAll(Enumerable.Range(0, 16).Select(async k =>
            {
                for (int i = 0; i < 40; i++)
                {
                    var body = await c.GetByteArrayAsync(u + (i % 4 == 0 ? "/big" : "/index.html"));
                    if (body.Length is 5 or 1 << 20) Interlocked.Increment(ref ok);
                }
            }));
            T.Eq(640, ok);
            T.NotContains("\"level\":\"error\"", s.LogText());
        });

        T.Add("deadlines: an End without its Begin never counts busy time (no spurious minimum-rate aborts)", () =>
        {
            var d = new TestDeadlines();
            d.StartRate(1000);
            d.EndWrite(500);
            d.EndRead(500);
            T.Eq(0L, d.RateBusyMs);
            d.BeginWrite();
            d.EndWrite(500);
            T.True(d.RateBusyMs < 1000);
            T.Eq(500L, d.RateBytes);
            d.RateWritesOnly = true;
            d.BeginRead();
            d.EndRead(100); // a multiplexed connection's always-pending read isn't the client being slow
            T.Eq(500L, d.RateBytes);
            d.CountBytes(100);
            T.Eq(600L, d.RateBytes);
            return Task.CompletedTask;
        });

        T.Add("http2: streams past max_concurrent_streams are refused while the others run", async () =>
        {
            await using var up = new FakeUpstream(async (st, rd) => { await rd.ReadRequestAsync(); await Task.Delay(5000); });
            await using var s = TestServer.Start(Conf($"http2_max_concurrent_streams 4; location /slow/ {{ proxy_pass http://127.0.0.1:{up.Port}; }}"), Populate);
            await using var h = await RawH2.ConnectAsync(s.Port);
            for (int id = 1; id <= 9; id += 2)
                await h.SendHeadersAsync(id, true, (":method", "GET"), (":scheme", "https"), (":path", "/slow/x"), (":authority", "h2.test"));
            var (rst, code) = await h.ReadResetOrHeadersAsync(9);
            T.True(rst);
            T.Eq(H2Error.RefusedStream, code);
        });

        T.Add("http2: a stalled stream is cut at its own deadline; the connection survives", async () =>
        {
            await using var up = FakeUpstream.Echo();
            await using var s = TestServer.Start(Conf($"client_body_timeout 1s; location /up/ {{ proxy_pass http://127.0.0.1:{up.Port}; }}"), Populate);
            await using var h = await RawH2.ConnectAsync(s.Port);
            // A POST that never sends its body: the handler waits on it until client_body_timeout, then the stream is reset.
            await h.SendHeadersAsync(1, false, (":method", "POST"), (":scheme", "https"), (":path", "/up/x"), (":authority", "h2.test"), ("content-length", "10"));
            var (rst, _) = await h.ReadResetOrHeadersAsync(1, timeoutMs: 6000);
            T.True(rst);
            await h.SendHeadersAsync(3, true, (":method", "GET"), (":scheme", "https"), (":path", "/index.html"), (":authority", "h2.test"));
            T.Eq("200", await h.ReadStatusAsync(3));
            T.Contains("request body i/o timeout", s.LogText());
        });

        T.Add("http2: a client that never opens its window is cut at send_timeout", async () =>
        {
            await using var s = TestServer.Start(Conf("send_timeout 1s;"), Populate);
            await using var h = await RawH2.ConnectAsync(s.Port, initialWindow: 0);
            await h.SendHeadersAsync(1, true, (":method", "GET"), (":scheme", "https"), (":path", "/big"), (":authority", "h2.test"));
            T.Eq("200", await h.ReadStatusAsync(1));
            var (rst, _) = await h.ReadResetOrHeadersAsync(1, timeoutMs: 6000);
            T.True(rst);
        });

        T.Add("http2: garbage instead of the preface, and frames before SETTINGS, close the connection", async () =>
        {
            await using var s = TestServer.Start(Conf(), Populate);
            await using (var h = await RawH2.ConnectAsync(s.Port, preface: false))
            {
                await h.SendAsync("GET / HTTP/1.1\r\nHost: h2.test\r\n\r\n"u8.ToArray());
                T.True(await h.WaitClosedAsync());
            }
            await using (var h = await RawH2.ConnectAsync(s.Port, preface: false))
            {
                await h.SendAsync([.. FrameReader.Preface, .. FrameWriter.Ping(new byte[8], ack: false)]);
                T.Eq(H2Error.ProtocolError, await h.ReadGoAwayAsync());
            }
        });
    }

    private static byte[] H(params (string, string)[] fields)
    {
        var buf = new byte[64];
        int len = 0;
        foreach (var (n, v) in fields) HpackEncoder.Encode(ref buf, ref len, n, v);
        return buf[..len];
    }
}

/// <summary>A deliberately naive HTTP/2 client: frames by hand, for sending what a real client never would.</summary>
internal sealed class TestDeadlines : Httpgrl.Core.Hosting.Deadlines
{
    public override CancellationToken AbortToken => CancellationToken.None;
    public override bool IsAborted => false;
    public override string? AbortReason => null;
    public override void Abort(string reason, bool graceful = false) { }
}

internal sealed class RawH2 : IAsyncDisposable
{
    private readonly TcpClient _tcp;
    private readonly SslStream _ssl;
    private readonly byte[] _buf = new byte[1 << 20];
    private int _start, _end;
    private readonly HpackDecoder _hpack = new(4096, 1 << 20);
    public bool Closed { get; private set; }
    /// <summary>The server closed cleanly (close_notify or FIN), not with a reset.</summary>
    public bool ClosedCleanly { get; private set; }

    private RawH2(TcpClient tcp, SslStream ssl) { _tcp = tcp; _ssl = ssl; }

    public static async Task<RawH2> ConnectAsync(int port, bool preface = true, int initialWindow = 65535)
    {
        var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port);
        var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "h2.test", ApplicationProtocols = [SslApplicationProtocol.Http2] });
        if (ssl.NegotiatedApplicationProtocol != SslApplicationProtocol.Http2) throw new Exception("server didn't negotiate h2");
        var h = new RawH2(tcp, ssl);
        if (preface) await h.SendAsync([.. FrameReader.Preface, .. FrameWriter.Settings((SettingId.InitialWindowSize, (uint)initialWindow))]);
        return h;
    }

    public static byte[] Frame(FrameType type, byte flags, int sid, params byte[] payload)
    {
        var f = new byte[9 + payload.Length];
        FrameWriter.Header(f, payload.Length, type, flags, sid);
        payload.CopyTo(f, 9);
        return f;
    }

    public async Task SendAsync(byte[] data)
    {
        if (Closed) return;
        try { await _ssl.WriteAsync(data); }
        catch (Exception e) when (e is IOException or ObjectDisposedException) { Closed = true; }
    }

    public Task SendHeadersAsync(int sid, bool endStream, params (string, string)[] fields)
    {
        var buf = new byte[64];
        int len = 0;
        foreach (var (n, v) in fields) HpackEncoder.Encode(ref buf, ref len, n, v);
        return SendRawHeadersAsync(sid, endStream, buf[..len]);
    }

    public Task SendRawHeadersAsync(int sid, bool endStream, byte[] block, bool endHeaders = true) =>
        SendAsync(Frame(FrameType.Headers, (byte)((endHeaders ? FrameFlags.EndHeaders : 0) | (endStream ? FrameFlags.EndStream : 0)), sid, block));

    /// <summary>The next frame, answering PINGs and SETTINGS as a client must; null when the connection closes.</summary>
    private async Task<(Frame F, byte[] P)?> NextAsync(int timeoutMs)
    {
        using var cts = new CancellationTokenSource(timeoutMs);
        while (true)
        {
            int n = FrameReader.TryRead(_buf.AsSpan(_start, _end - _start), 1 << 20, out var f, out var p);
            if (n > 0)
            {
                var payload = p.ToArray();
                _start += n;
                if (f.Type == FrameType.Settings && !f.Has(FrameFlags.Ack)) { await SendAsync(FrameWriter.SettingsAck()); continue; }
                return (f, payload);
            }
            if (_start > 0) { Buffer.BlockCopy(_buf, _start, _buf, 0, _end - _start); _end -= _start; _start = 0; }
            int r;
            try { r = await _ssl.ReadAsync(_buf.AsMemory(_end), cts.Token); }
            catch (Exception e) when (e is IOException or OperationCanceledException or ObjectDisposedException) { Closed = true; return null; }
            if (r == 0) { Closed = ClosedCleanly = true; return null; }
            _end += r;
        }
    }

    /// <summary>The next frame (HEADERS decoded, to keep HPACK in step: see <see cref="LastStatus"/>); null when the connection closes.</summary>
    public async Task<(Frame F, byte[] P)?> NextFrameAsync(int timeoutMs = 10_000)
    {
        var x = await NextAsync(timeoutMs);
        if (x is { } y && y.F.Type == FrameType.Headers)
        {
            LastStatus = null;
            _hpack.Decode(y.P, (n, v) => { if (n.SequenceEqual(":status"u8)) LastStatus = Encoding.ASCII.GetString(v); });
        }
        return x;
    }

    public string? LastStatus { get; private set; }

    /// <summary>The value the server's first SETTINGS frame gives <paramref name="id"/>, or null if it doesn't.</summary>
    public async Task<uint?> ReadSettingAsync(ushort id, int timeoutMs = 5000)
    {
        using var cts = new CancellationTokenSource(timeoutMs);
        while (true)
        {
            int n = FrameReader.TryRead(_buf.AsSpan(_start, _end - _start), 1 << 20, out var f, out var p);
            if (n > 0)
            {
                var payload = p.ToArray();
                _start += n;
                if (f.Type != FrameType.Settings || f.Has(FrameFlags.Ack)) continue;
                await SendAsync(FrameWriter.SettingsAck());
                for (int i = 0; i + 6 <= payload.Length; i += 6)
                    if (BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(i)) == id) return BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(i + 2));
                return null;
            }
            if (_start > 0) { Buffer.BlockCopy(_buf, _start, _buf, 0, _end - _start); _end -= _start; _start = 0; }
            int r = await _ssl.ReadAsync(_buf.AsMemory(_end), cts.Token);
            if (r == 0) return null;
            _end += r;
        }
    }

    public async Task<string?> ReadStatusAsync(int sid, int timeoutMs = 10_000)
    {
        while (await NextAsync(timeoutMs) is { } x)
        {
            if (x.F.Type == FrameType.Headers && x.F.StreamId == sid)
            {
                string? status = null;
                _hpack.Decode(x.P, (n, v) => { if (n.SequenceEqual(":status"u8)) status = Encoding.ASCII.GetString(v); });
                return status;
            }
            if (x.F.Type == FrameType.Headers) _hpack.Decode(x.P, (_, _) => { });
            if (x.F.Type == FrameType.RstStream && x.F.StreamId == sid) return "RST " + (H2Error)BinaryPrimitives.ReadUInt32BigEndian(x.P);
        }
        return null;
    }

    /// <summary>Whether <paramref name="sid"/> is reset (and with what) before a response starts or finishes on it.</summary>
    public async Task<(bool Reset, H2Error Code)> ReadResetOrHeadersAsync(int sid, int timeoutMs = 10_000)
    {
        while (await NextAsync(timeoutMs) is { } x)
        {
            if (x.F.Type == FrameType.Headers) _hpack.Decode(x.P, (_, _) => { });
            if (x.F.StreamId != sid) continue;
            if (x.F.Type == FrameType.RstStream) return (true, (H2Error)BinaryPrimitives.ReadUInt32BigEndian(x.P));
            if (x.F.Has(FrameFlags.EndStream)) return (false, H2Error.NoError);
        }
        return (false, H2Error.NoError);
    }

    public async Task<H2Error?> ReadGoAwayAsync(int timeoutMs = 10_000)
    {
        while (await NextAsync(timeoutMs) is { } x)
        {
            if (x.F.Type == FrameType.Headers) { try { _hpack.Decode(x.P, (_, _) => { }); } catch (HpackException) { } }
            if (x.F.Type == FrameType.GoAway) return (H2Error)BinaryPrimitives.ReadUInt32BigEndian(x.P.AsSpan(4));
        }
        return null;
    }

    public async Task<bool> WaitClosedAsync(int timeoutMs = 5000)
    {
        while (await NextAsync(timeoutMs) is not null) { }
        return Closed;
    }

    public async ValueTask DisposeAsync()
    {
        try { await _ssl.DisposeAsync(); } catch (Exception) { }
        _tcp.Dispose();
    }
}
