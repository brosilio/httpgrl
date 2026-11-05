using System.Net;
using Httpgrl.Core.Http3;
using Httpgrl.Core.Quic;

namespace Httpgrl.Tests;

/// <summary>HTTP/3 end to end: our HTTP/3 client against the real server, for behaviour and for the attacks.</summary>
internal static class Http3SessionTests
{
    private static string Conf(string server = "", string http = "", string listen = "listen 127.0.0.1:0 ssl; listen 127.0.0.1:0 quic;") => $$"""
        http { {{http}}
          server { {{listen}} server_name h3.test; http3 on;
            ssl_certificate {DIR}/h3.crt; ssl_certificate_key {DIR}/h3.key; root {DIR}/www;
            {{server}} } }
        """;

    private static void Populate(string d)
    {
        ProxyTests.MakeCert("h3.test", d, "h3").Dispose();
        Directory.CreateDirectory(Path.Combine(d, "www"));
        File.WriteAllText(Path.Combine(d, "www", "index.html"), "hello");
        var big = new byte[1 << 20];
        new Random(3).NextBytes(big);
        File.WriteAllBytes(Path.Combine(d, "www", "big"), big);
    }

    private static H3Client Client(TestServer s, string sni = "h3.test")
    {
        var c = new H3Client(s.QuicEndPoint, Path.Combine(s.Dir, "h3.crt"), sni);
        if (!c.Connect()) throw new Exception("HTTP/3 handshake failed: " + c.C.CloseReason);
        return c;
    }

    /// <summary>The H3 error the server closed the connection with (application CONNECTION_CLOSE), or null.</summary>
    private static H3Error? ClosedWith(H3Client c)
    {
        c.Udp.Run(() => { c.Pump(); return c.C.IsClosed || c.C.IsDraining; }, 5000);
        return c.C.CloseCode == QuicError.ApplicationError && c.C.ClosedByPeer ? (H3Error)c.C.ApplicationCloseCode : null;
    }

    private static void Case(string name, Func<Task> body) => T.Add("http3: " + name, async () =>
    {
        if (QuicTls.Unavailable is not null) return;
        await body();
    });

    public static void Register()
    {
        Case("files, HEAD, 404, uploads through the proxy, and 100 concurrent requests on one connection", async () =>
        {
            await using var up = FakeUpstream.Echo();
            await using var s = TestServer.Start(Conf($"location /echo/ {{ proxy_pass http://127.0.0.1:{up.Port}; client_max_body_size 4m; }}"), Populate);
            using var c = Client(s);
            var r = c.Get("/index.html");
            T.Eq("200", r.Status);
            T.Eq("hello", r.Text);
            T.Eq("5", r.Header("content-length"));
            var big = c.Get("/big");
            var want = File.ReadAllBytes(Path.Combine(s.Dir, "www", "big"));
            if (!big.Body.ToArray().AsSpan().SequenceEqual(want))
                throw new Exception($"big: status {big.Status}, {big.Body.Length} of {want.Length} bytes, done {big.Done}, reset {big.Reset}, closed {c.C.CloseCode} {c.C.CloseReason}; client recv {c.C.BytesReceived} sent {c.C.BytesSent}, inflight {c.C.Recovery.BytesInFlight}, deadline {(c.C.Deadline - QuicEndpoint.Now()) / 1000} ms; server conns {s.Server.QuicConnections}");
            T.Eq("404", c.Get("/nope").Status);
            var head = c.Wait(c.Send("HEAD", "/big"));
            T.Eq("200", head.Status);
            T.Eq(0L, head.Body.Length);
            // An upload with content-length, and one without (a body of unknown length): both reach the upstream intact.
            var body = new byte[300_000];
            new Random(7).NextBytes(body);
            var posted = c.Wait(c.Send("POST", "/echo/x", body, true, ("content-length", body.Length.ToString())));
            T.Eq("200", posted.Status);
            T.True(posted.Body.ToArray().AsSpan().EndsWith(body)); // the echo is the request head, then the body
            var chunked = c.Wait(c.Send("POST", "/echo/y", body));
            T.Eq("200", chunked.Status);
            T.True(chunked.Body.ToArray().AsSpan().EndsWith(body));
            // Many at once: the stream limit (128) allows them all.
            var ids = Enumerable.Range(0, 100).Select(_ => c.Send("GET", "/index.html")).ToList();
            T.True(ids.All(id => c.Wait(id).Text == "hello"));
            var log = s.LogText();
            T.Contains("\"proto\":\"HTTP/3.0\"", log);
            T.NotContains("\"level\":\"error\"", log);
        });

        Case("interop: curl's own HTTP/3 stack (ngtcp2/nghttp3) fetches, uploads and verifies the certificate (skipped without it)", async () =>
        {
            if (!CurlHasHttp3()) { Console.WriteLine("    (skipped: curl without HTTP/3)"); return; }
            await using var up = FakeUpstream.Echo();
            await using var s = TestServer.Start(Conf($"location /echo/ {{ proxy_pass http://127.0.0.1:{up.Port}; }}"), Populate);
            var q = s.QuicEndPoint;
            string Curl(params string[] args)
            {
                var psi = new System.Diagnostics.ProcessStartInfo("curl", ["-sS", "--http3-only", "--cacert", Path.Combine(s.Dir, "h3.crt"),
                    "--resolve", $"h3.test:{q.Port}:127.0.0.1", "--max-time", "10", .. args]) { RedirectStandardOutput = true, RedirectStandardError = true };
                using var p = System.Diagnostics.Process.Start(psi)!;
                string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                p.WaitForExit();
                return o;
            }
            T.Eq("hello", Curl($"https://h3.test:{q.Port}/index.html"));
            T.Eq("3 200 1048576", Curl("-o", "/dev/null", "-w", "%{http_version} %{http_code} %{size_download}", $"https://h3.test:{q.Port}/big"));
            T.Contains("posted-by-curl", Curl("-d", "posted-by-curl", $"https://h3.test:{q.Port}/echo/x"));
            T.Contains("\"proto\":\"HTTP/3.0\"", s.LogText());
        });

        Case("WebSockets over HTTP/3 (RFC 9220) reach an HTTP/1.1 WebSocket backend through the proxy; other protocols are refused", async () =>
        {
            await using var ws = FakeUpstream.WebSocketEcho();
            await using var s = TestServer.Start(Conf($"location /ws {{ proxy_pass http://127.0.0.1:{ws.Port}; proxy_read_timeout 5s; }}"), Populate);
            using var c = Client(s);
            long id = c.SendRaw(H3Client.Headers((":method", "CONNECT"), (":protocol", "websocket"), (":scheme", "https"), (":authority", "h3.test"),
                (":path", "/ws"), ("sec-websocket-version", "13")), fin: false);
            var r = c.Wait(id, 300); // the 200 arrives; the stream stays open
            c.Udp.Run(() => { c.Pump(); return r.Status is not null; }, 5000);
            T.Eq("200", r.Status);
            // A masked text frame "hi" inside a DATA frame; the echo comes back unmasked.
            byte[] mask = [1, 2, 3, 4];
            byte[] frame = [0x81, 0x82, .. mask, (byte)('h' ^ 1), (byte)('i' ^ 2)];
            c.C.StreamWrite(id, H3Client.Frame(H3FrameType.Data, frame), fin: false);
            c.Udp.Run(() => { c.Pump(); return r.Body.Length >= 4; }, 5000);
            T.Eq("8102" + Convert.ToHexStringLower("hi"u8), Convert.ToHexStringLower(r.Body.ToArray().AsSpan(0, 4)));
            // Extended CONNECT for anything but websocket: 501. Plain CONNECT: 405.
            var other = c.Wait(c.SendRaw(H3Client.Headers((":method", "CONNECT"), (":protocol", "webtransport"), (":scheme", "https"), (":authority", "h3.test"), (":path", "/ws")), fin: false), 3000);
            T.Eq("501", other.Status);
            var plain = c.Wait(c.SendRaw(H3Client.Headers((":method", "CONNECT"), (":authority", "h3.test:443"))), 3000);
            T.Eq("405", plain.Status);
        });

        Case("a stalled upload is cut at client_body_timeout (the stream, not the connection); the stream limit holds", async () =>
        {
            await using var up = FakeUpstream.Echo();
            await using var s = TestServer.Start(Conf($"client_body_timeout 1s; http3_max_concurrent_streams 4; location /echo/ {{ proxy_pass http://127.0.0.1:{up.Port}; }}"), Populate);
            using var c = Client(s);
            // Headers promising 100 bytes, then 10, then nothing.
            long stalled = c.SendRaw([.. H3Client.Headers((":method", "POST"), (":scheme", "https"), (":authority", "h3.test"), (":path", "/echo/x"), ("content-length", "100")),
                .. H3Client.Frame(H3FrameType.Data, new byte[10])], fin: false);
            var r = c.Wait(stalled, 5000);
            T.True(r.Reset is not null || r.Status is "408" or "400");
            T.Eq("hello", c.Get("/index.html").Text); // the connection lives on
            // The client may open only as many request streams as we allow at once.
            T.Eq(4L, (long)c.C.PeerParameters!.InitialMaxStreamsBidi);
        });

        Case("opt-in: a quic listener without http3 on is a config error; Alt-Svc only where HTTP/3 is served", async () =>
        {
            T.Throws<Httpgrl.ConfigException>(() => TestServer.Start(Conf().Replace("http3 on;", ""), Populate));
            T.Throws<Httpgrl.ConfigException>(() => TestServer.Start(Conf(listen: "listen 127.0.0.1:0 ssl quic;"), Populate));
            int quicPort = Ports.FreeUdpPort();
            await using (var s = TestServer.Start(Conf(listen: $"listen 127.0.0.1:0 ssl; listen 127.0.0.1:{quicPort} quic;"), Populate))
            {
                var resp = await TlsGet(s.Port, "/index.html");
                T.Contains($"Alt-Svc: h3=\":{quicPort}\"; ma=86400", resp);
                using var c = Client(s);
                T.Eq(null, c.Get("/index.html").Header("alt-svc")); // not on HTTP/3 itself
            }
            // An explicit add_header Alt-Svc wins.
            await using (var s = TestServer.Start(Conf("add_header Alt-Svc 'clear';", listen: $"listen 127.0.0.1:0 ssl; listen 127.0.0.1:{quicPort} quic;"), Populate))
                T.Contains("Alt-Svc: clear", await TlsGet(s.Port, "/index.html"));
        });

        Case("client certificates over HTTP/3: the same verdicts as TCP (CA-only, chain, expiry, purpose, CRL), refusals with TLS alerts", async () =>
        {
            var pki = ClientAuthTests.P;
            string Conf(string mode, string extra = "") => $$"""
                http { ssl_certificate {DIR}/srv.crt; ssl_certificate_key {DIR}/srv.key; http3 on;
                  server { listen 127.0.0.1:0 ssl default_server; listen 127.0.0.1:0 quic default_server; server_name open.test; return 200 "open"; }
                  server { listen 127.0.0.1:0 ssl; listen 127.0.0.1:0 quic; server_name secure.test;
                    ssl_verify_client {{mode}}; ssl_client_certificate {DIR}/ca.crt; ssl_verify_depth 2; {{extra}}
                    return 200 "$ssl_client_verify|$ssl_client_s_dn"; } }
                """;
            void Populate(string d)
            {
                File.WriteAllText(Path.Combine(d, "srv.crt"), pki.Server.ExportCertificatePem());
                File.WriteAllText(Path.Combine(d, "srv.key"), pki.ServerKey);
                File.WriteAllText(Path.Combine(d, "ca.crt"), pki.Root.ExportCertificatePem());
                foreach (var (name, cert, chain) in new[] { ("alice", pki.Alice, (System.Security.Cryptography.X509Certificates.X509Certificate2?)null),
                    ("bob", pki.Bob, pki.Intermediate), ("mallory", pki.Mallory, null), ("expired", pki.Expired, null), ("serveronly", pki.ServerOnly, null) })
                {
                    File.WriteAllText(Path.Combine(d, name + ".crt"), cert.ExportCertificatePem() + "\n" + (chain?.ExportCertificatePem() ?? ""));
                    File.WriteAllText(Path.Combine(d, name + ".key"), System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions.GetECDsaPrivateKey(cert)!.ExportPkcs8PrivateKeyPem());
                }
                File.WriteAllText(Path.Combine(d, "crl.pem"), ClientAuthTests.CrlPem(pki.Root, pki.Carol, pki.Alice));
            }
            H3Client Connect(TestServer s, string sni, string? who)
            {
                var c = new H3Client(s.QuicEndPoint, Path.Combine(s.Dir, "srv.crt"), sni,
                    certFile: who is null ? null : Path.Combine(s.Dir, who + ".crt"), keyFile: who is null ? null : Path.Combine(s.Dir, who + ".key"));
                c.Connect();
                return c;
            }
            // What the server did: the response body, or the TLS alert it closed with.
            string Outcome(TestServer s, string? who, string sni = "secure.test", string authority = "secure.test")
            {
                using var c = Connect(s, sni, who);
                if (!c.C.IsClosed && !c.C.IsDraining)
                {
                    var r = c.Wait(c.SendRaw(H3Client.Headers((":method", "GET"), (":scheme", "https"), (":authority", authority), (":path", "/"))), 5000);
                    if (r.Status is not null) return r.Status == "200" ? r.Text : r.Status;
                }
                c.Udp.Run(() => c.C.IsClosed || c.C.IsDraining, 3000);
                return c.C.CloseCode is >= QuicError.CryptoError and <= QuicError.CryptoError + 255 ? "alert " + (int)(c.C.CloseCode - QuicError.CryptoError) : "closed " + c.C.CloseCode;
            }
            await using (var s = TestServer.Start(Conf("on"), Populate))
            {
                T.Eq("SUCCESS|CN=alice", Outcome(s, "alice"));
                T.Eq("SUCCESS|CN=bob", Outcome(s, "bob"));           // through the intermediate it sent
                T.Eq("alert 116", Outcome(s, null));                 // certificate_required
                T.Eq("alert 42", Outcome(s, "mallory"));             // another CA: bad_certificate
                T.Eq("alert 42", Outcome(s, "expired"));
                T.Eq("alert 42", Outcome(s, "serveronly"));          // not for client authentication
                T.Eq("open", Outcome(s, null, "open.test", "open.test")); // the other name asks for nothing
                // Host switches across policies: misdirected, both ways (as on TCP).
                T.Eq("421", Outcome(s, null, "open.test", "secure.test"));
                T.Eq("421", Outcome(s, "alice", "secure.test", "open.test"));
            }
            await using (var s = TestServer.Start(Conf("optional"), Populate))
                T.Eq("NONE|", Outcome(s, null));
            await using (var s = TestServer.Start(Conf("optional_no_ca"), Populate))
            {
                var o = Outcome(s, "mallory"); // accepted, with the reason recorded (its wording depends on the chain built)
                T.True(o.StartsWith("FAILED:", StringComparison.Ordinal) && o.EndsWith("|CN=mallory", StringComparison.Ordinal));
            }
            await using (var s = TestServer.Start(Conf("on", "ssl_crl {DIR}/crl.pem;"), Populate))
            {
                T.Eq("alert 42", Outcome(s, "alice"));               // revoked
                T.Eq("alert 42", Outcome(s, "bob"));                 // no CRL from its intermediate: fails closed
            }
        });

        Case("TLS sessions resume over QUIC (OpenSSL's client), never on servers that check client certificates (skipped without openssl -quic)", async () =>
        {
            if (!OpenSslHasQuic()) { Console.WriteLine("    (skipped: openssl without -quic)"); return; }
            var conf = """
                http { http3 on; ssl_certificate {DIR}/h3.crt; ssl_certificate_key {DIR}/h3.key;
                  server { listen 127.0.0.1:0 ssl; listen 127.0.0.1:0 quic; server_name h3.test; root {DIR}/www; }
                  server { listen 127.0.0.1:0 ssl; listen 127.0.0.1:0 quic; server_name secure.test; root {DIR}/www;
                    ssl_verify_client optional_no_ca; } }
                """;
            await using var s = TestServer.Start(conf, Populate);
            var q = s.QuicEndPoint;
            string Handshake(string sni, string sessFlag, string sessFile)
            {
                var psi = new System.Diagnostics.ProcessStartInfo("openssl", ["s_client", "-quic", "-alpn", "h3", "-connect", $"127.0.0.1:{q.Port}",
                    "-servername", sni, "-CAfile", Path.Combine(s.Dir, "h3.crt"), sessFlag, sessFile]) { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
                using var p = System.Diagnostics.Process.Start(psi)!;
                Thread.Sleep(700); // long enough for the post-handshake ticket
                p.StandardInput.Close();
                string o = p.StandardOutput.ReadToEnd();
                p.WaitForExit(5000);
                return o.Contains("Reused, TLSv1.3") ? "reused" : o.Contains("New, TLSv1.3") ? "new" : "failed";
            }
            var sess = Path.Combine(s.Dir, "sess.pem");
            T.Eq("new", Handshake("h3.test", "-sess_out", sess));
            T.Eq("reused", Handshake("h3.test", "-sess_in", sess));
            var sess2 = Path.Combine(s.Dir, "sess2.pem");
            T.Eq("new", Handshake("secure.test", "-sess_out", sess2));
            T.True(!File.Exists(sess2) || Handshake("secure.test", "-sess_in", sess2) == "new"); // no ticket to resume with
        });

        Case("a default server with ssl_reject_handshake: named servers get HTTP/3; no SNI, or the default's name, gets no handshake", async () =>
        {
            var conf = """
                http {
                  server { listen 127.0.0.1:0 ssl default_server; listen 127.0.0.1:0 quic default_server; server_name _; http3 on; ssl_reject_handshake on; }
                  server { listen 127.0.0.1:0 ssl; listen 127.0.0.1:0 quic; server_name h3.test; http3 on;
                    ssl_certificate {DIR}/h3.crt; ssl_certificate_key {DIR}/h3.key; root {DIR}/www; }
                }
                """;
            await using var s = TestServer.Start(conf, Populate);
            using (var c = Client(s)) T.Eq("hello", c.Get("/index.html").Text);
            using (var c = new H3Client(s.QuicEndPoint, Path.Combine(s.Dir, "h3.crt"), sni: "other.test"))
            {
                T.True(!c.Connect());
                T.True(c.C.CloseReason?.Contains("112") == true || c.C.CloseCode is not null); // unrecognized_name: no certificate shown
            }
        });

        Case("malformed requests reset their stream with H3_MESSAGE_ERROR; the connection carries on", async () =>
        {
            await using var s = TestServer.Start(Conf(), Populate);
            using var c = Client(s);
            (string, string)[] ok = [(":method", "GET"), (":scheme", "https"), (":authority", "h3.test"), (":path", "/index.html")];
            foreach (var fields in new (string, string)[][]
            {
                [.. ok, ("Upper-Case", "x")],                               // field names are lower-case
                [(":method", "GET"), (":scheme", "https"), (":authority", "h3.test")], // no :path
                [.. ok, ("connection", "close")],                          // connection-specific
                [.. ok, ("te", "gzip")],                                   // TE other than trailers
                [(":method", "GET"), (":scheme", "http"), (":authority", "h3.test"), (":path", "/")], // not https
                [.. ok, ("content-length", "5")],                          // a length with no body (FIN follows)
            })
            {
                var r = c.Wait(c.SendRaw(H3Client.Headers(fields)));
                T.Eq((ulong)H3Error.MessageError, r.Reset ?? 0);
            }
            // A stream that ends without a request.
            var empty = c.Wait(c.SendRaw([]));
            T.Eq((ulong)H3Error.RequestIncomplete, empty.Reset ?? 0);
            T.Eq("hello", c.Get("/index.html").Text);
        });

        Case("framing violations close the connection with the right code", async () =>
        {
            await using var s = TestServer.Start(Conf(), Populate);
            (string Why, Action<H3Client> Do, H3Error Code)[] cases =
            [
                ("DATA before HEADERS", c => c.SendRaw(H3Client.Frame(H3FrameType.Data, "x"u8)), H3Error.FrameUnexpected),
                ("an HTTP/2 frame type", c => c.SendRaw([0x02, 0x00]), H3Error.FrameUnexpected),
                ("SETTINGS on a request stream", c => c.SendRaw(H3Client.Frame(H3FrameType.Settings, [])), H3Error.FrameUnexpected),
                ("a stream ending inside a frame", c => c.SendRaw([0x01, 0x10, 0x00]), H3Error.FrameError),
                ("a dynamic QPACK reference", c => c.SendRaw(H3Client.Frame(H3FrameType.Headers, [0x02, 0x00, 0x80])), H3Error.QpackDecompressionFailed),
                ("a second control stream", c => c.SendUni([(byte)H3StreamType.Control, .. H3FrameWriter.Settings()]), H3Error.StreamCreationError),
                ("a push stream from a client", c => c.SendUni([(byte)H3StreamType.Push, 0x00]), H3Error.StreamCreationError),
                ("a QPACK insert with capacity 0", c => c.SendUni([(byte)H3StreamType.QpackEncoder, 0xc0 | 17, 0x01, 0x61]), H3Error.QpackEncoderStreamError),
                ("a decoder acknowledgment of nothing", c => c.SendUni([(byte)H3StreamType.QpackDecoder, 0x84]), H3Error.QpackDecoderStreamError),
            ];
            foreach (var (why, act, code) in cases)
            {
                using var c = Client(s);
                act(c);
                var got = ClosedWith(c);
                if (got != code) throw new Exception($"{why}: expected {code}, got {got?.ToString() ?? "no close"} ({c.C.CloseReason})");
            }
            // A control stream that doesn't start with SETTINGS.
            using (var c = new H3Client(s.QuicEndPoint, Path.Combine(s.Dir, "h3.crt")))
            {
                T.True(c.Connect(settings: false));
                c.SendUni([(byte)H3StreamType.Control, .. H3FrameWriter.GoAway(0)]);
                T.Eq(H3Error.MissingSettings, ClosedWith(c));
            }
            // Unknown (reserved) stream types are refused, the connection kept.
            using (var c = Client(s))
            {
                c.SendUni([0x21, 1, 2, 3]);
                T.Eq("hello", c.Get("/index.html").Text);
                T.True(!c.C.IsClosed);
            }
        });

        Case("reload: GOAWAY, requests in flight finish, later streams are rejected (retry-safe), the old connection closes", async () =>
        {
            await using var up = new FakeUpstream(async (st, rd) =>
            {
                await rd.ReadRequestAsync();
                await Task.Delay(1500);
                await st.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nslow"u8.ToArray());
            });
            var conf = "reload_drain_timeout 10s;\n" + Conf($"location /slow {{ proxy_pass http://127.0.0.1:{up.Port}; }}");
            await using var s = TestServer.Start(conf, Populate);
            using var c = Client(s);
            T.Eq("hello", c.Get("/index.html").Text);
            long slow = c.Send("GET", "/slow");
            c.Udp.Run(() => { c.Pump(); return false; }, 300);
            T.True(await s.Reload(conf.Replace("hello", "x")));
            c.Udp.Run(() => { c.Pump(); return false; }, 500);
            var late = c.Wait(c.Send("GET", "/index.html"));
            T.Eq((ulong)H3Error.RequestRejected, late.Reset ?? 0);
            T.Eq("slow", c.Wait(slow).Text);
            T.True(c.Udp.Run(() => { c.Pump(); return c.C.IsClosed || c.C.IsDraining; }, 5000));
            T.Eq(H3Error.NoError, (H3Error)c.C.ApplicationCloseCode);
            using var fresh = Client(s);
            T.Eq("200", fresh.Get("/index.html").Status);
        });
    }

    private static bool OpenSslHasQuic()
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("openssl", ["s_client", "-help"]) { RedirectStandardOutput = true, RedirectStandardError = true };
            using var p = System.Diagnostics.Process.Start(psi)!;
            string v = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit();
            return v.Contains("-quic", StringComparison.Ordinal);
        }
        catch (System.ComponentModel.Win32Exception) { return false; }
    }

    private static bool CurlHasHttp3()
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("curl", ["-V"]) { RedirectStandardOutput = true };
            using var p = System.Diagnostics.Process.Start(psi)!;
            string v = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            return v.Contains("HTTP3", StringComparison.Ordinal);
        }
        catch (System.ComponentModel.Win32Exception) { return false; }
    }

    private static async Task<string> TlsGet(int port, string path)
    {
        using var tcp = new System.Net.Sockets.TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port);
        using var ssl = new System.Net.Security.SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync("h3.test");
        await ssl.WriteAsync(System.Text.Encoding.ASCII.GetBytes($"GET {path} HTTP/1.1\r\nHost: h3.test\r\nConnection: close\r\n\r\n"));
        using var ms = new MemoryStream();
        await ssl.CopyToAsync(ms);
        return System.Text.Encoding.Latin1.GetString(ms.ToArray());
    }

    private static class Ports
    {
        public static int FreeUdpPort()
        {
            using var u = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp);
            u.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            return ((IPEndPoint)u.LocalEndPoint!).Port;
        }
    }
}
