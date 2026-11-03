using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using static Httpgrl.Tests.Client;

namespace Httpgrl.Tests;

/// <summary>listen ... proxy_protocol (v1 and v2), with TLS too.</summary>
internal static class ProxyProtocolTests
{
    private const string Show = "return 200 \"[$proxy_protocol_addr]:[$proxy_protocol_port]>[$proxy_protocol_server_addr]:[$proxy_protocol_server_port]|$remote_addr\";";
    private static readonly byte[] Req = "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n"u8.ToArray();

    private static byte[] V2(byte cmd, byte famProto, byte[] addrs, byte[]? tlv = null)
    {
        tlv ??= [];
        var b = new List<byte> { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, (byte)(0x20 | cmd), famProto };
        int len = addrs.Length + tlv.Length;
        b.Add((byte)(len >> 8)); b.Add((byte)len);
        b.AddRange(addrs); b.AddRange(tlv);
        return b.ToArray();
    }

    private static async Task<string> Send(int port, params byte[][] parts)
    {
        using var c = await Connect(port);
        foreach (var p in parts) { await c.SendAsync(p, SocketFlags.None); await Task.Delay(5); }
        return await ReadToClose(c, 3000);
    }

    public static void Register()
    {
        T.Add("proxy_protocol: v1 and v2 headers give the real client; the request right behind them is intact", async () =>
        {
            await using var s = TestServer.Start($"http {{ server {{ listen 127.0.0.1:0 proxy_protocol; {Show} }} }}");
            var v1 = Encoding.ASCII.GetBytes("PROXY TCP4 203.0.113.7 198.51.100.1 4242 443\r\n");
            T.Eq("[203.0.113.7]:[4242]>[198.51.100.1]:[443]|127.0.0.1", Body(await Send(s.Port, [.. v1, .. Req]))); // one packet: no over-read
            T.Eq("[2001:db8::1]:[1]>[2001:db8::2]:[65535]|127.0.0.1", Body(await Send(s.Port, Encoding.ASCII.GetBytes("PROXY TCP6 2001:db8::1 2001:db8::2 1 65535\r\n"), Req)));
            T.Eq("[]:[]>[]:[]|127.0.0.1", Body(await Send(s.Port, Encoding.ASCII.GetBytes("PROXY UNKNOWN whatever\r\n"), Req)));
            // Trickled one byte at a time.
            var parts = v1.Select(b => new[] { b }).Append(Req).ToArray();
            T.Eq("[203.0.113.7]:[4242]>[198.51.100.1]:[443]|127.0.0.1", Body(await Send(s.Port, parts)));

            byte[] v4 = [203, 0, 113, 9, 10, 0, 0, 1, 0x1F, 0x90, 0x01, 0xBB];
            T.Eq("[203.0.113.9]:[8080]>[10.0.0.1]:[443]|127.0.0.1", Body(await Send(s.Port, V2(1, 0x11, v4, [0x03, 0x00, 0x04, 1, 2, 3, 4]), Req)));
            var v6 = new byte[36];
            v6[0] = 0x20; v6[1] = 0x01; v6[2] = 0x0d; v6[3] = 0xb8; v6[15] = 5; v6[16] = 0x20; v6[17] = 0x01; v6[18] = 0x0d; v6[19] = 0xb8; v6[31] = 6;
            v6[32] = 0; v6[33] = 80; v6[34] = 1; v6[35] = 0xBB;
            T.Eq("[2001:db8::5]:[80]>[2001:db8::6]:[443]|127.0.0.1", Body(await Send(s.Port, V2(1, 0x21, v6), Req)));
            T.Eq("[]:[]>[]:[]|127.0.0.1", Body(await Send(s.Port, V2(0, 0x00, []), Req))); // LOCAL
        });

        T.Add("proxy_protocol: missing, malformed or slow headers close the connection; elsewhere a header is just a bad request", async () =>
        {
            await using var s = TestServer.Start($"http {{ ssl_handshake_timeout 1s; server {{ listen 127.0.0.1:0 proxy_protocol; {Show} }} }}");
            T.Eq("", await Send(s.Port, Req));                                                            // no header
            foreach (var bad in new[] { "PROXY TCP4 1.2.3.4 5.6.7.8 080 443\r\n", "PROXY TCP4 1.2.3.4 5.6.7.8 1 99999\r\n", "PROXY TCP4 ::1 5.6.7.8 1 2\r\n",
                                        "PROXY TCP4 1.2.3.4  5.6.7.8 1 2\r\n", "PROXY TCP5 1.2.3.4 5.6.7.8 1 2\r\n", "PROXY TCP4 1.2.3.4 5.6.7.8 1 2\n", "PROXY " + new string('1', 200) + "\r\n" })
                T.Eq("", await Send(s.Port, Encoding.ASCII.GetBytes(bad), Req));
            T.Eq("", await Send(s.Port, V2(1, 0x11, [1, 2, 3]), Req));                                // address block too short
            T.Eq("", await Send(s.Port, V2(5, 0x11, new byte[12]), Req));                             // unknown command
            var sw = System.Diagnostics.Stopwatch.StartNew();
            using (var c = await Connect(s.Port))
            {
                await c.SendAsync("PROXY TCP4 1.2.3.4"u8.ToArray(), SocketFlags.None);              // ...and nothing more
                var r = await ReadToClose(c, 5000);
                T.True(r is "" or "<<RESET>>", r);                                                    // cut by the timeout, nothing sent
            }
            T.True(sw.ElapsedMilliseconds is > 800 and < 3000, $"{sw.ElapsedMilliseconds} ms");
            T.Contains("PROXY protocol header", s.LogText());

            await using var plain = TestServer.Start($"http {{ server {{ listen 127.0.0.1:0; {Show} }} }}");
            T.Eq(400, Status(await Send(plain.Port, Encoding.ASCII.GetBytes("PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n"), Req)));
            T.Contains("conflicting \"proxy_protocol\"", T.Throws<ConfigException>(() => TestServer.Start(
                "http { server { listen 127.0.0.1:18999 proxy_protocol; } server { listen 127.0.0.1:18999; } }")).Message);
        });

        T.Add("proxy_protocol: in front of TLS, as a TCP relay sends it", async () =>
        {
            await using var s = TestServer.Start($$"""http { server { listen 127.0.0.1:0 ssl proxy_protocol; ssl_certificate {DIR}/c.crt; ssl_certificate_key {DIR}/c.key; {{Show}} } }""",
                d => ProxyTests.MakeCert("relay.test", d, "c").Dispose());
            using var c = await Connect(s.Port);
            await c.SendAsync("PROXY TCP4 192.0.2.44 192.0.2.1 50000 8443\r\n"u8.ToArray(), SocketFlags.None);
            await using var ssl = new SslStream(new NetworkStream(c, ownsSocket: false));
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "relay.test", RemoteCertificateValidationCallback = (_, _, _, _) => true });
            await ssl.WriteAsync(Req);
            var resp = await new StreamReader(ssl, Encoding.ASCII).ReadToEndAsync();
            T.Eq("[192.0.2.44]:[50000]>[192.0.2.1]:[8443]|127.0.0.1", Body(resp));
        });
    }
}
