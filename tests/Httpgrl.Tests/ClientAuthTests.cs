using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static Httpgrl.Tests.Client;

namespace Httpgrl.Tests;

/// <summary>ssl_verify_client: every way a client might get past the certificate check.</summary>
internal static class ClientAuthTests
{
    private const string Rejected = "<<REJECTED>>";

    private static readonly Pki P = new();

    // One TLS port, two names: open.test asks for nothing, secure.test applies the policy under test.
    private static string Conf(string verify, string extra = "") => $$"""
        http {
          ssl_certificate {DIR}/srv.crt; ssl_certificate_key {DIR}/srv.key;
          server { listen 127.0.0.1:0 ssl default_server; server_name open.test; return 200 "open"; }
          server {
            listen 127.0.0.1:0 ssl; server_name secure.test;
            ssl_verify_client {{verify}}; ssl_client_certificate {DIR}/ca.crt; {{extra}}
            return 200 "$ssl_client_verify|$ssl_client_s_dn|$ssl_client_fingerprint";
          }
        }
        """;

    private static void Populate(string d)
    {
        File.WriteAllText(Path.Combine(d, "srv.crt"), P.Server.ExportCertificatePem());
        File.WriteAllText(Path.Combine(d, "srv.key"), P.ServerKey);
        File.WriteAllText(Path.Combine(d, "ca.crt"), P.Root.ExportCertificatePem());
    }

    public static void Register()
    {
        T.Add("mtls: on accepts a certificate issued by the configured CA and exposes it as variables", async () =>
        {
            await using var s = TestServer.Start(Conf("on"), Populate);
            var resp = await Get(s.Port, "secure.test", P.Alice);
            T.Eq(200, Status(resp));
            var fp = Convert.ToHexStringLower(SHA256.HashData(P.Alice.RawData));
            T.Eq("SUCCESS|CN=alice|" + fp, Body(resp));
            T.Contains("\"client_verify\":\"SUCCESS\"", s.LogText());
        });

        T.Add("mtls: on rejects no certificate, a foreign CA, an expired one and one not for client auth", async () =>
        {
            await using var s = TestServer.Start(Conf("on"), Populate);
            T.Eq(Rejected, await Get(s.Port, "secure.test", null));
            T.Eq(Rejected, await Get(s.Port, "secure.test", P.Mallory));
            T.Eq(Rejected, await Get(s.Port, "secure.test", P.Expired));
            T.Eq(Rejected, await Get(s.Port, "secure.test", P.ServerOnly));
            var log = s.LogText();
            T.Contains("client certificate rejected", log);
            T.Contains("expired", log);
            T.Contains("not valid for client authentication", log);
            // TLS 1.2 too, where the handshake itself fails.
            T.Eq(Rejected, await Get(s.Port, "secure.test", P.Mallory, protocols: SslProtocols.Tls12));
            T.Eq(200, Status(await Get(s.Port, "secure.test", P.Alice, protocols: SslProtocols.Tls12)));
        });

        T.Add("mtls: verify depth counts intermediates (nginx default 1)", async () =>
        {
            await using (var s = TestServer.Start(Conf("on"), Populate))
                T.Eq(Rejected, await Get(s.Port, "secure.test", P.Bob, [P.Intermediate]));
            await using (var s = TestServer.Start(Conf("on", "ssl_verify_depth 2;"), Populate))
            {
                var resp = await Get(s.Port, "secure.test", P.Bob, [P.Intermediate]);
                T.Eq(200, Status(resp));
                T.True(Body(resp).StartsWith("SUCCESS|CN=bob|", StringComparison.Ordinal));
                // Again (no resumption shortcut), then without the intermediate: no path to the root.
                T.Eq(200, Status(await Get(s.Port, "secure.test", P.Bob, [P.Intermediate])));
                T.Eq(Rejected, await Get(s.Port, "secure.test", P.Bob));
            }
        });

        T.Add("mtls: optional allows no certificate but still rejects a bad one", async () =>
        {
            await using var s = TestServer.Start(Conf("optional"), Populate);
            T.Eq("NONE||", Body(await Get(s.Port, "secure.test", null)));
            T.Eq(Rejected, await Get(s.Port, "secure.test", P.Mallory));
            T.True(Body(await Get(s.Port, "secure.test", P.Alice)).StartsWith("SUCCESS|", StringComparison.Ordinal));
        });

        T.Add("mtls: optional_no_ca tolerates an unknown issuer only", async () =>
        {
            await using var s = TestServer.Start(Conf("optional_no_ca"), Populate);
            var resp = await Get(s.Port, "secure.test", P.Mallory);
            T.Eq(200, Status(resp));
            T.True(Body(resp).StartsWith("FAILED:", StringComparison.Ordinal));
            T.Contains("|CN=mallory|", Body(resp));
            // An expired certificate is not an "unknown CA" problem.
            T.Eq(Rejected, await Get(s.Port, "secure.test", P.Expired));
        });

        T.Add("mtls: a handshake for one name can't be reused to reach a server with a different policy (421)", async () =>
        {
            await using var s = TestServer.Start(Conf("on"), Populate);
            T.Eq(200, Status(await Get(s.Port, "open.test", null, host: "open.test")));
            T.Eq(421, Status(await Get(s.Port, "open.test", null, host: "secure.test")));
            // No SNI lands on the default (open) server: same answer.
            T.Eq(421, Status(await Get(s.Port, "", null, host: "secure.test")));
            // And the reverse: verified for secure.test, asking open.test is a different policy too.
            T.Eq(421, Status(await Get(s.Port, "secure.test", P.Alice, host: "open.test")));
        });

        T.Add("mtls: identity forwarded upstream can't be forged with request headers", async () =>
        {
            await using var up = FakeUpstream.Echo();
            await using var s = TestServer.Start(Conf("optional", "").Replace("return 200 \"$ssl_client_verify|$ssl_client_s_dn|$ssl_client_fingerprint\";", $$"""
                location / {
                  proxy_pass http://127.0.0.1:{{up.Port}};
                  proxy_set_header X-Client-Verify $ssl_client_verify;
                  proxy_set_header X-Client-DN $ssl_client_s_dn;
                  proxy_set_header X-Client-Cert $ssl_client_escaped_cert;
                }
                """), Populate);
            const string Forged = "X-Client-Verify: SUCCESS\r\nX-Client-DN: CN=admin\r\nX-Client-Cert: x\r\n";
            var anon = Body(await Get(s.Port, "secure.test", null, extraHeaders: Forged));
            T.Contains("X-Client-Verify: NONE\r\n", anon);
            T.True(!(anon.Contains("admin", StringComparison.Ordinal) || anon.Contains("X-Client-Cert", StringComparison.Ordinal)));
            var alice = Body(await Get(s.Port, "secure.test", P.Alice, extraHeaders: Forged));
            T.Contains("X-Client-Verify: SUCCESS\r\nX-Client-DN: CN=alice\r\n", alice);
            T.Contains("X-Client-Cert: -----BEGIN%20CERTIFICATE-----", alice);
            T.True(!alice.Contains("admin", StringComparison.Ordinal));
        });

        T.Add("mtls: config errors (missing CA, unsupported revocation directives)", () =>
        {
            const string NoCa = """
                http { server { listen 127.0.0.1:0 ssl; ssl_certificate {DIR}/srv.crt; ssl_certificate_key {DIR}/srv.key; ssl_verify_client on; } }
                """;
            T.Contains("ssl_client_certificate", T.Throws<ConfigException>(() => TestServer.Start(NoCa, Populate)).Message);
            T.Contains("not supported", T.Throws<ConfigException>(() => TestServer.Start(Conf("on", "ssl_crl {DIR}/x.crl;"), Populate)).Message);
            T.Contains("invalid value", T.Throws<ConfigException>(() => TestServer.Start(Conf("maybe"), Populate)).Message);
            return Task.CompletedTask;
        });
    }

    /// <summary>One request over TLS; <see cref="Rejected"/> if the server refused the handshake or closed without answering.</summary>
    private static async Task<string> Get(int port, string sni, X509Certificate2? cert, X509Certificate2[]? chain = null,
        string? host = null, SslProtocols protocols = SslProtocols.None, string extraHeaders = "")
    {
        using var c = await Connect(port);
        await using var ssl = new SslStream(new NetworkStream(c, ownsSocket: false));
        var opts = new SslClientAuthenticationOptions
        {
            TargetHost = sni,
            EnabledSslProtocols = protocols,
            RemoteCertificateValidationCallback = (_, _, _, _) => true,
        };
        if (cert is not null) opts.ClientCertificateContext = SslStreamCertificateContext.Create(cert, new X509Certificate2Collection(chain ?? []), offline: true);
        try
        {
            using var cts = new CancellationTokenSource(5000);
            await ssl.AuthenticateAsClientAsync(opts, cts.Token);
            // Under TLS 1.3 the server judges our certificate after our side of the handshake is done:
            // a rejection arrives as an alert on the first read.
            await ssl.WriteAsync(Encoding.ASCII.GetBytes($"GET / HTTP/1.1\r\nHost: {host ?? sni}\r\nConnection: close\r\n{extraHeaders}\r\n"), cts.Token);
            var resp = await new StreamReader(ssl, Encoding.Latin1).ReadToEndAsync(cts.Token);
            return resp.Length == 0 ? Rejected : resp;
        }
        catch (Exception e) when (e is AuthenticationException or IOException or SocketException) { return Rejected; }
    }

    /// <summary>A throwaway PKI: root → (alice, expired, server-only), root → intermediate → bob, and an unrelated CA → mallory.</summary>
    private sealed class Pki
    {
        public readonly X509Certificate2 Root, Intermediate, Server, Alice, Bob, Mallory, Expired, ServerOnly;
        public readonly string ServerKey;

        public Pki()
        {
            var now = DateTimeOffset.UtcNow;
            Root = Ca("CN=test root", null, now);
            Intermediate = Ca("CN=test intermediate", Root, now);
            var other = Ca("CN=other root", null, now);
            Alice = Leaf("CN=alice", Root, now.AddDays(-1), now.AddDays(30), clientAuth: true);
            Bob = Leaf("CN=bob", Intermediate, now.AddDays(-1), now.AddDays(30), clientAuth: true);
            Mallory = Leaf("CN=mallory", other, now.AddDays(-1), now.AddDays(30), clientAuth: true);
            Expired = Leaf("CN=expired", Root, now.AddDays(-30), now.AddDays(-1), clientAuth: true);
            ServerOnly = Leaf("CN=server-only", Root, now.AddDays(-1), now.AddDays(30), clientAuth: false);

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var req = new CertificateRequest("CN=secure.test", key, HashAlgorithmName.SHA256);
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("secure.test");
            san.AddDnsName("open.test");
            req.CertificateExtensions.Add(san.Build());
            Server = req.CreateSelfSigned(now.AddDays(-1), now.AddDays(30));
            ServerKey = key.ExportPkcs8PrivateKeyPem();
        }

        private static X509Certificate2 Ca(string name, X509Certificate2? issuer, DateTimeOffset now)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var req = new CertificateRequest(name, key, HashAlgorithmName.SHA256);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
            if (issuer is null) return req.CreateSelfSigned(now.AddDays(-60), now.AddDays(60));
            using var signed = req.Create(issuer, now.AddDays(-60), now.AddDays(60), Serial());
            return signed.CopyWithPrivateKey(key);
        }

        private static X509Certificate2 Leaf(string name, X509Certificate2 issuer, DateTimeOffset from, DateTimeOffset to, bool clientAuth)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var req = new CertificateRequest(name, key, HashAlgorithmName.SHA256);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            var eku = new OidCollection { new Oid(clientAuth ? "1.3.6.1.5.5.7.3.2" : "1.3.6.1.5.5.7.3.1") };
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, false));
            using var signed = req.Create(issuer, from, to, Serial());
            return signed.CopyWithPrivateKey(key);
        }

        private static byte[] Serial() { var s = RandomNumberGenerator.GetBytes(12); s[0] &= 0x7F; return s; }
    }
}
