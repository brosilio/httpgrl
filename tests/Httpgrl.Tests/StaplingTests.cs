using System.Diagnostics;

namespace Httpgrl.Tests;

/// <summary>OCSP stapling driven by httpgrl, against a local responder (no network). Needs the openssl CLI to see the staple.</summary>
internal static class StaplingTests
{
    private const string Conf = "http { server { listen 127.0.0.1:0 ssl; server_name staple.test; ssl_certificate {DIR}/s.crt; ssl_certificate_key {DIR}/s.key; STAPLING return 200 ok; } }";

    private static string With(string stapling) => Conf.Replace("STAPLING", stapling);

    public static void Register()
    {
        T.Add("ssl_stapling: fetched once on first use, verified, stapled; off never contacts the responder", async () =>
        {
            if (!HasOpenSsl()) { Console.WriteLine("    (skipped: no openssl CLI)"); return; }
            await using var pki = new OcspPki("staple.test");
            await using (var s = TestServer.Start(With("ssl_stapling on; ssl_stapling_verify on;"), d => pki.WriteFiles(d, "s")))
            {
                T.Eq(0, pki.Requests);                         // nothing at load: the first handshake starts it
                await Eventually(async () => await Staple(s.Port) == "good");
                for (int k = 0; k < 5; k++) T.Eq("good", await Staple(s.Port));
                T.Eq(1, pki.Requests);
                T.Contains("OCSP response stapled", s.LogText());
            }
            await using var quiet = new OcspPki("staple.test");
            await using (var s = TestServer.Start(With(""), d => quiet.WriteFiles(d, "s")))
            {
                T.Eq("none", await Staple(s.Port));
                T.Eq(0, quiet.Requests);
            }
        });

        T.Add("ssl_stapling: a failing responder costs one fetch per backoff period, not one per handshake", async () =>
        {
            if (!HasOpenSsl()) { Console.WriteLine("    (skipped: no openssl CLI)"); return; }
            await using var pki = new OcspPki("staple.test") { Fail = true };
            await using var s = TestServer.Start(With("ssl_stapling on;"), d => pki.WriteFiles(d, "s"));
            for (int k = 0; k < 30; k++) T.Eq("none", await Staple(s.Port));
            T.Eq(1, pki.Requests);                             // the platform's fetcher would have made ~30
            T.Contains("OCSP fetch failed; not stapling", s.LogText());
        });

        T.Add("ssl_stapling: an outage keeps the cached response until it expires, then stops stapling", async () =>
        {
            if (!HasOpenSsl()) { Console.WriteLine("    (skipped: no openssl CLI)"); return; }
            await using var pki = new OcspPki("staple.test") { Validity = TimeSpan.FromSeconds(4) };
            await using var s = TestServer.Start(With("ssl_stapling on;"), d => pki.WriteFiles(d, "s"));
            await Eventually(async () => await Staple(s.Port) == "good");
            pki.Fail = true;
            T.Eq("good", await Staple(s.Port));
            await Task.Delay(4500);
            T.Eq("none", await Staple(s.Port));                // expired: never staple a stale response
            T.Eq(1, pki.Requests);
        });

        T.Add("ssl_stapling: revoked is stapled (and logged); forged, wrongly delegated or failing responses never are", async () =>
        {
            if (!HasOpenSsl()) { Console.WriteLine("    (skipped: no openssl CLI)"); return; }
            async Task<(string Staple, string Log)> Run(OcspPki pki)
            {
                await using var s = TestServer.Start(With("ssl_stapling on;"), d => pki.WriteFiles(d, "s"));
                await Staple(s.Port);
                await Eventually(async () => pki.Requests > 0);
                await Task.Delay(300);
                return (await Staple(s.Port), s.LogText());
            }
            await using (var pki = new OcspPki("staple.test") { Revoked = true })
            {
                var (st, log) = await Run(pki);
                T.Eq("revoked", st);
                T.Contains("REVOKED", log);
            }
            await using (var pki = new OcspPki("staple.test") { Delegated = true })
                T.Eq("good", (await Run(pki)).Staple);         // a responder certificate the CA delegated to
            await using (var pki = new OcspPki("staple.test") { DelegatedWithoutEku = true })
            {
                var (st, log) = await Run(pki);
                T.Eq("none", st);
                T.Contains("authorized for OCSP signing", log);
            }
            await using (var pki = new OcspPki("staple.test") { BadSignature = true })
            {
                var (st, log) = await Run(pki);
                T.Eq("none", st);
                T.Contains("bad signature", log);
            }
        });

        T.Add("ssl_stapling_file and ssl_stapling_responder; reload keeps the staple without refetching", async () =>
        {
            if (!HasOpenSsl()) { Console.WriteLine("    (skipped: no openssl CLI)"); return; }
            await using var pki = new OcspPki("staple.test");
            await using (var s = TestServer.Start(With("ssl_stapling on; ssl_stapling_file {DIR}/resp.der;"), d =>
            {
                pki.WriteFiles(d, "s");
                File.WriteAllBytes(Path.Combine(d, "resp.der"), pki.MakeResponse());
            }))
            {
                T.Eq("good", await Staple(s.Port));            // stapled from the first handshake
                T.Eq(0, pki.Requests);                         // and nothing is fetched
            }
            // The certificate names a dead responder; the override points at the live one.
            await using var live = new OcspPki("staple.test");
            await using var deadAia = new OcspPki("staple.test", "http://127.0.0.1:1/");
            await using (var s = TestServer.Start(With($"ssl_stapling on; ssl_stapling_responder {live.Url};"), d =>
            {
                // deadAia's certificate, answered by a responder that signs as deadAia's CA.
                deadAia.WriteFiles(d, "s");
            }))
            {
                // live signs with a different CA, so its response must be refused: the override changes where, not who.
                await Staple(s.Port);
                await Eventually(async () => live.Requests > 0);
                await Task.Delay(300);
                T.Eq("none", await Staple(s.Port));
                T.Contains("signed by neither the issuer nor a delegated responder", s.LogText());
            }
            await using (var s = TestServer.Start(With($"ssl_stapling on; ssl_stapling_responder {pki.Url};"), d => pki.WriteFiles(d, "s")))
            {
                await Eventually(async () => await Staple(s.Port) == "good");
                int before = pki.Requests;
                T.True(await s.Reload(With($"ssl_stapling on; ssl_stapling_responder {pki.Url};")));
                T.Eq("good", await Staple(s.Port));            // stapled straight away by the new configuration
                await Task.Delay(300);
                T.Eq(before, pki.Requests);                    // without fetching again
            }
        });

        T.Add("ssl_stapling: config errors and warnings", async () =>
        {
            await using var pki = new OcspPki("staple.test");
            await using var other = new OcspPki("staple.test");
            string Err(string d, Action<string>? extra = null) => T.Throws<ConfigException>(() => TestServer.Start(With(d), dd => { pki.WriteFiles(dd, "s"); extra?.Invoke(dd); })).Message;
            T.Contains("always verified", Err("ssl_stapling on; ssl_stapling_verify off;"));
            T.Contains("invalid responder URL", Err("ssl_stapling on; ssl_stapling_responder ftp://x/;"));
            T.Contains("isn't a valid OCSP response", Err("ssl_stapling on; ssl_stapling_file {DIR}/bad.der;", d => File.WriteAllBytes(Path.Combine(d, "bad.der"), [1, 2, 3])));
            T.Contains("not about this certificate", Err("ssl_stapling on; ssl_stapling_file {DIR}/o.der;", d => File.WriteAllBytes(Path.Combine(d, "o.der"), other.MakeResponse())));
            await using (var s = TestServer.Start(With("ssl_stapling on;"), d => ProxyTests.MakeCert("staple.test", d, "s").Dispose()))
                T.Contains("include the issuer", s.LogText()); // self-signed: no issuer in the file
            await using (var s = TestServer.Start(With("ssl_stapling on;"), d =>
            {
                pki.WriteFiles(d, "s");
                File.WriteAllText(Path.Combine(d, "s.crt"), pki.Leaf.ExportCertificatePem()); // leaf only
            }))
                T.Contains("include the issuer", s.LogText());
        });
    }

    private static bool HasOpenSsl()
    {
        try { using var p = Process.Start(new ProcessStartInfo("openssl", ["version"]) { RedirectStandardOutput = true })!; p.WaitForExit(); return p.ExitCode == 0; }
        catch (System.ComponentModel.Win32Exception) { return false; }
    }

    private static async Task Eventually(Func<Task<bool>> cond)
    {
        for (int k = 0; k < 60; k++)
        {
            if (await cond()) return;
            await Task.Delay(50);
        }
        throw new Exception("condition not met within 3 s");
    }

    /// <summary>The stapled certificate status as openssl sees it: "good", "revoked" or "none".</summary>
    private static async Task<string> Staple(int port)
    {
        using var p = Process.Start(new ProcessStartInfo("openssl", ["s_client", "-connect", $"127.0.0.1:{port}", "-servername", "staple.test", "-status"])
        { RedirectStandardOutput = true, RedirectStandardInput = true, RedirectStandardError = true })!;
        p.StandardInput.Close();
        var o = await p.StandardOutput.ReadToEndAsync();
        await p.WaitForExitAsync();
        if (!o.Contains("Server certificate", StringComparison.Ordinal)) throw new Exception("handshake failed: " + o);
        if (o.Contains("Cert Status: good", StringComparison.Ordinal)) return "good";
        if (o.Contains("Cert Status: revoked", StringComparison.Ordinal)) return "revoked";
        return "none";
    }
}
