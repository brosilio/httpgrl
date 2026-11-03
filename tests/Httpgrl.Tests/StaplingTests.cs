using System.Diagnostics;

namespace Httpgrl.Tests;

/// <summary>OCSP stapling, against a local responder (no network). Needs the openssl CLI to see the staple.</summary>
internal static class StaplingTests
{
    private const string Conf = "http { server { listen 127.0.0.1:0 ssl; server_name staple.test; ssl_certificate {DIR}/s.crt; ssl_certificate_key {DIR}/s.key; STAPLING return 200 ok; } }";

    public static void Register()
    {
        T.Add("ssl_stapling: a verified response is stapled and cached; off never contacts the responder", async () =>
        {
            if (!HasOpenSsl()) { Console.WriteLine("    (skipped: no openssl CLI)"); return; }
            await using var pki = new OcspPki("staple.test");
            await using (var s = TestServer.Start(Conf.Replace("STAPLING", "ssl_stapling on; ssl_stapling_verify on;"), d => pki.WriteFiles(d, "s")))
            {
                T.Eq("good", await Staple(s.Port));
                T.Eq("good", await Staple(s.Port));
                T.Eq("good", await Staple(s.Port));
                T.Eq(1, pki.Requests); // fetched once, then reused
            }
            await using var quiet = new OcspPki("staple.test");
            await using (var s = TestServer.Start(Conf.Replace("STAPLING", ""), d => quiet.WriteFiles(d, "s")))
            {
                T.Eq("none", await Staple(s.Port));
                T.Eq("none", await Staple(s.Port));
                T.Eq(0, quiet.Requests); // nothing leaves the machine unless stapling is on
            }
        });

        T.Add("ssl_stapling: revoked is stapled honestly; failing or forged responses aren't, and handshakes still work", async () =>
        {
            if (!HasOpenSsl()) { Console.WriteLine("    (skipped: no openssl CLI)"); return; }
            await using (var pki = new OcspPki("staple.test") { Revoked = true })
            await using (var s = TestServer.Start(Conf.Replace("STAPLING", "ssl_stapling on;"), d => pki.WriteFiles(d, "s")))
                T.Eq("revoked", await Staple(s.Port));
            await using (var pki = new OcspPki("staple.test") { Fail = true })
            await using (var s = TestServer.Start(Conf.Replace("STAPLING", "ssl_stapling on;"), d => pki.WriteFiles(d, "s")))
            {
                T.Eq("none", await Staple(s.Port));
                T.Eq("none", await Staple(s.Port));
            }
            await using (var pki = new OcspPki("staple.test") { BadSignature = true })
            await using (var s = TestServer.Start(Conf.Replace("STAPLING", "ssl_stapling on;"), d => pki.WriteFiles(d, "s")))
                T.Eq("none", await Staple(s.Port)); // signed by the wrong key: never stapled
        });

        T.Add("ssl_stapling: config errors and load-time warnings", async () =>
        {
            await using var pki = new OcspPki("staple.test");
            string Err(string d) => T.Throws<ConfigException>(() => TestServer.Start(Conf.Replace("STAPLING", d), dd => pki.WriteFiles(dd, "s"))).Message;
            T.Contains("always verified", Err("ssl_stapling on; ssl_stapling_verify off;"));
            T.Contains("not supported", Err("ssl_stapling on; ssl_stapling_file /x.der;"));
            T.Contains("not supported", Err("ssl_stapling on; ssl_stapling_responder http://x/;"));
            // A certificate without a responder URL: stapling would silently do nothing, so it says so.
            await using var s = TestServer.Start(Conf.Replace("STAPLING", "ssl_stapling on;"), d => ProxyTests.MakeCert("staple.test", d, "s").Dispose());
            T.Contains("names no OCSP responder", s.LogText());
        });
    }

    private static bool HasOpenSsl()
    {
        try { using var p = Process.Start(new ProcessStartInfo("openssl", ["version"]) { RedirectStandardOutput = true })!; p.WaitForExit(); return p.ExitCode == 0; }
        catch (System.ComponentModel.Win32Exception) { return false; }
    }

    /// <summary>The stapled certificate status as openssl sees it: "good", "revoked" or "none".</summary>
    private static async Task<string> Staple(int port)
    {
        using var p = Process.Start(new ProcessStartInfo("openssl", ["s_client", "-connect", $"127.0.0.1:{port}", "-servername", "staple.test", "-status"])
        { RedirectStandardOutput = true, RedirectStandardInput = true, RedirectStandardError = true })!;
        p.StandardInput.Close();
        var o = await p.StandardOutput.ReadToEndAsync();
        await p.WaitForExitAsync();
        if (!o.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal) && !o.Contains("Server certificate", StringComparison.Ordinal)) throw new Exception("handshake failed: " + o);
        if (o.Contains("Cert Status: good", StringComparison.Ordinal)) return "good";
        if (o.Contains("Cert Status: revoked", StringComparison.Ordinal)) return "revoked";
        return "none";
    }
}
