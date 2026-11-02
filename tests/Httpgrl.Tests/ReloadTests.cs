using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static Httpgrl.Tests.Client;

namespace Httpgrl.Tests;

/// <summary>Configuration reload: what changes, what doesn't, and what happens to connections caught in between.</summary>
internal static class ReloadTests
{
    private static string Says(string text, string listen = "127.0.0.1:0") =>
        $$"""http { server { listen {{listen}}; return 200 "{{text}}"; } }""";

    private static string Get(string path = "/") => $"GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";

    public static void Register()
    {
        T.Add("reload: new connections get the new configuration; a broken one is refused and changes nothing", async () =>
        {
            await using var s = TestServer.Start(Says("one"));
            int port = s.Port;
            T.Eq("one", Body(await s.Raw(Get())));
            T.True(await s.Reload(Says("two")));
            T.Eq(port, s.Port); // same socket, never closed
            T.Eq("two", Body(await s.Raw(Get())));

            T.True(!await s.Reload("http { server { listen 127.0.0.1:0; bogus_directive on; } }"));
            T.True(!await s.Reload("http { server { listen 127.0.0.1:0; ssl_certificate {DIR}/missing.crt; ssl_certificate_key {DIR}/missing.key; listen 127.0.0.1:0 ssl; } }"));
            T.Eq("two", Body(await s.Raw(Get())));
            var log = s.LogText();
            T.Contains("configuration reloaded", log);
            T.Contains("reload failed, keeping the running configuration", log);
        });

        T.Add("reload: idle keep-alive connections close; an in-flight request finishes on the old configuration", async () =>
        {
            var release = new TaskCompletionSource();
            await using var up = new FakeUpstream(async (st, rd) =>
            {
                await rd.ReadRequestAsync();
                await release.Task;
                await st.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nold"u8.ToArray());
            });
            await using var s = TestServer.Start($$"""http { server { listen 127.0.0.1:0; location / { proxy_pass http://127.0.0.1:{{up.Port}}; } location /idle { return 200 "idle"; } } }""");

            using var idle = await Connect(s.Port);
            await idle.SendAsync(Encoding.ASCII.GetBytes("GET /idle HTTP/1.1\r\nHost: t\r\n\r\n"));
            T.Eq("idle", Body(await ReadOne(idle)));

            using var busy = await Connect(s.Port);
            await busy.SendAsync(Encoding.ASCII.GetBytes("GET /slow HTTP/1.1\r\nHost: t\r\n\r\n"));
            for (int i = 0; i < 100 && up.Accepted == 0; i++) await Task.Delay(20);

            T.True(await s.Reload(Says("new")));
            // The idle connection is closed right away...
            T.Eq("", await ReadToClose(idle, 2000));
            // ...the busy one gets its old-configuration answer, then the connection closes instead of being kept.
            release.SetResult();
            var resp = await ReadToClose(busy, 5000);
            T.Eq(200, Status(resp));
            T.Eq("old", Body(resp));
            T.Eq("new", Body(await s.Raw(Get())));
        });

        T.Add("reload: listeners are opened and closed to match; a port in use fails the reload as a whole", async () =>
        {
            await using var s = TestServer.Start(Says("a"));
            int oldPort = s.Port, newPort = FreePort();
            T.True(await s.Reload(Says("b", $"127.0.0.1:{newPort}")));
            T.Eq(newPort, s.Port);
            T.Eq("b", Body(await Raw(newPort, Get())));
            T.Throws<SocketException>(() => Raw(oldPort, Get(), 1000).GetAwaiter().GetResult()); // refused

            using var squatter = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            squatter.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            squatter.Listen();
            int taken = ((IPEndPoint)squatter.LocalEndPoint!).Port;
            var both = $$"""http { server { listen 127.0.0.1:{{newPort}}; listen 127.0.0.1:{{taken}}; return 200 "c"; } }""";
            T.True(!await s.Reload(both));
            T.Eq("b", Body(await Raw(newPort, Get())));
            T.Contains("cannot listen", s.LogText());
        });

        T.Add("reload: rotated certificates are picked up", async () =>
        {
            const string Conf = """http { server { listen 127.0.0.1:0 ssl; ssl_certificate {DIR}/c.crt; ssl_certificate_key {DIR}/c.key; return 200 "tls"; } }""";
            await using var s = TestServer.Start(Conf, d => ProxyTests.MakeCert("first.test", d, "c").Dispose());
            T.Contains("CN=first.test", await ServerCertSubject(s.Port));
            ProxyTests.MakeCert("second.test", s.Dir, "c").Dispose();
            T.Contains("CN=first.test", await ServerCertSubject(s.Port)); // nothing happens until reload
            T.True(await s.Reload(Conf));
            T.Contains("CN=second.test", await ServerCertSubject(s.Port));
        });

        T.Add("reload: the old configuration's upstream keep-alive pool is closed once it's unused", async () =>
        {
            int closed = 0;
            await using var up = new FakeUpstream(async (st, rd) =>
            {
                while (true)
                {
                    var (head, _) = await rd.ReadRequestAsync();
                    if (head.Length == 0) { Interlocked.Increment(ref closed); return; }
                    await st.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nup"u8.ToArray());
                }
            });
            var conf = $$"""http { server { listen 127.0.0.1:0; location / { proxy_pass http://127.0.0.1:{{up.Port}}; } } }""";
            await using var s = TestServer.Start(conf);
            T.Eq("up", Body(await s.Raw(Get())));
            await Task.Delay(100);
            T.Eq(0, Volatile.Read(ref closed)); // pooled
            T.True(await s.Reload(conf));
            for (int i = 0; i < 100 && Volatile.Read(ref closed) == 0; i++) await Task.Delay(20);
            T.Eq(1, Volatile.Read(ref closed));
            T.Eq("up", Body(await s.Raw(Get()))); // the new generation has its own pool
        });
    }

    private static async Task<string> ServerCertSubject(int port)
    {
        using var c = await Connect(port);
        await using var ssl = new SslStream(new NetworkStream(c, ownsSocket: false));
        X509Certificate? seen = null;
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "x.test",
            RemoteCertificateValidationCallback = (_, cert, _, _) => { seen = cert; return true; },
        });
        return seen!.Subject;
    }

    private static int FreePort()
    {
        using var l = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        l.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)l.LocalEndPoint!).Port;
    }
}
