using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static Httpgrl.Tests.Client;

namespace Httpgrl.Tests;

/// <summary>
/// Reverse tunnels: an agent (listen tunnel:NAME) dials a remote (upstream { tunnel; } + tunnel_accept) and serves the
/// requests the remote sends back down. Both ends run in-process; every test owns its servers and certificates.
/// </summary>
internal static class TunnelTests
{
    private static readonly Lazy<Pki> P = new(() => new Pki());

    private static string RemoteConf(int port = 0, string upstream = "tunnel;", string extra = "", string accept = "tunnel_accept home;") => $$"""
        http {
          upstream home { {{upstream}} }
          server {
            listen 127.0.0.1:{{port}} ssl default_server; server_name relay.test;
            ssl_certificate {DIR}/relay.crt; ssl_certificate_key {DIR}/relay.key;
            ssl_verify_client optional; ssl_client_certificate {DIR}/agents.crt;
            proxy_connect_timeout 1s;
            location = /.well-known/httpgrl-tunnel { {{accept}} }
            location / { proxy_pass http://home; {{extra}} }
          }
        }
        """;

    private static string AgentConf(int remotePort, string cert = "home", string body = "return 200 \"agent $request_method $request_uri\";", string tunnel = "pool 2;") => $$"""
        http {
          tunnel home {
            connect 127.0.0.1:{{remotePort}}; server_name relay.test;
            certificate {DIR}/{{cert}}.crt; certificate_key {DIR}/{{cert}}.key;
            trusted_certificate {DIR}/relay.crt;
            {{tunnel}}
          }
          server {
            listen tunnel:home;
            root {DIR}/www;
            location / { {{body}} }
            location /files/ { }
          }
        }
        """;

    private static void PopulateRemote(string d)
    {
        File.WriteAllText(Path.Combine(d, "relay.crt"), P.Value.Relay.ExportCertificatePem());
        File.WriteAllText(Path.Combine(d, "relay.key"), P.Value.RelayKey);
        File.WriteAllText(Path.Combine(d, "agents.crt"), P.Value.AgentCa.ExportCertificatePem());
    }

    private static void PopulateAgent(string d)
    {
        File.WriteAllText(Path.Combine(d, "relay.crt"), P.Value.Relay.ExportCertificatePem());
        foreach (var (name, cert) in P.Value.Agents)
        {
            File.WriteAllText(Path.Combine(d, name + ".crt"), cert.ExportCertificatePem());
            File.WriteAllText(Path.Combine(d, name + ".key"), cert.GetECDsaPrivateKey()!.ExportPkcs8PrivateKeyPem());
        }
        Directory.CreateDirectory(Path.Combine(d, "www", "files"));
        var big = new byte[3 << 20];
        new Random(7).NextBytes(big);
        File.WriteAllBytes(Path.Combine(d, "www", "files", "big.bin"), big);
    }

    public static void Register()
    {
        T.Add("tunnel: requests reach the agent over connections it dialed, and the pool refills", async () =>
        {
            await using var remote = TestServer.Start(RemoteConf(), PopulateRemote);
            await using var agent = TestServer.Start(AgentConf(remote.Port), PopulateAgent);
            await Parked(agent, 2);
            var resp = await Https(remote.Port, "GET /hello?x=1 HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n");
            T.Eq(200, Status(resp));
            T.Eq("agent GET /hello?x=1", Body(resp));

            // More at once than the pool holds: the rest wait for the agent to park replacements.
            var many = await Task.WhenAll(Enumerable.Range(0, 12).Select(k => Https(remote.Port, $"GET /n{k} HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n")));
            for (int k = 0; k < many.Length; k++)
                if (Body(many[k]) != $"agent GET /n{k}") throw new Exception($"request {k}: {many[k]}\nREMOTE\n{remote.LogText()}\nAGENT\n{agent.LogText()}");
            await Parked(agent, 2);

            // A body big enough to stream, byte-exact.
            var big = await HttpsBytes(remote.Port, "GET /files/big.bin HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n");
            T.True(big.AsSpan().EndsWith(File.ReadAllBytes(Path.Combine(agent.Dir, "www", "files", "big.bin"))));
            T.Contains("tunnel started", agent.LogText());
        });

        T.Add("tunnel: request bodies and keep-alive reuse work through the tunnel", async () =>
        {
            await using var backend = FakeUpstream.Echo();
            await using var remote = TestServer.Start(RemoteConf(), PopulateRemote);
            await using var agent = TestServer.Start(AgentConf(remote.Port, body: $"proxy_pass http://127.0.0.1:{backend.Port};", tunnel: "pool 1;"), PopulateAgent);
            await Parked(agent, 1);
            for (int k = 0; k < 3; k++)
            {
                var resp = await Https(remote.Port, $"POST /up HTTP/1.1\r\nHost: relay.test\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello there");
                T.Eq(200, Status(resp));
                T.Contains("POST /up HTTP/1.1", Body(resp));
                T.True(Body(resp).EndsWith("hello there", StringComparison.Ordinal));
                var chunked = await Https(remote.Port, "PUT /c HTTP/1.1\r\nHost: relay.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n");
                T.Eq(200, Status(chunked));
                T.True(Dechunked(chunked).EndsWith("hello", StringComparison.Ordinal) || Body(chunked).EndsWith("hello", StringComparison.Ordinal));
            }
            // Connections went back to the pool after each request instead of being redialed for every one (a pool of
            // one holds at most the parked one plus the replacement dialed while it served).
            T.True(agent.Server.TunnelCounts("home")!.Value.Total <= 2);
        });

        T.Add("tunnel: an agent can only park under its own certificate's name", async () =>
        {
            await using var remote = TestServer.Start(RemoteConf(), PopulateRemote);
            await using (var agent = TestServer.Start(AgentConf(remote.Port, cert: "nas"), PopulateAgent))
            {
                await Eventually(() => agent.LogText().Contains("remote answered 403"));
                T.Eq(0, agent.Server.TunnelCounts("home")!.Value.Total);
            }
            T.Contains("no verified client certificate for this tunnel", remote.LogText());
            T.Contains("\"subject\":\"CN=nas\"", remote.LogText());
            // client= names a different certificate for the tunnel.
            await remote.Reload(RemoteConf(accept: "tunnel_accept home client=nas;"));
            await using (var agent = TestServer.Start(AgentConf(remote.Port, cert: "nas"), PopulateAgent))
            {
                await Parked(agent, 2);
                T.Eq(200, Status(await Https(remote.Port, "GET / HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n")));
            }
            // No certificate at all, or one from a CA the remote doesn't know: refused before anything is parked.
            T.Eq(403, Status(await FakeAgentHandshake(remote.Port, null)));
            T.Eq("<<REJECTED>>", await FakeAgentHandshake(remote.Port, P.Value.Stranger));
        });

        T.Add("tunnel: the handshake must be a GET upgrade to our protocol", async () =>
        {
            await using var remote = TestServer.Start(RemoteConf(), PopulateRemote);
            var home = P.Value.Agents["home"];
            T.Eq(400, Status(await FakeAgentHandshake(remote.Port, home, "GET /.well-known/httpgrl-tunnel HTTP/1.1\r\nHost: relay.test\r\n\r\n")));
            T.Eq(400, Status(await FakeAgentHandshake(remote.Port, home, "GET /.well-known/httpgrl-tunnel HTTP/1.1\r\nHost: relay.test\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n")));
            T.Eq(400, Status(await FakeAgentHandshake(remote.Port, home, "POST /.well-known/httpgrl-tunnel HTTP/1.1\r\nHost: relay.test\r\nConnection: upgrade\r\nUpgrade: httpgrl-tunnel\r\nContent-Length: 1\r\n\r\nx")));
            T.Eq(101, Status(await FakeAgentHandshake(remote.Port, home)));
        });

        T.Add("tunnel: max= bounds the connections agents can hold at the remote", async () =>
        {
            await using var remote = TestServer.Start(RemoteConf(upstream: "tunnel max=2;"), PopulateRemote);
            await using var agent = TestServer.Start(AgentConf(remote.Port, tunnel: "pool 5;"), PopulateAgent);
            await Eventually(() => remote.LogText().Contains("pool full"));
            await Task.Delay(300);
            T.Eq(2, agent.Server.TunnelCounts("home")!.Value.Total);
            T.Contains("remote answered 503", agent.LogText());
            T.Eq(200, Status(await Https(remote.Port, "GET / HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n")));
        });

        T.Add("tunnel: with no agent connected requests fail fast, and work again once it reconnects", async () =>
        {
            await using var remote = TestServer.Start(RemoteConf(), PopulateRemote);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            T.Eq(502, Status(await Https(remote.Port, "GET / HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n")));
            T.True(sw.ElapsedMilliseconds < 2500); // at most the 1s connect timeout, then immediately once it's been empty that long
            sw.Restart();
            T.Eq(502, Status(await Https(remote.Port, "GET / HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n")));
            T.True(sw.ElapsedMilliseconds < 500);
            T.Contains("no tunnel connection available", remote.LogText());

            await using (var agent = TestServer.Start(AgentConf(remote.Port), PopulateAgent))
            {
                await Parked(agent, 2);
                T.Eq(200, Status(await Https(remote.Port, "GET / HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n")));
            }
            // The agent went away: its parked connections leave the pool at once, so nothing waits on a dead one.
            await Task.Delay(300);
            sw.Restart();
            T.Eq(502, Status(await Https(remote.Port, "GET / HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n")));
            T.True(sw.ElapsedMilliseconds < 2500);
            T.NotContains("upstream timed out", remote.LogText());
        });

        T.Add("tunnel: the agent redials with backoff after the remote restarts", async () =>
        {
            int port;
            await using var holder = new PortHolder();
            port = holder.Release();
            var r1 = TestServer.Start(RemoteConf(port), PopulateRemote);
            await using var agent = TestServer.Start(AgentConf(port), PopulateAgent);
            await Parked(agent, 2);
            await r1.DisposeAsync();
            await Eventually(() => agent.Server.TunnelCounts("home")!.Value.Total == 0);
            await Task.Delay(1500); // a failed attempt or two while it's down
            await using var r2 = TestServer.Start(RemoteConf(port), PopulateRemote);
            await Parked(agent, 2, timeoutMs: 20_000);
            T.Eq(200, Status(await Https(port, "GET /back HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n")));
            var log = agent.LogText();
            T.Contains("tunnel connect failed", log);
            T.Contains("tunnel connected", log);
        });

        T.Add("tunnel: a remote reload hands the tunnel over without failing requests", async () =>
        {
            await using var remote = TestServer.Start(RemoteConf(), PopulateRemote);
            await using var agent = TestServer.Start(AgentConf(remote.Port), PopulateAgent);
            await Parked(agent, 2);
            T.True(await remote.Reload(RemoteConf(extra: "add_header X-Gen two;")));
            // Parked connections of the old configuration close; requests wait the moment it takes the agent to redial.
            for (int k = 0; k < 5; k++)
            {
                var resp = await Https(remote.Port, "GET / HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n");
                T.Eq(200, Status(resp));
                T.Eq("two", Header(resp, "X-Gen"));
            }
            await Parked(agent, 2);
        });

        T.Add("tunnel: an agent reload keeps its connections unless the tunnel's identity changed", async () =>
        {
            await using var remote = TestServer.Start(RemoteConf(accept: "tunnel_accept home client=nas;"), PopulateRemote);
            await using var agent = TestServer.Start(AgentConf(remote.Port, cert: "nas"), PopulateAgent);
            await Parked(agent, 2);
            T.True(await agent.Reload(AgentConf(remote.Port, cert: "nas", body: "return 200 \"v2\";")));
            // Same remote, certificate and trust: the parked connections carry on, under the new configuration.
            T.Eq("v2", Body(await Https(remote.Port, "GET / HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n")));
            await Parked(agent, 2);
            T.Eq(0, Count(remote.LogText(), "\"status\":101")); // nothing was closed

            // A different certificate: connections made with the old one are closed and replaced.
            P.Value.ReissueInto(agent.Dir, "nas2", "nas");
            T.True(await agent.Reload(AgentConf(remote.Port, cert: "nas2", body: "return 200 \"v3\";")));
            // A parked connection's 101 is logged when it ends: the two made with the old certificate were closed.
            await Eventually(() => Count(remote.LogText(), "\"status\":101") >= 2);
            await Parked(agent, 2);
            T.Eq("v3", Body(await Https(remote.Port, "GET / HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n")));
        });

        T.Add("tunnel: a misbehaving agent gets the strict upstream treatment", async () =>
        {
            await using var remote = TestServer.Start(RemoteConf(), PopulateRemote);
            var home = P.Value.Agents["home"];

            // Ambiguous framing in the answer: 502, never relayed.
            await using (var evil = await FakeAgent.Start(remote.Port, home, async s =>
            {
                await ReadHead(s);
                await s.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"u8.ToArray());
                await Task.Delay(1000);
            }))
            {
                var resp = await Https(remote.Port, "GET / HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n");
                T.Eq(502, Status(resp));
            }
            T.Contains("both Content-Length and Transfer-Encoding", remote.LogText());

            // Bytes sent while parked (an answer to nothing, queued to desync the next request): dropped from the pool.
            await using (var evil = await FakeAgent.Start(remote.Port, home, async s =>
            {
                await s.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nforged"u8.ToArray());
                await Task.Delay(3000);
            }))
            {
                await Task.Delay(300);
                var resp = await Https(remote.Port, "GET / HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n");
                T.Eq(502, Status(resp));
                T.NotContains("forged", resp);
            }
        });

        T.Add("tunnel: WebSocket upgrades pass through the tunnel", async () =>
        {
            await using var ws = FakeUpstream.WebSocketEcho();
            await using var remote = TestServer.Start(RemoteConf(), PopulateRemote);
            await using var agent = TestServer.Start(AgentConf(remote.Port, body: $"proxy_pass http://127.0.0.1:{ws.Port};"), PopulateAgent);
            await Parked(agent, 2);
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(IPAddress.Loopback, remote.Port);
            var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync("relay.test");
            var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
            await ssl.WriteAsync(Encoding.ASCII.GetBytes($"GET /ws HTTP/1.1\r\nHost: relay.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"));
            var head = await ReadHead(ssl);
            T.Contains("101", head);
            using var sock = System.Net.WebSockets.WebSocket.CreateFromStream(ssl, false, null, TimeSpan.Zero);
            await sock.SendAsync("ping through the tunnel"u8.ToArray(), System.Net.WebSockets.WebSocketMessageType.Text, true, default);
            var buf = new byte[256];
            var r = await sock.ReceiveAsync(buf, default);
            T.Eq("ping through the tunnel", Encoding.UTF8.GetString(buf, 0, r.Count));
        });

        T.Add("tunnel: configuration errors", () =>
        {
            void Bad(string conf, string message, Action<string>? populate = null)
            {
                var e = T.Throws<ConfigException>(() => TestServer.Start(conf, populate ?? (d => { PopulateRemote(d); PopulateAgent(d); })).DisposeAsync().AsTask().GetAwaiter().GetResult());
                T.Contains(message, e.Message);
            }
            Bad("http { upstream home { tunnel; server 127.0.0.1:1; } server { listen 127.0.0.1:0; location / { proxy_pass http://home; } } }", "can't also have \"server\" entries");
            Bad("http { upstream home { tunnel; health_check; } server { listen 127.0.0.1:0; location / { proxy_pass http://home; } } }", "\"health_check\" doesn't apply");
            Bad("http { upstream home { tunnel; } server { listen 127.0.0.1:0; location / { proxy_pass https://home; } } }", "use http://");
            Bad("http { server { listen 127.0.0.1:0; location / { tunnel_accept home; } } }", "no \"upstream home { tunnel; }\" block");
            Bad("http { upstream home { server 127.0.0.1:1; } server { listen 127.0.0.1:0; location / { tunnel_accept home; } } }", "no \"upstream home { tunnel; }\" block");
            Bad("http { server { listen tunnel:nope; } }", "no tunnel \"nope\" defined");
            Bad("http { tunnel t { connect relay.test:443; } server { listen tunnel:t; } }", "no \"certificate\"/\"certificate_key\"");
            Bad("http { tunnel t { certificate {DIR}/home.crt; certificate_key {DIR}/home.key; } server { listen tunnel:t; } }", "no \"connect\"");
            Bad("http { tunnel t { connect 192.0.2.1:443; certificate {DIR}/home.crt; certificate_key {DIR}/home.key; } server { listen tunnel:t; } }", "set \"server_name\"");
            Bad("http { tunnel t { connect relay.test; certificate {DIR}/home.crt; certificate_key {DIR}/home.key; pool 8; max 4; } server { listen tunnel:t; } }", "\"max\" is smaller than \"pool\"");
            Bad("http { tunnel t { connect relay.test; certificate {DIR}/home.crt; certificate_key {DIR}/home.key; } server { listen tunnel:t ssl; } }", "doesn't apply to a tunnel");
            Bad("http { tunnel t { connect relay.test; certificate {DIR}/nope.crt; certificate_key {DIR}/home.key; } server { listen tunnel:t; } }", "cannot load certificate");
            Bad("http { tunnel t { connect relay.test; uri relative; } server { listen tunnel:t; } }", "expected an absolute path");
        });

        T.Add("tunnel: handshake response parser", () =>
        {
            int P(string s) => Httpgrl.Core.Modules.TunnelHandshake.Parse(Encoding.Latin1.GetBytes(s), out _);
            const string ok = "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: httpgrl-tunnel\r\n\r\n";
            T.Eq(ok.Length, P(ok));
            T.Eq(ok.Length, P(ok + "GET / HTTP/1.1\r\n"));
            T.Eq(0, P(ok[..20]));
            T.Eq(0, P("HTTP/1."));
            T.Eq(-1, P("HTTP/1.0 101 x\r\nConnection: upgrade\r\nUpgrade: httpgrl-tunnel\r\n\r\n"));
            T.Eq(-1, P("HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n"));
            T.Eq(-1, P("HTTP/1.1 101 Switching Protocols\r\nUpgrade: httpgrl-tunnel\r\n\r\n"));
            T.Eq(-1, P("HTTP/1.1 200 OK\r\nConnection: upgrade\r\nUpgrade: httpgrl-tunnel\r\n\r\n"));
            T.Eq(-1, P("HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: httpgrl-tunnel\nX: y\r\n\r\n"));
            T.Eq(-1, P("HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade : httpgrl-tunnel\r\n\r\n"));
            T.Eq(-1, P("HTTP/1.1 101 Switching Protocols\r\n" + new string('a', 9000)));
            T.Eq(-1, P("garbage\r\n"));
        });
    }

    // ------------------------------------------------------------------ helpers

    private static int Count(string hay, string needle)
    {
        int n = 0;
        for (int i = hay.IndexOf(needle, StringComparison.Ordinal); i >= 0; i = hay.IndexOf(needle, i + 1, StringComparison.Ordinal)) n++;
        return n;
    }

    private static async Task Parked(TestServer agent, int idle, int timeoutMs = 5000)
    {
        long until = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < until)
        {
            if (agent.Server.TunnelCounts("home") is { } c && c.Idle >= idle) { await Task.Delay(100); return; } // and give the remote a moment to park them
            await Task.Delay(25);
        }
        throw new Exception($"tunnel never had {idle} idle connections: {agent.Server.TunnelCounts("home")}\n{agent.LogText()}");
    }

    private static async Task Eventually(Func<bool> cond)
    {
        for (int k = 0; k < 100; k++)
        {
            if (cond()) return;
            await Task.Delay(50);
        }
        throw new Exception("condition not met within 5 s");
    }

    private static async Task<string> Https(int port, string request) => Encoding.Latin1.GetString(await HttpsBytes(port, request));

    private static async Task<byte[]> HttpsBytes(int port, string request)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port);
        await using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync("relay.test");
        await ssl.WriteAsync(Encoding.Latin1.GetBytes(request));
        using var cts = new CancellationTokenSource(10_000);
        var ms = new MemoryStream();
        var buf = new byte[64 << 10];
        try
        {
            int n;
            while ((n = await ssl.ReadAsync(buf, cts.Token)) > 0) ms.Write(buf, 0, n);
        }
        catch (IOException) { }
        return ms.ToArray();
    }

    private static async Task<string> ReadHead(Stream s)
    {
        var sb = new StringBuilder();
        var one = new byte[1];
        while (!sb.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
        {
            if (await s.ReadAsync(one) == 0) break;
            sb.Append((char)one[0]);
        }
        return sb.ToString();
    }

    private const string Handshake = "GET /.well-known/httpgrl-tunnel HTTP/1.1\r\nHost: relay.test\r\nConnection: upgrade\r\nUpgrade: httpgrl-tunnel\r\n\r\n";

    /// <summary>One raw handshake as an agent would send it. Returns the response head, or "&lt;&lt;REJECTED&gt;&gt;" if TLS refused us.</summary>
    private static async Task<string> FakeAgentHandshake(int port, X509Certificate2? cert, string request = Handshake)
    {
        try
        {
            await using var a = await FakeAgent.Connect(port, cert);
            await a.Ssl.WriteAsync(Encoding.ASCII.GetBytes(request));
            var head = await ReadHead(a.Ssl);
            // TLS 1.3 checks the client certificate after the client considers the handshake done: the refusal shows up
            // as an alert (an exception) or, depending on timing, as the connection closing with no response at all.
            return head.Length == 0 ? "<<REJECTED>>" : head;
        }
        catch (Exception e) when (e is IOException or System.Security.Authentication.AuthenticationException) { return "<<REJECTED>>"; }
    }

    /// <summary>A scripted agent: handshakes as an agent would, then runs <c>script</c> on the turned-around connection.</summary>
    private sealed class FakeAgent : IAsyncDisposable
    {
        public required TcpClient Tcp;
        public required SslStream Ssl;
        private Task? _script;

        public static async Task<FakeAgent> Connect(int port, X509Certificate2? cert)
        {
            var tcp = new TcpClient();
            await tcp.ConnectAsync(IPAddress.Loopback, port);
            var ssl = new SslStream(tcp.GetStream(), false);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "relay.test",
                ClientCertificates = cert is null ? null : [cert],
                LocalCertificateSelectionCallback = (_, _, _, _, _) => cert!,
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
            });
            // TLS 1.3 reports a refused client certificate only on the first read.
            return new FakeAgent { Tcp = tcp, Ssl = ssl };
        }

        public static async Task<FakeAgent> Start(int port, X509Certificate2 cert, Func<Stream, Task> script)
        {
            var a = await Connect(port, cert);
            await a.Ssl.WriteAsync(Encoding.ASCII.GetBytes(Handshake));
            var head = await ReadHead(a.Ssl);
            if (!head.StartsWith("HTTP/1.1 101", StringComparison.Ordinal)) throw new Exception("fake agent not accepted: " + head);
            a._script = Task.Run(async () => { try { await script(a.Ssl); } catch (Exception) { } });
            return a;
        }

        public async ValueTask DisposeAsync()
        {
            try { Tcp.Client.Shutdown(SocketShutdown.Both); } catch (Exception) { }
            Tcp.Dispose();
            if (_script is not null) await _script;
        }
    }

    /// <summary>Reserves a free port number until <see cref="Release"/> (for a remote that must come back on the same port).</summary>
    private sealed class PortHolder : IAsyncDisposable
    {
        private readonly Socket _s = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        public PortHolder() => _s.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        public int Release()
        {
            int p = ((IPEndPoint)_s.LocalEndPoint!).Port;
            _s.Dispose();
            return p;
        }
        public ValueTask DisposeAsync() { _s.Dispose(); return ValueTask.CompletedTask; }
    }

    private sealed class Pki
    {
        public readonly X509Certificate2 AgentCa, Relay, Stranger;
        public readonly string RelayKey;
        public readonly Dictionary<string, X509Certificate2> Agents = new();

        public Pki()
        {
            var now = DateTimeOffset.UtcNow;
            AgentCa = Ca("CN=agent ca", now);
            Agents["home"] = Leaf("home", AgentCa, now);
            Agents["nas"] = Leaf("nas", AgentCa, now);
            Stranger = Leaf("home", Ca("CN=someone else", now), now);
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var req = new CertificateRequest("CN=relay.test", key, HashAlgorithmName.SHA256);
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("relay.test");
            req.CertificateExtensions.Add(san.Build());
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            Relay = req.CreateSelfSigned(now.AddDays(-1), now.AddDays(30));
            RelayKey = key.ExportPkcs8PrivateKeyPem();
        }

        /// <summary>A fresh certificate (new key) for <paramref name="cn"/>, written as <paramref name="file"/>.crt/.key.</summary>
        public void ReissueInto(string dir, string file, string cn)
        {
            var c = Leaf(cn, AgentCa, DateTimeOffset.UtcNow);
            File.WriteAllText(Path.Combine(dir, file + ".crt"), c.ExportCertificatePem());
            File.WriteAllText(Path.Combine(dir, file + ".key"), c.GetECDsaPrivateKey()!.ExportPkcs8PrivateKeyPem());
        }

        private static X509Certificate2 Ca(string name, DateTimeOffset now)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var req = new CertificateRequest(name, key, HashAlgorithmName.SHA256);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
            return req.CreateSelfSigned(now.AddDays(-60), now.AddDays(60));
        }

        private static X509Certificate2 Leaf(string cn, X509Certificate2 issuer, DateTimeOffset now)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var req = new CertificateRequest("CN=" + cn, key, HashAlgorithmName.SHA256);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, false));
            var serial = RandomNumberGenerator.GetBytes(12);
            serial[0] &= 0x7F;
            using var signed = req.Create(issuer, now.AddDays(-1), now.AddDays(30), serial);
            return signed.CopyWithPrivateKey(key);
        }
    }
}
