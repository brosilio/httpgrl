using Httpgrl.Quic;

namespace Httpgrl.Tests;

/// <summary>The TLS 1.3 handshake through OpenSSL's QUIC TLS API, client and server in memory, no packets.</summary>
internal static class QuicTlsTests
{
    /// <summary>Records what TLS hands a connection: CRYPTO bytes per level, and secrets.</summary>
    internal sealed class Host(byte[]? answer = null) : IQuicTlsHost
    {
        public readonly List<byte>[] Out = [new(), new(), new(), new()];
        public readonly Dictionary<(QuicLevel, bool), (QuicCipher, byte[])> Secrets = new();
        public byte[]? PeerParameters;
        public Func<byte[], byte[]?>? Check;

        public void OnCryptoData(QuicLevel level, ReadOnlySpan<byte> data) => Out[(int)level].AddRange(data.ToArray());
        public void OnSecret(QuicLevel level, bool write, QuicCipher cipher, ReadOnlySpan<byte> secret) => Secrets[(level, write)] = (cipher, secret.ToArray());
        public byte[]? OnPeerTransportParameters(ReadOnlySpan<byte> raw)
        {
            PeerParameters = raw.ToArray();
            return Check is not null ? Check(PeerParameters) : answer;
        }
    }

    /// <summary>Move what each side wrote to the other, level by level, until nothing moves. False if either side failed.</summary>
    internal static bool Pump(QuicTls a, Host ah, QuicTls b, Host bh)
    {
        for (int round = 0; round < 20; round++)
        {
            bool moved = false;
            foreach (var (from, fh, to) in new[] { (a, ah, b), (b, bh, a) })
                for (int l = 0; l < 4; l++)
                {
                    if (fh.Out[l].Count == 0) continue;
                    var data = fh.Out[l].ToArray();
                    fh.Out[l].Clear();
                    to.Receive((QuicLevel)l, data);
                    if (!to.Advance()) return false;
                    moved = true;
                }
            if (!moved) return true;
        }
        throw new Exception("handshake didn't settle");
    }

    private static byte[] Params(byte[] scid, byte[]? odcid = null) =>
        new TransportParameters { InitialScid = scid, OriginalDcid = odcid, InitialMaxData = 1 << 20, InitialMaxStreamsBidi = 100, MaxIdleTimeoutMs = 30000 }.ToArray();

    public static void Register()
    {
        T.Add("quic tls: client and server complete a handshake through OpenSSL's QUIC TLS API; secrets, ALPN, SNI and parameters agree", () =>
        {
            if (QuicTls.Unavailable is { } why) { Console.WriteLine("    (skipped: " + why + ")"); return; }
            var dir = Directory.CreateTempSubdirectory("httpgrl-quictls-").FullName;
            try
            {
                ProxyTests.MakeCert("quic.test", dir, "q").Dispose();
                using var sctx = QuicTlsContext.Server(Path.Combine(dir, "q.crt"), Path.Combine(dir, "q.key"), ["h3"]);
                using var cctx = QuicTlsContext.Client(Path.Combine(dir, "q.crt"));
                var sh = new Host(Params([0xbb], odcid: [0x01, 0x02]));
                var ch = new Host();
                using var server = QuicTls.Server(sctx, name => name == "quic.test" ? sctx : null, sh);
                using var client = QuicTls.Client(cctx, "quic.test", ["h3", "hq-interop"], Params([0xaa]), ch);

                T.True(client.Advance()); // ClientHello
                T.True(ch.Out[0].Count > 200);
                T.True(Pump(client, ch, server, sh));
                T.True(client.HandshakeComplete && server.HandshakeComplete);
                T.Eq("h3", client.Alpn);
                T.Eq("h3", server.Alpn);
                T.Eq("quic.test", server.ServerName);
                // Each side's write secret is the other's read secret, at both levels.
                foreach (var level in new[] { QuicLevel.Handshake, QuicLevel.OneRtt })
                {
                    T.True(sh.Secrets.ContainsKey((level, true)) && ch.Secrets.ContainsKey((level, false)));
                    T.True(sh.Secrets[(level, true)].Item2.AsSpan().SequenceEqual(ch.Secrets[(level, false)].Item2));
                    T.True(ch.Secrets[(level, true)].Item2.AsSpan().SequenceEqual(sh.Secrets[(level, false)].Item2));
                    T.True(sh.Secrets[(level, true)].Item1 is QuicCipher.Aes128Gcm or QuicCipher.Aes256Gcm);
                }
                // Transport parameters crossed over intact.
                T.Eq("aa", Convert.ToHexStringLower(TransportParameters.Parse(sh.PeerParameters!, fromServer: false).InitialScid!));
                var stp = TransportParameters.Parse(ch.PeerParameters!, fromServer: true);
                T.Eq("bb", Convert.ToHexStringLower(stp.InitialScid!));
                T.Eq("0102", Convert.ToHexStringLower(stp.OriginalDcid!));
                // Session tickets arrive after the handshake, at 1-RTT; the client takes them with a zero-byte read.
                T.True(ch.Out[3].Count == 0);
                T.True(Pump(client, ch, server, sh));
            }
            finally { Directory.Delete(dir, true); }
        });

        T.Add("quic tls: no common ALPN, no ALPN, an unknown SNI, bad parameters, and an untrusted certificate all fail with the right code", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            var dir = Directory.CreateTempSubdirectory("httpgrl-quictls-").FullName;
            try
            {
                ProxyTests.MakeCert("quic.test", dir, "q").Dispose();
                ProxyTests.MakeCert("other.test", dir, "o").Dispose();
                using var sctx = QuicTlsContext.Server(Path.Combine(dir, "q.crt"), Path.Combine(dir, "q.key"), ["h3"]);
                using var trusting = QuicTlsContext.Client(Path.Combine(dir, "q.crt"));
                using var distrusting = QuicTlsContext.Client(Path.Combine(dir, "o.crt"));

                QuicError? Run(QuicTlsContext cctx, string sni, string[] alpn, Func<byte[], byte[]?>? check = null, bool clientSide = false)
                {
                    var sh = new Host(Params([0xbb], odcid: [1])) { Check = check };
                    var ch = new Host();
                    using var server = QuicTls.Server(sctx, name => name == "quic.test" ? sctx : null, sh);
                    using var client = QuicTls.Client(cctx, sni, alpn, Params([0xaa]), ch);
                    client.Advance();
                    bool ok = Pump(client, ch, server, sh);
                    if (ok) return null;
                    return clientSide ? client.Error : server.Error ?? client.Error;
                }
                T.Eq(QuicError.CryptoError + 120, Run(trusting, "quic.test", ["h2"])); // no_application_protocol
                T.Eq(QuicError.CryptoError + 112, Run(trusting, "nope.test", ["h3"])); // unrecognized_name
                T.Eq(QuicError.CryptoError + 120, Run(trusting, "quic.test", [])); // no ALPN offered at all: QUIC requires it
                T.Eq(QuicError.TransportParameterError, Run(trusting, "quic.test", ["h3"], raw =>
                {
                    TransportParameters.Parse(raw, fromServer: false);
                    throw new QuicException(QuicError.TransportParameterError, "refused for the test");
                }));
                var untrusted = Run(distrusting, "quic.test", ["h3"], clientSide: true);
                T.True(untrusted is >= QuicError.CryptoError and <= QuicError.CryptoError + 255);
                T.True(Run(trusting, "quic.test", ["h3"]) is null);
            }
            finally { Directory.Delete(dir, true); }
        });

        T.Add("quic tls: CRYPTO data at a level already left behind is a PROTOCOL_VIOLATION", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            var dir = Directory.CreateTempSubdirectory("httpgrl-quictls-").FullName;
            try
            {
                ProxyTests.MakeCert("quic.test", dir, "q").Dispose();
                using var sctx = QuicTlsContext.Server(Path.Combine(dir, "q.crt"), Path.Combine(dir, "q.key"), ["h3"]);
                using var cctx = QuicTlsContext.ClientWithoutVerification();
                var sh = new Host(Params([0xbb], odcid: [1]));
                var ch = new Host();
                using var server = QuicTls.Server(sctx, _ => sctx, sh);
                using var client = QuicTls.Client(cctx, "quic.test", ["h3"], Params([0xaa]), ch);
                client.Advance();
                T.True(Pump(client, ch, server, sh));
                var e = Assert(() => server.Receive(QuicLevel.Initial, [1, 2, 3]));
                T.Eq(QuicError.ProtocolViolation, e);
            }
            finally { Directory.Delete(dir, true); }
        });
    }

    private static QuicError Assert(Action a)
    {
        try { a(); }
        catch (QuicException e) { return e.Code; }
        throw new Exception("accepted");
    }
}
