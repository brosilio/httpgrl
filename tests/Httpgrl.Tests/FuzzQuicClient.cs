using System.Net;
using Httpgrl.Quic;

namespace Httpgrl.Tests;

internal static partial class Fuzz
{
    private static QuicTlsContext? _fuzzClientTls;
    private static readonly EndPoint FuzzServer = new IPEndPoint(IPAddress.Parse("198.51.100.1"), 443);

    /// <summary>
    /// What a client accepts before the server has spoken: a fresh client (its first Initial sent) gets one datagram
    /// "from the server". The first byte picks the shape, so the client's random connection IDs can be filled in: 0 raw
    /// bytes; 1 a Version Negotiation echoing our IDs, the rest its version list; 2 an authentic Retry, the rest its
    /// token; 3 the same Retry with one byte flipped where the input says. Invariants: nothing escapes Receive; a new
    /// DCID only ever comes from an authentic Retry with a token and a new SCID; the only way to end is Version
    /// Negotiation without v1 (CONNECTION_REFUSED); the client can always send afterwards.
    /// </summary>
    private static Target QuicClientHandshakeTarget() => new("quic-client-handshake",
        [[0, 0xc0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0], [1, 0xff, 0, 0, 0x1d], [1, 0, 0, 0, 1], [2, 0xaa, 0xbb], [3, 5, 0xaa], [2], [1]],
        B("\x00", "\x01", "\x02", "\x03", "\xff", "\x00\x00\x00\x01", "\xc0", "\xf0", "\x40"),
        data =>
        {
            if (QuicTls.Unavailable is not null || data.Length == 0) return false;
            lock (QuicConnGate)
            {
                _fuzzClientTls ??= QuicTlsContext.ClientWithoutVerification();
                using var c = QuicConnection.Client(_fuzzClientTls, "quic.test", ["test"], new QuicOptions(), QuicNet.Cids, FuzzServer, 1_000_000);
                var buf = new byte[1500];
                c.Send(buf, 1_000_000, out _);
                var dcid0 = c.DestinationCid;
                var body = data.AsSpan(1);
                byte[] dgram;
                bool authenticRetry = false;
                switch (data[0] % 4)
                {
                    case 1:
                    {
                        var d = new List<byte> { 0x80, 0, 0, 0, 0, (byte)c.SourceCid.Length };
                        d.AddRange(c.SourceCid);
                        d.Add((byte)dcid0.Length);
                        d.AddRange(dcid0);
                        d.AddRange(body.ToArray());
                        dgram = [.. d];
                        break;
                    }
                    case 2:
                    case 3:
                    {
                        var newScid = new byte[8];
                        new Random(body.Length).NextBytes(newScid);
                        var token = data[0] % 4 == 3 && body.Length > 0 ? body[1..].ToArray() : body.ToArray();
                        dgram = new byte[64 + token.Length];
                        int n = Packets.WriteRetry(dgram, c.SourceCid, newScid, token, dcid0, 0);
                        dgram = dgram[..n];
                        authenticRetry = token.Length > 0;
                        if (data[0] % 4 == 3 && body.Length > 0)
                        {
                            dgram[body[0] % dgram.Length] ^= 0x01;
                            authenticRetry = false; // a flipped bit anywhere breaks the integrity tag (or the header)
                        }
                        break;
                    }
                    default: dgram = body.ToArray(); break;
                }
                if (dgram.Length == 0) return false;
                try { c.Receive(dgram, FuzzServer, 1_000_100); }
                catch (Exception e) { throw new Finding($"{e.GetType().Name} escaped Receive: {e.Message}"); }
                bool newDcid = !c.DestinationCid.AsSpan().SequenceEqual(dcid0);
                if (newDcid && !authenticRetry) throw new Finding("the client took a new DCID from something other than an authentic Retry");
                if (authenticRetry && !newDcid) throw new Finding("the client ignored an authentic Retry");
                if (newDcid && c.DestinationCid.AsSpan().SequenceEqual(dcid0)) throw new Finding("a Retry handed back our own DCID");
                if (c.CloseCode is { } code && code != QuicError.ConnectionRefused) throw new Finding("the client closed before the handshake: " + code + " " + c.CloseReason);
                try { c.Send(buf, 1_000_200, out _); }
                catch (Exception e) { throw new Finding($"{e.GetType().Name} sending afterwards: {e.Message}"); }
                return newDcid || c.CloseCode is not null;
            }
        }, MaxLen: 1400, Serial: true);

    private static QuicNet? _quicClientNet;

    /// <summary>
    /// The mirror of quic-connection: a live client connection fed arbitrary 1-RTT frame payloads, as if from the
    /// server. Only QuicException may come out of frame handling; the client's replies must never make the server find
    /// a malformed frame, nor the client fail internally.
    /// </summary>
    private static Target QuicClientFramesTarget()
    {
        var seed = new byte[512];
        int p = 0;
        p += QuicFrameWriter.Stream(seed.AsSpan(p), 1, 0, "hello"u8, false);
        p += QuicFrameWriter.Stream(seed.AsSpan(p), 3, 0, "x"u8, true);
        p += QuicFrameWriter.MaxData(seed.AsSpan(p), 1 << 30);
        p += QuicFrameWriter.MaxStreams(seed.AsSpan(p), true, 10);
        p += QuicFrameWriter.Ping(seed.AsSpan(p));
        byte[][] seeds = [seed[..p], Convert.FromHexString("1e"), Convert.FromHexString("1801000801020304050607080000000000000000000000000000000000"),
            Convert.FromHexString("07040102030405"), Convert.FromHexString("1c000000"), Convert.FromHexString("1d0000"), Convert.FromHexString("3000")];
        return new Target("quic-client-frames", seeds,
            B("\x1e", "\x07", "\x08", "\x0b", "\x18", "\x19", "\x1c", "\x1d", "\x30", "\x31", "\x00", "\x01", "\x40\x00", "\xff"),
            data =>
            {
                lock (QuicConnGate)
                {
                    if (QuicTls.Unavailable is not null) return false;
                    var net = _quicClientNet;
                    if (net is null || net.Server is null || net.Server.IsDraining || net.Server.IsClosed || net.Client.IsDraining || net.Client.IsClosed)
                    {
                        net?.Dispose();
                        net = _quicClientNet = new QuicNet(seed: 2, server: new QuicOptions { MaxDatagramFrameSize = 1200 }, client: new QuicOptions { MaxDatagramFrameSize = 1200, MaxStreamsBidi = 20 });
                        if (!net.Run(() => net.Connected && net.Client.HandshakeConfirmed && net.Server!.HandshakeConfirmed)) throw new Finding("handshake failed");
                    }
                    var client = net.Client;
                    try { client.InjectFrames(data, net.Now); }
                    catch (Exception e) { throw new Finding($"{e.GetType().Name} escaped the client's frame handling: {e.Message}"); }
                    bool closedByClient = client.IsDraining || client.IsClosed;
                    try { net.Run(() => false, maxUs: 300_000); }
                    catch (Exception e) when (e is not Finding) { throw new Finding($"{e.GetType().Name} while settling: {e.Message}\n{e.StackTrace}"); }
                    while (client.TryGetEvent(out _)) { }
                    while (net.Server!.TryGetEvent(out _)) { }
                    var s = net.Server;
                    if (s.CloseCode is QuicError.FrameEncodingError or QuicError.InternalError or QuicError.TransportParameterError or QuicError.KeyUpdateError
                        or (>= QuicError.CryptoError and <= QuicError.CryptoError + 255) && !s.ClosedByPeer)
                        throw new Finding($"the client's replies made the server close: {s.CloseCode} ({s.CloseReason})");
                    if (client.CloseCode is QuicError.InternalError && !client.ClosedByPeer) throw new Finding("the client hit an internal error: " + client.CloseReason);
                    return !closedByClient;
                }
            }, MaxLen: 1024, Serial: true);
    }
}
