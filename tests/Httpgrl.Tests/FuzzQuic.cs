using Httpgrl.Core.Quic;

namespace Httpgrl.Tests;

internal static partial class Fuzz
{
    /// <summary>Variable-length integers: whatever reads must re-encode to the same bytes, and minimally to the same value.</summary>
    private static Target QuicVarIntTarget() => new("quic-varint",
        [[0x25], [0x40, 0x25], [0x7b, 0xbd], [0x9d, 0x7f, 0x3e, 0x7d], [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]],
        B("\x00", "\x3f", "\x40", "\x7f\xff", "\x80", "\xbf\xff\xff\xff", "\xc0", "\xff"),
        data =>
        {
            if (!VarInt.TryRead(data, out ulong v, out int n)) return false;
            if (n is not (1 or 2 or 4 or 8) || n > data.Length || v > VarInt.Max) throw new Finding($"read {v} in {n} bytes");
            Span<byte> b = stackalloc byte[8];
            VarInt.WriteFixed(b, v, n);
            if (!b[..n].SequenceEqual(data.AsSpan(0, n))) throw new Finding("doesn't re-encode to its own bytes");
            int m = VarInt.Write(b, v);
            if (m > n || !VarInt.TryRead(b[..m], out ulong w, out _) || w != v) throw new Finding("minimal encoding differs");
            return true;
        }, MaxLen: 16);

    /// <summary>
    /// Datagrams of coalesced packets: every parsed packet lies inside what's left, its parts inside it, and v1 long
    /// headers leave room for the header-protection sample. Initial packets are then unprotected and opened with the
    /// keys their DCID implies, which must fail or succeed but never throw.
    /// </summary>
    private static Target QuicPacketTarget() => new("quic-packet",
        [QuicVectors.ClientPacket[..400], QuicVectors.ServerPacket, QuicVectors.Retry, [.. QuicVectors.ServerPacket, .. QuicVectors.ServerPacket],
            Convert.FromHexString("c01a2a3a4a080102030405060708040a0b0c0d00"), Convert.FromHexString("4001020304050607080900112233445566778899aabbccddeeff")],
        B("\xc0\x00\x00\x00\x01", "\xe0\x00\x00\x00\x01", "\xf0\x00\x00\x00\x01", "\x40", "\x00", "\x08", "\x14", "\x15", "\x40\x14", "\x44\x9e", "\xff"),
        data =>
        {
            var rest = (byte[])data.Clone();
            int at = 0, packets = 0;
            while (at < rest.Length)
            {
                var d = rest.AsSpan(at);
                if (!Packets.TryParse(d, 8, out var h)) return packets > 0;
                if (h.Length <= 0 || h.Length > d.Length) throw new Finding($"packet of {h.Length} bytes in {d.Length}");
                if (h.DcidOffset + h.DcidLength > h.Length || h.ScidOffset + h.ScidLength > h.Length || h.TokenOffset + h.TokenLength > h.Length)
                    throw new Finding("a header field outside its packet");
                if (h.Type is PacketType.Initial or PacketType.Handshake or PacketType.ZeroRtt)
                {
                    if (h.DcidLength > 20 || h.ScidLength > 20) throw new Finding("v1 connection ID over 20 bytes");
                    if (h.PnOffset + 4 + 16 > h.Length) throw new Finding("no room for the header-protection sample");
                }
                if (h.Type == PacketType.Initial)
                {
                    var (client, _) = QuicKeys.InitialSecrets(h.Dcid(d));
                    using var keys = new PacketKeys(QuicCipher.Aes128Gcm, client);
                    var p = d[..h.Length];
                    int pnLen = keys.Unmask(p, h.PnOffset, out ulong tr);
                    if (pnLen is < 1 or > 4) throw new Finding("packet number length");
                    keys.Open(p, h.PnOffset + pnLen, Packets.DecodePacketNumber(-1, tr, pnLen * 8));
                }
                packets++;
                at += h.Length;
            }
            return true;
        }, MaxLen: 2048);

    /// <summary>
    /// Frame payloads, read as every packet type from either role: only QuicException escapes; spans stay inside the
    /// payload; STREAM and CRYPTO end at or below 2^62; ACK ranges are strictly descending, non-negative, and re-encode
    /// to the same ranges.
    /// </summary>
    private static Target QuicFramesTarget()
    {
        var seed = new byte[256];
        int p = 0;
        p += QuicFrameWriter.Ack(seed.AsSpan(p), [(90, 100), (50, 60), (0, 10)], 7);
        p += QuicFrameWriter.Crypto(seed.AsSpan(p), 5, "abc"u8);
        p += QuicFrameWriter.Stream(seed.AsSpan(p), 4, 9, "xyz"u8, true);
        p += QuicFrameWriter.NewConnectionId(seed.AsSpan(p), 3, 1, [1, 2, 3, 4], new byte[16]);
        p += QuicFrameWriter.ConnectionClose(seed.AsSpan(p), 1, 8, "why"u8);
        p += QuicFrameWriter.Datagram(seed.AsSpan(p), "dg"u8);
        byte[][] seeds = [seed[..p], Convert.FromHexString("0100000000030500010203040506"), Convert.FromHexString("1e1a01020304050607081b0102030405060708"),
            Convert.FromHexString("0c0405616263"), Convert.FromHexString("1201101302100f0405")];
        return new Target("quic-frames", seeds,
            B("\x00", "\x01", "\x02", "\x03", "\x06", "\x08", "\x0f", "\x18", "\x1c", "\x1d", "\x30", "\x31", "\x40", "\x80", "\xc0", "\xff", "\x3f"),
            data =>
            {
                bool any = false;
                foreach (var pt in new[] { PacketType.Initial, PacketType.Handshake, PacketType.OneRtt })
                    foreach (bool fromClient in new[] { true, false })
                    {
                        var r = new QuicFrameReader(data, pt, fromClient);
                        try
                        {
                            while (r.TryNext(out var f))
                            {
                                any = true;
                                if (!f.Data.IsEmpty && !data.AsSpan().Overlaps(f.Data)) throw new Finding("frame data outside the payload");
                                if ((f.IsStream || f.Type == QuicFrameType.Crypto) && f.Offset + (ulong)f.Data.Length > VarInt.Max) throw new Finding("data beyond 2^62");
                                if (f.Type is QuicFrameType.Ack or QuicFrameType.AckEcn) CheckAck(f.Ack);
                            }
                        }
                        catch (QuicException) { }
                    }
                return any;
            }, MaxLen: 1024);
    }

    private static void CheckAck(AckFrame a)
    {
        var ranges = new List<(long, long)>();
        ulong prevSmallest = ulong.MaxValue;
        foreach (var (s, l) in a)
        {
            if (s > l || l > a.Largest) throw new Finding($"ACK range ({s}, {l}) under largest {a.Largest}");
            if (prevSmallest != ulong.MaxValue && l + 1 >= prevSmallest) throw new Finding("ACK ranges not strictly descending with a gap");
            prevSmallest = s;
            ranges.Add(((long)s, (long)l));
        }
        if (ranges.Count != a.RangeCount + 1) throw new Finding("ACK range count");
        var buf = new byte[QuicFrameWriter.AckMaxSize(ranges.Count)];
        int n = QuicFrameWriter.Ack(buf, [.. ranges], a.Delay);
        var r = new QuicFrameReader(buf.AsSpan(0, n), PacketType.OneRtt, true);
        if (!r.TryNext(out var back)) throw new Finding("re-encoded ACK unreadable");
        int i = 0;
        foreach (var x in back.Ack)
            if (i >= ranges.Count || ((long)x.Smallest, (long)x.Largest) != ranges[i++]) throw new Finding("ACK doesn't round-trip");
        if (i != ranges.Count) throw new Finding("ACK lost ranges");
    }

    /// <summary>Transport parameters from either role: only QuicException escapes, and what parses re-encodes to the same values.</summary>
    private static Target QuicTransportParametersTarget() => new("quic-tp",
        [Convert.FromHexString("0408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff"),
            new TransportParameters { OriginalDcid = [1, 2], InitialScid = [3], RetryScid = [4], StatelessResetToken = new byte[16], MaxDatagramFrameSize = 1200, ActiveConnectionIdLimit = 3, DisableActiveMigration = true }.ToArray()],
        B("\x00", "\x01", "\x02", "\x03", "\x0a", "\x0b", "\x0c", "\x0d", "\x0e", "\x0f", "\x10", "\x20", "\x40\x20", "\x1b", "\x08", "\x10", "\xff"),
        data =>
        {
            bool any = false;
            foreach (bool fromServer in new[] { false, true })
            {
                TransportParameters tp;
                try { tp = TransportParameters.Parse(data, fromServer); }
                catch (QuicException) { continue; }
                any = true;
                var back = TransportParameters.Parse(tp.ToArray(), fromServer);
                if (back.InitialMaxData != tp.InitialMaxData || back.MaxIdleTimeoutMs != tp.MaxIdleTimeoutMs || back.MaxUdpPayloadSize != tp.MaxUdpPayloadSize
                    || back.InitialMaxStreamsBidi != tp.InitialMaxStreamsBidi || back.InitialMaxStreamsUni != tp.InitialMaxStreamsUni
                    || back.AckDelayExponent != tp.AckDelayExponent || back.MaxAckDelayMs != tp.MaxAckDelayMs || back.ActiveConnectionIdLimit != tp.ActiveConnectionIdLimit
                    || back.MaxDatagramFrameSize != tp.MaxDatagramFrameSize || back.DisableActiveMigration != tp.DisableActiveMigration
                    || !back.InitialScid.AsSpan().SequenceEqual(tp.InitialScid) || !back.OriginalDcid.AsSpan().SequenceEqual(tp.OriginalDcid))
                    throw new Finding("transport parameters don't round-trip");
            }
            return any;
        }, MaxLen: 512);
}

internal static partial class Fuzz
{
    private static readonly object QuicConnGate = new();
    private static QuicNet? _quicNet;

    /// <summary>
    /// A live server connection (handshake done over the virtual network) fed arbitrary 1-RTT frame payloads. Only
    /// QuicException may come out of frame handling (turned into CONNECTION_CLOSE); afterwards the server's replies
    /// must never make the client find a malformed frame, nor the server fail internally, and the exchange must settle.
    /// </summary>
    private static Target QuicConnectionTarget()
    {
        var seed = new byte[512];
        int p = 0;
        p += QuicFrameWriter.Stream(seed.AsSpan(p), 0, 0, "hello"u8, false);
        p += QuicFrameWriter.Stream(seed.AsSpan(p), 4, 10, "x"u8, true);
        p += QuicFrameWriter.MaxData(seed.AsSpan(p), 1 << 30);
        p += QuicFrameWriter.MaxStreamData(seed.AsSpan(p), 0, 1 << 20);
        p += QuicFrameWriter.ResetStream(seed.AsSpan(p), 8, 1, 5);
        p += QuicFrameWriter.StopSending(seed.AsSpan(p), 0, 3);
        p += QuicFrameWriter.MaxStreams(seed.AsSpan(p), true, 10);
        p += QuicFrameWriter.Ping(seed.AsSpan(p));
        byte[][] seeds = [seed[..p], Convert.FromHexString("0a02000568656c6c6f"), Convert.FromHexString("1801000801020304050607080000000000000000000000000000000000"),
            Convert.FromHexString("190005"), Convert.FromHexString("1a0102030405060708"), Convert.FromHexString("0201000000"), Convert.FromHexString("1c000000"), Convert.FromHexString("1600")];
        return new Target("quic-connection", seeds,
            B("\x08", "\x0a", "\x0b", "\x0f", "\x04", "\x05", "\x10", "\x11", "\x12", "\x13", "\x18", "\x19", "\x02", "\x1c", "\x1d", "\x00", "\x02", "\x03", "\x40\x00", "\x80\x00\x00\x00", "\xff"),
            data =>
            {
                lock (QuicConnGate) return RunQuicConnection(data);
            }, MaxLen: 1024, Serial: true);
    }

    private static bool RunQuicConnection(byte[] data)
    {
        if (QuicTls.Unavailable is not null) return false;
        var net = _quicNet;
        if (net is null || net.Server is null || net.Server.IsDraining || net.Server.IsClosed || net.Client.IsDraining || net.Client.IsClosed)
        {
            net?.Dispose();
            net = _quicNet = new QuicNet(seed: 1, server: new QuicOptions { MaxDatagramFrameSize = 1200, MaxStreamsBidi = 20 },
                client: new QuicOptions { MaxDatagramFrameSize = 1200 });
            if (!net.Run(() => net.Connected && net.Client.HandshakeConfirmed && net.Server!.HandshakeConfirmed)) throw new Finding("handshake failed");
        }
        var server = net.Server!;
        try { server.InjectFrames(data, net.Now); }
        catch (Exception e) { throw new Finding($"{e.GetType().Name} escaped frame handling: {e.Message}"); }
        bool closedByServer = server.IsDraining || server.IsClosed;
        // Let the server's reaction reach the client, and the client's answer come back.
        try { net.Run(() => false, maxUs: 300_000); }
        catch (Exception e) when (e is not Finding) { throw new Finding($"{e.GetType().Name} while settling: {e.Message}\n{e.StackTrace}"); }
        while (net.Client.TryGetEvent(out _)) { }
        while (server.TryGetEvent(out _)) { }
        // Injected frames can make the server's view diverge from the client's (streams or connection IDs the client
        // never created), so the client may object to the state of what it's sent: stream state, limits, flow control,
        // protocol violations about IDs. What it must never see is a malformed frame, or the server falling over.
        var c = net.Client;
        if (c.CloseCode is QuicError.FrameEncodingError or QuicError.InternalError or QuicError.TransportParameterError or QuicError.KeyUpdateError
            or (>= QuicError.CryptoError and <= QuicError.CryptoError + 255) && !c.ClosedByPeer)
            throw new Finding($"the server's replies made the client close: {c.CloseCode} ({c.CloseReason})");
        if (server.CloseCode is QuicError.InternalError && !server.ClosedByPeer) throw new Finding("the server hit an internal error: " + server.CloseReason);
        return !closedByServer;
    }
}
