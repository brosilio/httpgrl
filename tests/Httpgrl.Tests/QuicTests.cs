using Httpgrl.Core.Quic;

namespace Httpgrl.Tests;

/// <summary>QUIC building blocks: varints, packet headers, packet protection (RFC 9001 vectors), frames, transport parameters.</summary>
internal static class QuicTests
{
    private static byte[] H(string hex) => Convert.FromHexString(hex.Replace(" ", ""));

    private static QuicError Fails(Action a)
    {
        try { a(); }
        catch (QuicException e) { return e.Code; }
        throw new Exception("accepted");
    }

    private static QuicError FrameFails(byte[] payload, PacketType pt = PacketType.OneRtt, bool fromClient = true) => Fails(() =>
    {
        var r = new QuicFrameReader(payload, pt, fromClient);
        while (r.TryNext(out _)) { }
    });

    private static int FrameCount(byte[] payload, PacketType pt = PacketType.OneRtt, bool fromClient = true)
    {
        var r = new QuicFrameReader(payload, pt, fromClient);
        int n = 0;
        while (r.TryNext(out _)) n++;
        return n;
    }

    public static void Register()
    {
        T.Add("quic varint: RFC 9000 A.1 examples, shortest encodings, truncation", () =>
        {
            (string Hex, ulong V)[] cases = [("c2197c5eff14e88c", 151288809941952652), ("9d7f3e7d", 494878333), ("7bbd", 15293), ("25", 37), ("4025", 37)];
            foreach (var (hex, v) in cases)
            {
                T.True(VarInt.TryRead(H(hex), out var got, out int n));
                T.Eq(v, got);
                T.Eq(hex.Length / 2, n);
                T.True(!VarInt.TryRead(H(hex)[..^1], out _, out _));
            }
            Span<byte> buf = stackalloc byte[8];
            foreach (var v in new ulong[] { 0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, VarInt.Max })
            {
                int n = VarInt.Write(buf, v);
                T.Eq(VarInt.Size(v), n);
                T.True(VarInt.TryRead(buf[..n], out var back, out _) && back == v);
            }
            T.Eq(1, VarInt.Write(buf, 37));
            T.Eq(0x25, (int)buf[0]);
        });

        T.Add("quic clock: the endpoint's microsecond clock is positive, monotonic and close to real time (no overflow)", () =>
        {
            long a = QuicEndpoint.Now();
            Thread.Sleep(50);
            long b = QuicEndpoint.Now();
            T.True(a > 0 && b > a);
            T.True(b - a is >= 45_000 and < 1_000_000);
        });

        T.Add("quic packet numbers: RFC 9000 A.2/A.3 examples, and decoding near the window edges", () =>
        {
            T.Eq(0xa82f9b32L, Packets.DecodePacketNumber(0xa82f30ea, 0x9b32, 16));
            T.Eq(2, Packets.PacketNumberLength(0xac5c02, 0xabe8b3));
            T.Eq(3, Packets.PacketNumberLength(0xace8fe, 0xabe8b3));
            T.Eq(1, Packets.PacketNumberLength(0, -1));
            // A wrap of the 8-bit window, either way.
            T.Eq(256L, Packets.DecodePacketNumber(255, 0x00, 8));
            T.Eq(255L, Packets.DecodePacketNumber(256, 0xff, 8));
            T.Eq(0L, Packets.DecodePacketNumber(-1, 0, 8));
        });

        T.Add("quic keys: Initial secrets, key, IV, header protection (A.1) and the key-update secret (A.5) match RFC 9001", () =>
        {
            var (client, server) = QuicKeys.InitialSecrets(H("8394c8f03e515708"));
            T.Eq("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea", Convert.ToHexStringLower(client));
            T.Eq("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b", Convert.ToHexStringLower(server));
            using var ck = new PacketKeys(QuicCipher.Aes128Gcm, client);
            using var sk = new PacketKeys(QuicCipher.Aes128Gcm, server);
            T.Eq("fa044b2f42a3fd3b46fb255c", Convert.ToHexStringLower(ck.Iv));
            T.Eq("0ac1493ca1905853b0bba03e", Convert.ToHexStringLower(sk.Iv));
            Span<byte> mask = stackalloc byte[5];
            ck.Mask(H("d1b1c98dd7689fb8ec11d242b123dc9b"), mask);
            T.Eq("437b9aec36", Convert.ToHexStringLower(mask));
            sk.Mask(H("2cd0991cd25b0aac406a5816b6394100"), mask);
            T.Eq("2ec0d8356a", Convert.ToHexStringLower(mask));
            // The key-update secret: RFC 9001 A.5's "quic ku" (SHA-256, as for AES-128-GCM).
            T.Eq("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9",
                Convert.ToHexStringLower(QuicKeys.NextSecret(QuicCipher.Aes128Gcm, H("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"))));
        });

        T.Add("quic protection: ChaCha20-Poly1305 reproduces RFC 9001 A.5 (key, IV, header-protection mask, the 21-byte packet)", () =>
        {
            if (QuicTls.Unavailable is not null) return;
            var secret = H("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
            using var k = new PacketKeys(QuicCipher.ChaCha20, secret);
            T.Eq("e0459b3474bdd0e44a41c144", Convert.ToHexStringLower(k.Iv));
            Span<byte> mask = stackalloc byte[5];
            k.Mask(H("5e5cd55c41f69080575d7999c25a5bfb"), mask);
            T.Eq("aefefe7d03", Convert.ToHexStringLower(mask));
            var packet = new byte[4 + 1 + 16];
            H("4200bff4").CopyTo(packet, 0);
            packet[4] = 0x01; // PING
            k.Seal(packet, 1, 3, 654360564);
            T.Eq("4cfe4189655e5cd55c41f69080575d7999c25a5bfb", Convert.ToHexStringLower(packet));
            // And back: unmask, decode the packet number, open.
            using var r = new PacketKeys(QuicCipher.ChaCha20, secret);
            int pnLen = r.Unmask(packet, 1, out ulong tr);
            T.Eq(3, pnLen);
            T.Eq(654360564L, Packets.DecodePacketNumber(654360563, tr, 24));
            T.True(r.Open(packet, 4, 654360564));
            T.Eq(1, (int)packet[4]);
        });

        T.Add("quic protection: sealing the RFC 9001 client and server Initials gives the RFC's bytes", () =>
        {
            var (client, server) = QuicKeys.InitialSecrets(H("8394c8f03e515708"));
            using (var ck = new PacketKeys(QuicCipher.Aes128Gcm, client))
            {
                var hdr = QuicVectors.ClientHeader;
                var packet = new byte[1200];
                hdr.CopyTo(packet, 0);
                QuicVectors.ClientCrypto.CopyTo(packet, hdr.Length); // the rest of the 1162 bytes stays PADDING
                ck.Seal(packet, 18, 4, 2);
                T.Eq(Convert.ToHexStringLower(QuicVectors.ClientPacket), Convert.ToHexStringLower(packet));
            }
            using (var sk = new PacketKeys(QuicCipher.Aes128Gcm, server))
            {
                var hdr = QuicVectors.ServerHeader;
                var packet = new byte[hdr.Length + QuicVectors.ServerPayload.Length + 16];
                hdr.CopyTo(packet, 0);
                QuicVectors.ServerPayload.CopyTo(packet, hdr.Length);
                sk.Seal(packet, 18, 2, 1);
                T.Eq(Convert.ToHexStringLower(QuicVectors.ServerPacket), Convert.ToHexStringLower(packet));
            }
        });

        T.Add("quic protection: the server opens the RFC client Initial; a flipped bit anywhere fails it", () =>
        {
            var datagram = QuicVectors.ClientPacket;
            T.True(Packets.TryParse(datagram, 8, out var h));
            T.Eq(PacketType.Initial, h.Type);
            T.Eq("8394c8f03e515708", Convert.ToHexStringLower(h.Dcid(datagram)));
            T.Eq(0, h.ScidLength);
            T.Eq(0, h.TokenLength);
            T.Eq(18, h.PnOffset);
            T.Eq(1200, h.Length);
            var (client, _) = QuicKeys.InitialSecrets(h.Dcid(datagram));
            using var keys = new PacketKeys(QuicCipher.Aes128Gcm, client);

            var p = (byte[])datagram.Clone();
            int pnLen = keys.Unmask(p, h.PnOffset, out ulong truncated);
            T.Eq(4, pnLen);
            long pn = Packets.DecodePacketNumber(-1, truncated, pnLen * 8);
            T.Eq(2L, pn);
            T.True(keys.Open(p.AsSpan(0, h.Length), h.PnOffset + pnLen, pn));
            var payload = p.AsSpan(h.PnOffset + pnLen, h.Length - h.PnOffset - pnLen - 16);
            T.Eq(1162, payload.Length);
            T.True(payload[..QuicVectors.ClientCrypto.Length].SequenceEqual(QuicVectors.ClientCrypto));

            foreach (int at in new[] { 0, 5, 18, 30, 600, 1199 })
            {
                var bad = (byte[])datagram.Clone();
                bad[at] ^= 0x01;
                if (!Packets.TryParse(bad, 8, out var bh)) continue; // a broken header is dropped earlier
                var (cs, _) = QuicKeys.InitialSecrets(bh.Dcid(bad));
                using var k = new PacketKeys(QuicCipher.Aes128Gcm, cs);
                int n = k.Unmask(bad, bh.PnOffset, out ulong tr);
                T.True(!k.Open(bad.AsSpan(0, bh.Length), bh.PnOffset + n, Packets.DecodePacketNumber(-1, tr, n * 8)));
            }
        });

        T.Add("quic Retry: the RFC 9001 A.4 packet, and its integrity tag binds the original connection ID", () =>
        {
            var d = new byte[64];
            int n = Packets.WriteRetry(d, [], H("f067a5502a4262b5"), "token"u8, H("8394c8f03e515708"), 0x0f);
            T.Eq(Convert.ToHexStringLower(QuicVectors.Retry), Convert.ToHexStringLower(d.AsSpan(0, n)));
            T.True(RetryIntegrity.Verify(QuicVectors.Retry, H("8394c8f03e515708")));
            T.True(!RetryIntegrity.Verify(QuicVectors.Retry, H("8394c8f03e515709")));
            T.True(Packets.TryParse(QuicVectors.Retry, 8, out var h) && h.Type == PacketType.Retry);
        });

        T.Add("quic headers: version negotiation, coalesced packets, and malformed headers dropped", () =>
        {
            // An unknown version still yields its connection IDs (the invariants), for Version Negotiation.
            var unknown = H("c01a2a3a4a 08 0102030405060708 04 a1a2a3a4 00");
            T.True(Packets.TryParse(unknown, 8, out var u));
            T.Eq(PacketType.UnknownVersion, u.Type);
            var vn = new byte[64];
            int n = Packets.WriteVersionNegotiation(vn, u.Dcid(unknown), u.Scid(unknown), 0x55);
            T.Eq("d500000000" + "04a1a2a3a4" + "080102030405060708" + "00000001", Convert.ToHexStringLower(vn.AsSpan(0, n)));

            // Two packets in one datagram: the Length field says where the first ends.
            var hs = new byte[] { 0xe0, 0, 0, 0, 1, 0, 0, 0x40, 20 }.Concat(new byte[20]).ToArray();
            var datagram = QuicVectors.ServerPacket.Concat(hs).ToArray();
            T.True(Packets.TryParse(datagram, 8, out var first) && first.Type == PacketType.Initial);
            T.Eq(QuicVectors.ServerPacket.Length, first.Length);
            T.True(Packets.TryParse(datagram.AsSpan(first.Length), 8, out var second) && second.Type == PacketType.Handshake);
            T.Eq(hs.Length, second.Length);

            // Fixed bit clear, CIDs over 20 bytes in v1, a Length past the datagram, a token past it, a short header with no room.
            var noFixed = (byte[])QuicVectors.ClientPacket.Clone();
            noFixed[0] &= 0xBF;
            T.True(!Packets.TryParse(noFixed, 8, out _));
            T.True(!Packets.TryParse(H("c000000001 15" + new string('a', 42) + "00 00 4014" + new string('0', 40)), 8, out _));
            T.True(!Packets.TryParse(H("c000000001 00 00 00 4100" + new string('0', 40)), 8, out _));
            T.True(!Packets.TryParse(H("c000000001 00 00 4100" + new string('0', 40)), 8, out _));
            T.True(!Packets.TryParse(H("40 0102030405060708"), 8, out _));
            T.True(!Packets.TryParse(H("40 0102030405060708 00112233445566778899aabbccddeeff00"), 8, out _)); // no room for the sample
            T.True(Packets.TryParse(H("40 0102030405060708 00112233445566778899aabbccddeeff0011223344"), 8, out _));
            T.True(!Packets.TryParse(H("c000000001 00 00 00 05 0000000000"), 8, out _)); // too short to sample
        });

        T.Add("quic frames: every writer's output reads back; ACK ranges walk largest first", () =>
        {
            var buf = new byte[512];
            int p = 0;
            p += QuicFrameWriter.Ping(buf.AsSpan(p));
            p += QuicFrameWriter.Ack(buf.AsSpan(p), [(90, 100), (50, 60), (0, 10)], 7);
            p += QuicFrameWriter.Crypto(buf.AsSpan(p), 1000, "hello"u8);
            p += QuicFrameWriter.Stream(buf.AsSpan(p), 4, 0, "abc"u8, fin: false);
            p += QuicFrameWriter.Stream(buf.AsSpan(p), 8, 1 << 20, "d"u8, fin: true);
            p += QuicFrameWriter.ResetStream(buf.AsSpan(p), 4, 9, 3);
            p += QuicFrameWriter.StopSending(buf.AsSpan(p), 4, 10);
            p += QuicFrameWriter.MaxData(buf.AsSpan(p), 1 << 30);
            p += QuicFrameWriter.MaxStreamData(buf.AsSpan(p), 4, 77);
            p += QuicFrameWriter.MaxStreams(buf.AsSpan(p), true, 100);
            p += QuicFrameWriter.StreamsBlocked(buf.AsSpan(p), false, 3);
            p += QuicFrameWriter.NewConnectionId(buf.AsSpan(p), 5, 2, [1, 2, 3, 4, 5, 6, 7, 8], new byte[16]);
            p += QuicFrameWriter.RetireConnectionId(buf.AsSpan(p), 1);
            p += QuicFrameWriter.PathChallenge(buf.AsSpan(p), [1, 2, 3, 4, 5, 6, 7, 8]);
            p += QuicFrameWriter.Datagram(buf.AsSpan(p), "dg"u8);
            p += QuicFrameWriter.Padding(buf.AsSpan(p), 30);
            p += QuicFrameWriter.ConnectionClose(buf.AsSpan(p), 0x0a, 0x08, "bye"u8);

            var r = new QuicFrameReader(buf.AsSpan(0, p), PacketType.OneRtt, fromClient: true);
            var types = new List<ulong>();
            while (r.TryNext(out var f))
            {
                types.Add(f.Type);
                switch (f.Type)
                {
                    case QuicFrameType.Ack:
                        T.Eq(100UL, f.Ack.Largest);
                        T.Eq(7UL, f.Ack.Delay);
                        var ranges = new List<(ulong, ulong)>();
                        foreach (var x in f.Ack) ranges.Add(x);
                        T.Eq("(90, 100) (50, 60) (0, 10)", string.Join(" ", ranges));
                        break;
                    case QuicFrameType.Crypto: T.Eq(1000UL, f.Offset); T.True(f.Data.SequenceEqual("hello"u8)); break;
                    case QuicFrameType.NewConnectionId: T.Eq(5UL, f.Value); T.Eq(2UL, f.Extra); T.Eq(8, f.Data.Length); break;
                    case QuicFrameType.DatagramLen: T.True(f.Data.SequenceEqual("dg"u8)); break;
                    case QuicFrameType.ConnectionClose: T.Eq(0x0aUL, f.ErrorCode); T.Eq(0x08UL, f.Extra); T.True(f.Data.SequenceEqual("bye"u8)); break;
                    default:
                        if (f.IsStream && f.StreamId == 8) { T.Eq(1UL << 20, f.Offset); T.True(f.Fin); T.True(f.Data.SequenceEqual("d"u8)); }
                        if (f.IsStream && f.StreamId == 4) { T.Eq(0UL, f.Offset); T.True(!f.Fin); T.True(f.Data.SequenceEqual("abc"u8)); }
                        break;
                }
            }
            T.Eq(17, types.Count); // the padding run is one frame
            // A STREAM frame without LEN runs to the end of the packet.
            var r2 = new QuicFrameReader(H("0c 04 05 616263"), PacketType.OneRtt, true);
            T.True(r2.TryNext(out var s) && s.Offset == 5 && s.Data.SequenceEqual("abc"u8));
        });

        T.Add("quic frames: malformed, disallowed and out-of-range frames are the right errors", () =>
        {
            T.Eq(QuicError.FrameEncodingError, FrameFails(H("21"))); // unknown type
            T.Eq(QuicError.ProtocolViolation, FrameFails(H("4001"))); // PING, not minimally encoded
            T.Eq(QuicError.FrameEncodingError, FrameFails(H("02 05 00 00 06"))); // first range below zero
            T.Eq(QuicError.FrameEncodingError, FrameFails(H("02 05 00 01 01 03 00"))); // a gap below zero
            T.Eq(QuicError.FrameEncodingError, FrameFails(H("02 05 00 3f 00"))); // a range count the bytes can't hold
            T.Eq(QuicError.FrameEncodingError, FrameFails(H("06 00 05 6162"))); // CRYPTO past the packet
            T.Eq(QuicError.FrameEncodingError, FrameFails(H("0e 04 ffffffffffffffff 01 61"))); // STREAM beyond 2^62
            T.Eq(QuicError.FrameEncodingError, FrameFails(H("12 d000000000000001"))); // MAX_STREAMS beyond 2^60
            T.Eq(QuicError.FrameEncodingError, FrameFails(H("18 01 02 08 0102030405060708" + new string('0', 32)))); // Retire Prior To > seq
            T.Eq(QuicError.FrameEncodingError, FrameFails(H("18 01 00 00" + new string('0', 32)))); // empty connection ID
            T.Eq(QuicError.FrameEncodingError, FrameFails(H("18 01 00 15" + new string('a', 42) + new string('0', 32)))); // 21 bytes
            T.Eq(QuicError.FrameEncodingError, FrameFails(H("1a 0102"))); // short PATH_CHALLENGE
            T.Eq(QuicError.FrameEncodingError, FrameFails(H("07 00"), fromClient: false)); // empty NEW_TOKEN
            // Role: clients send neither NEW_TOKEN nor HANDSHAKE_DONE.
            T.Eq(QuicError.ProtocolViolation, FrameFails(H("07 01 61")));
            T.Eq(QuicError.ProtocolViolation, FrameFails(H("1e")));
            T.Eq(1, FrameCount(H("1e"), fromClient: false));
            // Initial and Handshake packets carry only PADDING, PING, ACK, CRYPTO and transport CONNECTION_CLOSE.
            T.Eq(QuicError.ProtocolViolation, FrameFails(H("08 00 00"), PacketType.Initial));
            T.Eq(QuicError.ProtocolViolation, FrameFails(H("1d 00 00"), PacketType.Handshake));
            T.Eq(QuicError.ProtocolViolation, FrameFails(H("30"), PacketType.Initial));
            T.Eq(3, FrameCount(H("01 06 00 01 61 1c 00 00 00"), PacketType.Initial));
        });

        T.Add("quic transport parameters: the RFC 9001 ClientHello's, round trips, and every violation refused", () =>
        {
            // The quic_transport_parameters extension of the ClientHello in RFC 9001 A.2.
            var tp = TransportParameters.Parse(H("0408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff"), fromServer: false);
            T.Eq(VarInt.Max, tp.InitialMaxData);
            T.Eq(0xffffUL, tp.InitialMaxStreamDataBidiLocal);
            T.Eq(0xffffUL, tp.InitialMaxStreamDataBidiRemote);
            T.Eq(0xffffUL, tp.InitialMaxStreamDataUni);
            T.Eq(16UL, tp.InitialMaxStreamsBidi);
            T.Eq(16UL, tp.InitialMaxStreamsUni);
            T.Eq(30000UL, tp.MaxIdleTimeoutMs);
            T.Eq("8394c8f03e515708", Convert.ToHexStringLower(tp.InitialScid!));

            var ours = new TransportParameters
            {
                OriginalDcid = H("0102030405060708"), InitialScid = H("a1a2a3a4a5a6a7a8"), RetryScid = H("b1b2"),
                StatelessResetToken = new byte[16], MaxIdleTimeoutMs = 30000, InitialMaxData = 1 << 20, InitialMaxStreamsBidi = 100,
                InitialMaxStreamDataBidiRemote = 1 << 18, ActiveConnectionIdLimit = 4, MaxDatagramFrameSize = 1200, DisableActiveMigration = true,
                AckDelayExponent = 2, MaxAckDelayMs = 20,
            };
            var back = TransportParameters.Parse(ours.ToArray(), fromServer: true);
            T.Eq("0102030405060708", Convert.ToHexStringLower(back.OriginalDcid!));
            T.Eq("b1b2", Convert.ToHexStringLower(back.RetryScid!));
            T.Eq(1200UL, back.MaxDatagramFrameSize);
            T.Eq(4UL, back.ActiveConnectionIdLimit);
            T.True(back.DisableActiveMigration);
            T.Eq(2UL, back.AckDelayExponent);
            T.Eq(20UL, back.MaxAckDelayMs);

            const string scid = "0f0101";
            QuicError Bad(string hex, bool fromServer = false) => Fails(() => TransportParameters.Parse(H(hex), fromServer));
            T.Eq(QuicError.TransportParameterError, Bad(scid + "010105" + "010106")); // duplicate
            T.Eq(QuicError.TransportParameterError, Bad(scid + "000101")); // original_destination_connection_id from a client
            T.Eq(QuicError.TransportParameterError, Bad(scid + "02" + "10" + new string('0', 32))); // stateless_reset_token from a client
            T.Eq(QuicError.TransportParameterError, Bad(scid + "100101")); // retry_source_connection_id from a client
            T.Eq(QuicError.TransportParameterError, Bad(scid + "0a0115")); // ack_delay_exponent 21
            T.Eq(QuicError.TransportParameterError, Bad(scid + "0b0480004000")); // max_ack_delay 2^14
            T.Eq(QuicError.TransportParameterError, Bad(scid + "030244af")); // max_udp_payload_size 1199
            T.Eq(QuicError.TransportParameterError, Bad(scid + "0e0101")); // active_connection_id_limit 1
            T.Eq(QuicError.TransportParameterError, Bad(scid + "0c0100")); // disable_active_migration with a value
            T.Eq(QuicError.TransportParameterError, Bad(scid + "01020005")); // an integer shorter than its parameter
            T.Eq(QuicError.TransportParameterError, Bad("010105")); // no initial_source_connection_id
            T.Eq(QuicError.TransportParameterError, Bad(scid, fromServer: true)); // a server must echo the original DCID
            T.Eq(QuicError.TransportParameterError, Bad(scid + "0105")); // value past the end
            // Unknown and grease (31N+27) parameters are ignored; repeating one is still a duplicate.
            T.Eq(5UL, TransportParameters.Parse(H(scid + "1b00" + "4a4a03616263" + "010105"), false).MaxIdleTimeoutMs);
            T.Eq(QuicError.TransportParameterError, Bad(scid + "1b00" + "1b00"));
        });
    }
}
