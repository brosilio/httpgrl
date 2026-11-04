using System.Buffers.Binary;

namespace Httpgrl.Core.Quic;

internal enum PacketType : byte
{
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    OneRtt,
    /// <summary>A long header with a version we don't speak (or version 0): answer with Version Negotiation, or drop.</summary>
    UnknownVersion,
}

/// <summary>
/// Where the parts of one packet sit in its datagram. Only the unprotected parts are read here: the packet number and
/// the reserved bits are under header protection until <see cref="PacketKeys.Open"/>.
/// </summary>
internal struct PacketHeader
{
    public PacketType Type;
    public uint Version;
    public int DcidOffset, DcidLength;
    public int ScidOffset, ScidLength;
    public int TokenOffset, TokenLength;
    /// <summary>Offset of the (protected) packet number, from the packet's start.</summary>
    public int PnOffset;
    /// <summary>The whole packet's length in the datagram: header and payload (coalesced packets follow it).</summary>
    public int Length;

    public readonly ReadOnlySpan<byte> Dcid(ReadOnlySpan<byte> packet) => packet.Slice(DcidOffset, DcidLength);
    public readonly ReadOnlySpan<byte> Scid(ReadOnlySpan<byte> packet) => packet.Slice(ScidOffset, ScidLength);
    public readonly ReadOnlySpan<byte> Token(ReadOnlySpan<byte> packet) => packet.Slice(TokenOffset, TokenLength);
}

/// <summary>QUIC packet headers (RFC 8999 invariants, RFC 9000 17), version negotiation and Retry.</summary>
internal static class Packets
{
    public const uint Version1 = 0x0000_0001;
    public const int MaxCidLength = 20;
    /// <summary>The smallest datagram that may carry a client's Initial (RFC 9000 14.1).</summary>
    public const int MinInitialDatagram = 1200;

    /// <summary>
    /// Parse the packet at the start of <paramref name="d"/> (a datagram, or what's left of it after coalesced packets).
    /// <paramref name="shortDcidLength"/>: the length of our connection IDs, which short headers don't state. False:
    /// not a packet we can make sense of; drop the rest of the datagram (RFC 9000 12.2).
    /// </summary>
    public static bool TryParse(ReadOnlySpan<byte> d, int shortDcidLength, out PacketHeader h)
    {
        h = default;
        if (d.IsEmpty) return false;
        byte first = d[0];
        if ((first & 0x80) == 0)
        {
            // Short header (1-RTT): flags, DCID of the length we chose, then the protected packet number.
            if ((first & 0x40) == 0) return false; // fixed bit
            if (d.Length < 1 + shortDcidLength) return false;
            h.Type = PacketType.OneRtt;
            h.Version = Version1;
            h.DcidOffset = 1;
            h.DcidLength = shortDcidLength;
            h.PnOffset = 1 + shortDcidLength;
            h.Length = d.Length; // a short-header packet runs to the end of the datagram
            return h.PnOffset < d.Length;
        }

        // Long header invariants (RFC 8999 5.1): flags, version, DCID length and DCID, SCID length and SCID.
        if (d.Length < 7) return false;
        h.Version = BinaryPrimitives.ReadUInt32BigEndian(d[1..]);
        int p = 5;
        int dcidLen = d[p++];
        if (d.Length < p + dcidLen + 1) return false;
        h.DcidOffset = p;
        h.DcidLength = dcidLen;
        p += dcidLen;
        int scidLen = d[p++];
        if (d.Length < p + scidLen) return false;
        h.ScidOffset = p;
        h.ScidLength = scidLen;
        p += scidLen;

        if (h.Version != Version1)
        {
            h.Type = PacketType.UnknownVersion;
            h.Length = d.Length;
            return true;
        }
        if (dcidLen > MaxCidLength || scidLen > MaxCidLength) return false;
        if ((first & 0x40) == 0) return false; // fixed bit
        h.Type = (PacketType)((first >> 4) & 0x03);
        if (h.Type == PacketType.Retry)
        {
            h.Length = d.Length;
            return true;
        }
        if (h.Type == PacketType.Initial)
        {
            if (!VarInt.TryRead(d[p..], out ulong tokenLen, out int n)) return false;
            p += n;
            if (tokenLen > (ulong)(d.Length - p)) return false;
            h.TokenOffset = p;
            h.TokenLength = (int)tokenLen;
            p += (int)tokenLen;
        }
        if (!VarInt.TryRead(d[p..], out ulong length, out int m)) return false;
        p += m;
        // Length covers the packet number and the payload; it must fit the datagram, and leave room for the
        // smallest packet number plus the header-protection sample (RFC 9001 5.4.2).
        if (length > (ulong)(d.Length - p) || length < 20) return false;
        h.PnOffset = p;
        h.Length = p + (int)length;
        return true;
    }

    /// <summary>
    /// A Version Negotiation packet answering a packet with an unknown version (RFC 9000 17.2.1): the client's
    /// connection IDs swapped, and the versions we support. The bytes written.
    /// </summary>
    public static int WriteVersionNegotiation(Span<byte> d, ReadOnlySpan<byte> clientDcid, ReadOnlySpan<byte> clientScid, byte random)
    {
        int p = 0;
        d[p++] = (byte)(0x80 | (random & 0x7F));
        BinaryPrimitives.WriteUInt32BigEndian(d[p..], 0);
        p += 4;
        d[p++] = (byte)clientScid.Length;
        clientScid.CopyTo(d[p..]);
        p += clientScid.Length;
        d[p++] = (byte)clientDcid.Length;
        clientDcid.CopyTo(d[p..]);
        p += clientDcid.Length;
        BinaryPrimitives.WriteUInt32BigEndian(d[p..], Version1);
        return p + 4;
    }

    /// <summary>
    /// A Retry packet (RFC 9000 17.2.5): a new connection ID for the client to use, an address-validation token, and
    /// the integrity tag over <paramref name="originalDcid"/> (RFC 9001 5.8). The bytes written.
    /// </summary>
    public static int WriteRetry(Span<byte> d, ReadOnlySpan<byte> clientScid, ReadOnlySpan<byte> newScid, ReadOnlySpan<byte> token,
        ReadOnlySpan<byte> originalDcid, byte random)
    {
        int p = 0;
        d[p++] = (byte)(0xF0 | (random & 0x0F));
        BinaryPrimitives.WriteUInt32BigEndian(d[p..], Version1);
        p += 4;
        d[p++] = (byte)clientScid.Length;
        clientScid.CopyTo(d[p..]);
        p += clientScid.Length;
        d[p++] = (byte)newScid.Length;
        newScid.CopyTo(d[p..]);
        p += newScid.Length;
        token.CopyTo(d[p..]);
        p += token.Length;
        RetryIntegrity.Tag(d[..p], originalDcid, d.Slice(p, 16));
        return p + 16;
    }

    /// <summary>
    /// The full packet number from its truncated form (RFC 9000 A.3). <paramref name="largest"/>: the largest packet
    /// number successfully processed in this space, or -1.
    /// </summary>
    public static long DecodePacketNumber(long largest, ulong truncated, int bits)
    {
        long expected = largest + 1;
        long win = 1L << bits, hwin = win / 2, mask = win - 1;
        long candidate = (expected & ~mask) | (long)truncated;
        if (candidate <= expected - hwin && candidate < (1L << 62) - win) return candidate + win;
        if (candidate > expected + hwin && candidate >= win) return candidate - win;
        return candidate;
    }

    /// <summary>
    /// How many bytes to encode <paramref name="pn"/> in, given the largest one the peer acknowledged (-1: none),
    /// so the peer can decode it even after reordering (RFC 9000 17.1, A.2).
    /// </summary>
    public static int PacketNumberLength(long pn, long largestAcked)
    {
        long unacked = largestAcked < 0 ? pn + 1 : pn - largestAcked;
        // Twice the range in flight, to be decodable: 1 byte covers 2^7, 2 bytes 2^15, and so on.
        if (unacked < 1L << 7) return 1;
        if (unacked < 1L << 15) return 2;
        if (unacked < 1L << 23) return 3;
        return 4;
    }
}
