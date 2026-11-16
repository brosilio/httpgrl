namespace Httpgrl.Quic;

/// <summary>QUIC frame types (RFC 9000 19, RFC 9221 4). Ranges (ACK, STREAM, ...) are named by their first value.</summary>
internal static class QuicFrameType
{
    public const ulong Padding = 0x00, Ping = 0x01, Ack = 0x02, AckEcn = 0x03, ResetStream = 0x04, StopSending = 0x05,
        Crypto = 0x06, NewToken = 0x07, Stream = 0x08, StreamMax = 0x0f, MaxData = 0x10, MaxStreamData = 0x11,
        MaxStreamsBidi = 0x12, MaxStreamsUni = 0x13, DataBlocked = 0x14, StreamDataBlocked = 0x15, StreamsBlockedBidi = 0x16,
        StreamsBlockedUni = 0x17, NewConnectionId = 0x18, RetireConnectionId = 0x19, PathChallenge = 0x1a,
        PathResponse = 0x1b, ConnectionClose = 0x1c, ConnectionCloseApp = 0x1d, HandshakeDone = 0x1e,
        Datagram = 0x30, DatagramLen = 0x31;

    // STREAM frame type bits.
    public const byte StreamOff = 0x04, StreamLen = 0x02, StreamFin = 0x01;

    public static bool IsStream(ulong t) => t is >= Stream and <= StreamMax;

    /// <summary>Whether a frame makes its packet ack-eliciting (RFC 9002 2): everything but ACK, PADDING and CONNECTION_CLOSE.</summary>
    public static bool IsAckEliciting(ulong t) => t is not (Padding or Ack or AckEcn or ConnectionClose or ConnectionCloseApp);
}

/// <summary>An ACK frame's ranges, validated when parsed: iterating them can't fail.</summary>
internal ref struct AckFrame
{
    public ulong Largest, Delay, FirstRange;
    public int RangeCount;
    public ReadOnlySpan<byte> Ranges;
    public bool Ecn;
    public ulong Ect0, Ect1, Ce;

    /// <summary>The acknowledged ranges, largest first, as (smallest, largest) inclusive.</summary>
    public readonly Enumerator GetEnumerator() => new(this);

    public ref struct Enumerator
    {
        private QuicReader _r;
        private int _left;
        private ulong _smallest;
        private bool _started;
        private readonly ulong _largest, _first;
        public (ulong Smallest, ulong Largest) Current { get; private set; }

        public Enumerator(AckFrame a)
        {
            _r = new QuicReader(a.Ranges, QuicError.FrameEncodingError);
            _left = a.RangeCount;
            _largest = a.Largest;
            _first = a.FirstRange;
        }

        public bool MoveNext()
        {
            if (!_started)
            {
                _started = true;
                _smallest = _largest - _first;
                Current = (_smallest, _largest);
                return true;
            }
            if (_left == 0) return false;
            _left--;
            ulong gap = _r.VarInt(), len = _r.VarInt();
            ulong largest = _smallest - gap - 2;
            _smallest = largest - len;
            Current = (_smallest, largest);
            return true;
        }
    }
}

/// <summary>One parsed frame. Which fields mean something depends on <see cref="Type"/>; spans point into the packet.</summary>
internal ref struct QuicFrame
{
    public ulong Type;
    /// <summary>STREAM, RESET_STREAM, STOP_SENDING, MAX_STREAM_DATA, STREAM_DATA_BLOCKED.</summary>
    public ulong StreamId;
    /// <summary>STREAM, CRYPTO.</summary>
    public ulong Offset;
    /// <summary>
    /// MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, the BLOCKED frames' limits, RESET_STREAM's final size, the sequence
    /// number of NEW_CONNECTION_ID and RETIRE_CONNECTION_ID.
    /// </summary>
    public ulong Value;
    /// <summary>RESET_STREAM, STOP_SENDING, CONNECTION_CLOSE.</summary>
    public ulong ErrorCode;
    /// <summary>NEW_CONNECTION_ID's Retire Prior To; CONNECTION_CLOSE's (transport) offending frame type.</summary>
    public ulong Extra;
    public bool Fin;
    /// <summary>
    /// STREAM, CRYPTO and DATAGRAM data; NEW_TOKEN's token; NEW_CONNECTION_ID's connection ID; PATH_CHALLENGE and
    /// PATH_RESPONSE data; CONNECTION_CLOSE's reason phrase.
    /// </summary>
    public ReadOnlySpan<byte> Data;
    /// <summary>NEW_CONNECTION_ID's stateless reset token.</summary>
    public ReadOnlySpan<byte> ResetToken;
    public AckFrame Ack;

    public readonly bool IsStream => QuicFrameType.IsStream(Type);
}

/// <summary>
/// Reads the frames of a decrypted packet payload (RFC 9000 12.4, 19), checking encodings, limits, which frames the
/// packet type may carry (Table 3), and which frames the sender's role may send. A violation is a
/// <see cref="QuicException"/>. What depends on connection state (stream directions, flow control, negotiated
/// DATAGRAM support) is the connection's to check.
/// </summary>
internal ref struct QuicFrameReader(ReadOnlySpan<byte> payload, PacketType packet, bool fromClient)
{
    private readonly ReadOnlySpan<byte> _payload = payload;
    private QuicReader _r = new(payload, QuicError.FrameEncodingError);
    private readonly PacketType _packet = packet;
    private readonly bool _fromClient = fromClient;

    private const ulong MaxStreams = 1UL << 60;

    public bool TryNext(out QuicFrame f)
    {
        f = default;
        if (_r.End) return false;
        int start = _r.Position;
        ulong t = _r.VarInt();
        // Frame types must use their shortest encoding (12.4).
        if (_r.Position - start != VarInt.Size(t)) throw new QuicException(QuicError.ProtocolViolation, "frame type not minimally encoded", t);
        f.Type = t;
        if (_packet is PacketType.Initial or PacketType.Handshake
            && t is not (QuicFrameType.Padding or QuicFrameType.Ping or QuicFrameType.Ack or QuicFrameType.AckEcn or QuicFrameType.Crypto or QuicFrameType.ConnectionClose))
            throw new QuicException(QuicError.ProtocolViolation, "frame not allowed in this packet type", t);

        switch (t)
        {
            case QuicFrameType.Padding:
                while (!_r.End && _r.Rest[0] == 0) _r.Byte(); // a run of padding is one frame
                return true;
            case QuicFrameType.Ping:
            case QuicFrameType.HandshakeDone:
                if (t == QuicFrameType.HandshakeDone && _fromClient) throw new QuicException(QuicError.ProtocolViolation, "HANDSHAKE_DONE from a client", t);
                return true;
            case QuicFrameType.Ack:
            case QuicFrameType.AckEcn:
                f.Ack = ReadAck(t);
                return true;
            case QuicFrameType.ResetStream:
                f.StreamId = _r.VarInt(t);
                f.ErrorCode = _r.VarInt(t);
                f.Value = _r.VarInt(t);
                return true;
            case QuicFrameType.StopSending:
                f.StreamId = _r.VarInt(t);
                f.ErrorCode = _r.VarInt(t);
                return true;
            case QuicFrameType.Crypto:
            {
                f.Offset = _r.VarInt(t);
                int len = _r.Length(_r.Remaining, t);
                if (f.Offset + (ulong)len > VarInt.Max) throw new QuicException(QuicError.FrameEncodingError, "CRYPTO beyond 2^62", t);
                f.Data = _r.Bytes(len, t);
                return true;
            }
            case QuicFrameType.NewToken:
            {
                if (_fromClient) throw new QuicException(QuicError.ProtocolViolation, "NEW_TOKEN from a client", t);
                int len = _r.Length(_r.Remaining, t);
                if (len == 0) throw new QuicException(QuicError.FrameEncodingError, "empty NEW_TOKEN", t);
                f.Data = _r.Bytes(len, t);
                return true;
            }
            case QuicFrameType.MaxData:
            case QuicFrameType.DataBlocked:
                f.Value = _r.VarInt(t);
                return true;
            case QuicFrameType.MaxStreamData:
            case QuicFrameType.StreamDataBlocked:
                f.StreamId = _r.VarInt(t);
                f.Value = _r.VarInt(t);
                return true;
            case QuicFrameType.MaxStreamsBidi:
            case QuicFrameType.MaxStreamsUni:
            case QuicFrameType.StreamsBlockedBidi:
            case QuicFrameType.StreamsBlockedUni:
                f.Value = _r.VarInt(t);
                if (f.Value > MaxStreams) throw new QuicException(QuicError.FrameEncodingError, "stream count beyond 2^60", t);
                return true;
            case QuicFrameType.NewConnectionId:
            {
                f.Value = _r.VarInt(t);
                f.Extra = _r.VarInt(t);
                if (f.Extra > f.Value) throw new QuicException(QuicError.FrameEncodingError, "Retire Prior To beyond the sequence number", t);
                int len = _r.Byte(t);
                if (len is < 1 or > Packets.MaxCidLength) throw new QuicException(QuicError.FrameEncodingError, "connection ID length", t);
                f.Data = _r.Bytes(len, t);
                f.ResetToken = _r.Bytes(16, t);
                return true;
            }
            case QuicFrameType.RetireConnectionId:
                f.Value = _r.VarInt(t);
                return true;
            case QuicFrameType.PathChallenge:
            case QuicFrameType.PathResponse:
                f.Data = _r.Bytes(8, t);
                return true;
            case QuicFrameType.ConnectionClose:
            case QuicFrameType.ConnectionCloseApp:
            {
                f.ErrorCode = _r.VarInt(t);
                if (t == QuicFrameType.ConnectionClose) f.Extra = _r.VarInt(t);
                int len = _r.Length(_r.Remaining, t);
                f.Data = _r.Bytes(len, t);
                return true;
            }
            case QuicFrameType.Datagram:
                f.Data = _r.Bytes(_r.Remaining, t);
                return true;
            case QuicFrameType.DatagramLen:
                f.Data = _r.Bytes(_r.Length(_r.Remaining, t), t);
                return true;
        }
        if (QuicFrameType.IsStream(t))
        {
            f.StreamId = _r.VarInt(t);
            f.Offset = (t & QuicFrameType.StreamOff) != 0 ? _r.VarInt(t) : 0;
            int len = (t & QuicFrameType.StreamLen) != 0 ? _r.Length(_r.Remaining, t) : _r.Remaining;
            if (f.Offset + (ulong)len > VarInt.Max) throw new QuicException(QuicError.FrameEncodingError, "STREAM beyond 2^62", t);
            f.Data = _r.Bytes(len, t);
            f.Fin = (t & QuicFrameType.StreamFin) != 0;
            return true;
        }
        throw new QuicException(QuicError.FrameEncodingError, "unknown frame type", t);
    }

    private AckFrame ReadAck(ulong t)
    {
        var a = new AckFrame();
        a.Largest = _r.VarInt(t);
        a.Delay = _r.VarInt(t);
        ulong count = _r.VarInt(t);
        a.FirstRange = _r.VarInt(t);
        if (a.FirstRange > a.Largest) throw new QuicException(QuicError.FrameEncodingError, "ACK range below zero", t);
        // Each further range is at least two bytes: a count beyond that is a lie, whatever follows.
        if (count > (ulong)_r.Remaining / 2) throw new QuicException(QuicError.FrameEncodingError, "ACK range count", t);
        a.RangeCount = (int)count;
        int rangesStart = _r.Position;
        ulong smallest = a.Largest - a.FirstRange;
        for (int i = 0; i < a.RangeCount; i++)
        {
            ulong gap = _r.VarInt(t), len = _r.VarInt(t);
            // largest = smallest - gap - 2, smallest' = largest - len: neither may go below zero.
            if (gap + 2 > smallest || len > smallest - gap - 2) throw new QuicException(QuicError.FrameEncodingError, "ACK range below zero", t);
            smallest = smallest - gap - 2 - len;
        }
        a.Ranges = _payload.Slice(rangesStart, _r.Position - rangesStart);
        if (t == QuicFrameType.AckEcn)
        {
            a.Ecn = true;
            a.Ect0 = _r.VarInt(t);
            a.Ect1 = _r.VarInt(t);
            a.Ce = _r.VarInt(t);
        }
        return a;
    }
}

/// <summary>Frame encoders. Each writes one frame at the start of the span and returns its size.</summary>
internal static class QuicFrameWriter
{
    public static int Ping(Span<byte> d) { d[0] = (byte)QuicFrameType.Ping; return 1; }
    public static int HandshakeDone(Span<byte> d) { d[0] = (byte)QuicFrameType.HandshakeDone; return 1; }

    public static int Padding(Span<byte> d, int n) { d[..n].Clear(); return n; }

    /// <summary>
    /// An ACK frame for <paramref name="ranges"/>: (smallest, largest) inclusive, largest first, disjoint and not
    /// adjacent. <paramref name="delay"/> is already scaled by the ack-delay exponent.
    /// </summary>
    public static int Ack(Span<byte> d, ReadOnlySpan<(long Smallest, long Largest)> ranges, ulong delay)
    {
        int p = 0;
        p += VarInt.Write(d[p..], QuicFrameType.Ack);
        p += VarInt.Write(d[p..], (ulong)ranges[0].Largest);
        p += VarInt.Write(d[p..], delay);
        p += VarInt.Write(d[p..], (ulong)(ranges.Length - 1));
        p += VarInt.Write(d[p..], (ulong)(ranges[0].Largest - ranges[0].Smallest));
        for (int i = 1; i < ranges.Length; i++)
        {
            p += VarInt.Write(d[p..], (ulong)(ranges[i - 1].Smallest - ranges[i].Largest - 2));
            p += VarInt.Write(d[p..], (ulong)(ranges[i].Largest - ranges[i].Smallest));
        }
        return p;
    }

    /// <summary>The most bytes <see cref="Ack"/> can take for <paramref name="count"/> ranges.</summary>
    public static int AckMaxSize(int count) => 1 + 8 + 8 + 8 + 8 + (count - 1) * 16;

    public static int Crypto(Span<byte> d, ulong offset, ReadOnlySpan<byte> data)
    {
        int p = 0;
        p += VarInt.Write(d[p..], QuicFrameType.Crypto);
        p += VarInt.Write(d[p..], offset);
        p += VarInt.Write(d[p..], (ulong)data.Length);
        data.CopyTo(d[p..]);
        return p + data.Length;
    }

    /// <summary>The overhead of a CRYPTO frame before its data.</summary>
    public static int CryptoOverhead(ulong offset, int length) => 1 + VarInt.Size(offset) + VarInt.Size((ulong)length);

    /// <summary>A STREAM frame, always with an explicit length (so more frames may follow).</summary>
    public static int Stream(Span<byte> d, ulong streamId, ulong offset, ReadOnlySpan<byte> data, bool fin)
    {
        int p = 0;
        byte type = (byte)((byte)QuicFrameType.Stream | QuicFrameType.StreamLen | (offset > 0 ? QuicFrameType.StreamOff : 0) | (fin ? QuicFrameType.StreamFin : 0));
        d[p++] = type;
        p += VarInt.Write(d[p..], streamId);
        if (offset > 0) p += VarInt.Write(d[p..], offset);
        p += VarInt.Write(d[p..], (ulong)data.Length);
        data.CopyTo(d[p..]);
        return p + data.Length;
    }

    public static int StreamOverhead(ulong streamId, ulong offset, int length) =>
        1 + VarInt.Size(streamId) + (offset > 0 ? VarInt.Size(offset) : 0) + VarInt.Size((ulong)length);

    private static int TwoInts(Span<byte> d, ulong type, ulong a, ulong b)
    {
        int p = VarInt.Write(d, type);
        p += VarInt.Write(d[p..], a);
        return p + VarInt.Write(d[p..], b);
    }

    private static int OneInt(Span<byte> d, ulong type, ulong a)
    {
        int p = VarInt.Write(d, type);
        return p + VarInt.Write(d[p..], a);
    }

    public static int ResetStream(Span<byte> d, ulong streamId, ulong error, ulong finalSize)
    {
        int p = TwoInts(d, QuicFrameType.ResetStream, streamId, error);
        return p + VarInt.Write(d[p..], finalSize);
    }

    public static int StopSending(Span<byte> d, ulong streamId, ulong error) => TwoInts(d, QuicFrameType.StopSending, streamId, error);
    public static int MaxData(Span<byte> d, ulong max) => OneInt(d, QuicFrameType.MaxData, max);
    public static int MaxStreamData(Span<byte> d, ulong streamId, ulong max) => TwoInts(d, QuicFrameType.MaxStreamData, streamId, max);
    public static int MaxStreams(Span<byte> d, bool bidi, ulong max) => OneInt(d, bidi ? QuicFrameType.MaxStreamsBidi : QuicFrameType.MaxStreamsUni, max);
    public static int DataBlocked(Span<byte> d, ulong limit) => OneInt(d, QuicFrameType.DataBlocked, limit);
    public static int StreamDataBlocked(Span<byte> d, ulong streamId, ulong limit) => TwoInts(d, QuicFrameType.StreamDataBlocked, streamId, limit);
    public static int StreamsBlocked(Span<byte> d, bool bidi, ulong limit) => OneInt(d, bidi ? QuicFrameType.StreamsBlockedBidi : QuicFrameType.StreamsBlockedUni, limit);
    public static int RetireConnectionId(Span<byte> d, ulong seq) => OneInt(d, QuicFrameType.RetireConnectionId, seq);

    public static int NewConnectionId(Span<byte> d, ulong seq, ulong retirePriorTo, ReadOnlySpan<byte> cid, ReadOnlySpan<byte> resetToken)
    {
        int p = TwoInts(d, QuicFrameType.NewConnectionId, seq, retirePriorTo);
        d[p++] = (byte)cid.Length;
        cid.CopyTo(d[p..]);
        p += cid.Length;
        resetToken[..16].CopyTo(d[p..]);
        return p + 16;
    }

    public static int NewToken(Span<byte> d, ReadOnlySpan<byte> token)
    {
        int p = OneInt(d, QuicFrameType.NewToken, (ulong)token.Length);
        token.CopyTo(d[p..]);
        return p + token.Length;
    }

    public static int PathChallenge(Span<byte> d, ReadOnlySpan<byte> data, bool response = false)
    {
        d[0] = (byte)(response ? QuicFrameType.PathResponse : QuicFrameType.PathChallenge);
        data[..8].CopyTo(d[1..]);
        return 9;
    }

    /// <summary>CONNECTION_CLOSE: transport (with the offending frame type) or, with <paramref name="app"/>, application.</summary>
    public static int ConnectionClose(Span<byte> d, ulong error, ulong frameType, ReadOnlySpan<byte> reason, bool app = false)
    {
        int p = VarInt.Write(d, app ? QuicFrameType.ConnectionCloseApp : QuicFrameType.ConnectionClose);
        p += VarInt.Write(d[p..], error);
        if (!app) p += VarInt.Write(d[p..], frameType);
        p += VarInt.Write(d[p..], (ulong)reason.Length);
        reason.CopyTo(d[p..]);
        return p + reason.Length;
    }

    public static int Datagram(Span<byte> d, ReadOnlySpan<byte> data)
    {
        int p = OneInt(d, QuicFrameType.DatagramLen, (ulong)data.Length);
        data.CopyTo(d[p..]);
        return p + data.Length;
    }
}
