using System.Buffers.Binary;

namespace Httpgrl.Core.Http2;

/// <summary>RFC 9113 6: frame types. Anything else is an extension frame, ignored (outside a header block).</summary>
internal enum FrameType : byte
{
    Data = 0, Headers = 1, Priority = 2, RstStream = 3, Settings = 4, PushPromise = 5, Ping = 6, GoAway = 7, WindowUpdate = 8, Continuation = 9,
}

/// <summary>RFC 9113 7: error codes.</summary>
internal enum H2Error : uint
{
    NoError = 0, ProtocolError = 1, InternalError = 2, FlowControlError = 3, SettingsTimeout = 4, StreamClosed = 5,
    FrameSizeError = 6, RefusedStream = 7, Cancel = 8, CompressionError = 9, ConnectError = 10, EnhanceYourCalm = 11,
    InadequateSecurity = 12, Http11Required = 13,
}

internal static class FrameFlags
{
    public const byte EndStream = 0x1, Ack = 0x1, EndHeaders = 0x4, Padded = 0x8, Priority = 0x20;
}

/// <summary>RFC 9113 6.5.2: settings identifiers.</summary>
internal static class SettingId
{
    public const ushort HeaderTableSize = 1, EnablePush = 2, MaxConcurrentStreams = 3, InitialWindowSize = 4, MaxFrameSize = 5,
        MaxHeaderListSize = 6, EnableConnectProtocol = 8;
}

/// <summary>
/// A protocol violation. <see cref="StreamId"/> 0 is a connection error (GOAWAY, then close); otherwise a stream error
/// (RST_STREAM for that stream only). RFC 9113 5.4.
/// </summary>
internal sealed class H2Exception(H2Error code, int streamId, string message) : Exception(message)
{
    public H2Error Code { get; } = code;
    public int StreamId { get; } = streamId;
    public bool IsConnectionError => StreamId == 0;
}

/// <summary>One frame's header, with the payload located and its padding (and HEADERS priority fields) stripped.</summary>
internal readonly struct Frame(FrameType type, byte flags, int streamId, int length)
{
    public readonly FrameType Type = type;
    public readonly byte Flags = flags;
    public readonly int StreamId = streamId;
    /// <summary>Length on the wire (what counts against flow control, padding included, for DATA).</summary>
    public readonly int Length = length;
    public bool Has(byte flag) => (Flags & flag) != 0;
}

/// <summary>
/// Frame parsing and per-type validation (RFC 9113 4.1, 6), with nothing interpreted beyond what's needed to know a frame
/// is well-formed. Stream state, flow control and settings semantics are the session's.
/// </summary>
internal static class FrameReader
{
    public const int HeaderSize = 9;
    /// <summary>The client connection preface, RFC 9113 3.4.</summary>
    public static ReadOnlySpan<byte> Preface => "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8;

    /// <summary>
    /// Read the frame at the start of <paramref name="buf"/>. Returns the bytes it occupies, or 0 if more are needed.
    /// <paramref name="payload"/> is the frame's content without padding (and, for HEADERS, without priority fields).
    /// Throws <see cref="H2Exception"/> on a malformed frame. Unknown types are returned as they are, for the caller to skip.
    /// </summary>
    public static int TryRead(ReadOnlySpan<byte> buf, int maxFrameSize, out Frame frame, out ReadOnlySpan<byte> payload)
    {
        frame = default;
        payload = default;
        if (buf.Length < HeaderSize) return 0;
        int length = (buf[0] << 16) | (buf[1] << 8) | buf[2];
        var type = (FrameType)buf[3];
        byte flags = buf[4];
        int sid = (int)(BinaryPrimitives.ReadUInt32BigEndian(buf[5..]) & 0x7FFFFFFF); // the reserved bit is ignored (4.1)
        // An oversized frame is a connection error whatever its type: we can't know where the next one starts.
        if (length > maxFrameSize) throw new H2Exception(H2Error.FrameSizeError, 0, $"frame of {length} bytes exceeds SETTINGS_MAX_FRAME_SIZE");
        if (buf.Length < HeaderSize + length) return 0;
        var p = buf.Slice(HeaderSize, length);
        frame = new Frame(type, flags, sid, length);

        switch (type)
        {
            case FrameType.Data:
                if (sid == 0) throw Conn(H2Error.ProtocolError, "DATA on stream 0");
                payload = Unpad(p, flags, sid);
                break;
            case FrameType.Headers:
                if (sid == 0) throw Conn(H2Error.ProtocolError, "HEADERS on stream 0");
                p = Unpad(p, flags, sid);
                if ((flags & FrameFlags.Priority) != 0)
                {
                    if (p.Length < 5) throw Conn(H2Error.FrameSizeError, "HEADERS too short for its priority fields");
                    // RFC 9113 calls this a stream error, but rejecting HEADERS before its field block is decoded would
                    // desynchronize HPACK for the whole connection, so it ends the connection instead (always permitted).
                    if ((int)(BinaryPrimitives.ReadUInt32BigEndian(p) & 0x7FFFFFFF) == sid) throw Conn(H2Error.ProtocolError, "stream depends on itself");
                    p = p[5..];
                }
                payload = p;
                break;
            case FrameType.Priority:
                if (sid == 0) throw Conn(H2Error.ProtocolError, "PRIORITY on stream 0");
                if (length != 5) throw new H2Exception(H2Error.FrameSizeError, sid, "PRIORITY must be 5 bytes");
                if ((int)(BinaryPrimitives.ReadUInt32BigEndian(p) & 0x7FFFFFFF) == sid) throw new H2Exception(H2Error.ProtocolError, sid, "stream depends on itself");
                payload = p;
                break;
            case FrameType.RstStream:
                if (sid == 0) throw Conn(H2Error.ProtocolError, "RST_STREAM on stream 0");
                if (length != 4) throw Conn(H2Error.FrameSizeError, "RST_STREAM must be 4 bytes");
                payload = p;
                break;
            case FrameType.Settings:
                if (sid != 0) throw Conn(H2Error.ProtocolError, "SETTINGS on a stream");
                if ((flags & FrameFlags.Ack) != 0 && length != 0) throw Conn(H2Error.FrameSizeError, "SETTINGS ACK with a payload");
                if (length % 6 != 0) throw Conn(H2Error.FrameSizeError, "SETTINGS length not a multiple of 6");
                ValidateSettings(p);
                payload = p;
                break;
            case FrameType.PushPromise:
                // Clients can't push (RFC 9113 8.4), and we advertise SETTINGS_ENABLE_PUSH 0 besides.
                throw Conn(H2Error.ProtocolError, "PUSH_PROMISE from a client");
            case FrameType.Ping:
                if (sid != 0) throw Conn(H2Error.ProtocolError, "PING on a stream");
                if (length != 8) throw Conn(H2Error.FrameSizeError, "PING must be 8 bytes");
                payload = p;
                break;
            case FrameType.GoAway:
                if (sid != 0) throw Conn(H2Error.ProtocolError, "GOAWAY on a stream");
                if (length < 8) throw Conn(H2Error.FrameSizeError, "GOAWAY shorter than 8 bytes");
                payload = p;
                break;
            case FrameType.WindowUpdate:
                if (length != 4) throw Conn(H2Error.FrameSizeError, "WINDOW_UPDATE must be 4 bytes");
                if ((BinaryPrimitives.ReadUInt32BigEndian(p) & 0x7FFFFFFF) == 0)
                    throw new H2Exception(H2Error.ProtocolError, sid, "WINDOW_UPDATE with a zero increment"); // stream or connection error by sid
                payload = p;
                break;
            case FrameType.Continuation:
                if (sid == 0) throw Conn(H2Error.ProtocolError, "CONTINUATION on stream 0");
                payload = p;
                break;
            default:
                payload = p; // extension frame: the caller ignores it
                break;
        }
        return HeaderSize + length;
    }

    private static ReadOnlySpan<byte> Unpad(ReadOnlySpan<byte> p, byte flags, int sid)
    {
        if ((flags & FrameFlags.Padded) == 0) return p;
        if (p.Length < 1) throw Conn(H2Error.FrameSizeError, "padded frame without a pad length");
        int pad = p[0];
        // RFC 9113 6.1/6.2: padding as long as the payload (or longer) is a connection PROTOCOL_ERROR.
        if (pad >= p.Length) throw Conn(H2Error.ProtocolError, "padding longer than the payload");
        return p.Slice(1, p.Length - 1 - pad);
    }

    /// <summary>RFC 9113 6.5.2: values that are always errors, whoever sends them.</summary>
    private static void ValidateSettings(ReadOnlySpan<byte> p)
    {
        for (int i = 0; i + 6 <= p.Length; i += 6)
        {
            ushort id = BinaryPrimitives.ReadUInt16BigEndian(p[i..]);
            uint v = BinaryPrimitives.ReadUInt32BigEndian(p[(i + 2)..]);
            switch (id)
            {
                case SettingId.EnablePush when v > 1: throw Conn(H2Error.ProtocolError, "SETTINGS_ENABLE_PUSH not 0 or 1");
                case SettingId.InitialWindowSize when v > 0x7FFFFFFF: throw Conn(H2Error.FlowControlError, "SETTINGS_INITIAL_WINDOW_SIZE above 2^31-1");
                case SettingId.MaxFrameSize when v < 16384 || v > 16777215: throw Conn(H2Error.ProtocolError, "SETTINGS_MAX_FRAME_SIZE out of range");
                case SettingId.EnableConnectProtocol when v > 1: throw Conn(H2Error.ProtocolError, "SETTINGS_ENABLE_CONNECT_PROTOCOL not 0 or 1");
            }
        }
    }

    private static H2Exception Conn(H2Error code, string message) => new(code, 0, message);
}

/// <summary>Frame serialization helpers (the session owns buffering and ordering).</summary>
internal static class FrameWriter
{
    public static void Header(Span<byte> dest, int length, FrameType type, byte flags, int streamId)
    {
        dest[0] = (byte)(length >> 16);
        dest[1] = (byte)(length >> 8);
        dest[2] = (byte)length;
        dest[3] = (byte)type;
        dest[4] = flags;
        BinaryPrimitives.WriteUInt32BigEndian(dest[5..], (uint)streamId & 0x7FFFFFFF);
    }

    /// <summary>A SETTINGS frame with the given (id, value) pairs.</summary>
    public static byte[] Settings(params (ushort Id, uint Value)[] settings)
    {
        var f = new byte[FrameReader.HeaderSize + 6 * settings.Length];
        Header(f, 6 * settings.Length, FrameType.Settings, 0, 0);
        for (int i = 0; i < settings.Length; i++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(f.AsSpan(FrameReader.HeaderSize + 6 * i), settings[i].Id);
            BinaryPrimitives.WriteUInt32BigEndian(f.AsSpan(FrameReader.HeaderSize + 6 * i + 2), settings[i].Value);
        }
        return f;
    }

    public static byte[] SettingsAck()
    {
        var f = new byte[FrameReader.HeaderSize];
        Header(f, 0, FrameType.Settings, FrameFlags.Ack, 0);
        return f;
    }

    public static byte[] Ping(ReadOnlySpan<byte> opaque, bool ack)
    {
        var f = new byte[FrameReader.HeaderSize + 8];
        Header(f, 8, FrameType.Ping, ack ? FrameFlags.Ack : (byte)0, 0);
        opaque.CopyTo(f.AsSpan(FrameReader.HeaderSize));
        return f;
    }

    public static byte[] GoAway(int lastStreamId, H2Error code)
    {
        var f = new byte[FrameReader.HeaderSize + 8];
        Header(f, 8, FrameType.GoAway, 0, 0);
        BinaryPrimitives.WriteUInt32BigEndian(f.AsSpan(FrameReader.HeaderSize), (uint)lastStreamId & 0x7FFFFFFF);
        BinaryPrimitives.WriteUInt32BigEndian(f.AsSpan(FrameReader.HeaderSize + 4), (uint)code);
        return f;
    }

    public static byte[] RstStream(int streamId, H2Error code)
    {
        var f = new byte[FrameReader.HeaderSize + 4];
        Header(f, 4, FrameType.RstStream, 0, streamId);
        BinaryPrimitives.WriteUInt32BigEndian(f.AsSpan(FrameReader.HeaderSize), (uint)code);
        return f;
    }

    public static byte[] WindowUpdate(int streamId, int increment)
    {
        var f = new byte[FrameReader.HeaderSize + 4];
        Header(f, 4, FrameType.WindowUpdate, 0, streamId);
        BinaryPrimitives.WriteUInt32BigEndian(f.AsSpan(FrameReader.HeaderSize), (uint)increment & 0x7FFFFFFF);
        return f;
    }
}
