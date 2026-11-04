using Httpgrl.Core.Quic;

namespace Httpgrl.Core.Http3;

/// <summary>HTTP/3 error codes (RFC 9114 8.1) and QPACK's (RFC 9204 6).</summary>
internal enum H3Error : ulong
{
    NoError = 0x100,
    GeneralProtocolError = 0x101,
    InternalError = 0x102,
    StreamCreationError = 0x103,
    ClosedCriticalStream = 0x104,
    FrameUnexpected = 0x105,
    FrameError = 0x106,
    ExcessiveLoad = 0x107,
    IdError = 0x108,
    SettingsError = 0x109,
    MissingSettings = 0x10a,
    RequestRejected = 0x10b,
    RequestCancelled = 0x10c,
    RequestIncomplete = 0x10d,
    MessageError = 0x10e,
    ConnectError = 0x10f,
    VersionFallback = 0x110,
    QpackDecompressionFailed = 0x200,
    QpackEncoderStreamError = 0x201,
    QpackDecoderStreamError = 0x202,
}

/// <summary>An HTTP/3 error: of the connection (CONNECTION_CLOSE), or of one stream (reset it).</summary>
internal sealed class H3Exception(H3Error code, string message, bool connection = true) : Exception(message)
{
    public H3Error Code { get; } = code;
    public bool IsConnectionError { get; } = connection;
}

internal static class H3FrameType
{
    public const ulong Data = 0x00, Headers = 0x01, CancelPush = 0x03, Settings = 0x04, PushPromise = 0x05, GoAway = 0x07, MaxPushId = 0x0d;

    /// <summary>HTTP/2 frame types with no HTTP/3 meaning: receiving one is H3_FRAME_UNEXPECTED (RFC 9114 7.2.8).</summary>
    public static bool IsHttp2Only(ulong t) => t is 0x02 or 0x06 or 0x08 or 0x09;
}

internal static class H3StreamType
{
    public const ulong Control = 0x00, Push = 0x01, QpackEncoder = 0x02, QpackDecoder = 0x03;
}

internal static class H3Settings
{
    public const ulong QpackMaxTableCapacity = 0x01, MaxFieldSectionSize = 0x06, QpackBlockedStreams = 0x07,
        EnableConnectProtocol = 0x08, H3Datagram = 0x33;

    /// <summary>HTTP/2 setting identifiers, reserved in HTTP/3: receiving one is H3_SETTINGS_ERROR (7.2.4.1).</summary>
    public static bool IsHttp2Only(ulong id) => id is 0x02 or 0x03 or 0x04 or 0x05;
}

/// <summary>
/// Reads HTTP/3 frames from a stream's bytes as they arrive. A frame's payload is collected whole only for the types
/// that need it (HEADERS, SETTINGS, the control frames), bounded by <c>maxPayload</c>; DATA payload is handed out as
/// it comes; unknown types are skipped without buffering (7.2.8).
/// </summary>
internal sealed class H3FrameReader(int maxPayload)
{
    private enum Phase { Type, Length, Payload, Skip, Data }
    private Phase _phase = Phase.Type;
    private readonly byte[] _varint = new byte[8];
    private int _varLen;
    private ulong _type;
    private long _left;
    private byte[] _payload = new byte[256];
    private int _payloadLen;

    /// <summary>The frame being read (valid while a callback runs).</summary>
    public ulong Type => _type;
    /// <summary>True between frames (a stream may only end there, 7.1).</summary>
    public bool AtBoundary => _phase == Phase.Type && _varLen == 0;

    /// <summary>
    /// Feed bytes. <paramref name="onFrame"/> gets each complete non-DATA frame (type, payload);
    /// <paramref name="onData"/> each piece of DATA payload (type is DATA). Throws <see cref="H3Exception"/>.
    /// </summary>
    public void Feed(ReadOnlySpan<byte> data, H3FrameHandler onFrame, H3DataHandler onData)
    {
        while (!data.IsEmpty)
        {
            switch (_phase)
            {
                case Phase.Type:
                case Phase.Length:
                {
                    // A varint, possibly split across reads: first byte tells its length.
                    if (_varLen == 0) _varint[0] = data[0];
                    int need = 1 << (_varint[0] >> 6);
                    int take = Math.Min(need - _varLen, data.Length);
                    data[..take].CopyTo(_varint.AsSpan(_varLen));
                    _varLen += take;
                    data = data[take..];
                    if (_varLen < need) return;
                    VarInt.TryRead(_varint.AsSpan(0, need), out ulong v, out _);
                    _varLen = 0;
                    if (_phase == Phase.Type)
                    {
                        _type = v;
                        _phase = Phase.Length;
                        break;
                    }
                    if (v > (ulong)long.MaxValue) throw new H3Exception(H3Error.FrameError, "frame length");
                    _left = (long)v;
                    if (H3FrameType.IsHttp2Only(_type)) throw new H3Exception(H3Error.FrameUnexpected, "an HTTP/2 frame type");
                    if (_type == H3FrameType.Data) _phase = Phase.Data;
                    else if (IsKnown(_type))
                    {
                        if (_left > maxPayload) throw new H3Exception(H3Error.ExcessiveLoad, "frame payload too large");
                        if (_payload.Length < _left) _payload = new byte[Math.Max((int)_left, _payload.Length * 2)];
                        _payloadLen = 0;
                        _phase = Phase.Payload;
                    }
                    else _phase = Phase.Skip;
                    if (_left == 0) Complete(onFrame, onData);
                    break;
                }
                case Phase.Payload:
                {
                    int take = (int)Math.Min(_left, data.Length);
                    data[..take].CopyTo(_payload.AsSpan(_payloadLen));
                    _payloadLen += take;
                    _left -= take;
                    data = data[take..];
                    if (_left == 0) Complete(onFrame, onData);
                    break;
                }
                case Phase.Skip:
                {
                    int take = (int)Math.Min(_left, data.Length);
                    _left -= take;
                    data = data[take..];
                    if (_left == 0) _phase = Phase.Type;
                    break;
                }
                case Phase.Data:
                {
                    int take = (int)Math.Min(_left, data.Length);
                    _left -= take;
                    onData(data[..take]);
                    data = data[take..];
                    if (_left == 0) _phase = Phase.Type;
                    break;
                }
            }
        }
    }

    private void Complete(H3FrameHandler onFrame, H3DataHandler onData)
    {
        var phase = _phase;
        _phase = Phase.Type;
        if (phase == Phase.Payload) onFrame(_type, _payload.AsSpan(0, _payloadLen));
        else if (phase == Phase.Data) onData(default); // an empty DATA frame
    }

    private static bool IsKnown(ulong t) => t is H3FrameType.Headers or H3FrameType.CancelPush or H3FrameType.Settings or H3FrameType.PushPromise
        or H3FrameType.GoAway or H3FrameType.MaxPushId;
}

internal delegate void H3FrameHandler(ulong type, ReadOnlySpan<byte> payload);
internal delegate void H3DataHandler(ReadOnlySpan<byte> data);

internal static class H3FrameWriter
{
    /// <summary>A frame header (type, length); the bytes written.</summary>
    public static int Header(Span<byte> d, ulong type, long length)
    {
        int p = VarInt.Write(d, type);
        return p + VarInt.Write(d[p..], (ulong)length);
    }

    public static byte[] Settings(params (ulong Id, ulong Value)[] settings)
    {
        Span<byte> body = stackalloc byte[settings.Length * 16];
        int n = 0;
        foreach (var (id, v) in settings)
        {
            n += VarInt.Write(body[n..], id);
            n += VarInt.Write(body[n..], v);
        }
        var f = new byte[16 + n];
        int h = Header(f, H3FrameType.Settings, n);
        body[..n].CopyTo(f.AsSpan(h));
        return f[..(h + n)];
    }

    public static byte[] GoAway(long id)
    {
        Span<byte> body = stackalloc byte[8];
        int n = VarInt.Write(body, (ulong)id);
        var f = new byte[16 + n];
        int h = Header(f, H3FrameType.GoAway, n);
        body[..n].CopyTo(f.AsSpan(h));
        return f[..(h + n)];
    }

    /// <summary>Parse a SETTINGS payload (7.2.4): no duplicates, no HTTP/2 identifiers; unknown ones ignored.</summary>
    public static Dictionary<ulong, ulong> ParseSettings(ReadOnlySpan<byte> payload)
    {
        var d = new Dictionary<ulong, ulong>();
        var r = new QuicReader(payload, QuicError.FrameEncodingError);
        try
        {
            while (!r.End)
            {
                ulong id = r.VarInt(), v = r.VarInt();
                if (H3Settings.IsHttp2Only(id)) throw new H3Exception(H3Error.SettingsError, "an HTTP/2 setting");
                if (!d.TryAdd(id, v)) throw new H3Exception(H3Error.SettingsError, "duplicate setting");
            }
        }
        catch (QuicException) { throw new H3Exception(H3Error.FrameError, "malformed SETTINGS"); }
        return d;
    }
}
