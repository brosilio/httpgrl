namespace Httpgrl.Quic;

/// <summary>Stream ID arithmetic (RFC 9000 2.1): the low bit is the initiator, the next the direction.</summary>
public static class StreamId
{
    public static bool IsBidi(long id) => (id & 2) == 0;
    public static bool IsClientInitiated(long id) => (id & 1) == 0;
    /// <summary>The stream's ordinal among those of its type (0, 1, 2, ...).</summary>
    public static long Index(long id) => id >> 2;
    public static long First(bool client, bool bidi) => (client ? 0 : 1) | (bidi ? 0 : 2);
}

/// <summary>
/// One stream's state. A bidirectional stream has both halves; a unidirectional one only the sending half (ours) or
/// the receiving half (the peer's).
/// </summary>
internal sealed class QuicStream(long id, bool local, SendBuffer? send, RecvBuffer? recv)
{
    public readonly long Id = id;
    public readonly bool Local = local;
    public readonly SendBuffer? Send = send;
    public readonly RecvBuffer? Recv = recv;

    // Sending: the peer's limit (MAX_STREAM_DATA), and our RESET_STREAM.
    public long SendMax;
    public bool ResetPending, ResetSent, ResetAcked;
    public ulong ResetError;
    public long BlockedSentAt = -1;
    /// <summary>The peer asked us to stop (STOP_SENDING), with this error.</summary>
    public ulong? StopRequested;

    // Receiving: our advertised limit, the peer's RESET_STREAM, our STOP_SENDING.
    public long RecvMax;
    public bool MaxDataPending;
    public ulong? PeerReset;
    public bool StopPending, StopSent;
    public ulong StopError;
    /// <summary>The application has seen the end (FIN read, or the reset reported).</summary>
    public bool RecvDone;
    public bool InSendQueue;

    public bool SendDone => Send is null || ResetAcked || (!ResetPending && !ResetSent && Send.AllAcked);
    public bool Finished => SendDone && (Recv is null || RecvDone);
}

public enum QuicEventKind : byte
{
    /// <summary>The handshake completed (ALPN and SNI are known).</summary>
    Connected,
    /// <summary>The peer opened a stream.</summary>
    StreamOpened,
    /// <summary>Data (or the end, or a reset) is ready to read.</summary>
    StreamReadable,
    /// <summary>A stream can take more data.</summary>
    StreamWritable,
    /// <summary>The peer asked us to stop sending on a stream (we reset it with <see cref="QuicEvent.Error"/>).</summary>
    StopSending,
    DatagramReceived,
    /// <summary>A new connection ID of ours, to route to this connection; or one retired, to stop routing.</summary>
    CidIssued,
    CidRetired,
    /// <summary>The peer's new address (<see cref="QuicConnection.Path"/>) passed validation.</summary>
    PathValidated,
    /// <summary>The connection is finished and can be forgotten.</summary>
    Closed,
}

public struct QuicEvent
{
    public QuicEventKind Kind;
    public long StreamId;
    public ulong Error;
    public byte[]? Cid;
}
