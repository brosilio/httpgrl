namespace Httpgrl.Core.Quic;

/// <summary>QUIC transport error codes (RFC 9000 20.1). TLS alerts are <see cref="CryptoError"/> + the alert.</summary>
internal enum QuicError : ulong
{
    NoError = 0x00,
    InternalError = 0x01,
    ConnectionRefused = 0x02,
    FlowControlError = 0x03,
    StreamLimitError = 0x04,
    StreamStateError = 0x05,
    FinalSizeError = 0x06,
    FrameEncodingError = 0x07,
    TransportParameterError = 0x08,
    ConnectionIdLimitError = 0x09,
    ProtocolViolation = 0x0a,
    InvalidToken = 0x0b,
    ApplicationError = 0x0c,
    CryptoBufferExceeded = 0x0d,
    KeyUpdateError = 0x0e,
    AeadLimitReached = 0x0f,
    NoViablePath = 0x10,
    CryptoError = 0x100,
}

/// <summary>A connection error: closes the connection with CONNECTION_CLOSE carrying <see cref="Code"/>.</summary>
internal sealed class QuicException(QuicError code, string message, ulong frameType = 0) : Exception(message)
{
    public QuicError Code { get; } = code;
    /// <summary>The frame type that caused it, for CONNECTION_CLOSE (0 when it wasn't a frame).</summary>
    public ulong FrameType { get; } = frameType;
}
