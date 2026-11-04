using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Httpgrl.Core.Quic;

/// <summary>Limits and windows a connection advertises and enforces.</summary>
internal sealed class QuicOptions
{
    public int MaxIdleTimeoutMs = 30_000;
    public int HandshakeTimeoutMs = 10_000;
    public long ConnectionReceiveWindow = 4 << 20;
    public long StreamReceiveWindow = 1 << 20;
    public int MaxStreamsBidi = 100;
    public int MaxStreamsUni = 3;
    /// <summary>The largest DATAGRAM frame we take (RFC 9221); 0: not offered.</summary>
    public int MaxDatagramFrameSize = 0;
    public int MaxAckDelayMs = 25;
    public int AckDelayExponent = 3;
    public int ActiveConnectionIdLimit = 4;
    /// <summary>Out-of-order CRYPTO data held per level before CRYPTO_BUFFER_EXCEEDED.</summary>
    public int MaxCryptoBuffer = 64 << 10;
    /// <summary>Unacknowledged data a stream may hold before writes are refused (back-pressure).</summary>
    public int StreamSendBuffer = 1 << 20;
    public int MaxQueuedDatagrams = 64;
    /// <summary>The datagram size we send (QUIC's minimum path MTU; larger paths aren't probed yet).</summary>
    public int MaxDatagramSize = 1200;
    /// <summary>Packets sent under one 1-RTT key before we update it (RFC 9001 6), well inside AES-GCM's 2^23 limit.</summary>
    public long KeyUpdateAfter = PacketKeys.ConfidentialityLimit / 2;
}

/// <summary>
/// A QUIC connection (RFC 9000, 9001, 9002, 9221) as a state machine without I/O: datagrams in through
/// <see cref="Receive"/>, datagrams out through <see cref="Send"/>, time through <see cref="Deadline"/> and
/// <see cref="OnTimeout"/>. Times are microseconds on the caller's clock, which can be virtual: that's what makes
/// the network simulator's tests deterministic. Not thread-safe: one caller at a time.
/// </summary>
internal sealed class QuicConnection : IQuicTlsHost, IDisposable
{
    private enum State { Handshake, Active, Closing, Draining, Closed }

    private sealed class Pns
    {
        public PacketKeys? Send, Recv;
        public long NextPn;
        public readonly RangeSet Received = new();
        public long LargestReceived = -1, LargestReceivedTime;
        public int AckElicitingUnacked;
        public long AckDeadline;
        public bool AckNew;
        public readonly SendBuffer CryptoSend = new();
        public readonly RecvBuffer CryptoRecv = new();
        public int Probes;
        public bool Discarded;
    }

    public readonly bool IsServer;
    private readonly QuicOptions _o;
    private readonly QuicTls _tls;
    private readonly Pns[] _pns = [new(), new(), new()];
    public readonly Recovery Recovery;
    private State _state = State.Handshake;

    // Connection IDs.
    private byte[] _dcid;                     // where we send
    private readonly byte[] _scid;            // our first CID (long headers' SCID)
    private readonly byte[] _originalDcid;    // client: the DCID of its first Initial; server: the client's first DCID
    private byte[]? _retryScid;               // the SCID of a Retry (client: received; server: issued)
    private byte[] _clientDcid = [];          // server: the DCID of the client's Initials (Initial keys come from it)
    private bool _peerCidSet;
    private readonly Func<(byte[] Cid, byte[] ResetToken)> _newCid;
    private readonly List<(long Seq, byte[] Cid, byte[] Token, bool Sent, bool Acked)> _ourCids = new();
    private readonly List<(long Seq, byte[] Cid, byte[] Token)> _peerCids = new();
    private long _peerCidRetirePriorTo;
    private readonly Queue<long> _retireCidPending = new();
    public byte[]? PeerStatelessResetToken { get; private set; }
    private byte[]? _token = null;            // client: a Retry token to echo in Initials

    // Transport parameters.
    private TransportParameters? _peer;
    private long _peerMaxData, _connSent;      // send credit, and new bytes sent
    private long _connRecvMax, _connRecvHighest, _connRead;
    private bool _maxDataPending;
    private long _dataBlockedAt = -1;
    private long _peerMaxStreamsBidi, _peerMaxStreamsUni;   // streams we may open
    private long _maxStreamsBidi, _maxStreamsUni;            // streams the peer may open (advertised)
    private bool _maxStreamsBidiPending, _maxStreamsUniPending;
    private long _peerStreamsBidiClosed, _peerStreamsUniClosed;
    private long _nextBidi, _nextUni;
    private long _peerOpenedBidi, _peerOpenedUni;          // peer streams opened so far (count)
    private readonly Dictionary<long, QuicStream> _streams = new();
    private readonly LinkedList<QuicStream> _sendQueue = new();

    // Handshake progress.
    private bool _handshakeDonePending, _handshakeConfirmed, _connectedRaised;
    private bool _addressValidated;
    private long _bytesReceived, _bytesSent;
    private bool _retried;

    // Timers and closing.
    private readonly long _created;
    private long _lastActivity, _closeDeadline;
    private long _idleTimeout;
    private bool _ackElicitingSinceReceive;
    private ulong _closeError, _closeFrameType;
    private bool _closeApp, _closeDue;
    private string _closeReason = "";

    // 1-RTT key updates (RFC 9001 6): the secrets of the current generation, phase bits each way, the next receive
    // keys (derived on demand), and the previous ones (kept briefly for reordered packets).
    private byte[]? _appSendSecret, _appRecvSecret;
    private QuicCipher _appCipher;
    private int _sendPhase, _recvPhase;
    private PacketKeys? _nextRecv, _prevRecv;
    private byte[]? _nextRecvSecret;
    private long _recvPhaseStartPn, _prevRecvUntil;
    private long _keyUpdatePn = -1;   // the first packet sent under our latest send keys
    public int KeyUpdates { get; private set; }

    // Datagrams.
    private readonly Queue<byte[]> _dgOut = new(), _dgIn = new();

    private readonly Queue<QuicEvent> _events = new();
    private readonly List<SentPacket> _acked = new(), _lost = new();
    private readonly List<(long, long)> _ackRanges = new();
    private readonly Stack<SentPacket> _packetPool = new();
    private readonly List<(byte[] Packet, int Space)> _undecryptable = new();

    /// <summary>Why the connection ended (null while it hasn't): the code, whether it was the application's, and by whom.</summary>
    public QuicError? CloseCode { get; private set; }
    public ulong ApplicationCloseCode { get; private set; }
    public bool ClosedByPeer { get; private set; }
    public string? CloseReason => CloseCode is null ? null : _closeReason;
    public bool IsClosed => _state == State.Closed;
    public bool IsDraining => _state is State.Closing or State.Draining;
    public bool HandshakeComplete => _tls.HandshakeComplete;
    public bool HandshakeConfirmed => _handshakeConfirmed;
    public bool AddressValidated => _addressValidated;
    public string? Alpn => _tls.Alpn;
    public string? ServerName => _tls.ServerName;
    public QuicTlsContext TlsContext => _tls.Context;
    public byte[] SourceCid => _scid;
    public byte[] OriginalDcid => _originalDcid;
    public TransportParameters? PeerParameters => _peer;
    public long BytesReceived => _bytesReceived;
    public long BytesSent => _bytesSent;

    private QuicConnection(bool server, QuicOptions o, Func<string?, QuicTlsContext?>? select, QuicTlsContext ctx, string? sni, string[]? alpn,
        byte[] dcid, byte[] scid, byte[] originalDcid, byte[]? scidResetToken, Func<(byte[], byte[])> newCid, long now)
    {
        IsServer = server;
        _o = o;
        _dcid = dcid;
        _scid = scid;
        _originalDcid = originalDcid;
        _newCid = newCid;
        _created = _lastActivity = now;
        Recovery = new Recovery(o.MaxDatagramSize);
        Recovery.MaxAckDelay = 25_000;
        _connRecvMax = o.ConnectionReceiveWindow;
        _maxStreamsBidi = o.MaxStreamsBidi;
        _maxStreamsUni = o.MaxStreamsUni;
        _nextBidi = StreamId.First(!server, bidi: true);
        _nextUni = StreamId.First(!server, bidi: false);
        _idleTimeout = o.MaxIdleTimeoutMs * 1000L;
        _ourCids.Add((0, scid, scidResetToken ?? new byte[16], true, true));
        InstallInitialKeys(server ? originalDcid : dcid);
        _tls = server
            ? QuicTls.Server(ctx, select!, this)
            : QuicTls.Client(ctx, sni!, alpn!, OurParameters().ToArray(), this);
    }

    /// <summary>
    /// A server connection for a client's first Initial. <paramref name="clientDcid"/>: the DCID it chose (Initial
    /// keys come from it); <paramref name="originalDcid"/>: the same, or the pre-Retry one if this follows a Retry
    /// (with <paramref name="retryScid"/> the Retry's SCID). <paramref name="validated"/>: a Retry token proved the
    /// client's address.
    /// </summary>
    public static QuicConnection Server(QuicTlsContext ctx, Func<string?, QuicTlsContext?> select, QuicOptions o,
        byte[] clientDcid, byte[] clientScid, byte[] originalDcid, byte[]? retryScid, bool validated,
        byte[] scid, byte[] resetToken, Func<(byte[], byte[])> newCid, long now)
    {
        var c = new QuicConnection(true, o, select, ctx, null, null, clientScid, scid, originalDcid, resetToken, newCid, now)
        {
            _retryScid = retryScid,
            _addressValidated = validated,
            _peerCidSet = true,
            _clientDcid = clientDcid,
        };
        // Initial keys follow the DCID the client actually used (it differs from the original after a Retry).
        if (!clientDcid.AsSpan().SequenceEqual(originalDcid)) c.InstallInitialKeys(clientDcid);
        return c;
    }

    /// <summary>A client connection (tests and tools): random connection IDs; the first <see cref="Send"/> carries the ClientHello.</summary>
    public static QuicConnection Client(QuicTlsContext ctx, string sni, string[] alpn, QuicOptions o, Func<(byte[], byte[])> newCid, long now)
    {
        var dcid = RandomNumberGenerator.GetBytes(8);
        var scid = RandomNumberGenerator.GetBytes(8);
        var c = new QuicConnection(false, o, null, ctx, sni, alpn, dcid, scid, dcid, null, newCid, now) { _addressValidated = true };
        c._tls.Advance();
        return c;
    }

    private TransportParameters OurParameters() => new()
    {
        OriginalDcid = IsServer ? _originalDcid : null,
        RetryScid = IsServer ? _retryScid : null,
        InitialScid = _scid,
        StatelessResetToken = IsServer ? _ourCids[0].Token : null,
        MaxIdleTimeoutMs = (ulong)_o.MaxIdleTimeoutMs,
        MaxUdpPayloadSize = 1472,
        InitialMaxData = (ulong)_o.ConnectionReceiveWindow,
        InitialMaxStreamDataBidiLocal = (ulong)_o.StreamReceiveWindow,
        InitialMaxStreamDataBidiRemote = (ulong)_o.StreamReceiveWindow,
        InitialMaxStreamDataUni = (ulong)_o.StreamReceiveWindow,
        InitialMaxStreamsBidi = (ulong)_o.MaxStreamsBidi,
        InitialMaxStreamsUni = (ulong)_o.MaxStreamsUni,
        AckDelayExponent = (ulong)_o.AckDelayExponent,
        MaxAckDelayMs = (ulong)_o.MaxAckDelayMs,
        ActiveConnectionIdLimit = (ulong)_o.ActiveConnectionIdLimit,
        MaxDatagramFrameSize = (ulong)_o.MaxDatagramFrameSize,
        DisableActiveMigration = true, // until path validation and migration land
    };

    private void InstallInitialKeys(ReadOnlySpan<byte> dcid)
    {
        var (client, server) = QuicKeys.InitialSecrets(dcid);
        var p = _pns[0];
        p.Send?.Dispose();
        p.Recv?.Dispose();
        p.Send = new PacketKeys(QuicCipher.Aes128Gcm, IsServer ? server : client);
        p.Recv = new PacketKeys(QuicCipher.Aes128Gcm, IsServer ? client : server);
        CryptographicOperations.ZeroMemory(client);
        CryptographicOperations.ZeroMemory(server);
    }

    // ------------------------------------------------------------------ TLS host

    void IQuicTlsHost.OnCryptoData(QuicLevel level, ReadOnlySpan<byte> data) => _pns[SpaceOf(level)].CryptoSend.Write(data);

    void IQuicTlsHost.OnSecret(QuicLevel level, bool write, QuicCipher cipher, ReadOnlySpan<byte> secret)
    {
        var p = _pns[SpaceOf(level)];
        var keys = new PacketKeys(cipher, secret);
        if (write) { p.Send?.Dispose(); p.Send = keys; }
        else { p.Recv?.Dispose(); p.Recv = keys; }
        if (level == QuicLevel.OneRtt)
        {
            _appCipher = cipher;
            if (write) _appSendSecret = secret.ToArray(); else _appRecvSecret = secret.ToArray();
        }
    }

    byte[]? IQuicTlsHost.OnPeerTransportParameters(ReadOnlySpan<byte> raw)
    {
        var tp = TransportParameters.Parse(raw, fromServer: !IsServer);
        // The connection IDs each side used must match what it claims (RFC 9000 7.3).
        if (!tp.InitialScid.AsSpan().SequenceEqual(_dcid) && (IsServer || _peerCidSet))
            throw new QuicException(QuicError.TransportParameterError, "initial_source_connection_id doesn't match");
        if (!IsServer)
        {
            if (!tp.OriginalDcid.AsSpan().SequenceEqual(_originalDcid)) throw new QuicException(QuicError.TransportParameterError, "original_destination_connection_id doesn't match");
            if (_retried != tp.RetryScid is not null || (_retried && !tp.RetryScid.AsSpan().SequenceEqual(_retryScid)))
                throw new QuicException(QuicError.TransportParameterError, "retry_source_connection_id doesn't match");
            PeerStatelessResetToken = tp.StatelessResetToken;
        }
        _peer = tp;
        _peerMaxData = (long)Math.Min(tp.InitialMaxData, VarInt.Max);
        _peerMaxStreamsBidi = (long)tp.InitialMaxStreamsBidi;
        _peerMaxStreamsUni = (long)tp.InitialMaxStreamsUni;
        Recovery.MaxAckDelay = (long)tp.MaxAckDelayMs * 1000;
        if (tp.MaxIdleTimeoutMs > 0 && ((long)tp.MaxIdleTimeoutMs * 1000 < _idleTimeout || _idleTimeout == 0)) _idleTimeout = (long)tp.MaxIdleTimeoutMs * 1000;
        return IsServer ? OurParameters().ToArray() : null;
    }

    private static int SpaceOf(QuicLevel level) => level switch { QuicLevel.Initial => 0, QuicLevel.Handshake => 1, _ => 2 };
    private static QuicLevel LevelOf(int space) => space switch { 0 => QuicLevel.Initial, 1 => QuicLevel.Handshake, _ => QuicLevel.OneRtt };

    // ------------------------------------------------------------------ receiving

    /// <summary>Process one datagram from the peer.</summary>
    public void Receive(Span<byte> datagram, long now)
    {
        if (_state is State.Closed) return;
        _bytesReceived += datagram.Length;
        int at = 0;
        while (at < datagram.Length && _state != State.Closed)
        {
            var d = datagram[at..];
            if (!Packets.TryParse(d, _scid.Length, out var h)) break;
            var packet = d[..h.Length];
            at += h.Length;
            try { ReceivePacket(packet, h, now); }
            catch (QuicException e) { CloseWithError(e.Code, e.FrameType, e.Message, app: false, now); return; }
        }
    }

    private void ReceivePacket(Span<byte> packet, PacketHeader h, long now)
    {
        if (h.Type == PacketType.UnknownVersion)
        {
            // Version Negotiation (version 0) only matters to a client that hasn't heard from the server: we speak v1
            // only, so there's nothing to negotiate to. Anything else is dropped (RFC 9000 6.2).
            if (!IsServer && h.Version == 0 && !_peerCidSet && _pns[0].LargestReceived < 0)
                CloseWithError(QuicError.ConnectionRefused, 0, "server doesn't support QUIC v1", app: false, now, silent: true);
            return;
        }
        if (h.Type == PacketType.Retry)
        {
            ReceiveRetry(packet, h);
            return;
        }
        if (h.Type == PacketType.ZeroRtt) return; // never accepted
        int space = h.Type switch { PacketType.Initial => 0, PacketType.Handshake => 1, _ => 2 };
        var p = _pns[space];
        if (p.Discarded) return;
        // Long headers must be addressed to us; short ones were routed by DCID already.
        if (h.Type != PacketType.OneRtt && !IsOurCid(h.Dcid(packet))) return;
        if (p.Recv is null)
        {
            // Keys not yet available (reordering): keep a few to retry once they arrive.
            if (_undecryptable.Count < 8) _undecryptable.Add((packet.ToArray(), space));
            return;
        }
        int pnLen = p.Recv.Unmask(packet, h.PnOffset, out ulong truncated);
        long pn = Packets.DecodePacketNumber(p.LargestReceived, truncated, pnLen * 8);
        int headerLen = h.PnOffset + pnLen;
        var keys = p.Recv;
        bool newPhase = false;
        if (h.Type == PacketType.OneRtt)
        {
            if (_prevRecv is not null && now > _prevRecvUntil) { _prevRecv.Dispose(); _prevRecv = null; }
            int phase = (packet[0] >> 2) & 1;
            if (phase != _recvPhase)
            {
                if (_prevRecv is not null && pn < _recvPhaseStartPn) keys = _prevRecv; // from before the last update
                else if (_appRecvSecret is not null)
                {
                    if (_nextRecv is null)
                    {
                        _nextRecvSecret = QuicKeys.NextSecret(_appCipher, _appRecvSecret);
                        _nextRecv = p.Recv.NextGeneration(_nextRecvSecret);
                    }
                    keys = _nextRecv;
                    newPhase = true;
                }
            }
        }
        if (!keys.Open(packet, headerLen, pn))
        {
            // Undecryptable, and ending in a reset token the peer gave us: it lost our state (RFC 9000 10.3.1).
            if (h.Type == PacketType.OneRtt && packet.Length >= 21 && IsStatelessReset(packet[^16..]))
            {
                ClosedByPeer = true;
                CloseCode = QuicError.NoError;
                _closeReason = "stateless reset";
                Finish();
                return;
            }
            if (p.Recv.Forged >= PacketKeys.IntegrityLimit) CloseWithError(QuicError.AeadLimitReached, 0, "too many forged packets", app: false, now);
            return;
        }
        // Reserved bits must be zero once protection is off (RFC 9000 17.2, 17.3.1).
        if ((packet[0] & (h.Type == PacketType.OneRtt ? 0x18 : 0x0C)) != 0) throw new QuicException(QuicError.ProtocolViolation, "reserved bits set");
        if (p.Received.Contains(pn)) return; // duplicate
        if (newPhase) OnPeerKeyUpdate(pn, now);

        if (!IsServer && space == 0 && !_peerCidSet)
        {
            // The server's first Initial names the connection ID we use from now on (RFC 9000 7.2).
            _dcid = h.Scid(packet).ToArray();
            _peerCidSet = true;
        }
        if (IsServer && space == 1) _addressValidated = true; // a Handshake packet proves the client got our Initial (8.1)

        _lastActivity = now;
        _ackElicitingSinceReceive = false;
        if (_state is State.Closing)
        {
            _closeDue = true; // answer anything in the closing period with our CONNECTION_CLOSE again
            return;
        }
        if (_state is State.Draining) return;

        bool ackEliciting = ProcessFrames(packet[headerLen..^PacketKeys.TagLength], h.Type, space, now);
        p.Received.Add(pn, pn + 1);
        p.Received.KeepHighest(32);
        p.AckNew = true;
        if (pn > p.LargestReceived)
        {
            p.LargestReceived = pn;
            p.LargestReceivedTime = now;
        }
        if (ackEliciting)
        {
            p.AckElicitingUnacked++;
            if (p.AckDeadline == 0) p.AckDeadline = now + (space == 2 ? _o.MaxAckDelayMs * 1000L : 0);
        }
        // A server stops using Initial keys once it has a Handshake packet (RFC 9001 4.9.1).
        if (IsServer && space == 1 && !_pns[0].Discarded) DiscardSpace(0);
        AfterTls(now);
    }

    /// <summary>A packet authenticated under the next keys: the peer updated, or answered our update (RFC 9001 6.2, 6.3).</summary>
    private void OnPeerKeyUpdate(long pn, long now)
    {
        if (!_handshakeConfirmed) throw new QuicException(QuicError.KeyUpdateError, "key update before the handshake was confirmed");
        var p = _pns[2];
        _prevRecv?.Dispose();
        _prevRecv = p.Recv;
        _prevRecvUntil = now + 3 * Recovery.Pto;
        p.Recv = _nextRecv;
        _appRecvSecret = _nextRecvSecret;
        _nextRecv = null;
        _nextRecvSecret = null;
        _recvPhase ^= 1;
        _recvPhaseStartPn = pn;
        if (_sendPhase != _recvPhase) RotateSendKeys(); // the peer started it: follow
    }

    private void RotateSendKeys()
    {
        var p = _pns[2];
        _appSendSecret = QuicKeys.NextSecret(_appCipher, _appSendSecret!);
        var old = p.Send!;
        p.Send = old.NextGeneration(_appSendSecret);
        old.Dispose();
        _sendPhase ^= 1;
        _keyUpdatePn = p.NextPn;
        KeyUpdates++;
    }

    /// <summary>
    /// Whether we may start a key update: the handshake confirmed, the peer caught up with our last one, and our last
    /// update's first packet acknowledged (RFC 9001 6.1).
    /// </summary>
    private bool CanInitiateKeyUpdate =>
        _handshakeConfirmed && _appSendSecret is not null && _sendPhase == _recvPhase
        && (_keyUpdatePn < 0 || Recovery.Spaces[2].LargestAcked >= _keyUpdatePn);

    private bool IsStatelessReset(ReadOnlySpan<byte> tail)
    {
        bool match = false;
        if (PeerStatelessResetToken is { } t) match |= CryptographicOperations.FixedTimeEquals(t, tail);
        foreach (var c in _peerCids) match |= CryptographicOperations.FixedTimeEquals(c.Token, tail);
        return match;
    }

    private bool IsOurCid(ReadOnlySpan<byte> dcid)
    {
        foreach (var c in _ourCids) if (dcid.SequenceEqual(c.Cid)) return true;
        // Until it hears from us, a client sends its Initials (and maybe 0-RTT) to the DCID it chose.
        return IsServer && dcid.SequenceEqual(_clientDcid);
    }

    private void ReceiveRetry(Span<byte> packet, PacketHeader h)
    {
        // A client accepts one Retry, before anything else from the server, that authenticates (RFC 9000 17.2.5.2).
        if (IsServer || _retried || _peerCidSet) return;
        if (!RetryIntegrity.Verify(packet, _originalDcid)) return;
        int tokenStart = h.ScidOffset + h.ScidLength;
        var token = packet[tokenStart..^PacketKeys.TagLength];
        if (token.IsEmpty) return;
        _retried = true;
        _retryScid = h.Scid(packet).ToArray();
        _dcid = _retryScid;
        _token = token.ToArray();
        InstallInitialKeys(_dcid);
        // Start the Initial over: everything sent so far is forgotten, the ClientHello goes again from offset 0.
        var s = Recovery.Spaces[0];
        foreach (var sp in s.Sent)
            foreach (var f in sp.Frames)
                if (f.Kind == SentKind.Crypto) _pns[0].CryptoSend.OnLost(f.A, (int)f.B, false);
        Recovery.Discard(0);
        Recovery.Spaces[0].Discarded = false;
    }

    /// <summary>Handle a decrypted payload's frames; true if any was ack-eliciting.</summary>
    private bool ProcessFrames(ReadOnlySpan<byte> payload, PacketType type, int space, long now)
    {
        if (payload.IsEmpty) throw new QuicException(QuicError.ProtocolViolation, "packet with no frames");
        var r = new QuicFrameReader(payload, type, fromClient: IsServer);
        bool ackEliciting = false;
        while (r.TryNext(out var f))
        {
            ackEliciting |= QuicFrameType.IsAckEliciting(f.Type);
            switch (f.Type)
            {
                case QuicFrameType.Padding:
                case QuicFrameType.Ping:
                    break;
                case QuicFrameType.Ack:
                case QuicFrameType.AckEcn:
                    OnAckFrame(space, f.Ack, now);
                    break;
                case QuicFrameType.Crypto:
                    OnCrypto(space, f.Offset, f.Data);
                    break;
                case QuicFrameType.ConnectionClose:
                case QuicFrameType.ConnectionCloseApp:
                    ClosedByPeer = true;
                    CloseCode = f.Type == QuicFrameType.ConnectionCloseApp ? QuicError.ApplicationError : (QuicError)f.ErrorCode;
                    ApplicationCloseCode = f.Type == QuicFrameType.ConnectionCloseApp ? f.ErrorCode : 0;
                    _closeReason = System.Text.Encoding.UTF8.GetString(f.Data[..Math.Min(f.Data.Length, 256)]);
                    _state = State.Draining;
                    _closeDeadline = now + 3 * Recovery.Pto;
                    return false;
                case QuicFrameType.HandshakeDone:
                    if (!_handshakeConfirmed)
                    {
                        _handshakeConfirmed = true;
                        DiscardSpace(1);
                    }
                    break;
                case QuicFrameType.NewToken:
                    break; // we don't resume with tokens (yet)
                case QuicFrameType.MaxData:
                    if ((long)f.Value > _peerMaxData) _peerMaxData = (long)f.Value;
                    break;
                case QuicFrameType.MaxStreamsBidi:
                    if ((long)f.Value > _peerMaxStreamsBidi) _peerMaxStreamsBidi = (long)f.Value;
                    break;
                case QuicFrameType.MaxStreamsUni:
                    if ((long)f.Value > _peerMaxStreamsUni) _peerMaxStreamsUni = (long)f.Value;
                    break;
                case QuicFrameType.DataBlocked:
                case QuicFrameType.StreamsBlockedBidi:
                case QuicFrameType.StreamsBlockedUni:
                    break; // informational: our credit updates follow reads
                case QuicFrameType.StreamDataBlocked:
                    PeerStream((long)f.StreamId, f.Type, receiving: true);
                    break;
                case QuicFrameType.MaxStreamData:
                {
                    var s = PeerStream((long)f.StreamId, f.Type, receiving: false);
                    if (s is not null && (long)f.Value > s.SendMax)
                    {
                        s.SendMax = (long)f.Value;
                        Enqueue(s);
                    }
                    break;
                }
                case QuicFrameType.ResetStream:
                    OnResetStream((long)f.StreamId, f.ErrorCode, (long)f.Value);
                    break;
                case QuicFrameType.StopSending:
                    OnStopSending((long)f.StreamId, f.ErrorCode);
                    break;
                case QuicFrameType.NewConnectionId:
                    OnNewConnectionId((long)f.Value, (long)f.Extra, f.Data, f.ResetToken);
                    break;
                case QuicFrameType.RetireConnectionId:
                    OnRetireConnectionId((long)f.Value, now);
                    break;
                case QuicFrameType.PathChallenge:
                    _pathResponse = f.Data.ToArray();
                    break;
                case QuicFrameType.PathResponse:
                    break; // we don't probe paths yet
                case QuicFrameType.Datagram:
                case QuicFrameType.DatagramLen:
                    if (_o.MaxDatagramFrameSize == 0 || f.Data.Length > _o.MaxDatagramFrameSize)
                        throw new QuicException(QuicError.ProtocolViolation, "DATAGRAM not negotiated or too large", f.Type);
                    if (_dgIn.Count < _o.MaxQueuedDatagrams)
                    {
                        _dgIn.Enqueue(f.Data.ToArray());
                        Raise(QuicEventKind.DatagramReceived);
                    }
                    break;
                default:
                    if (f.IsStream) OnStreamFrame((long)f.StreamId, (long)f.Offset, f.Data, f.Fin, f.Type);
                    break;
            }
        }
        return ackEliciting;
    }

    private byte[]? _pathResponse;

    private void OnAckFrame(int space, AckFrame ack, long now)
    {
        _ackRanges.Clear();
        foreach (var (lo, hi) in ack) _ackRanges.Add(((long)lo, (long)hi));
        long delay = space == 2 && _peer is not null ? (long)Math.Min(ack.Delay << (int)_peer.AckDelayExponent, (ulong)long.MaxValue / 2) : 0;
        _acked.Clear();
        _lost.Clear();
        if (!Recovery.OnAck(space, _ackRanges, delay, now, _handshakeConfirmed, _acked, _lost))
            throw new QuicException(QuicError.ProtocolViolation, "ACK of a packet never sent", QuicFrameType.Ack);
        foreach (var sp in _acked) OnPacketAcked(space, sp);
        foreach (var sp in _lost) OnPacketLost(space, sp);
        Recycle(_acked);
        Recycle(_lost);
        // A client knows the handshake is confirmed when the server acknowledges 1-RTT data (RFC 9001 4.1.2).
        if (!IsServer && space == 2 && _tls.HandshakeComplete && !_handshakeConfirmed)
        {
            _handshakeConfirmed = true;
            DiscardSpace(1);
        }
    }

    private void Recycle(List<SentPacket> list)
    {
        foreach (var p in list)
        {
            p.Reset();
            if (_packetPool.Count < 256) _packetPool.Push(p);
        }
        list.Clear();
    }

    private void OnPacketAcked(int space, SentPacket p)
    {
        foreach (var f in p.Frames)
        {
            switch (f.Kind)
            {
                case SentKind.Crypto: _pns[space].CryptoSend.OnAcked(f.A, (int)f.B, false); break;
                case SentKind.Stream:
                    if (_streams.TryGetValue(f.Id, out var s) && s.Send is not null)
                    {
                        s.Send.OnAcked(f.A, (int)f.B, f.Fin);
                        if (s.Send.Buffered < _o.StreamSendBuffer / 2) Raise(QuicEventKind.StreamWritable, s.Id);
                        MaybeFinish(s);
                    }
                    break;
                case SentKind.ResetStream:
                    if (_streams.TryGetValue(f.Id, out var rs)) { rs.ResetAcked = true; MaybeFinish(rs); }
                    break;
                case SentKind.HandshakeDone: _handshakeDonePending = false; break;
                case SentKind.NewConnectionId:
                    for (int i = 0; i < _ourCids.Count; i++)
                        if (_ourCids[i].Seq == f.A) _ourCids[i] = _ourCids[i] with { Acked = true };
                    break;
            }
        }
    }

    private void OnPacketLost(int space, SentPacket p)
    {
        foreach (var f in p.Frames)
        {
            switch (f.Kind)
            {
                case SentKind.Crypto: _pns[space].CryptoSend.OnLost(f.A, (int)f.B, false); break;
                case SentKind.Stream:
                    if (_streams.TryGetValue(f.Id, out var s) && s.Send is not null && !s.ResetPending && !s.ResetSent)
                    {
                        s.Send.OnLost(f.A, (int)f.B, f.Fin);
                        Enqueue(s);
                    }
                    break;
                case SentKind.MaxData: _maxDataPending = true; break;
                case SentKind.MaxStreamData:
                    if (_streams.TryGetValue(f.Id, out var ms) && ms.Recv is not null && !ms.Recv.FinKnown) { ms.MaxDataPending = true; Enqueue(ms); }
                    break;
                case SentKind.MaxStreamsBidi: _maxStreamsBidiPending = true; break;
                case SentKind.MaxStreamsUni: _maxStreamsUniPending = true; break;
                case SentKind.HandshakeDone: if (!_handshakeConfirmed || IsServer) _handshakeDonePending = true; break;
                case SentKind.ResetStream:
                    if (_streams.TryGetValue(f.Id, out var rs) && !rs.ResetAcked) { rs.ResetPending = true; rs.ResetSent = false; Enqueue(rs); }
                    break;
                case SentKind.StopSending:
                    if (_streams.TryGetValue(f.Id, out var ss) && ss.Recv is not null && !ss.Recv.FinKnown) { ss.StopPending = true; Enqueue(ss); }
                    break;
                case SentKind.NewConnectionId:
                    for (int i = 0; i < _ourCids.Count; i++)
                        if (_ourCids[i].Seq == f.A && !_ourCids[i].Acked) _ourCids[i] = _ourCids[i] with { Sent = false };
                    break;
                case SentKind.RetireConnectionId: _retireCidPending.Enqueue(f.A); break;
                case SentKind.DataBlocked: _dataBlockedAt = -1; break;
                case SentKind.StreamDataBlocked:
                    if (_streams.TryGetValue(f.Id, out var bs)) bs.BlockedSentAt = -1;
                    break;
            }
        }
    }

    private void OnCrypto(int space, ulong offset, ReadOnlySpan<byte> data)
    {
        var p = _pns[space];
        p.CryptoRecv.Write((long)offset, data, false, p.CryptoRecv.ReadOffset + _o.MaxCryptoBuffer, QuicFrameType.Crypto);
        int n = p.CryptoRecv.Readable;
        if (n == 0) return;
        _tls.Receive(LevelOf(space), p.CryptoRecv.Peek());
        p.CryptoRecv.Consume(n);
        if (!_tls.Advance())
        {
            var code = _tls.Error ?? QuicError.InternalError;
            throw new QuicException(code, _tls.ErrorReason ?? "TLS failure", QuicFrameType.Crypto);
        }
    }

    /// <summary>After TLS made progress: install what it produced, and replay packets that were waiting for keys.</summary>
    private void AfterTls(long now)
    {
        if (_tls.HandshakeComplete && _state == State.Handshake)
        {
            _state = State.Active;
            if (IsServer)
            {
                // The server's handshake is confirmed as soon as it completes (RFC 9001 4.1.2).
                _handshakeConfirmed = true;
                _handshakeDonePending = true;
                _addressValidated = true;
                DiscardSpace(1);
            }
            IssueCids();
        }
        if (_tls.HandshakeComplete && !_connectedRaised)
        {
            _connectedRaised = true;
            Raise(QuicEventKind.Connected);
        }
        if (_undecryptable.Count > 0)
        {
            var waiting = _undecryptable.ToArray();
            _undecryptable.Clear();
            foreach (var (packet, space) in waiting)
            {
                if (_pns[space].Recv is null) { _undecryptable.Add((packet, space)); continue; }
                if (Packets.TryParse(packet, _scid.Length, out var h)) ReceivePacket(packet, h, now);
            }
        }
    }

    private void DiscardSpace(int space)
    {
        var p = _pns[space];
        if (p.Discarded) return;
        p.Discarded = true;
        p.Send?.Dispose();
        p.Recv?.Dispose();
        p.Send = p.Recv = null;
        p.CryptoSend.Release();
        p.CryptoRecv.Release();
        p.AckElicitingUnacked = 0;
        p.AckDeadline = 0;
        p.Probes = 0;
        Recovery.Discard(space);
    }

    // ------------------------------------------------------------------ connection IDs

    private void IssueCids()
    {
        if (_peer is null) return;
        int want = (int)Math.Min(_peer.ActiveConnectionIdLimit, (ulong)_o.ActiveConnectionIdLimit) - 1;
        for (int i = 0; i < want; i++)
        {
            var (cid, token) = _newCid();
            long seq = _ourCids.Count == 0 ? 0 : _ourCids[^1].Seq + 1;
            _ourCids.Add((seq, cid, token, false, false));
            _events.Enqueue(new QuicEvent { Kind = QuicEventKind.CidIssued, Cid = cid });
        }
    }

    private void OnNewConnectionId(long seq, long retirePriorTo, ReadOnlySpan<byte> cid, ReadOnlySpan<byte> token)
    {
        if (_dcid.Length == 0) throw new QuicException(QuicError.ProtocolViolation, "NEW_CONNECTION_ID with zero-length connection IDs", QuicFrameType.NewConnectionId);
        foreach (var c in _peerCids)
        {
            if (c.Seq == seq)
            {
                if (!c.Cid.AsSpan().SequenceEqual(cid) || !c.Token.AsSpan().SequenceEqual(token))
                    throw new QuicException(QuicError.ProtocolViolation, "NEW_CONNECTION_ID reuses a sequence number", QuicFrameType.NewConnectionId);
                return;
            }
        }
        if (seq < _peerCidRetirePriorTo) { _retireCidPending.Enqueue(seq); return; }
        _peerCids.Add((seq, cid.ToArray(), token.ToArray()));
        if (retirePriorTo > _peerCidRetirePriorTo)
        {
            _peerCidRetirePriorTo = retirePriorTo;
            for (int i = _peerCids.Count - 1; i >= 0; i--)
                if (_peerCids[i].Seq < retirePriorTo)
                {
                    _retireCidPending.Enqueue(_peerCids[i].Seq);
                    if (_peerCids[i].Cid.AsSpan().SequenceEqual(_dcid) && _peerCids.Count > 1)
                        _dcid = _peerCids.Find(x => x.Seq >= retirePriorTo).Cid ?? _dcid;
                    _peerCids.RemoveAt(i);
                }
        }
        // Count the one in use (sequence 0, from the handshake) against our limit too.
        if (_peerCids.Count + 1 > _o.ActiveConnectionIdLimit)
            throw new QuicException(QuicError.ConnectionIdLimitError, "too many connection IDs", QuicFrameType.NewConnectionId);
        if (_retireCidPending.Count > 64) throw new QuicException(QuicError.ConnectionIdLimitError, "too many retirements outstanding", QuicFrameType.NewConnectionId);
    }

    private void OnRetireConnectionId(long seq, long now)
    {
        long highest = _ourCids.Count == 0 ? -1 : _ourCids[^1].Seq;
        if (seq > highest) throw new QuicException(QuicError.ProtocolViolation, "RETIRE_CONNECTION_ID for a sequence number never issued", QuicFrameType.RetireConnectionId);
        int i = _ourCids.FindIndex(c => c.Seq == seq);
        if (i < 0) return;
        _events.Enqueue(new QuicEvent { Kind = QuicEventKind.CidRetired, Cid = _ourCids[i].Cid });
        _ourCids.RemoveAt(i);
        // Keep the peer supplied with as many as it may use.
        if (_peer is not null && _ourCids.Count < (int)Math.Min(_peer.ActiveConnectionIdLimit, (ulong)_o.ActiveConnectionIdLimit))
        {
            var (cid, token) = _newCid();
            _ourCids.Add((highest + 1, cid, token, false, false));
            _events.Enqueue(new QuicEvent { Kind = QuicEventKind.CidIssued, Cid = cid });
        }
        _ = now;
    }

    // ------------------------------------------------------------------ streams

    /// <summary>
    /// The stream a peer's frame names, opening it (and every lower one of its type) if the peer may (RFC 9000 3.2,
    /// 4.6). <paramref name="receiving"/>: the frame needs a receiving half (STREAM, RESET_STREAM, ...) or a sending
    /// half (MAX_STREAM_DATA, STOP_SENDING). Null if the stream is already finished and forgotten.
    /// </summary>
    private QuicStream? PeerStream(long id, ulong frameType, bool receiving)
    {
        bool local = StreamId.IsClientInitiated(id) == !IsServer;
        bool bidi = StreamId.IsBidi(id);
        if (!bidi && (local == receiving))
            throw new QuicException(QuicError.StreamStateError, receiving ? "data on a send-only stream" : "flow control for a receive-only stream", frameType);
        if (_streams.TryGetValue(id, out var s)) return s;
        long index = StreamId.Index(id);
        if (local)
        {
            long next = bidi ? _nextBidi : _nextUni;
            if (id >= next) throw new QuicException(QuicError.StreamStateError, "frame for a stream we never opened", frameType);
            return null; // ours, finished
        }
        long opened = bidi ? _peerOpenedBidi : _peerOpenedUni;
        if (index < opened) return null; // finished and forgotten
        long limit = bidi ? _maxStreamsBidi : _maxStreamsUni;
        if (index >= limit) throw new QuicException(QuicError.StreamLimitError, "stream beyond MAX_STREAMS", frameType);
        for (long i = opened; i <= index; i++)
        {
            long sid = (i << 2) | (id & 3);
            var ns = NewStream(sid, local: false);
            _streams[sid] = ns;
            Raise(QuicEventKind.StreamOpened, sid);
        }
        if (bidi) _peerOpenedBidi = index + 1; else _peerOpenedUni = index + 1;
        return _streams[id];
    }

    private QuicStream NewStream(long id, bool local)
    {
        bool bidi = StreamId.IsBidi(id);
        var s = new QuicStream(id, local, bidi || local ? new SendBuffer() : null, bidi || !local ? new RecvBuffer() : null);
        if (s.Recv is not null) s.RecvMax = _o.StreamReceiveWindow;
        if (s.Send is not null && _peer is not null)
            s.SendMax = (long)(bidi ? (local ? _peer.InitialMaxStreamDataBidiRemote : _peer.InitialMaxStreamDataBidiLocal) : _peer.InitialMaxStreamDataUni);
        return s;
    }

    private void OnStreamFrame(long id, long offset, ReadOnlySpan<byte> data, bool fin, ulong frameType)
    {
        var s = PeerStream(id, frameType, receiving: true);
        if (s?.Recv is null || s.PeerReset is not null) return;
        long before = s.Recv.Highest;
        s.Recv.Write(offset, data, fin, s.RecvMax, frameType);
        long grew = s.Recv.Highest - before;
        if (grew > 0)
        {
            _connRecvHighest += grew;
            if (_connRecvHighest > _connRecvMax) throw new QuicException(QuicError.FlowControlError, "connection flow control exceeded", frameType);
        }
        if (s.Recv.Readable > 0 || s.Recv.Complete) Raise(QuicEventKind.StreamReadable, id);
    }

    private void OnResetStream(long id, ulong error, long finalSize)
    {
        var s = PeerStream(id, QuicFrameType.ResetStream, receiving: true);
        if (s?.Recv is null || s.PeerReset is not null) return;
        long before = s.Recv.Highest;
        s.Recv.SetFinalSize(finalSize, QuicFrameType.ResetStream);
        if (finalSize > s.RecvMax) throw new QuicException(QuicError.FlowControlError, "reset beyond the stream's limit", QuicFrameType.ResetStream);
        _connRecvHighest += finalSize - before;
        if (_connRecvHighest > _connRecvMax) throw new QuicException(QuicError.FlowControlError, "connection flow control exceeded", QuicFrameType.ResetStream);
        // The unread bytes count as consumed: credit the connection now.
        _connRead += finalSize - s.Recv.ReadOffset;
        s.PeerReset = error;
        s.Recv.Release();
        UpdateConnectionCredit();
        Raise(QuicEventKind.StreamReadable, id);
    }

    private void OnStopSending(long id, ulong error)
    {
        var s = PeerStream(id, QuicFrameType.StopSending, receiving: false);
        if (s?.Send is null || s.StopRequested is not null) return;
        s.StopRequested = error;
        // Answer with a reset (RFC 9000 3.5).
        ResetStream(id, error);
        _events.Enqueue(new QuicEvent { Kind = QuicEventKind.StopSending, StreamId = id, Error = error });
    }

    /// <summary>Open a stream of ours; -1 if the peer's MAX_STREAMS doesn't allow another yet.</summary>
    public long OpenStream(bool bidi)
    {
        if (_peer is null || _state is not (State.Active or State.Handshake)) return -1;
        long next = bidi ? _nextBidi : _nextUni;
        if (StreamId.Index(next) >= (bidi ? _peerMaxStreamsBidi : _peerMaxStreamsUni)) return -1;
        var s = NewStream(next, local: true);
        _streams[next] = s;
        if (bidi) _nextBidi += 4; else _nextUni += 4;
        return next;
    }

    /// <summary>Queue data on a stream; how much was taken (less when its send buffer is full). -1: no such stream or it can't send.</summary>
    public int StreamWrite(long id, ReadOnlySpan<byte> data, bool fin)
    {
        if (!_streams.TryGetValue(id, out var s) || s.Send is null || s.ResetPending || s.ResetSent || s.Send.Finished) return -1;
        int n = Math.Min(data.Length, Math.Max(0, _o.StreamSendBuffer - s.Send.Buffered));
        s.Send.Write(data[..n]);
        if (fin && n == data.Length) s.Send.Finish();
        if (n > 0 || fin) Enqueue(s);
        return n;
    }

    /// <summary>
    /// Read from a stream. <paramref name="fin"/>: the end has been reached. <paramref name="reset"/>: the peer reset
    /// it (with that error). Returns the bytes read.
    /// </summary>
    public int StreamRead(long id, Span<byte> dest, out bool fin, out ulong? reset)
    {
        fin = false;
        reset = null;
        if (!_streams.TryGetValue(id, out var s) || s.Recv is null) return 0;
        if (s.PeerReset is { } err)
        {
            reset = err;
            s.RecvDone = true;
            MaybeFinish(s);
            return 0;
        }
        int n = s.Recv.Read(dest);
        if (n > 0)
        {
            _connRead += n;
            // More credit when half the window has been read (RFC 9000 4.2).
            if (!s.Recv.FinKnown && s.RecvMax - s.Recv.ReadOffset < _o.StreamReceiveWindow / 2)
            {
                s.RecvMax = s.Recv.ReadOffset + _o.StreamReceiveWindow;
                s.MaxDataPending = true;
                Enqueue(s);
            }
            UpdateConnectionCredit();
        }
        if (s.Recv.Complete)
        {
            fin = true;
            s.RecvDone = true;
            MaybeFinish(s);
        }
        return n;
    }

    private void UpdateConnectionCredit()
    {
        if (_connRecvMax - _connRead < _o.ConnectionReceiveWindow / 2)
        {
            _connRecvMax = _connRead + _o.ConnectionReceiveWindow;
            _maxDataPending = true;
        }
    }

    /// <summary>Abandon sending on a stream (RESET_STREAM).</summary>
    public void ResetStream(long id, ulong error)
    {
        if (!_streams.TryGetValue(id, out var s) || s.Send is null || s.ResetPending || s.ResetSent) return;
        if (s.Send.AllAcked && s.Send.Finished) return; // already delivered in full
        s.ResetPending = true;
        s.ResetError = error;
        Enqueue(s);
    }

    /// <summary>Ask the peer to stop sending on a stream (STOP_SENDING); what arrives meanwhile is discarded.</summary>
    public void StopSending(long id, ulong error)
    {
        if (!_streams.TryGetValue(id, out var s) || s.Recv is null || s.Recv.FinKnown || s.StopPending || s.StopSent) return;
        s.StopPending = true;
        s.StopError = error;
        Enqueue(s);
    }

    public bool StreamExists(long id) => _streams.ContainsKey(id);

    private void Enqueue(QuicStream s)
    {
        if (s.InSendQueue) return;
        s.InSendQueue = true;
        _sendQueue.AddLast(s);
    }

    private void MaybeFinish(QuicStream s)
    {
        if (!s.Finished || !_streams.Remove(s.Id)) return;
        s.Send?.Release();
        s.Recv?.Release();
        if (s.Local) return;
        // A peer stream is done: let the peer open another (RFC 9000 4.6).
        if (StreamId.IsBidi(s.Id))
        {
            _peerStreamsBidiClosed++;
            if (_maxStreamsBidi - _peerOpenedBidi < _o.MaxStreamsBidi / 2 + 1 || _peerStreamsBidiClosed % Math.Max(1, _o.MaxStreamsBidi / 4) == 0)
            {
                _maxStreamsBidi = _peerStreamsBidiClosed + _o.MaxStreamsBidi;
                _maxStreamsBidiPending = true;
            }
        }
        else
        {
            _peerStreamsUniClosed++;
            _maxStreamsUni = _peerStreamsUniClosed + _o.MaxStreamsUni;
            _maxStreamsUniPending = true;
        }
    }

    // ------------------------------------------------------------------ datagrams and events

    /// <summary>Queue a DATAGRAM (RFC 9221). False if the peer doesn't take them, it's too large, or the queue is full.</summary>
    public bool SendDatagram(ReadOnlySpan<byte> data)
    {
        if (_peer is null || _peer.MaxDatagramFrameSize == 0 || (ulong)data.Length + 9 > _peer.MaxDatagramFrameSize || _dgOut.Count >= _o.MaxQueuedDatagrams) return false;
        if (data.Length > _o.MaxDatagramSize - 64) return false;
        _dgOut.Enqueue(data.ToArray());
        return true;
    }

    public bool TryReceiveDatagram(out byte[] data) => _dgIn.TryDequeue(out data!);

    public bool TryGetEvent(out QuicEvent e) => _events.TryDequeue(out e);

    private void Raise(QuicEventKind kind, long stream = -1) => _events.Enqueue(new QuicEvent { Kind = kind, StreamId = stream });

    // ------------------------------------------------------------------ closing and timers

    /// <summary>Close with an application error code (CONNECTION_CLOSE 0x1d).</summary>
    public void Close(ulong appError, string reason, long now) => CloseWithError(QuicError.ApplicationError, 0, reason, app: true, now, appCode: appError);

    private void CloseWithError(QuicError code, ulong frameType, string reason, bool app, long now, bool silent = false, ulong appCode = 0)
    {
        if (_state is State.Closing or State.Draining or State.Closed) return;
        CloseCode = code;
        ApplicationCloseCode = appCode;
        _closeError = app ? appCode : (ulong)code;
        _closeFrameType = frameType;
        _closeApp = app;
        _closeReason = reason;
        if (silent)
        {
            Finish();
            return;
        }
        _state = State.Closing;
        _closeDue = true;
        _closeDeadline = now + 3 * Recovery.Pto;
    }

    private void Finish()
    {
        if (_state == State.Closed) return;
        _state = State.Closed;
        foreach (var s in _streams.Values) { s.Send?.Release(); s.Recv?.Release(); }
        _streams.Clear();
        _events.Enqueue(new QuicEvent { Kind = QuicEventKind.Closed });
    }

    /// <summary>When <see cref="OnTimeout"/> must next run; 0 when there's nothing pending (closed).</summary>
    public long Deadline
    {
        get
        {
            if (_state == State.Closed) return 0;
            if (_state is State.Closing or State.Draining) return _closeDeadline;
            long t = IdleDeadline;
            if (!_tls.HandshakeComplete) t = Math.Min(t, _created + _o.HandshakeTimeoutMs * 1000L);
            long loss = Recovery.Deadline(_handshakeConfirmed, AmplificationBlocked, IsServer || _handshakeConfirmed, out _, out _);
            if (loss != 0) t = Math.Min(t, loss);
            foreach (var p in _pns)
                if (p.AckElicitingUnacked > 0 && !p.Discarded) t = Math.Min(t, p.AckDeadline);
            return t;
        }
    }

    private long IdleDeadline => _lastActivity + Math.Max(_idleTimeout, 3 * Recovery.Pto);

    public void OnTimeout(long now)
    {
        if (_state == State.Closed) return;
        if (_state is State.Closing or State.Draining)
        {
            if (now >= _closeDeadline) Finish();
            return;
        }
        if (now >= IdleDeadline)
        {
            CloseCode ??= QuicError.NoError;
            _closeReason = "idle timeout";
            Finish(); // silently (RFC 9000 10.1)
            return;
        }
        if (!_tls.HandshakeComplete && now >= _created + _o.HandshakeTimeoutMs * 1000L)
        {
            CloseCode = QuicError.ConnectionRefused;
            _closeReason = "handshake timeout";
            Finish();
            return;
        }
        long loss = Recovery.Deadline(_handshakeConfirmed, AmplificationBlocked, IsServer || _handshakeConfirmed, out int space, out bool pto);
        if (loss != 0 && now >= loss)
        {
            if (!pto)
            {
                _lost.Clear();
                Recovery.DetectLost(space, now, _lost);
                foreach (var sp in _lost) OnPacketLost(space, sp);
                Recycle(_lost);
            }
            else
            {
                Recovery.PtoCount++;
                if (space < 0) space = 0;
                // Probes: two ack-eliciting packets, carrying the oldest unacknowledged data if there is any.
                var p = _pns[space];
                if (p.Discarded && space == 0 && !_pns[1].Discarded) { space = 1; p = _pns[1]; }
                p.Probes = 2;
                var s = Recovery.Spaces[space];
                if (s.Sent.Count > 0)
                    foreach (var f in s.Sent[0].Frames)
                    {
                        if (f.Kind == SentKind.Crypto) p.CryptoSend.OnLost(f.A, (int)f.B, false);
                        else if (f.Kind == SentKind.Stream && _streams.TryGetValue(f.Id, out var st) && st.Send is not null)
                        {
                            st.Send.OnLost(f.A, (int)f.B, f.Fin);
                            Enqueue(st);
                        }
                    }
            }
        }
    }

    private bool AmplificationBlocked => IsServer && !_addressValidated && _bytesSent + _o.MaxDatagramSize > 3 * _bytesReceived;

    // ------------------------------------------------------------------ sending

    private struct Building
    {
        public int Start, PnOffset, PnLen, LengthOffset, End;
        public long Pn;
        public int Space;
        public bool AckEliciting, HasInitial;
        public SentPacket Sent;
    }

    private readonly Building[] _building = new Building[3];

    /// <summary>
    /// The next datagram to send, written to <paramref name="buf"/> (at least the max datagram size); its length, 0
    /// for nothing to send now.
    /// </summary>
    public int Send(Span<byte> buf, long now)
    {
        if (_state is State.Closed or State.Draining) return 0;
        int limit = Math.Min(buf.Length, _o.MaxDatagramSize);
        if (IsServer && !_addressValidated)
        {
            long allowance = 3 * _bytesReceived - _bytesSent;
            if (allowance < limit) limit = (int)Math.Max(0, allowance);
            if (limit < 64) return 0;
        }
        if (_state == State.Closing)
        {
            if (!_closeDue) return 0;
            _closeDue = false;
            return SendClose(buf[..limit], now);
        }

        int count = 0, pos = 0;
        bool ccOpen = Recovery.CanSend(_o.MaxDatagramSize);
        for (int space = 0; space < 3; space++)
        {
            var p = _pns[space];
            if (p.Send is null || p.Discarded) continue;
            if (space == 2 && !_tls.HandshakeComplete && IsServer) continue; // no 1-RTT before the handshake completes (0.5-RTT data not sent)
            if (!Wants(space, now, ccOpen)) continue;
            if (limit - pos < 64) break;
            ref var b = ref _building[count];
            if (!Build(space, buf, pos, limit, now, ccOpen || p.Probes > 0, ref b)) continue;
            pos = b.End;
            count++;
            if (b.Sent.AckEliciting && p.Probes > 0) p.Probes--;
            if (space == 2) break; // a short-header packet runs to the end of the datagram
        }
        if (count == 0) return 0;

        // Datagrams with an ack-eliciting Initial (all of a client's Initials) go out at 1200 bytes at least (14.1).
        bool pad = false;
        for (int i = 0; i < count; i++)
            if (_building[i].Space == 0 && (!IsServer || _building[i].AckEliciting)) pad = true;
        if (pad && pos < 1200 && limit >= 1200)
        {
            ref var last = ref _building[count - 1];
            int extra = 1200 - pos;
            buf.Slice(last.End - PacketKeys.TagLength, extra).Clear();
            // Move the tag space out by `extra`: the padding goes at the end of the payload.
            last.End += extra;
            last.Sent.InFlight = true; // padding counts in flight (RFC 9002 2)
            pos += extra;
        }
        for (int i = 0; i < count; i++) Seal(buf, ref _building[i], now);
        _bytesSent += pos;
        return pos;
    }

    private bool Wants(int space, long now, bool ccOpen)
    {
        var p = _pns[space];
        if (p.AckElicitingUnacked > 0 && p.Received.IsEmpty) { p.AckElicitingUnacked = 0; p.AckDeadline = 0; } // nothing to acknowledge
        if (p.AckElicitingUnacked > 0 && (space < 2 || p.AckElicitingUnacked >= 2 || now >= p.AckDeadline)) return true;
        if (p.Probes > 0) return true;
        if (!ccOpen) return false;
        if (p.CryptoSend.HasData(long.MaxValue)) return true;
        if (space != 2) return false;
        return _handshakeDonePending || _maxDataPending || _maxStreamsBidiPending || _maxStreamsUniPending || _pathResponse is not null
            || _retireCidPending.Count > 0 || _ourCids.Exists(c => !c.Sent) || _dgOut.Count > 0 || HasStreamWork();
    }

    private bool HasStreamWork()
    {
        foreach (var s in _sendQueue)
        {
            if (s.ResetPending || s.StopPending || s.MaxDataPending) return true;
            if (s.Send is not null && !s.ResetSent && s.Send.HasData(Math.Min(s.SendMax, s.Send.Sent + (_peerMaxData - _connSent)))) return true;
        }
        return false;
    }

    private SentPacket NewSent() => _packetPool.Count > 0 ? _packetPool.Pop() : new SentPacket();

    /// <summary>Write one packet's header and frames (unprotected) into buf[pos..limit); false if nothing worth sending fit.</summary>
    private bool Build(int space, Span<byte> buf, int pos, int limit, long now, bool mayElicit, ref Building b)
    {
        var p = _pns[space];
        long pn = p.NextPn;
        int pnLen = Packets.PacketNumberLength(pn, Recovery.Spaces[space].LargestAcked);
        int w = pos;
        b = new Building { Start = pos, Space = space, Pn = pn, PnLen = pnLen, LengthOffset = -1 };
        if (space < 2)
        {
            buf[w++] = (byte)(0xC0 | (space == 0 ? 0x00 : 0x20) | (pnLen - 1));
            BinaryPrimitives.WriteUInt32BigEndian(buf[w..], Packets.Version1);
            w += 4;
            buf[w++] = (byte)_dcid.Length;
            _dcid.CopyTo(buf[w..]);
            w += _dcid.Length;
            buf[w++] = (byte)_scid.Length;
            _scid.CopyTo(buf[w..]);
            w += _scid.Length;
            if (space == 0)
            {
                var token = IsServer ? null : _token;
                w += VarInt.Write(buf[w..], (ulong)(token?.Length ?? 0));
                if (token is not null) { token.CopyTo(buf[w..]); w += token.Length; }
            }
            b.LengthOffset = w;
            w += 2; // the Length field, filled in when sealing (2-byte varint: up to 16383)
            b.HasInitial = space == 0;
        }
        else
        {
            buf[w++] = (byte)(0x40 | (_sendPhase << 2) | (pnLen - 1));
            _dcid.CopyTo(buf[w..]);
            w += _dcid.Length;
        }
        b.PnOffset = w;
        w += pnLen;
        int payloadStart = w;
        int end = limit - PacketKeys.TagLength;
        if (end - payloadStart < 24) return false;
        var sent = NewSent();
        sent.Pn = pn;
        var d = buf[..end];

        // ACK first: whenever there's something new to acknowledge in this space.
        if (p.AckNew && !p.Received.IsEmpty)
        {
            int n = WriteAck(d[w..], p, space, now);
            if (n > 0)
            {
                w += n;
                sent.Frames.Add(new SentFrame { Kind = SentKind.Ack, A = p.LargestReceived });
                p.AckNew = false;
                p.AckElicitingUnacked = 0;
                p.AckDeadline = 0;
            }
        }
        if (mayElicit)
        {
            if (space == 2) w = WriteControl(d, w, sent);
            // CRYPTO.
            while (end - w > 16 && p.CryptoSend.Next(end - w - 16, long.MaxValue, out long off, out var data, out _))
            {
                int n = QuicFrameWriter.Crypto(d[w..], (ulong)off, data);
                sent.Frames.Add(new SentFrame { Kind = SentKind.Crypto, A = off, B = data.Length });
                p.CryptoSend.OnSent(off, data.Length, false);
                w += n;
            }
            if (space == 2)
            {
                while (_dgOut.Count > 0 && end - w >= _dgOut.Peek().Length + 9)
                {
                    w += QuicFrameWriter.Datagram(d[w..], _dgOut.Dequeue());
                    sent.Frames.Add(new SentFrame { Kind = SentKind.Ping }); // ack-eliciting; a lost datagram stays lost
                }
                w = WriteStreams(d, w, end, sent);
            }
            if (p.Probes > 0 && !HasElicitingFrame(sent))
            {
                d[w++] = (byte)QuicFrameType.Ping;
                sent.Frames.Add(new SentFrame { Kind = SentKind.Ping });
            }
        }
        if (w == payloadStart)
        {
            sent.Reset();
            _packetPool.Push(sent);
            return false;
        }
        // The header-protection sample needs 4 bytes after the packet number's start (RFC 9001 5.4.2).
        while (w - b.PnOffset < 4) d[w++] = 0;
        sent.AckEliciting = HasElicitingFrame(sent);
        sent.InFlight = sent.AckEliciting; // padded ones too, below
        b.AckEliciting = sent.AckEliciting;
        b.End = w + PacketKeys.TagLength;
        b.Sent = sent;
        p.NextPn++;
        return true;
    }

    private static bool HasElicitingFrame(SentPacket sent)
    {
        foreach (var f in sent.Frames) if (f.Kind != SentKind.Ack) return true;
        return false;
    }

    private int WriteAck(Span<byte> d, Pns p, int space, long now)
    {
        int count = Math.Min(p.Received.Count, 32);
        Span<(long, long)> ranges = stackalloc (long, long)[count];
        for (int i = 0; i < count; i++)
        {
            var (s, e) = p.Received[p.Received.Count - 1 - i];
            ranges[i] = (s, e - 1);
        }
        ulong delay = space == 2 ? (ulong)Math.Max(0, now - p.LargestReceivedTime) >> _o.AckDelayExponent : 0;
        if (d.Length < QuicFrameWriter.AckMaxSize(count)) count = Math.Max(1, Math.Min(count, (d.Length - 40) / 16));
        if (d.Length < 40) return 0;
        return QuicFrameWriter.Ack(d, ranges[..count], delay);
    }

    private int WriteControl(Span<byte> d, int w, SentPacket sent)
    {
        int end = d.Length;
        if (_handshakeDonePending && IsServer && end - w > 1)
        {
            w += QuicFrameWriter.HandshakeDone(d[w..]);
            sent.Frames.Add(new SentFrame { Kind = SentKind.HandshakeDone });
            _handshakeDonePending = false;
        }
        if (_pathResponse is not null && end - w > 9)
        {
            w += QuicFrameWriter.PathChallenge(d[w..], _pathResponse, response: true);
            _pathResponse = null;
            sent.Frames.Add(new SentFrame { Kind = SentKind.Ping }); // ack-eliciting, not retransmitted
        }
        if (_maxDataPending && end - w > 9)
        {
            w += QuicFrameWriter.MaxData(d[w..], (ulong)_connRecvMax);
            sent.Frames.Add(new SentFrame { Kind = SentKind.MaxData });
            _maxDataPending = false;
        }
        if (_maxStreamsBidiPending && end - w > 9)
        {
            w += QuicFrameWriter.MaxStreams(d[w..], true, (ulong)_maxStreamsBidi);
            sent.Frames.Add(new SentFrame { Kind = SentKind.MaxStreamsBidi });
            _maxStreamsBidiPending = false;
        }
        if (_maxStreamsUniPending && end - w > 9)
        {
            w += QuicFrameWriter.MaxStreams(d[w..], false, (ulong)_maxStreamsUni);
            sent.Frames.Add(new SentFrame { Kind = SentKind.MaxStreamsUni });
            _maxStreamsUniPending = false;
        }
        for (int i = 0; i < _ourCids.Count && end - w > 48; i++)
        {
            var c = _ourCids[i];
            if (c.Sent) continue;
            w += QuicFrameWriter.NewConnectionId(d[w..], (ulong)c.Seq, 0, c.Cid, c.Token);
            sent.Frames.Add(new SentFrame { Kind = SentKind.NewConnectionId, A = c.Seq });
            _ourCids[i] = c with { Sent = true };
        }
        while (_retireCidPending.Count > 0 && end - w > 9)
        {
            long seq = _retireCidPending.Dequeue();
            w += QuicFrameWriter.RetireConnectionId(d[w..], (ulong)seq);
            sent.Frames.Add(new SentFrame { Kind = SentKind.RetireConnectionId, A = seq });
        }
        return w;
    }

    private int WriteStreams(Span<byte> d, int w, int end, SentPacket sent)
    {
        // Round robin: each stream in the queue gets a turn; ones with nothing left drop out.
        int turns = _sendQueue.Count;
        while (turns-- > 0 && end - w > 24 && _sendQueue.First is { } node)
        {
            var s = node.Value;
            _sendQueue.RemoveFirst();
            s.InSendQueue = false;
            if (s.StopPending && s.Recv is not null && end - w > 17)
            {
                w += QuicFrameWriter.StopSending(d[w..], (ulong)s.Id, s.StopError);
                sent.Frames.Add(new SentFrame { Kind = SentKind.StopSending, Id = s.Id });
                s.StopPending = false;
                s.StopSent = true;
            }
            if (s.MaxDataPending && s.Recv is not null && end - w > 17)
            {
                w += QuicFrameWriter.MaxStreamData(d[w..], (ulong)s.Id, (ulong)s.RecvMax);
                sent.Frames.Add(new SentFrame { Kind = SentKind.MaxStreamData, Id = s.Id });
                s.MaxDataPending = false;
            }
            if (s.ResetPending && s.Send is not null && end - w > 25)
            {
                w += QuicFrameWriter.ResetStream(d[w..], (ulong)s.Id, s.ResetError, (ulong)s.Send.Sent);
                sent.Frames.Add(new SentFrame { Kind = SentKind.ResetStream, Id = s.Id });
                s.ResetPending = false;
                s.ResetSent = true;
                s.Send.Release();
                MaybeFinish(s);
                continue;
            }
            if (s.Send is not null && !s.ResetSent)
            {
                long connCredit = _peerMaxData - _connSent;
                long limit = Math.Min(s.SendMax, s.Send.Sent + Math.Max(0, connCredit));
                while (end - w > 24)
                {
                    int room = end - w - QuicFrameWriter.StreamOverhead((ulong)s.Id, (ulong)s.Send.End, 16383);
                    if (room <= 0 || !s.Send.Next(room, limit, out long off, out var data, out bool fin)) break;
                    long newBytes = Math.Max(0, off + data.Length - s.Send.Sent);
                    w += QuicFrameWriter.Stream(d[w..], (ulong)s.Id, (ulong)off, data, fin);
                    sent.Frames.Add(new SentFrame { Kind = SentKind.Stream, Id = s.Id, A = off, B = data.Length, Fin = fin });
                    s.Send.OnSent(off, data.Length, fin);
                    _connSent += newBytes;
                    limit = Math.Min(s.SendMax, s.Send.Sent + Math.Max(0, _peerMaxData - _connSent));
                }
                // Blocked by flow control with data waiting: say so, once per limit (RFC 9000 4.1).
                if (s.Send.Sent < s.Send.End && s.Send.Sent >= s.SendMax && s.BlockedSentAt != s.SendMax && end - w > 17)
                {
                    w += QuicFrameWriter.StreamDataBlocked(d[w..], (ulong)s.Id, (ulong)s.SendMax);
                    sent.Frames.Add(new SentFrame { Kind = SentKind.StreamDataBlocked, Id = s.Id });
                    s.BlockedSentAt = s.SendMax;
                }
                if (_connSent >= _peerMaxData && s.Send.Sent < s.Send.End && _dataBlockedAt != _peerMaxData && end - w > 9)
                {
                    w += QuicFrameWriter.DataBlocked(d[w..], (ulong)_peerMaxData);
                    sent.Frames.Add(new SentFrame { Kind = SentKind.DataBlocked });
                    _dataBlockedAt = _peerMaxData;
                }
                if (s.Send.HasData(Math.Min(s.SendMax, s.Send.Sent + Math.Max(0, _peerMaxData - _connSent)))) Enqueue(s);
            }
        }
        return w;
    }

    private void Seal(Span<byte> buf, ref Building b, long now)
    {
        var p = _pns[b.Space];
        var packet = buf[b.Start..b.End];
        if (b.LengthOffset >= 0)
            VarInt.WriteFixed(buf[b.LengthOffset..], (ulong)(b.End - b.PnOffset), 2);
        // The packet number, in clear, before protection.
        for (int i = 0; i < b.PnLen; i++) buf[b.PnOffset + b.PnLen - 1 - i] = (byte)(b.Pn >> (8 * i));
        p.Send!.Seal(packet, b.PnOffset - b.Start, b.PnLen, b.Pn);
        var sent = b.Sent;
        sent.TimeSent = now;
        sent.Size = b.End - b.Start;
        Recovery.OnPacketSent(b.Space, sent);
        if (sent.AckEliciting)
        {
            // An ack-eliciting packet sent after receiving restarts the idle timer (RFC 9000 10.1).
            if (!_ackElicitingSinceReceive) _lastActivity = now;
            _ackElicitingSinceReceive = true;
        }
        // A client drops Initial keys once it sends a Handshake packet (RFC 9001 4.9.1).
        if (!IsServer && b.Space == 1 && !_pns[0].Discarded) DiscardSpace(0);
        if (b.Space == 2 && p.Send.Sealed >= _o.KeyUpdateAfter && CanInitiateKeyUpdate) RotateSendKeys();
        else if (p.Send.Sealed >= PacketKeys.ConfidentialityLimit - 1000) CloseWithError(QuicError.AeadLimitReached, 0, "AEAD limit reached without a key update", app: false, now);
    }

    private int SendClose(Span<byte> buf, long now)
    {
        // CONNECTION_CLOSE in the highest space we can (and, during the handshake, Initial too, so the peer can read it).
        int pos = 0, count = 0;
        for (int space = 2; space >= 0; space--)
        {
            var p = _pns[space];
            if (p.Send is null || p.Discarded) continue;
            if (space == 2 && !_tls.HandshakeComplete) continue;
            ref var b = ref _building[count];
            long pn = p.NextPn;
            int pnLen = 4;
            int w = pos;
            b = new Building { Start = pos, Space = space, Pn = pn, PnLen = pnLen, LengthOffset = -1 };
            if (space < 2)
            {
                buf[w++] = (byte)(0xC0 | (space == 0 ? 0x00 : 0x20) | (pnLen - 1));
                BinaryPrimitives.WriteUInt32BigEndian(buf[w..], Packets.Version1);
                w += 4;
                buf[w++] = (byte)_dcid.Length; _dcid.CopyTo(buf[w..]); w += _dcid.Length;
                buf[w++] = (byte)_scid.Length; _scid.CopyTo(buf[w..]); w += _scid.Length;
                if (space == 0) buf[w++] = 0;
                b.LengthOffset = w;
                w += 2;
            }
            else
            {
                buf[w++] = (byte)(0x40 | (_sendPhase << 2) | (pnLen - 1));
                _dcid.CopyTo(buf[w..]); w += _dcid.Length;
            }
            b.PnOffset = w;
            w += pnLen;
            // Application errors aren't revealed in Initial/Handshake packets: those carry a plain APPLICATION_ERROR (10.2.3).
            var reason = System.Text.Encoding.UTF8.GetBytes(_closeReason.Length > 64 ? _closeReason[..64] : _closeReason);
            if (_closeApp && space < 2) w += QuicFrameWriter.ConnectionClose(buf[w..], (ulong)QuicError.ApplicationError, 0, default);
            else w += QuicFrameWriter.ConnectionClose(buf[w..], _closeError, _closeFrameType, reason, app: _closeApp);
            b.End = w + PacketKeys.TagLength;
            b.Sent = NewSent();
            b.Sent.Pn = pn;
            p.NextPn++;
            pos = b.End;
            count++;
            if (space == 2 || buf.Length - pos < 128) break;
        }
        if (count == 0) return 0;
        for (int i = 0; i < count; i++)
        {
            ref var b = ref _building[i];
            var packet = buf[b.Start..b.End];
            if (b.LengthOffset >= 0) VarInt.WriteFixed(buf[b.LengthOffset..], (ulong)(b.End - b.PnOffset), 2);
            for (int k = 0; k < b.PnLen; k++) buf[b.PnOffset + b.PnLen - 1 - k] = (byte)(b.Pn >> (8 * k));
            _pns[b.Space].Send!.Seal(packet, b.PnOffset - b.Start, b.PnLen, b.Pn);
            b.Sent.Reset();
            _packetPool.Push(b.Sent);
        }
        _bytesSent += pos;
        _ = now;
        return pos;
    }

    /// <summary>
    /// For the fuzzer: process <paramref name="payload"/> as the frames of an authenticated 1-RTT packet. Protocol
    /// errors close the connection, exactly as for a real packet.
    /// </summary>
    internal void InjectFrames(ReadOnlySpan<byte> payload, long now)
    {
        if (_state is not State.Active) return;
        try
        {
            // As ReceivePacket does for a real packet: a fresh packet number, recorded and acknowledged.
            var p = _pns[2];
            long pn = p.LargestReceived + 1;
            bool ackEliciting = ProcessFrames(payload, PacketType.OneRtt, 2, now);
            p.Received.Add(pn, pn + 1);
            p.Received.KeepHighest(32);
            p.AckNew = true;
            p.LargestReceived = pn;
            p.LargestReceivedTime = now;
            if (ackEliciting)
            {
                p.AckElicitingUnacked++;
                if (p.AckDeadline == 0) p.AckDeadline = now + _o.MaxAckDelayMs * 1000L;
            }
            AfterTls(now);
        }
        catch (QuicException e) { CloseWithError(e.Code, e.FrameType, e.Message, app: false, now); }
    }

    public void Dispose()
    {
        foreach (var p in _pns)
        {
            p.Send?.Dispose();
            p.Recv?.Dispose();
            p.CryptoSend.Release();
            p.CryptoRecv.Release();
        }
        foreach (var s in _streams.Values) { s.Send?.Release(); s.Recv?.Release(); }
        _nextRecv?.Dispose();
        _prevRecv?.Dispose();
        if (_appSendSecret is not null) CryptographicOperations.ZeroMemory(_appSendSecret);
        if (_appRecvSecret is not null) CryptographicOperations.ZeroMemory(_appRecvSecret);
        _tls.Dispose();
    }
}
