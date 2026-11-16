using Httpgrl.HttpFields;
using Httpgrl.Quic;

namespace Httpgrl.Http3;

/// <summary>Limits and settings of a server's HTTP/3 connections.</summary>
public sealed class Http3ServerOptions
{
    /// <summary>The largest request field section we accept (SETTINGS_MAX_FIELD_SECTION_SIZE, and QPACK's limit).</summary>
    public int MaxFieldSectionSize = 32 << 10;
    /// <summary>Advertise extended CONNECT (RFC 9220), for WebSockets over HTTP/3.</summary>
    public bool EnableConnectProtocol = true;
    /// <summary>
    /// The whole request head (HEADERS) must arrive within this many microseconds of its stream opening. Never pushed
    /// out by partial bytes: the slow-loris defence. The QUIC idle timer is refreshed by any traffic, so it can't do this.
    /// </summary>
    public long RequestHeadTimeoutUs = 60_000_000;
}

/// <summary>
/// The application's side of one request stream. Called on the endpoint's thread, from inside
/// <see cref="Http3ServerConnection"/>.
/// </summary>
public interface IHttp3Request
{
    /// <summary>Room for more body: the connection keeps reading the QUIC stream while this holds (back-pressure).</summary>
    bool HasRoom { get; }

    /// <summary>DATA payload (or the end). False if it overruns what the request declared (content-length).</summary>
    bool Deliver(ReadOnlySpan<byte> data, bool end);

    /// <summary>The stream is gone (reset by the peer, a stream error, the connection closing): stop. It's already reset.</summary>
    void Abort(string reason, H3Error code);
}

/// <summary>What an <see cref="Http3ServerConnection"/> asks of its application. Every call is on the endpoint's thread.</summary>
public interface IHttp3ServerHandler
{
    /// <summary>The handshake is done and our control stream is open.</summary>
    void OnConnected(Http3ServerConnection connection) { }

    /// <summary>
    /// A request's HEADERS arrived (<paramref name="endStream"/>: and the stream ended right behind them, so there's no
    /// body). Decode them with <see cref="Http3ServerConnection.DecodeFields"/>. Throw an <see cref="H3Exception"/>:
    /// a stream error refuses the request, a connection error closes the connection.
    /// </summary>
    IHttp3Request OnRequest(Http3ServerConnection connection, long streamId, ReadOnlySpan<byte> fieldSection, bool endStream);

    /// <summary>Why a trailer field is unacceptable, or null if it's fine. Trailers are checked, then dropped.</summary>
    string? CheckTrailer(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value);

    /// <summary>The connection is being closed for a protocol error (for logging).</summary>
    void OnConnectionError(H3Error code, string reason) { }

    /// <summary>A request stream was reset for a protocol error (for logging).</summary>
    void OnStreamError(long streamId, H3Error code, string reason) { }
}

/// <summary>
/// HTTP/3 (RFC 9114) on one server QUIC connection: the control streams and SETTINGS, QPACK's streams, request
/// streams and their framing, GOAWAY, and the request-head deadline. What a request means is the application's
/// (<see cref="IHttp3ServerHandler"/>). Runs on the endpoint's thread, except the methods marked "any thread", which
/// post their work there.
/// </summary>
public sealed class Http3ServerConnection
{
    public readonly QuicConnection Quic;
    private readonly QuicEndpoint _ep;
    private readonly IHttp3ServerHandler _app;
    private readonly Http3ServerOptions _o;

    private sealed class Request(long id, long headerDeadline)
    {
        public readonly long Id = id;
        public readonly long HeaderDeadline = headerDeadline;
        public readonly H3FrameReader Reader = new(256 << 10);
        public IHttp3Request? Stream;
        public bool HeadersSeen, TrailersSeen, Fin, Done, Aborted;
        /// <summary>The request's field section, until we know whether the stream ends right behind it.</summary>
        public byte[]? HeadBlock;
        /// <summary>Waiting to be written: the application's current write, and its completion.</summary>
        public ReadOnlyMemory<byte> Pending;
        public bool PendingFin;
        public TaskCompletionSource? PendingDone;
    }

    private sealed class Uni
    {
        public long Type = -1;
        public readonly byte[] TypeBytes = new byte[8];
        public int TypeLen;
        public H3FrameReader? Reader;
        /// <summary>A QPACK instruction cut off at the end of a read, waiting for the rest.</summary>
        public byte[] Carry = [];
    }

    private readonly Dictionary<long, Request> _requests = new();
    private readonly Dictionary<long, Uni> _uni = new();
    private long _control = -1;
    private long _peerControl = -1, _peerEncoder = -1, _peerDecoder = -1;
    private bool _settingsSeen;
    private long _nextRequest;            // one past the highest request stream accepted (stream IDs: 0, 4, 8, ...)
    private long _goAway = -1;            // the stream ID our GOAWAY named (-1: none yet)
    private bool _closing;
    private readonly byte[] _buf = new byte[16 << 10];
    private readonly QpackDecoder _qpack;

    public Http3ServerConnection(QuicConnection quic, QuicEndpoint endpoint, IHttp3ServerHandler handler, Http3ServerOptions? options = null)
    {
        Quic = quic;
        _ep = endpoint;
        _app = handler;
        _o = options ?? new Http3ServerOptions();
        _qpack = new QpackDecoder(_o.MaxFieldSectionSize);
    }

    /// <summary>Request streams not yet finished (including ones whose handler still runs).</summary>
    public int Requests => _requests.Count;

    /// <summary>Whether a GOAWAY has gone out.</summary>
    public bool GoingAway => _goAway >= 0;

    /// <summary>Decodes a field section of this connection (QPACK, static table only). Throws <see cref="QpackException"/>.</summary>
    public void DecodeFields(ReadOnlySpan<byte> section, FieldHandler onField) => _qpack.Decode(section, onField);

    public void OnEvent(in QuicEvent e, long now)
    {
        try
        {
            switch (e.Kind)
            {
                case QuicEventKind.Connected: OnConnected(); break;
                case QuicEventKind.StreamOpened:
                case QuicEventKind.StreamReadable: Read(e.StreamId, now); break;
                case QuicEventKind.StreamWritable: ContinueWrite(e.StreamId); break;
                case QuicEventKind.StopSending:
                    // The client doesn't want the response (any more): stop the handler; QUIC already reset the stream.
                    if (_requests.TryGetValue(e.StreamId, out var r) && r.Stream is { } s) AbortStream(r, s, "stopped by the client", H3Error.RequestCancelled);
                    break;
            }
        }
        catch (H3Exception x) when (x.IsConnectionError) { Fail(x.Code, x.Message, now); }
    }

    private void Fail(H3Error code, string why, long now)
    {
        _app.OnConnectionError(code, why);
        Quic.Close((ulong)code, why, now);
    }

    private static void AbortStream(Request r, IHttp3Request s, string why, H3Error code)
    {
        r.Aborted = true;
        s.Abort(why, code);
    }

    private void OnConnected()
    {
        // Our control stream, with SETTINGS first (RFC 9114 6.2.1). No QPACK streams: our dynamic table is zero and we
        // never use the peer's (RFC 9204 4.2 lets us skip them).
        _control = Quic.OpenStream(bidi: false);
        if (_control < 0) throw new H3Exception(H3Error.StreamCreationError, "the client allows no unidirectional streams");
        var settings = _o.EnableConnectProtocol
            ? H3FrameWriter.Settings((H3Settings.MaxFieldSectionSize, (ulong)_o.MaxFieldSectionSize), (H3Settings.EnableConnectProtocol, 1))
            : H3FrameWriter.Settings((H3Settings.MaxFieldSectionSize, (ulong)_o.MaxFieldSectionSize));
        Quic.StreamWrite(_control, [(byte)H3StreamType.Control, .. settings], fin: false);
        _app.OnConnected(this);
    }

    // ------------------------------------------------------------------ reading

    private void Read(long id, long now)
    {
        if (StreamId.IsBidi(id))
        {
            if (!StreamId.IsClientInitiated(id)) return; // we open none
            ReadRequest(id, now);
        }
        else if (StreamId.IsClientInitiated(id)) ReadUni(id);
    }

    private void ReadUni(long id)
    {
        if (!_uni.TryGetValue(id, out var u)) _uni[id] = u = new Uni();
        while (true)
        {
            int n = Quic.StreamRead(id, _buf, out bool fin, out ulong? reset);
            if (reset is not null || (fin && n == 0))
            {
                if (u.Type is (long)H3StreamType.Control or (long)H3StreamType.QpackEncoder or (long)H3StreamType.QpackDecoder)
                    throw new H3Exception(H3Error.ClosedCriticalStream, "a critical stream ended");
                _uni.Remove(id);
                return;
            }
            if (n == 0) return;
            var data = _buf.AsSpan(0, n);
            if (u.Type < 0)
            {
                // The stream type (a varint, possibly split).
                int take = 0;
                while (take < data.Length && u.Type < 0)
                {
                    u.TypeBytes[u.TypeLen++] = data[take++];
                    int need = 1 << (u.TypeBytes[0] >> 6);
                    if (u.TypeLen == need)
                    {
                        VarInt.TryRead(u.TypeBytes.AsSpan(0, need), out ulong t, out _);
                        u.Type = (long)Math.Min(t, long.MaxValue);
                        ClassifyUni(id, u);
                    }
                }
                data = data[take..];
                if (u.Type < 0 || !_uni.ContainsKey(id)) continue;
            }
            switch ((ulong)u.Type)
            {
                case H3StreamType.Control:
                    u.Reader!.Feed(data, OnControlFrame, static _ => throw new H3Exception(H3Error.FrameUnexpected, "DATA on the control stream"));
                    break;
                case H3StreamType.QpackEncoder:
                case H3StreamType.QpackDecoder:
                {
                    var all = u.Carry.Length == 0 ? data : (ReadOnlySpan<byte>)[.. u.Carry, .. data];
                    int used = (ulong)u.Type == H3StreamType.QpackEncoder ? OnEncoderInstructions(all) : OnDecoderInstructions(all);
                    u.Carry = all[used..].ToArray();
                    if (u.Carry.Length > 16) throw new H3Exception((ulong)u.Type == H3StreamType.QpackEncoder ? H3Error.QpackEncoderStreamError : H3Error.QpackDecoderStreamError, "instruction too long");
                    break;
                }
                default: break; // ignored types: their bytes are discarded
            }
            if (fin) throw new H3Exception(H3Error.ClosedCriticalStream, "a critical stream ended");
        }
    }

    private void ClassifyUni(long id, Uni u)
    {
        switch ((ulong)u.Type)
        {
            case H3StreamType.Control:
                if (_peerControl >= 0) throw new H3Exception(H3Error.StreamCreationError, "a second control stream");
                _peerControl = id;
                u.Reader = new H3FrameReader(4096);
                break;
            case H3StreamType.QpackEncoder:
                if (_peerEncoder >= 0) throw new H3Exception(H3Error.StreamCreationError, "a second QPACK encoder stream");
                _peerEncoder = id;
                break;
            case H3StreamType.QpackDecoder:
                if (_peerDecoder >= 0) throw new H3Exception(H3Error.StreamCreationError, "a second QPACK decoder stream");
                _peerDecoder = id;
                break;
            case H3StreamType.Push:
                throw new H3Exception(H3Error.StreamCreationError, "a push stream from a client"); // only servers push (6.2.2)
            default:
                // Unknown and reserved types: refuse the stream, keep the connection (6.2).
                Quic.StopSending(id, (ulong)H3Error.StreamCreationError);
                _uni.Remove(id);
                break;
        }
    }

    private void OnControlFrame(ulong type, ReadOnlySpan<byte> payload)
    {
        if (!_settingsSeen)
        {
            if (type != H3FrameType.Settings) throw new H3Exception(H3Error.MissingSettings, "the control stream didn't start with SETTINGS");
            _settingsSeen = true;
            H3FrameWriter.ParseSettings(payload); // nothing in a client's settings changes what we send; it must parse
            return;
        }
        switch (type)
        {
            case H3FrameType.Settings: throw new H3Exception(H3Error.FrameUnexpected, "a second SETTINGS");
            case H3FrameType.Headers:
            case H3FrameType.PushPromise: throw new H3Exception(H3Error.FrameUnexpected, "a request frame on the control stream");
            case H3FrameType.GoAway: break; // a client's GOAWAY concerns pushes, which we never make
            case H3FrameType.MaxPushId: break;
            case H3FrameType.CancelPush: throw new H3Exception(H3Error.IdError, "CANCEL_PUSH for a push never promised");
        }
    }

    /// <summary>
    /// The length of a complete prefix integer at the start of <paramref name="s"/>, or 0 if it's cut off; the value in
    /// <paramref name="value"/>.
    /// </summary>
    private static int PrefixInt(ReadOnlySpan<byte> s, int prefix, out long value)
    {
        int max = (1 << prefix) - 1;
        value = s[0] & max;
        if (value < max) return 1;
        int shift = 0;
        for (int i = 1; i < s.Length; i++)
        {
            if (shift > 56) throw new H3Exception(H3Error.QpackDecoderStreamError, "integer too large");
            value += (long)(s[i] & 0x7F) << shift;
            shift += 7;
            if ((s[i] & 0x80) == 0) return i + 1;
        }
        return 0;
    }

    // Our dynamic table capacity is zero: the peer's encoder may only set the capacity to 0, never insert (RFC 9204 4.3).
    // Returns the bytes consumed (an instruction cut off at the end waits for the rest).
    private static int OnEncoderInstructions(ReadOnlySpan<byte> data)
    {
        int pos = 0;
        while (pos < data.Length)
        {
            if ((data[pos] & 0xE0) != 0x20) throw new H3Exception(H3Error.QpackEncoderStreamError, "an insert with a dynamic table capacity of zero");
            int n = PrefixInt(data[pos..], 5, out long cap);
            if (n == 0) break;
            if (cap != 0) throw new H3Exception(H3Error.QpackEncoderStreamError, "dynamic table capacity above the advertised 0");
            pos += n;
        }
        return pos;
    }

    // We never reference the dynamic table, so the peer's decoder has nothing to acknowledge (RFC 9204 4.4).
    private static int OnDecoderInstructions(ReadOnlySpan<byte> data)
    {
        int pos = 0;
        while (pos < data.Length)
        {
            byte b = data[pos];
            if ((b & 0x80) != 0) throw new H3Exception(H3Error.QpackDecoderStreamError, "Section Acknowledgment for a section without dynamic references");
            if ((b & 0xC0) == 0) throw new H3Exception(H3Error.QpackDecoderStreamError, "Insert Count Increment with nothing inserted");
            int n = PrefixInt(data[pos..], 6, out _); // Stream Cancellation: fine
            if (n == 0) break;
            pos += n;
        }
        return pos;
    }

    private void ReadRequest(long id, long now)
    {
        if (!_requests.TryGetValue(id, out var r))
        {
            if (_closing || (_goAway >= 0 && id >= _goAway))
            {
                // After our GOAWAY: not processed, so the client may safely retry it elsewhere (RFC 9114 5.2).
                Quic.StopSending(id, (ulong)H3Error.RequestRejected);
                Quic.ResetStream(id, (ulong)H3Error.RequestRejected);
                return;
            }
            _requests[id] = r = new Request(id, now + _o.RequestHeadTimeoutUs);
            if (id + 4 > _nextRequest) _nextRequest = id + 4;
        }
        if (r.Done) { Drain(id); return; }
        while (r.Stream is null || r.Stream.HasRoom || r.TrailersSeen)
        {
            int n = Quic.StreamRead(id, _buf, out bool fin, out ulong? reset);
            if (reset is not null)
            {
                r.Done = true;
                if (r.Stream is { } s) AbortStream(r, s, "reset by the client", H3Error.RequestCancelled);
                else _requests.Remove(id);
                return;
            }
            try
            {
                if (n > 0) r.Reader.Feed(_buf.AsSpan(0, n), (t, p) => OnRequestFrame(r, t, p), d => OnRequestData(r, d));
                // HEADERS has no END_STREAM flag in HTTP/3: a FIN right behind it (in what's arrived) means no body.
                if (r.HeadBlock is not null && (fin || Quic.StreamAvailable(id) == 0)) StartRequest(r, endStream: fin && r.Reader.AtBoundary);
                if (fin) OnRequestEnd(r);
            }
            catch (H3Exception x) when (!x.IsConnectionError) { StreamError(r, x.Code, x.Message); return; }
            if (n == 0 || fin) return;
        }
    }

    /// <summary>A request stream we've given up on (or that's done): discard what still arrives.</summary>
    private void Drain(long id)
    {
        while (Quic.StreamRead(id, _buf, out bool fin, out _) > 0) if (fin) break;
    }

    private void OnRequestFrame(Request r, ulong type, ReadOnlySpan<byte> payload)
    {
        switch (type)
        {
            case H3FrameType.Headers:
                if (r.TrailersSeen) throw new H3Exception(H3Error.FrameUnexpected, "a frame after the trailers");
                if (!r.HeadersSeen) { r.HeadersSeen = true; r.HeadBlock = payload.ToArray(); }
                else
                {
                    // Trailers: checked like any field, then dropped (as on HTTP/1.1 and HTTP/2).
                    r.TrailersSeen = true;
                    string? bad = null;
                    try { _qpack.Decode(payload, (n, v) => bad ??= _app.CheckTrailer(n, v)); }
                    catch (QpackException e) when (e.Limit) { bad = e.Message; }
                    catch (QpackException e) { throw new H3Exception(H3Error.QpackDecompressionFailed, e.Message); }
                    if (bad is not null) throw new H3Exception(H3Error.MessageError, bad, connection: false);
                }
                break;
            case H3FrameType.PushPromise:
            case H3FrameType.Settings:
            case H3FrameType.GoAway:
            case H3FrameType.MaxPushId:
            case H3FrameType.CancelPush:
                throw new H3Exception(H3Error.FrameUnexpected, "a control frame on a request stream");
        }
    }

    private void OnRequestData(Request r, ReadOnlySpan<byte> data)
    {
        if (!r.HeadersSeen) throw new H3Exception(H3Error.FrameUnexpected, "DATA before HEADERS");
        if (r.TrailersSeen) throw new H3Exception(H3Error.FrameUnexpected, "DATA after the trailers");
        if (r.HeadBlock is not null) StartRequest(r, endStream: false); // a body follows
        if (r.Stream is { } s && !s.Deliver(data, end: false))
            throw new H3Exception(H3Error.MessageError, "more DATA than content-length", connection: false);
    }

    private void OnRequestEnd(Request r)
    {
        r.Fin = true;
        if (!r.Reader.AtBoundary) throw new H3Exception(H3Error.FrameError, "the stream ended inside a frame");
        if (!r.HeadersSeen) throw new H3Exception(H3Error.RequestIncomplete, "the stream ended without a request", connection: false);
        if (r.Stream is { } s && !s.Deliver(default, end: true))
            throw new H3Exception(H3Error.MessageError, "DATA doesn't match content-length", connection: false);
    }

    private void StreamError(Request r, H3Error code, string why)
    {
        _app.OnStreamError(r.Id, code, why);
        r.Done = true;
        Quic.StopSending(r.Id, (ulong)code);
        Quic.ResetStream(r.Id, (ulong)code);
        if (r.Stream is { } s) AbortStream(r, s, why, code);
        else _requests.Remove(r.Id);
    }

    private void StartRequest(Request r, bool endStream)
    {
        var block = r.HeadBlock!;
        r.HeadBlock = null;
        r.Stream = _app.OnRequest(this, r.Id, block, endStream);
    }

    // ------------------------------------------------------------------ the application's side (any thread)

    /// <summary>
    /// Any thread: put bytes on a request stream (with the FIN, when asked). Completes once QUIC has taken them all
    /// (back-pressure); fails with <see cref="IOException"/> if the stream is gone.
    /// </summary>
    public Task WriteAsync(long streamId, ReadOnlyMemory<byte> data, bool fin)
    {
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _ep.Run(Quic, _ =>
        {
            if (!_requests.TryGetValue(streamId, out var r) || r.Aborted) { done.TrySetException(new IOException("stream reset")); return; }
            r.Pending = data;
            r.PendingFin = fin;
            r.PendingDone = done;
            ContinueWrite(streamId);
        });
        return done.Task;
    }

    /// <summary>Any thread: the application consumed body below its window: read more from the QUIC stream.</summary>
    public void ResumeReading(long streamId) => _ep.Run(Quic, _ => ReadRequest(streamId, QuicEndpoint.Now()));

    /// <summary>Any thread: reset a request stream both ways (the application gave up on it).</summary>
    public void ResetLater(long streamId, H3Error code) => _ep.Run(Quic, q =>
    {
        if (_requests.TryGetValue(streamId, out var r)) { r.Done = true; r.Aborted = true; }
        q.StopSending(streamId, (ulong)code);
        q.ResetStream(streamId, (ulong)code);
        FailWrite(streamId);
    });

    /// <summary>Any thread: fail a write that's waiting (the stream is gone).</summary>
    public void FailWrites(long streamId) => _ep.Run(Quic, _ => FailWrite(streamId));

    private void FailWrite(long streamId)
    {
        if (_requests.TryGetValue(streamId, out var r) && r.PendingDone is { } d)
        {
            r.PendingDone = null;
            r.Pending = default;
            d.TrySetException(new IOException("stream reset"));
        }
    }

    /// <summary>
    /// Any thread: the application is done with a request. The stream is forgotten (the rest of an unread upload is
    /// refused with STOP_SENDING), and the connection closes if it's winding down and this was the last.
    /// </summary>
    public void Finished(long streamId) => _ep.Run(Quic, _ =>
    {
        if (!_requests.Remove(streamId, out var r)) { MaybeClose(QuicEndpoint.Now()); return; }
        r.Done = true;
        if (!r.Fin) Quic.StopSending(r.Id, (ulong)H3Error.NoError);
        MaybeClose(QuicEndpoint.Now());
    });

    // ------------------------------------------------------------------ writing (endpoint thread)

    private void ContinueWrite(long id)
    {
        if (!_requests.TryGetValue(id, out var r) || r.PendingDone is null) return;
        int n = Quic.StreamWrite(id, r.Pending.Span, r.PendingFin);
        if (n < 0)
        {
            var d = r.PendingDone;
            r.PendingDone = null;
            d.TrySetException(new IOException("stream closed"));
            return;
        }
        r.Pending = r.Pending[n..];
        if (r.Pending.IsEmpty)
        {
            // All taken (with the FIN, when asked: StreamWrite finishes the stream once the last byte is in).
            var d = r.PendingDone;
            r.PendingDone = null;
            d.TrySetResult();
        }
    }

    // ------------------------------------------------------------------ winding down

    /// <summary>
    /// GOAWAY: stop taking requests. It names the first stream we won't process; later ones are refused with
    /// H3_REQUEST_REJECTED, which clients retry (RFC 9114 5.2). The connection closes once the running ones finish.
    /// </summary>
    public void GoAway()
    {
        if (_goAway >= 0 || _control < 0) return;
        _goAway = _nextRequest;
        Quic.StreamWrite(_control, H3FrameWriter.GoAway(_goAway), fin: false);
        MaybeClose(QuicEndpoint.Now()); // nothing running: done now, not at the next tick
    }

    private void MaybeClose(long now)
    {
        if (_goAway >= 0 && _requests.Count == 0 && !_closing)
        {
            _closing = true;
            Quic.Close((ulong)H3Error.NoError, "", now);
        }
    }

    /// <summary>Endpoint thread, once per loop turn: the request-head deadline, and closing after GOAWAY.</summary>
    public void Tick(long now)
    {
        // The QUIC idle timer is refreshed by traffic, so it cannot protect unfinished heads.
        // Include implicitly opened streams, and never extend this deadline for partial bytes.
        if (!_closing)
            foreach (var r in _requests.Values)
                if (!r.Done && r.Stream is null && now >= r.HeaderDeadline)
                {
                    _closing = true;
                    _ep.Run(Quic, _ => Fail(H3Error.ExcessiveLoad, "request header timeout", QuicEndpoint.Now()));
                    break;
                }
        if (_goAway >= 0) MaybeClose(now); // after a GOAWAY of any cause, an idle connection closes
    }

    /// <summary>Close now, whatever is running: every request is aborted with <paramref name="reason"/>.</summary>
    public void CloseNow(string reason, long now)
    {
        if (_closing) return;
        _closing = true;
        foreach (var r in _requests.Values)
            if (r.Stream is { } s) AbortStream(r, s, reason, H3Error.RequestCancelled);
        Quic.Close((ulong)H3Error.NoError, reason, now);
    }

    /// <summary>The QUIC connection is gone: stop every request.</summary>
    public void Closed()
    {
        foreach (var r in _requests.Values)
        {
            if (r.Stream is { } s) AbortStream(r, s, "connection closed", H3Error.RequestCancelled);
            r.PendingDone?.TrySetException(new IOException("connection closed"));
        }
        _requests.Clear();
    }
}
