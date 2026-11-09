using System.Net.Sockets;
using Httpgrl.Core.Hosting;
using Httpgrl.Core.Http;
using Httpgrl.Core.Http2;
using Httpgrl.Core.Modules;
using Httpgrl.Core.Pipeline;
using Httpgrl.Core.Quic;

namespace Httpgrl.Core.Http3;

/// <summary>
/// HTTP/3 (RFC 9114) on one QUIC connection: the control streams and SETTINGS, QPACK's streams, request streams and
/// their framing, GOAWAY. It runs on the endpoint's thread (every method but the handler-facing ones marked as such);
/// requests run on the thread pool through the same lifecycle as HTTP/1.1 and HTTP/2.
/// </summary>
internal sealed class Http3Connection
{
    public readonly QuicConnection Q;
    private readonly QuicEndpoint _ep;
    private readonly HttpRuntime _rt;
    private readonly VirtualHosts _hosts;
    private readonly ConnectionManager _mgr;
    private readonly ConnectionInfo _info;
    private readonly HttpCoreConf _core;
    private readonly ILogger _log;
    private readonly long _id;

    private sealed class Request(long id, long headerDeadline)
    {
        public readonly long Id = id;
        public readonly long HeaderDeadline = headerDeadline;
        public readonly H3FrameReader Reader = new(256 << 10);
        public H3Stream? Stream;
        public bool HeadersSeen, TrailersSeen, Fin, Done;
        /// <summary>The request's field section, until we know whether the stream ends right behind it.</summary>
        public byte[]? HeadBlock;
        /// <summary>Waiting to be written (endpoint thread): the handler's current write, and its completion.</summary>
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
    private int _active;                  // handlers running; touched from both sides
    private bool _closing;
    private readonly byte[] _buf = new byte[16 << 10];
    private readonly RequestHead _head;
    private readonly QpackDecoder _qpack;

    public Http3Connection(QuicConnection q, QuicEndpoint ep, HttpRuntime rt, VirtualHosts hosts, ConnectionManager mgr, HttpCoreConf core, long id)
    {
        Q = q;
        _ep = ep;
        _rt = rt;
        _hosts = hosts;
        _mgr = mgr;
        _core = core;
        _log = rt.Log;
        _id = id;
        _info = new ConnectionInfo(id, q.Path, ep.LocalEndPoint, isTls: true);
        _head = new RequestHead(core.UnderscoresInHeaders == true, HttpVersion.Http30);
        _qpack = new QpackDecoder(core.HeaderTotalMax);
        // A reload (or shutdown) retires this generation: GOAWAY at once, not at the endpoint's next idle tick.
        _retired = rt.RetiredToken.Register(static o => { var h = (Http3Connection)o!; h._ep.Run(h.Q, _ => h.Tick(QuicEndpoint.Now())); }, this);
    }

    private readonly CancellationTokenRegistration _retired;

    public void OnEvent(in QuicEvent e, long now)
    {
        try
        {
            switch (e.Kind)
            {
                case QuicEventKind.Connected: OnConnected(); break;
                case QuicEventKind.StreamOpened:
                case QuicEventKind.StreamReadable: Read(e.StreamId); break;
                case QuicEventKind.StreamWritable: ContinueWrite(e.StreamId); break;
                case QuicEventKind.StopSending:
                    // The client doesn't want the response (any more): stop the handler; QUIC already reset the stream.
                    if (_requests.TryGetValue(e.StreamId, out var r) && r.Stream is { } s) s.Abort("stopped by the client", H3Error.RequestCancelled, reset: false);
                    break;
            }
        }
        catch (H3Exception x) when (x.IsConnectionError) { Fail(x.Code, x.Message, now); }
    }

    private void Fail(H3Error code, string why, long now)
    {
        _log.Warn("security", new("event", why == "request header timeout" ? "header_deadline_exceeded" : "http3_connection_rejected"), new("conn", _id), new("remote", _info.RemoteAddress));
        _log.Info("http/3 connection error", new("conn", _id), new("code", code.ToString()), new("reason", why), new("remote", _info.RemoteAddress));
        Q.Close((ulong)code, why, now);
    }

    private void OnConnected()
    {
        _info.SetTls(Q.ServerName, "TLSv1.3", Q.ClientCertificate, Q.ClientVerify);
        // Our control stream, with SETTINGS first (RFC 9114 6.2.1). No QPACK streams: our dynamic table is zero and we
        // never use the peer's (RFC 9204 4.2 lets us skip them).
        _control = Q.OpenStream(bidi: false);
        if (_control < 0) throw new H3Exception(H3Error.StreamCreationError, "the client allows no unidirectional streams");
        var settings = H3FrameWriter.Settings(
            (H3Settings.MaxFieldSectionSize, (ulong)_core.HeaderTotalMax),
            (H3Settings.EnableConnectProtocol, 1)); // WebSockets over HTTP/3 (RFC 9220)
        Q.StreamWrite(_control, [(byte)H3StreamType.Control, .. settings], fin: false);
    }

    // ------------------------------------------------------------------ reading

    private void Read(long id)
    {
        if (StreamId.IsBidi(id))
        {
            if (!StreamId.IsClientInitiated(id)) return; // we open none
            ReadRequest(id);
        }
        else if (StreamId.IsClientInitiated(id)) ReadUni(id);
    }

    private void ReadUni(long id)
    {
        if (!_uni.TryGetValue(id, out var u)) _uni[id] = u = new Uni();
        while (true)
        {
            int n = Q.StreamRead(id, _buf, out bool fin, out ulong? reset);
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
                Q.StopSending(id, (ulong)H3Error.StreamCreationError);
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

    private void ReadRequest(long id)
    {
        if (!_requests.TryGetValue(id, out var r))
        {
            if (_closing || (_goAway >= 0 && id >= _goAway))
            {
                // After our GOAWAY: not processed, so the client may safely retry it elsewhere (RFC 9114 5.2).
                Q.StopSending(id, (ulong)H3Error.RequestRejected);
                Q.ResetStream(id, (ulong)H3Error.RequestRejected);
                return;
            }
            _requests[id] = r = new Request(id, QuicEndpoint.Now() + _core.ClientHeaderTimeoutMs * 1000L);
            if (id + 4 > _nextRequest) _nextRequest = id + 4;
        }
        if (r.Done) { Drain(id); return; }
        while (r.Stream is null || r.Stream.Body.HasRoom || r.TrailersSeen)
        {
            int n = Q.StreamRead(id, _buf, out bool fin, out ulong? reset);
            if (reset is not null)
            {
                r.Done = true;
                if (r.Stream is { } s) s.Abort("reset by the client", H3Error.RequestCancelled, reset: false);
                else _requests.Remove(id);
                return;
            }
            try
            {
                if (n > 0) r.Reader.Feed(_buf.AsSpan(0, n), (t, p) => OnRequestFrame(r, t, p), d => OnRequestData(r, d));
                // HEADERS has no END_STREAM flag in HTTP/3: a FIN right behind it (in what's arrived) means no body.
                if (r.HeadBlock is not null && (fin || Q.StreamAvailable(id) == 0)) StartRequest(r, endStream: fin && r.Reader.AtBoundary);
                if (fin) OnRequestEnd(r);
            }
            catch (H3Exception x) when (!x.IsConnectionError) { StreamError(r, x.Code, x.Message); return; }
            if (n == 0 || fin) return;
        }
    }

    /// <summary>A request stream we've given up on (or that's done): discard what still arrives.</summary>
    private void Drain(long id)
    {
        while (Q.StreamRead(id, _buf, out bool fin, out _) > 0) if (fin) break;
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
                    try { _qpack.Decode(payload, (n, v) => bad ??= RequestHead.CheckTrailer(n, v)); }
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
        if (r.Stream is { } s && !s.Body.Deliver(data, end: false))
            throw new H3Exception(H3Error.MessageError, "more DATA than content-length", connection: false);
    }

    private void OnRequestEnd(Request r)
    {
        r.Fin = true;
        if (!r.Reader.AtBoundary) throw new H3Exception(H3Error.FrameError, "the stream ended inside a frame");
        if (!r.HeadersSeen) throw new H3Exception(H3Error.RequestIncomplete, "the stream ended without a request", connection: false);
        if (r.Stream is { } s && !s.Body.Deliver(default, end: true))
            throw new H3Exception(H3Error.MessageError, "DATA doesn't match content-length", connection: false);
    }

    private void StreamError(Request r, H3Error code, string why)
    {
        _log.Info("http/3 stream error", new("event", "http3_stream_rejected"), new("conn", _id), new("stream", r.Id), new("code", code.ToString()), new("reason", why));
        r.Done = true;
        Q.StopSending(r.Id, (ulong)code);
        Q.ResetStream(r.Id, (ulong)code);
        if (r.Stream is { } s) s.Abort(why, code, reset: false);
        else _requests.Remove(r.Id);
    }

    private void StartRequest(Request r, bool endStream)
    {
        var block = r.HeadBlock!;
        r.HeadBlock = null;
        var stream = new H3Stream(r.Id, this);
        var ctx = new HttpContextImpl(_rt, _info, stream, stream.Body, stream.Wire) { Mgr = _mgr, Upgrader = () => new H3TunnelStream(stream) };
        stream.Ctx = ctx;
        ctx.BeginRequest();
        _head.Begin(ctx.Req);
        int code;
        try
        {
            _qpack.Decode(block, _head.OnField);
            // The request has no body if the stream already ended: HTTP/3 has no END_STREAM flag on HEADERS, so only a
            // FIN right behind tells us; until then a body may follow (content-length, or DATA of unknown length).
            code = _head.Finish(endStream);
        }
        catch (QpackException e) when (e.Limit) { code = 431; }
        catch (QpackException e) { throw new H3Exception(H3Error.QpackDecompressionFailed, e.Message); }
        if (code == -1)
        {
            ctx.EndRequest();
            throw new H3Exception(H3Error.MessageError, _head.Why ?? "malformed request", connection: false);
        }
        if (code == 0 && ctx.Req.ContentLengthValue >= 0) stream.Body.Expected = ctx.Req.ContentLengthValue;
        if (endStream) stream.Body.Deliver(default, end: true);
        if (code == 0 && ctx.Req.ExpectContinue) stream.Body.SendContinue = () => stream.Wire.SendInterimAsync(100);
        r.Stream = stream;
        _info.CountRequest();
        if (_info.Requests >= _core.KeepaliveRequestsMax) GoAway(); // keepalive_requests, as on the other protocols
        Interlocked.Increment(ref _active);
        _mgr.Track(stream);
        _ = Task.Run(() => RunStreamAsync(r, stream, code));
    }

    // ------------------------------------------------------------------ the handler's side (thread pool)

    private async Task RunStreamAsync(Request r, H3Stream s, int code)
    {
        var ctx = s.Ctx;
        try
        {
            int reject = RequestLifecycle.Route(ctx, _hosts, TlsServer(), code > 0 ? code : 0);
            ctx.SetKeepAlive(true);
            s.Phase = "processing";
            bool clean = await RequestLifecycle.RunAsync(ctx, reject).ConfigureAwait(false);
            if (!clean && !s.IsAborted) s.Abort(ctx.Dropped ? "dropped" : "response incomplete", ctx.Dropped ? H3Error.RequestCancelled : H3Error.InternalError, reset: true);
            await RequestLifecycle.FinishAsync(ctx, _mgr).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException or OperationCanceledException or InvalidOperationException) { }
        catch (Exception e)
        {
            _log.Error("http/3 stream failed", new("conn", _id), new("stream", s.Id), new("error", e.GetType().Name), new("detail", e.Message), new("stack", e.StackTrace));
        }
        finally
        {
            await RequestLifecycle.FinishAsync(ctx, _mgr).ConfigureAwait(false);
            ctx.EndRequest();
            ctx.Resp.ReturnBuffer();
            _mgr.Untrack(s);
            s.Body.Release();
            s.Dispose();
            Interlocked.Decrement(ref _active);
            _ep.Run(Q, _ => Finished(r));
        }
    }

    /// <summary>
    /// The server whose context the handshake finished under (SNI): its client-certificate policy is what was checked,
    /// so Route refuses (421) a Host leading to a server with a different one, exactly as on TCP.
    /// </summary>
    private ServerRt TlsServer()
    {
        var s = Q.ServerName is { } sni ? _hosts.Resolve(sni) : _hosts.Default;
        // The context may differ from that server's (no SNI, or the default had none): find the one it belongs to.
        if (!ReferenceEquals(s.Scope.Get<SslConf>().QuicTls, Q.TlsContext))
            foreach (var x in _hosts.Servers)
                if (ReferenceEquals(x.Scope.Get<SslConf>().QuicTls, Q.TlsContext)) return x;
        return s;
    }

    /// <summary>Handler side: put bytes on the stream, waiting until QUIC has taken them (back-pressure).</summary>
    public ValueTask WriteAsync(H3Stream s, ReadOnlyMemory<byte> data, bool fin)
    {
        if (s.IsAborted) return ValueTask.FromException(new IOException("stream reset"));
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _ep.Run(Q, _ =>
        {
            if (!_requests.TryGetValue(s.Id, out var r) || r.Done && r.Stream?.IsAborted == true) { done.TrySetException(new IOException("stream reset")); return; }
            r.Pending = data;
            r.PendingFin = fin;
            r.PendingDone = done;
            ContinueWrite(s.Id);
        });
        return new ValueTask(AwaitWrite(s, done.Task));
    }

    private static async Task AwaitWrite(H3Stream s, Task done)
    {
        s.BeginWrite();
        try { await done.ConfigureAwait(false); }
        finally { s.EndWrite(0); }
    }

    /// <summary>Handler side: the body was read below its window: read more from the QUIC stream.</summary>
    public void ResumeReading(H3Stream s) => _ep.Run(Q, _ => ReadRequest(s.Id));

    /// <summary>Handler side (or sweeper): reset the stream both ways.</summary>
    public void ResetLater(H3Stream s, H3Error code) => _ep.Run(Q, q =>
    {
        if (_requests.TryGetValue(s.Id, out var r)) r.Done = true;
        q.StopSending(s.Id, (ulong)code);
        q.ResetStream(s.Id, (ulong)code);
        FailWrites(s);
    });

    /// <summary>Any thread: fail a write that's waiting (the stream is gone).</summary>
    public void FailWrites(H3Stream s) => _ep.Run(Q, _ =>
    {
        if (_requests.TryGetValue(s.Id, out var r) && r.PendingDone is { } d)
        {
            r.PendingDone = null;
            r.Pending = default;
            d.TrySetException(new IOException("stream reset"));
        }
    });

    // ------------------------------------------------------------------ writing (endpoint thread)

    private void ContinueWrite(long id)
    {
        if (!_requests.TryGetValue(id, out var r) || r.PendingDone is null) return;
        int n = Q.StreamWrite(id, r.Pending.Span, r.PendingFin);
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

    /// <summary>A handler finished: forget the stream once both directions are done; close if we're winding down.</summary>
    private void Finished(Request r)
    {
        r.Done = true;
        if (!r.Fin) Q.StopSending(r.Id, (ulong)H3Error.NoError); // the rest of the upload isn't wanted
        _requests.Remove(r.Id);
        MaybeClose(QuicEndpoint.Now());
    }

    // ------------------------------------------------------------------ winding down

    /// <summary>
    /// GOAWAY: stop taking requests (reload, shutdown, keepalive_requests). It names the first stream we won't
    /// process; later ones are refused with H3_REQUEST_REJECTED, which clients retry (RFC 9114 5.2).
    /// </summary>
    public void GoAway()
    {
        if (_goAway >= 0 || _control < 0) return;
        _goAway = _nextRequest;
        Q.StreamWrite(_control, H3FrameWriter.GoAway(_goAway), fin: false);
        MaybeClose(QuicEndpoint.Now()); // nothing running: done now, not at the next tick
    }

    private void MaybeClose(long now)
    {
        if (_goAway >= 0 && Volatile.Read(ref _active) == 0 && _requests.Count == 0 && !_closing)
        {
            _closing = true;
            Q.Close((ulong)H3Error.NoError, "", now);
        }
    }

    /// <summary>Endpoint thread, once per loop turn: follow a reload (GOAWAY, then the drain deadline).</summary>
    public void Tick(long now)
    {
        // The QUIC idle timer is refreshed by traffic, so it cannot protect unfinished heads.
        // Include implicitly opened streams, and never extend this deadline for partial bytes.
        if (!_closing)
            foreach (var r in _requests.Values)
                if (!r.Done && r.Stream is null && now >= r.HeaderDeadline)
                {
                    _closing = true;
                    _ep.Run(Q, _ => Fail(H3Error.ExcessiveLoad, "request header timeout", QuicEndpoint.Now()));
                    break;
                }
        if (_goAway >= 0) MaybeClose(now); // after a GOAWAY of any cause, an idle connection closes
        if (!_rt.Retired) return;
        GoAway();
        MaybeClose(now);
        if (!_closing && Environment.TickCount64 > _rt.RetireDeadline)
        {
            _closing = true;
            foreach (var r in _requests.Values) r.Stream?.Abort("reload drain timeout", H3Error.RequestCancelled, reset: false);
            Q.Close((ulong)H3Error.NoError, "reload drain timeout", now);
        }
    }

    /// <summary>The QUIC connection is gone: stop every handler.</summary>
    public void Closed()
    {
        _retired.Dispose();
        foreach (var r in _requests.Values)
        {
            r.Stream?.Abort("connection closed", H3Error.RequestCancelled, reset: false);
            r.PendingDone?.TrySetException(new IOException("connection closed"));
        }
        _requests.Clear();
    }
}
