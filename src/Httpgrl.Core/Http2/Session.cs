using System.Buffers;
using System.Buffers.Binary;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Httpgrl.Core.Hosting;
using Httpgrl.Core.Http;
using Httpgrl.Core.Modules;
using Httpgrl.Core.Pipeline;

namespace Httpgrl.Core.Http2;

/// <summary>
/// One HTTP/2 connection (RFC 9113), server side, after TLS with ALPN "h2". A single reader parses frames and keeps
/// connection state (settings, HPACK, flow control, the stream table); every stream's request runs on its own task
/// through the same lifecycle as HTTP/1.1, with its own deadlines. Writes are serialized frame by frame.
///
/// Abuse budgets, each a GOAWAY ENHANCE_YOUR_CALM when exhausted:
/// - streams: at most <c>http2_max_concurrent_streams</c> handlers at once, and a reset stream keeps its slot until its
///   handler has actually stopped (so rapid reset can't outrun real work); streams the client resets, and ones refused
///   or malformed, also draw on a budget (legitimate bursts of completed requests don't);
/// - header blocks: bounded compressed size and fragment count (CONTINUATION floods);
/// - control frames that make us answer or carry nothing (SETTINGS, PING, RST_STREAM, unknown and empty frames) share
///   one budget, which refills with time and with every DATA frame we send: a client doing real work earns more.
///   WINDOW_UPDATE and PRIORITY are free: they never make us reply or allocate, and a client receiving data sends
///   WINDOW_UPDATEs in proportion to it.
/// </summary>
internal sealed class Http2Session
{
    public const int OurMaxFrame = 16384;
    public const int TableSize = 4096;
    public const int StreamWindow = 256 << 10;
    public const int ConnectionWindow = 1 << 20;
    private const int MaxBlockFrames = 32;
    private const int ControlBurst = 1000, ControlPerSecond = 200;

    private readonly Connection _conn;
    private readonly Stream _transport;
    private HttpRuntime _rt;
    private readonly ConnectionManager _mgr;
    private readonly VirtualHosts _hosts;
    private readonly ServerRt _tlsServer;
    private readonly ConnectionInfo _info;
    private readonly HttpCoreConf _core;
    private readonly int _maxStreams, _maxHeaderList;
    private readonly HpackDecoder _hpack;
    private readonly RequestHead _head;

    private readonly object _lock = new();
    private readonly Dictionary<int, H2Stream> _streams = new();
    private readonly List<Task> _handlers = new();
    private readonly SemaphoreSlim _write = new(1, 1);
    private readonly List<TaskCompletionSource> _windowWaiters = new();

    private int _lastStreamId, _active;
    private long _connSend = 65535;          // what we may send (the peer's connection window); under _lock
    private long _connRecv = ConnectionWindow; // what the peer may still send us; under _lock
    private long _connUnacked;                // read by handlers, not yet credited back; under _lock
    private int _peerInitialWindow = 65535, _peerMaxFrame = 16384;
    private volatile bool _goingAway;        // the final GOAWAY is out: no new streams
    private int _goAwaySent;                  // 0 none, 1 the drain's first GOAWAY (awaiting its PING), 2 the final one
    private int _closing;                     // the graceful close has begun (close_notify, FIN, then read to EOF)
    private bool _writeClosed;                // under _write: nothing more may be written
    private bool _peerGoAway;
    private int _goAwayLast = int.MaxValue;   // the final GOAWAY's last stream; under _lock
    private static readonly byte[] DrainPing = "h2drain!"u8.ToArray();

    // Budgets (token buckets, reader thread).
    private double _control = ControlBurst, _wasted;
    private long _controlAt = Environment.TickCount64, _wastedAt = Environment.TickCount64;

    // The header block being assembled (HEADERS + CONTINUATION).
    private byte[] _block = new byte[4096];
    private int _blockLen, _blockStream, _blockFrames;
    private bool _blockEndStream, _inBlock;
    private BlockMode _blockMode;

    /// <summary>What a header block is for. Every block is decoded, even one about to be refused: skipping it would desynchronize HPACK.</summary>
    private enum BlockMode : byte { Request, Trailers, RejectStream }

    private byte[] _in = ArrayPool<byte>.Shared.Rent(OurMaxFrame + FrameReader.HeaderSize + 4096);
    private int _start, _end;

    public Http2Session(Connection conn, Stream transport, HttpRuntime rt, ConnectionManager mgr, VirtualHosts hosts, ServerRt tlsServer, ConnectionInfo info, HttpCoreConf core)
    {
        _conn = conn;
        _transport = transport;
        _rt = rt;
        _mgr = mgr;
        _hosts = hosts;
        _tlsServer = tlsServer;
        _info = info;
        _core = core;
        _maxStreams = core.Http2MaxStreams;
        _maxHeaderList = core.HeaderTotalMax;
        _hpack = new HpackDecoder(TableSize, _maxHeaderList);
        _head = new RequestHead(core.UnderscoresInHeaders == true);
        _wasted = 2.0 * _maxStreams;
    }

    public async Task RunAsync()
    {
        CancellationTokenRegistration retired = default;
        try
        {
            _conn.Phase = "h2 preface";
            _conn.BaseDeadline = Environment.TickCount64 + _core.ClientHeaderTimeoutMs;
            if (!await ReadPrefaceAsync().ConfigureAwait(false)) return;
            await WriteAsync(
                FrameWriter.Settings((SettingId.HeaderTableSize, TableSize), (SettingId.EnablePush, 0), (SettingId.MaxConcurrentStreams, (uint)_maxStreams),
                    (SettingId.InitialWindowSize, StreamWindow), (SettingId.MaxFrameSize, OurMaxFrame), (SettingId.MaxHeaderListSize, (uint)_maxHeaderList),
                    (SettingId.EnableConnectProtocol, 1)), // WebSockets over HTTP/2 (RFC 8441)
                FrameWriter.WindowUpdate(0, ConnectionWindow - 65535)).ConfigureAwait(false);
            // Reload and shutdown wind the session down, once our SETTINGS are out (the first frame must be SETTINGS).
            retired = _rt.RetiredToken.Register(static s => ((Http2Session)s!).GoAwayLater(H2Error.NoError), this);

            // The slow-read defence, for the whole connection: its writes must keep up the minimum rate (send_min_rate).
            _conn.RateWritesOnly = true;
            _conn.DrainsItself = true; // reload and shutdown: GOAWAY, not the sweeper's close of an "idle" connection
            _conn.StartRate(_core.SendMinRateBps);
            bool first = true;
            while (true)
            {
                bool idle;
                lock (_lock) idle = _active == 0 && !_inBlock;
                if (Volatile.Read(ref _closing) != 0) { } // lingering: read (and ignore) until the client closes, or the deadline
                else if (idle)
                {
                    if (_goingAway || _peerGoAway) { CloseGracefully(); continue; } // nothing left to finish
                    _conn.SetIdle(_core.KeepaliveTimeoutMs);
                }
                else if (!_inBlock) { _conn.SetActive(); _conn.Phase = "h2"; _conn.BaseDeadline = 0; }

                var (ok, frame, off, len) = await ReadFrameAsync().ConfigureAwait(false);
                if (!ok) break;
                if (Volatile.Read(ref _closing) == 0) _conn.SetActive();
                if (first && (frame.Type != FrameType.Settings || frame.Has(FrameFlags.Ack)))
                    throw new H2Exception(H2Error.ProtocolError, 0, "the preface must be followed by SETTINGS");
                first = false;
                try { await DispatchAsync(frame, _in.AsMemory(off, len)).ConfigureAwait(false); }
                catch (H2Exception e) when (!e.IsConnectionError) { StreamError(e); }
            }
        }
        catch (H2Exception e)
        {
            _rt.Log.Info("http/2 connection error", new("conn", _conn.Id), new("code", e.Code.ToString()), new("reason", e.Message), new("remote", _info.RemoteAddress));
            await GoAwayAsync(e.Code).ConfigureAwait(false);
            await LingerAsync().ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException or OperationCanceledException) { }
        finally
        {
            retired.Dispose();
            Task[] handlers;
            H2Stream[] open;
            lock (_lock)
            {
                handlers = [.. _handlers];
                open = [.. _streams.Values];
            }
            foreach (var s in open) s.Abort("connection closed", H2Error.Cancel, sendReset: false);
            try { await Task.WhenAll(handlers).ConfigureAwait(false); } catch (Exception) { /* each logged its own end */ }
            ArrayPool<byte>.Shared.Return(_in);
            _in = [];
        }
    }

    // ------------------------------------------------------------------ reading

    private async ValueTask<bool> ReadPrefaceAsync()
    {
        int need = FrameReader.Preface.Length;
        while (_end - _start < need)
        {
            int n = await _transport.ReadAsync(_in.AsMemory(_end)).ConfigureAwait(false);
            if (n == 0) return false;
            _end += n;
            if (!PrefixMatches()) return false; // not HTTP/2: just close
        }
        _start += need;
        return true;
    }

    private bool PrefixMatches()
    {
        var p = FrameReader.Preface;
        int have = Math.Min(_end - _start, p.Length);
        return _in.AsSpan(_start, have).SequenceEqual(p[..have]);
    }

    private async ValueTask<(bool Ok, Frame Frame, int Off, int Len)> ReadFrameAsync()
    {
        while (true)
        {
            int n = TryRead(out var f, out int off, out int len);
            if (n > 0)
            {
                _start += n;
                return (true, f, off, len);
            }
            if (_start > 0 && _start == _end) _start = _end = 0;
            if (_end == _in.Length)
            {
                Buffer.BlockCopy(_in, _start, _in, 0, _end - _start);
                _end -= _start;
                _start = 0;
            }
            int r = await _transport.ReadAsync(_in.AsMemory(_end)).ConfigureAwait(false);
            if (r == 0) return (false, default, 0, 0);
            _end += r;
        }
    }

    private int TryRead(out Frame f, out int off, out int len)
    {
        var buf = _in.AsSpan(_start, _end - _start);
        int n = FrameReader.TryRead(buf, OurMaxFrame, out f, out var payload);
        if (n == 0 || payload.IsEmpty) { off = _start; len = 0; return n; }
        off = _start + (int)Unsafe.ByteOffset(ref MemoryMarshal.GetReference(buf), ref MemoryMarshal.GetReference(payload));
        len = payload.Length;
        return n;
    }

    // ------------------------------------------------------------------ dispatch

    private async ValueTask DispatchAsync(Frame f, ReadOnlyMemory<byte> payload)
    {
        if (_inBlock && f.Type != FrameType.Continuation)
            throw new H2Exception(H2Error.ProtocolError, 0, "a header block was interrupted");
        switch (f.Type)
        {
            case FrameType.Settings:
                Control();
                if (f.Has(FrameFlags.Ack)) return;
                ApplySettings(payload.Span);
                await WriteAsync(FrameWriter.SettingsAck()).ConfigureAwait(false);
                return;
            case FrameType.Ping:
                Control();
                if (!f.Has(FrameFlags.Ack)) await WriteAsync(FrameWriter.Ping(payload.Span, ack: true)).ConfigureAwait(false);
                else if (payload.Span.SequenceEqual(DrainPing)) FinalGoAway(); // a round trip after the first GOAWAY: nothing is in flight
                return;
            case FrameType.GoAway:
                _peerGoAway = true;
                return;
            case FrameType.WindowUpdate:
                WindowUpdate(f.StreamId, (int)(BinaryPrimitives.ReadUInt32BigEndian(payload.Span) & 0x7FFFFFFF));
                return;
            case FrameType.RstStream:
                Control();
                PeerReset(f.StreamId, (H2Error)BinaryPrimitives.ReadUInt32BigEndian(payload.Span));
                return;
            case FrameType.Priority:
                return;
            case FrameType.Headers:
                await HeadersAsync(f, payload).ConfigureAwait(false);
                return;
            case FrameType.Continuation:
                await ContinuationAsync(f, payload).ConfigureAwait(false);
                return;
            case FrameType.Data:
                await DataAsync(f, payload).ConfigureAwait(false);
                return;
            default:
                Control(); // extension frames: ignored, but not free
                return;
        }
    }

    /// <summary>
    /// A stream that did no useful work: reset by the client, refused, or malformed. Rapid reset (CVE-2023-44487) is
    /// exactly this, at speed. The bucket refills at the concurrency limit per second.
    /// </summary>
    private void Wasted()
    {
        long now = Environment.TickCount64;
        _wasted = Math.Min(2.0 * _maxStreams, _wasted + (now - _wastedAt) * _maxStreams / 1000.0);
        _wastedAt = now;
        if (--_wasted < 0) throw new H2Exception(H2Error.EnhanceYourCalm, 0, "too many streams reset, refused or malformed");
    }

    /// <summary>One control frame against the budget.</summary>
    private void Control()
    {
        long now = Environment.TickCount64;
        long earned = Interlocked.Exchange(ref _earned, 0); // DATA frames we've sent since: real work buys allowance
        _control = Math.Min(ControlBurst, _control + (now - _controlAt) * ControlPerSecond / 1000.0 + earned);
        _controlAt = now;
        if (--_control < 0) throw new H2Exception(H2Error.EnhanceYourCalm, 0, "too many control frames");
    }

    private long _earned;

    private void ApplySettings(ReadOnlySpan<byte> p)
    {
        for (int i = 0; i + 6 <= p.Length; i += 6)
        {
            ushort id = BinaryPrimitives.ReadUInt16BigEndian(p[i..]);
            uint v = BinaryPrimitives.ReadUInt32BigEndian(p[(i + 2)..]);
            if (id == SettingId.InitialWindowSize)
            {
                long delta = (long)v - _peerInitialWindow;
                lock (_lock)
                {
                    foreach (var s in _streams.Values)
                    {
                        s.SendWindow += delta;
                        if (s.SendWindow > int.MaxValue) throw new H2Exception(H2Error.FlowControlError, 0, "stream window overflow");
                    }
                }
                _peerInitialWindow = (int)v;
                WakeWriters();
            }
            else if (id == SettingId.MaxFrameSize) _peerMaxFrame = (int)v;
            // HEADER_TABLE_SIZE: our encoder never uses the dynamic table. Others don't concern a server.
        }
    }

    private void WindowUpdate(int sid, int increment)
    {
        lock (_lock)
        {
            if (sid == 0)
            {
                _connSend += increment;
                if (_connSend > int.MaxValue) throw new H2Exception(H2Error.FlowControlError, 0, "connection window overflow");
            }
            else if (_streams.TryGetValue(sid, out var s))
            {
                s.SendWindow += increment;
                if (s.SendWindow > int.MaxValue) throw new H2Exception(H2Error.FlowControlError, sid, "stream window overflow");
            }
            else if (sid > _lastStreamId) throw new H2Exception(H2Error.ProtocolError, 0, "WINDOW_UPDATE on an idle stream");
            // else: a stream we've closed; ignored
        }
        WakeWriters();
    }

    private void PeerReset(int sid, H2Error code)
    {
        H2Stream? s;
        lock (_lock)
        {
            if (sid > _lastStreamId) throw new H2Exception(H2Error.ProtocolError, 0, "RST_STREAM on an idle stream");
            _streams.TryGetValue(sid, out s);
        }
        if (s is null) return;
        Wasted();
        s.RemoteClosed = true;
        s.LocalClosed = true; // no more frames from us either
        s.Abort("reset by client (" + code + ")", code, sendReset: false);
    }

    private async ValueTask HeadersAsync(Frame f, ReadOnlyMemory<byte> payload)
    {
        int sid = f.StreamId;
        if ((sid & 1) == 0) throw new H2Exception(H2Error.ProtocolError, 0, "client stream IDs are odd");
        BlockMode mode;
        lock (_lock)
        {
            if (_streams.TryGetValue(sid, out var existing)) mode = existing.RemoteClosed ? BlockMode.RejectStream : BlockMode.Trailers;
            else if (sid <= _lastStreamId) throw new H2Exception(H2Error.StreamClosed, 0, "HEADERS on a closed stream"); // the connection ends: HPACK is moot
            else
            {
                mode = BlockMode.Request;
                _lastStreamId = sid;
            }
        }
        if (payload.Length == 0 && !f.Has(FrameFlags.EndHeaders)) Control(); // an empty fragment: no progress, not free
        _inBlock = true;
        _blockStream = sid;
        _blockFrames = 1;
        _blockLen = 0;
        _blockEndStream = f.Has(FrameFlags.EndStream);
        _blockMode = mode;
        _conn.Phase = "h2 header block";
        _conn.BaseDeadline = Environment.TickCount64 + _core.ClientHeaderTimeoutMs; // the whole block, like an HTTP/1.1 head
        Append(payload.Span);
        if (f.Has(FrameFlags.EndHeaders)) await BlockCompleteAsync().ConfigureAwait(false);
    }

    private async ValueTask ContinuationAsync(Frame f, ReadOnlyMemory<byte> payload)
    {
        if (!_inBlock || f.StreamId != _blockStream) throw new H2Exception(H2Error.ProtocolError, 0, "CONTINUATION without a header block");
        // CONTINUATION flood: a block of many (possibly empty) fragments, never ending.
        if (++_blockFrames > MaxBlockFrames) throw new H2Exception(H2Error.EnhanceYourCalm, 0, "header block in too many fragments");
        Append(payload.Span);
        if (f.Has(FrameFlags.EndHeaders)) await BlockCompleteAsync().ConfigureAwait(false);
    }

    private void Append(ReadOnlySpan<byte> fragment)
    {
        // Compressed size is bounded too: decoding is the expensive part, so an oversized block never gets that far.
        if (_blockLen + fragment.Length > _maxHeaderList + 4096) throw new H2Exception(H2Error.EnhanceYourCalm, 0, "header block too large");
        if (_block.Length < _blockLen + fragment.Length) Array.Resize(ref _block, Math.Max(_block.Length * 2, _blockLen + fragment.Length));
        fragment.CopyTo(_block.AsSpan(_blockLen));
        _blockLen += fragment.Length;
    }

    private async ValueTask BlockCompleteAsync()
    {
        _inBlock = false;
        _conn.BaseDeadline = 0;
        int sid = _blockStream;
        var block = _block.AsSpan(0, _blockLen);
        if (_blockMode == BlockMode.RejectStream)
        {
            try { _hpack.Decode(block, static (_, _) => { }); }
            catch (HpackException e) when (e.Limit) { }
            catch (HpackException e) { throw new H2Exception(H2Error.CompressionError, 0, e.Message); }
            throw new H2Exception(H2Error.StreamClosed, sid, "HEADERS after END_STREAM");
        }
        if (_blockMode == BlockMode.Trailers)
        {
            string? bad = null;
            try { _hpack.Decode(block, (n, v) => bad ??= RequestHead.CheckTrailer(n, v)); }
            catch (HpackException e) when (e.Limit) { bad = e.Message; }
            catch (HpackException e) { throw new H2Exception(H2Error.CompressionError, 0, e.Message); }
            if (!_blockEndStream) bad ??= "trailers without END_STREAM";
            H2Stream? s;
            lock (_lock) _streams.TryGetValue(sid, out s);
            if (s is null) return;
            if (bad is not null) { s.RemoteClosed = true; throw new H2Exception(H2Error.ProtocolError, sid, bad); }
            s.RemoteClosed = true;
            s.Body.Deliver(default, end: true);
            return;
        }

        // A new stream. Its block is decoded whatever happens next: skipping it would desynchronize HPACK.
        var stream = new H2Stream(sid, this, _peerInitialWindow, StreamWindow);
        var ctx = new HttpContextImpl(_rt, _info, stream, stream.Body, stream.Wire) { Mgr = _mgr, Upgrader = () => new H2TunnelStream(stream) };
        stream.Ctx = ctx;
        ctx.BeginRequest();
        _head.Begin(ctx.Req);
        int code;
        try
        {
            _hpack.Decode(block, _head.OnField);
            code = _head.Finish(_blockEndStream);
        }
        catch (HpackException e) when (e.Limit) { code = 431; }
        catch (HpackException e) { throw new H2Exception(H2Error.CompressionError, 0, e.Message); }

        if (code == -1)
        {
            Wasted();
            _rt.Log.Debug("malformed http/2 request", new("conn", _conn.Id), new("stream", (long)sid), new("reason", _head.Why));
            ResetLater(sid, H2Error.ProtocolError);
            return;
        }
        bool refuse;
        lock (_lock)
        {
            // A reset stream holds its slot until its handler has stopped: _active counts handlers, not open streams.
            refuse = _goingAway || _active >= _maxStreams;
            if (!refuse)
            {
                _active++;
                _streams[sid] = stream;
            }
        }
        if (refuse)
        {
            // Past our final GOAWAY the client knows the stream wasn't processed and retries it (6.8): just ignore it.
            if (_goingAway) return;
            Wasted();
            ResetLater(sid, H2Error.RefusedStream);
            return;
        }
        if (code == 0 && ctx.Req.ContentLengthValue >= 0) stream.Body.Expected = ctx.Req.ContentLengthValue;
        if (_blockEndStream)
        {
            stream.RemoteClosed = true;
            stream.Body.Deliver(default, end: true);
        }
        else if (code == 0 && ctx.Req.ExpectContinue) stream.Body.SendContinue = () => stream.Wire.SendInterimAsync(100);
        _info.CountRequest();
        if (_info.Requests >= _core.KeepaliveRequestsMax) GoAwayLater(H2Error.NoError); // keepalive_requests, as on HTTP/1.1
        _mgr.Track(stream);
        var t = Task.Run(() => RunStreamAsync(stream, code));
        lock (_lock) _handlers.Add(t);
    }

    private async ValueTask DataAsync(Frame f, ReadOnlyMemory<byte> payload)
    {
        int sid = f.StreamId;
        int padding = f.Length - payload.Length;
        H2Stream? s;
        lock (_lock)
        {
            if (sid > _lastStreamId) throw new H2Exception(H2Error.ProtocolError, 0, "DATA on an idle stream");
            // Every DATA frame counts against the connection window, whatever becomes of it.
            _connRecv -= f.Length;
            if (_connRecv < 0) throw new H2Exception(H2Error.FlowControlError, 0, "connection window exceeded");
            _streams.TryGetValue(sid, out s);
            if (s is not null && !s.RemoteClosed)
            {
                s.RecvWindow -= f.Length;
                if (s.RecvWindow < 0) throw new H2Exception(H2Error.FlowControlError, sid, "stream window exceeded");
            }
        }
        bool end = f.Has(FrameFlags.EndStream);
        if (payload.Length == 0 && !end) Control();
        bool ignored;
        lock (_lock) ignored = sid > _goAwayLast; // never admitted: the client retries it elsewhere
        if (s is null || s.RemoteClosed || WeReset(sid) || ignored)
        {
            // A stream that's closed (or never got a handler): give the window back. If we reset it, frames still in
            // flight are expected and must be ignored (RFC 9113 5.1); otherwise tell the client to stop.
            await CreditAsync(null, f.Length).ConfigureAwait(false);
            if (WeReset(sid) || ignored) return;
            if (s is null) ResetLater(sid, H2Error.StreamClosed);
            else throw new H2Exception(H2Error.StreamClosed, sid, "DATA after END_STREAM");
            return;
        }
        if (padding > 0) await CreditAsync(s, padding).ConfigureAwait(false); // padding is never read: credit it at once
        if (end) s.RemoteClosed = true;
        if (!s.Body.Deliver(payload.Span, end)) throw new H2Exception(H2Error.ProtocolError, sid, "DATA doesn't match content-length");
    }

    private void StreamError(H2Exception e)
    {
        H2Stream? s;
        lock (_lock) _streams.TryGetValue(e.StreamId, out s);
        _rt.Log.Debug("http/2 stream error", new("conn", _conn.Id), new("stream", (long)e.StreamId), new("code", e.Code.ToString()), new("reason", e.Message));
        if (s is not null) s.Abort(e.Message, e.Code, sendReset: true);
        else if (!WeReset(e.StreamId)) ResetLater(e.StreamId, e.Code);
    }

    // ------------------------------------------------------------------ streams

    private async Task RunStreamAsync(H2Stream s, int code)
    {
        var ctx = s.Ctx;
        try
        {
            int reject = RequestLifecycle.Route(ctx, _hosts, _tlsServer, code > 0 ? code : 0);
            ctx.SetKeepAlive(true);
            s.Phase = "processing";
            bool clean = await RequestLifecycle.RunAsync(ctx, reject).ConfigureAwait(false);
            if (!clean) { if (!s.LocalClosed) s.Abort(ctx.Dropped ? "dropped" : "response incomplete", ctx.Dropped ? H2Error.Cancel : H2Error.InternalError, sendReset: true); }
            else if (!s.RemoteClosed) ResetLater(s, H2Error.NoError); // the response is complete; the rest of the upload isn't wanted
            await RequestLifecycle.FinishAsync(ctx, _mgr).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException or OperationCanceledException or InvalidOperationException) { }
        catch (Exception e)
        {
            _rt.Log.Error("http/2 stream failed", new("conn", _conn.Id), new("stream", (long)s.Id), new("error", e.GetType().Name), new("detail", e.Message), new("stack", e.StackTrace));
        }
        finally
        {
            ctx.EndRequest();
            ctx.Resp.ReturnBuffer();
            _mgr.Untrack(s);
            long unread = s.Body.Release();
            lock (_lock)
            {
                _streams.Remove(s.Id);
                _active--;
            }
            if (unread > 0) await CreditAsync(null, (int)Math.Min(unread, int.MaxValue)).ConfigureAwait(false);
            s.Dispose();
            if (_active == 0 && (_goingAway || _peerGoAway)) CloseGracefully();
        }
    }

    /// <summary>A handler read <paramref name="n"/> body bytes: credit them back (stream and connection) in batches.</summary>
    public void Consumed(H2Stream s, int n) => _ = CreditAsync(s, n);

    private async ValueTask CreditAsync(H2Stream? s, int n)
    {
        byte[]? connFrame = null, streamFrame = null;
        lock (_lock)
        {
            _connUnacked += n;
            if (_connUnacked >= ConnectionWindow / 2)
            {
                _connRecv += _connUnacked; // before the peer can use the new credit
                connFrame = FrameWriter.WindowUpdate(0, (int)_connUnacked);
                _connUnacked = 0;
            }
            if (s is not null && !s.RemoteClosed)
            {
                long credit = StreamWindow - s.RecvWindow;
                if (credit >= StreamWindow / 2)
                {
                    s.RecvWindow += credit;
                    streamFrame = FrameWriter.WindowUpdate(s.Id, (int)credit);
                }
            }
        }
        if (connFrame is null && streamFrame is null) return;
        try { await WriteAsync(connFrame ?? streamFrame!, connFrame is not null ? streamFrame : null).ConfigureAwait(false); }
        catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException) { }
    }

    // ------------------------------------------------------------------ writing

    public void WakeWriters()
    {
        TaskCompletionSource[] w;
        lock (_lock)
        {
            if (_windowWaiters.Count == 0) return;
            w = [.. _windowWaiters];
            _windowWaiters.Clear();
        }
        foreach (var t in w) t.TrySetResult();
    }

    /// <summary>Reserve up to <paramref name="want"/> bytes of both windows, waiting (under the stream's write deadline) while either is empty.</summary>
    private async ValueTask<int> ReserveAsync(H2Stream s, int want)
    {
        while (true)
        {
            Task wait;
            lock (_lock)
            {
                if (s.IsAborted || s.LocalClosed) throw new OperationCanceledException("stream reset");
                long avail = Math.Min(Math.Min(_connSend, s.SendWindow), want);
                if (avail > 0)
                {
                    _connSend -= avail;
                    s.SendWindow -= avail;
                    return (int)avail;
                }
                var t = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                _windowWaiters.Add(t);
                wait = t.Task;
            }
            await wait.ConfigureAwait(false);
        }
    }

    public async ValueTask SendDataAsync(H2Stream s, ReadOnlyMemory<byte> data, bool endStream)
    {
        // A client that never opens its window is cut at send_timeout; a tunnel keeps the idle timeout UpgradeAsync set.
        if (s.IdleRefreshMs == 0) s.WriteOpTimeout = _core.SendTimeoutMs;
        do
        {
            // One measured write: waiting for window (send_timeout applies) plus putting the frame on the wire.
            int n = 0;
            bool last;
            s.BeginWrite();
            try
            {
                if (!data.IsEmpty) n = await ReserveAsync(s, Math.Min(data.Length, _peerMaxFrame)).ConfigureAwait(false);
                last = endStream && n == data.Length;
                var frame = ArrayPool<byte>.Shared.Rent(FrameReader.HeaderSize + n);
                try
                {
                    FrameWriter.Header(frame, n, FrameType.Data, last ? FrameFlags.EndStream : (byte)0, s.Id);
                    data.Span[..n].CopyTo(frame.AsSpan(FrameReader.HeaderSize));
                    await WriteStreamAsync(s, frame.AsMemory(0, FrameReader.HeaderSize + n), last).ConfigureAwait(false);
                }
                finally { ArrayPool<byte>.Shared.Return(frame); }
            }
            finally { s.EndWrite(n); }
            Interlocked.Increment(ref _earned);
            data = data[n..];
            if (last) return;
        }
        while (!data.IsEmpty);
    }

    /// <summary>A field block as HEADERS (and CONTINUATION, past the peer's frame size), written contiguously.</summary>
    public async ValueTask SendHeadersAsync(H2Stream s, ReadOnlyMemory<byte> block, bool endStream)
    {
        int frames = Math.Max(1, (block.Length + _peerMaxFrame - 1) / _peerMaxFrame);
        var buf = ArrayPool<byte>.Shared.Rent(block.Length + frames * FrameReader.HeaderSize);
        try
        {
            int pos = 0, at = 0;
            for (int k = 0; k < frames; k++)
            {
                int n = Math.Min(_peerMaxFrame, block.Length - at);
                byte flags = (byte)((k == frames - 1 ? FrameFlags.EndHeaders : 0) | (k == 0 && endStream ? FrameFlags.EndStream : 0));
                FrameWriter.Header(buf.AsSpan(pos), n, k == 0 ? FrameType.Headers : FrameType.Continuation, flags, s.Id);
                block.Span.Slice(at, n).CopyTo(buf.AsSpan(pos + FrameReader.HeaderSize));
                pos += FrameReader.HeaderSize + n;
                at += n;
            }
            await WriteStreamAsync(s, buf.AsMemory(0, pos), endStream).ConfigureAwait(false);
        }
        finally { ArrayPool<byte>.Shared.Return(buf); }
    }

    private async ValueTask WriteStreamAsync(H2Stream s, ReadOnlyMemory<byte> frames, bool ends)
    {
        await _write.WaitAsync().ConfigureAwait(false);
        try
        {
            if (s.LocalClosed || _writeClosed) throw new OperationCanceledException("stream reset");
            if (ends) s.LocalClosed = true;
            _conn.WriteOpTimeout = _core.SendTimeoutMs;
            await _transport.WriteAsync(frames).ConfigureAwait(false);
        }
        finally { _write.Release(); }
    }

    private async ValueTask WriteAsync(byte[] a, byte[]? b = null)
    {
        await _write.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_writeClosed) return;
            _conn.WriteOpTimeout = _core.SendTimeoutMs;
            await _transport.WriteAsync(a).ConfigureAwait(false);
            if (b is not null) await _transport.WriteAsync(b).ConfigureAwait(false);
        }
        finally { _write.Release(); }
    }

    /// <summary>Reset a stream from any thread (sweeper, handler, reader), without waiting.</summary>
    public void ResetLater(H2Stream s, H2Error code)
    {
        if (s.LocalClosed) return;
        s.LocalClosed = true;
        ResetLater(s.Id, code);
    }

    private void ResetLater(int sid, H2Error code)
    {
        lock (_resetIds)
        {
            if (!_resetIds.Add(sid)) return; // one RST_STREAM per stream
            _resetOrder.Enqueue(sid);
            if (_resetOrder.Count > 1024) _resetIds.Remove(_resetOrder.Dequeue());
        }
        _ = SafeWrite(FrameWriter.RstStream(sid, code));
    }

    // Streams we've reset (the most recent 1024): frames the client already had in flight on them are ignored.
    private readonly HashSet<int> _resetIds = new();
    private readonly Queue<int> _resetOrder = new();

    private bool WeReset(int sid)
    {
        lock (_resetIds) return _resetIds.Contains(sid);
    }

    private async Task SafeWrite(byte[] frame, byte[]? then = null)
    {
        try { await WriteAsync(frame, then).ConfigureAwait(false); }
        catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException) { }
    }

    /// <summary>
    /// Stop taking new streams (reload, shutdown, keepalive_requests); the ones running finish. In two steps (RFC 9113
    /// 6.8): a GOAWAY that refuses nothing yet, and a PING; when the PING comes back, requests the client sent before
    /// it saw the GOAWAY have arrived, and the final GOAWAY names the last of them. A single GOAWAY would drop the
    /// requests already on the wire, and the client couldn't tell whether they were processed.
    /// </summary>
    private void GoAwayLater(H2Error code)
    {
        if (Interlocked.CompareExchange(ref _goAwaySent, 1, 0) != 0) return;
        _ = SafeWrite(FrameWriter.GoAway(int.MaxValue, code), FrameWriter.Ping(DrainPing, ack: false));
        // A client that never answers the PING doesn't get to keep the connection: the final GOAWAY goes out anyway.
        _ = Task.Delay(1000).ContinueWith(static (_, s) => ((Http2Session)s!).FinalGoAway(), this, TaskScheduler.Default);
    }

    private void FinalGoAway()
    {
        if (Interlocked.Exchange(ref _goAwaySent, 2) == 2) return;
        int last;
        bool idle;
        lock (_lock)
        {
            _goingAway = true; // under the lock streams are admitted under: none gets in past "last"
            last = _goAwayLast = _lastStreamId;
            idle = _active == 0;
            // Queue the GOAWAY before releasing the lock. Once _goingAway is visible, the last stream's handler may
            // start the graceful close; queued first, the frame is written before that close marks writes closed.
            // (SafeWrite only queues here: the write lock is taken in order, nothing waits under _lock.)
            _ = SafeWrite(FrameWriter.GoAway(last, H2Error.NoError));
        }
        if (idle) CloseGracefully();
    }

    /// <summary>
    /// Nothing left to do: FIN after everything queued, then read until the client closes (bounded). Closing with the
    /// client's frames unread would reset the connection, and a reset loses our last frames.
    /// </summary>
    private void CloseGracefully()
    {
        if (Interlocked.Exchange(ref _closing, 1) != 0) return;
        _conn.Phase = "lingering close";
        _conn.BaseDeadline = Environment.TickCount64 + 2000;
        _ = CloseWriteAsync();
    }

    private async Task CloseWriteAsync()
    {
        await _write.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_writeClosed) return;
            _writeClosed = true;
            // A TCP FIN, no TLS close_notify: the reader still has a read pending on the SslStream, and OpenSSL's
            // SSL_shutdown racing SSL_read on one SSL corrupts its memory (seen as crashes in later handshakes).
            // HTTP/2 needs no close_notify: after GOAWAY, framing says the connection is complete.
            _conn.Socket.Shutdown(SocketShutdown.Send);
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException) { }
        finally { _write.Release(); }
    }

    /// <summary>
    /// After an error GOAWAY: stop sending and discard what the client still sends, briefly. Closing with its frames
    /// unread would reset the connection, and a reset makes the client drop our GOAWAY unread.
    /// </summary>
    private async ValueTask LingerAsync()
    {
        _conn.Phase = "lingering close";
        _conn.BaseDeadline = Environment.TickCount64 + 2000;
        try
        {
            // The reader has stopped (we're on it), and the write lock keeps handlers off the SslStream: only then may
            // TLS be shut down (OpenSSL doesn't tolerate SSL_shutdown racing another operation on the same SSL).
            await _write.WaitAsync().ConfigureAwait(false);
            try
            {
                if (!_writeClosed)
                {
                    _writeClosed = true;
                    if (_transport is SslStream ssl) await ssl.ShutdownAsync().ConfigureAwait(false);
                }
            }
            finally { _write.Release(); }
            _conn.Socket.Shutdown(SocketShutdown.Send);
            var buf = ArrayPool<byte>.Shared.Rent(16 << 10);
            try
            {
                long seen = 0;
                while (seen < 256 << 10)
                {
                    int n = await _conn.Socket.ReceiveAsync(buf.AsMemory(), SocketFlags.None).ConfigureAwait(false);
                    if (n <= 0) break;
                    seen += n;
                }
            }
            finally { ArrayPool<byte>.Shared.Return(buf); }
        }
        // Best-effort teardown: the client may already be gone, and close_notify then fails in ways of its own (an
        // exception type internal to .NET among them). Nothing here may escape as a connection failure.
        catch (Exception e) when (e is not OutOfMemoryException) { }
    }

    private async ValueTask GoAwayAsync(H2Error code)
    {
        int last;
        lock (_lock)
        {
            _goingAway = true;
            last = _goAwayLast = Math.Min(_goAwayLast, _lastStreamId);
        }
        if (Interlocked.Exchange(ref _goAwaySent, 2) == 2) return;
        try { await WriteAsync(FrameWriter.GoAway(last, code)).ConfigureAwait(false); }
        catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException) { }
    }
}
