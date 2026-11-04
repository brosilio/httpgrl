using System.Buffers;
using Httpgrl.Core.Hosting;
using Httpgrl.Core.Http;
using Httpgrl.Core.Quic;

namespace Httpgrl.Core.Http3;

/// <summary>
/// One HTTP/3 request stream, as the request pipeline sees it: its own deadlines (enforced by the sweeper; an expiry
/// resets the stream, not the connection), its request body and response wire. The QUIC stream itself lives on the
/// endpoint's thread; this object is the handler's side, and everything it does there goes through
/// <see cref="Http3Connection"/>.
/// </summary>
internal sealed class H3Stream : Deadlines
{
    public readonly long Id;
    public readonly Http3Connection Conn;
    public readonly H3RequestBody Body;
    public readonly H3ResponseWire Wire;
    public HttpContextImpl Ctx = null!;

    private readonly CancellationTokenSource _cts = new();
    private int _aborted;
    private string? _reason;

    public H3Stream(long id, Http3Connection conn)
    {
        Id = id;
        Conn = conn;
        Body = new H3RequestBody(this);
        Wire = new H3ResponseWire(this);
    }

    // A stream's bytes share the connection's congestion window with its siblings: its own rate says nothing about the
    // client. send_timeout (per write) still applies; QUIC's idle timeout covers a peer that stops acknowledging.
    public override bool MeasuresSendRate => false;

    public override CancellationToken AbortToken => _cts.Token;
    public override bool IsAborted => Volatile.Read(ref _aborted) != 0;
    public override string? AbortReason => _reason;

    /// <summary>Timed out (the sweeper) or cut by the server: reset the stream and stop the handler.</summary>
    public override void Abort(string reason, bool graceful = false) => Abort(reason, H3Error.RequestCancelled, reset: true);

    public void Abort(string reason, H3Error code, bool reset)
    {
        if (Interlocked.Exchange(ref _aborted, 1) != 0) return;
        _reason = reason;
        if (reset) Conn.ResetLater(this, code);
        try { _cts.Cancel(); } catch (ObjectDisposedException) { }
        Body.Wake();
        Wire.Fail();
    }

    public void Dispose() => _cts.Dispose();
}

/// <summary>
/// A request body: DATA payloads the endpoint's thread queues, read by the handler. The endpoint reads from the QUIC
/// stream only while less than <see cref="Window"/> is queued, and QUIC grants the peer more credit only as we read, so
/// a handler that reads slowly holds the upload to what's queued plus QUIC's stream window.
/// </summary>
internal sealed class H3RequestBody(H3Stream stream) : RequestBody
{
    public const int Window = 256 << 10;

    private sealed class Chunk(byte[] buf, int len)
    {
        public readonly byte[] Buf = buf;
        public int Off;
        public int Len = len;
    }

    private readonly Queue<Chunk> _queue = new();
    private readonly object _lock = new();
    private TaskCompletionSource? _waiter;
    private bool _ended, _started, _failed;
    private int _queued;
    private long _received, _read;
    /// <summary>The declared content-length, or -1.</summary>
    public long Expected = -1;

    public override bool IsComplete
    {
        get { lock (_lock) return _ended && _queue.Count == 0; }
    }

    public override bool Started => _started;

    /// <summary>Room for more: the endpoint keeps reading the QUIC stream while this holds.</summary>
    public bool HasRoom
    {
        get { lock (_lock) return _queued < Window && !_ended && !_failed; }
    }

    // HTTP/3 doesn't share a byte stream with the next request: an unread body is ended with STOP_SENDING.
    public override ValueTask<bool> DrainAsync(long limit) => ValueTask.FromResult(true);

    /// <summary>Endpoint thread: DATA payload (or the end). False if it overruns the declared content-length.</summary>
    public bool Deliver(ReadOnlySpan<byte> data, bool end)
    {
        TaskCompletionSource? w;
        lock (_lock)
        {
            if (_ended || _failed) return true;
            _received += data.Length;
            if (Expected >= 0 && (_received > Expected || (end && _received != Expected))) _failed = true;
            else
            {
                if (!data.IsEmpty)
                {
                    var b = ArrayPool<byte>.Shared.Rent(data.Length);
                    data.CopyTo(b);
                    _queue.Enqueue(new Chunk(b, data.Length));
                    _queued += data.Length;
                }
                if (end) _ended = true;
            }
            w = _waiter;
            _waiter = null;
        }
        w?.TrySetResult();
        return !_failed;
    }

    public void Wake()
    {
        TaskCompletionSource? w;
        lock (_lock) { w = _waiter; _waiter = null; }
        w?.TrySetResult();
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (buffer.IsEmpty) return 0;
        if (!_started)
        {
            _started = true;
            if (SendContinue is { } send) { SendContinue = null; await send().ConfigureAwait(false); }
            stream.Phase = "request body";
            stream.StartRate(MinRate);
        }
        while (true)
        {
            Task wait;
            bool resume = false;
            int n = 0;
            lock (_lock)
            {
                if (_failed) throw new HttpBodyException(400, "request body doesn't match its content-length");
                if (_queue.Count > 0)
                {
                    var c = _queue.Peek();
                    n = Math.Min(c.Len, buffer.Length);
                    c.Buf.AsSpan(c.Off, n).CopyTo(buffer.Span);
                    c.Off += n;
                    c.Len -= n;
                    if (c.Len == 0) { _queue.Dequeue(); ArrayPool<byte>.Shared.Return(c.Buf); }
                    resume = _queued >= Window && _queued - n < Window; // the endpoint stopped reading; it may go on
                    _queued -= n;
                    _read += n;
                    stream.CountBytes(n);
                    if (MaxSize > 0 && _read > MaxSize) throw new HttpBodyException(413, "request body too large");
                    if (_ended && _queue.Count == 0) stream.StopRate();
                }
                else if (_ended) { stream.StopRate(); return 0; }
                else if (stream.IsAborted) throw new OperationCanceledException("stream reset");
                if (n == 0)
                {
                    _waiter ??= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                    wait = _waiter.Task;
                }
                else wait = Task.CompletedTask;
            }
            if (n > 0)
            {
                if (resume) stream.Conn.ResumeReading(stream);
                return n;
            }
            stream.ReadOpTimeout = ReadTimeoutMs;
            stream.BeginRead();
            try { await wait.WaitAsync(ct).ConfigureAwait(false); }
            finally { stream.EndRead(0); }
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) => ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();
    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    /// <summary>The stream becomes a tunnel (WebSocket, RFC 9220): no body limits, rate or per-read timeout.</summary>
    public void PrepareTunnel()
    {
        _started = true;
        MaxSize = 0;
        MinRate = 0;
        ReadTimeoutMs = 0;
        SendContinue = null;
    }

    public void Release()
    {
        lock (_lock)
        {
            while (_queue.Count > 0) ArrayPool<byte>.Shared.Return(_queue.Dequeue().Buf);
            _queued = 0;
            _ended = true;
        }
    }
}

/// <summary>
/// A response on an HTTP/3 stream: one HEADERS frame (QPACK, no connection-specific fields), then DATA frames, then
/// the stream's FIN. The head waits for the first body bytes or a flush, so a small response is HEADERS plus one DATA
/// frame ending the stream. Writes wait until QUIC has taken the bytes (its stream send buffer is the back-pressure).
/// </summary>
internal sealed class H3ResponseWire(H3Stream stream) : ResponseWire
{
    private const int Room = 16; // in front of _buf's payload: space for a DATA frame header
    private byte[]? _head;
    private int _headLen;
    private bool _headPending, _noBody, _ended;
    private byte[]? _buf;
    private int _len;

    public override bool DirectFileSend => false;

    public override void Reset()
    {
        _headPending = _noBody = _ended = false;
        _headLen = _len = 0;
    }

    public override void Release()
    {
        if (_buf is { } b) { _buf = null; ArrayPool<byte>.Shared.Return(b); }
        _len = 0;
    }

    /// <summary>The stream is gone: make any write in progress fail rather than wait.</summary>
    public void Fail() => stream.Conn.FailWrites(stream);

    private static bool Excluded(string name) =>
        name.Equals("Connection", StringComparison.OrdinalIgnoreCase) || name.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) || name.Equals("Upgrade", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase) || name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Date", StringComparison.OrdinalIgnoreCase) || name.Equals("Server", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Alt-Svc", StringComparison.OrdinalIgnoreCase); // already on HTTP/3

    public override void BeginHead(HttpContextImpl ctx, int status, bool upgrade)
    {
        // An accepted WebSocket over HTTP/3 (RFC 9220) is a 200 on the CONNECT stream; its bytes are DATA frames.
        if (upgrade && !ctx.Req.ExtendedConnect) throw new InvalidOperationException("101 isn't possible on HTTP/3");
        var resp = ctx.Resp;
        _noBody = upgrade || ctx.Req.IsHead || HttpStatus.HasNoBody(status);
        _head ??= new byte[512];
        _headLen = Room; // the frame header goes in front once the block's length is known
        QpackEncoder.Begin(ref _head, ref _headLen);
        QpackEncoder.Encode(ref _head, ref _headLen, ":status", HttpStatus.Code(upgrade ? 200 : status));
        if (ctx.Loc.Core.Tokens) QpackEncoder.Encode(ref _head, ref _headLen, "server", "httpgrl/" + ServerInfo.Version);
        QpackEncoder.Encode(ref _head, ref _headLen, "date", HttpDate.Value);
        long cl = resp.ContentLength;
        if (cl >= 0 && status >= 200 && status != 204 && status != 304)
            QpackEncoder.Encode(ref _head, ref _headLen, "content-length", cl.ToString(System.Globalization.CultureInfo.InvariantCulture));
        var h = resp.Headers;
        for (int i = 0; i < h.Count; i++)
        {
            var name = h.NameAt(i);
            if (Excluded(name) || (upgrade && name.Equals("Sec-WebSocket-Accept", StringComparison.OrdinalIgnoreCase))) continue;
            QpackEncoder.Encode(ref _head, ref _headLen, name.ToLowerInvariant(), h.ValueAt(i));
        }
        _headPending = true;
    }

    public override ValueTask WriteBodyAsync(ReadOnlyMemory<byte> data)
    {
        _buf ??= ArrayPool<byte>.Shared.Rent(Room + (64 << 10));
        if (data.Length <= _buf.Length - Room - _len)
        {
            data.Span.CopyTo(_buf.AsSpan(Room + _len));
            _len += data.Length;
            return _len == _buf.Length - Room ? SendAsync(end: false) : ValueTask.CompletedTask;
        }
        return WriteSlowAsync(data);
    }

    private async ValueTask WriteSlowAsync(ReadOnlyMemory<byte> data)
    {
        await SendAsync(end: false).ConfigureAwait(false);
        var hdr = new byte[Room];
        int n = H3FrameWriter.Header(hdr, H3FrameType.Data, data.Length);
        await stream.Conn.WriteAsync(stream, hdr.AsMemory(0, n), fin: false).ConfigureAwait(false);
        await stream.Conn.WriteAsync(stream, data, fin: false).ConfigureAwait(false);
    }

    public override ValueTask SendFileAsync(ResponseImpl resp, FileResource file, long offset, long count) => throw new NotSupportedException();

    public override ValueTask FlushAsync() => SendAsync(end: false);

    public override ValueTask EndAsync(bool noBody) => SendAsync(end: true);

    /// <summary>A 1xx response ahead of the real one (100 Continue).</summary>
    public ValueTask SendInterimAsync(int status)
    {
        var block = new byte[32];
        int len = Room;
        QpackEncoder.Begin(ref block, ref len);
        QpackEncoder.Encode(ref block, ref len, ":status", HttpStatus.Code(status));
        return stream.Conn.WriteAsync(stream, Frame(block, len, H3FrameType.Headers), fin: false);
    }

    /// <summary>The bytes buf[Room..len) as a frame of <paramref name="type"/>, its header written just in front.</summary>
    private static ReadOnlyMemory<byte> Frame(byte[] buf, int len, ulong type)
    {
        Span<byte> hdr = stackalloc byte[Room];
        int h = H3FrameWriter.Header(hdr, type, len - Room);
        hdr[..h].CopyTo(buf.AsSpan(Room - h));
        return buf.AsMemory(Room - h, len - Room + h);
    }

    private async ValueTask SendAsync(bool end)
    {
        if (_ended || stream.IsAborted) return;
        if (_headPending)
        {
            _headPending = false;
            bool headEnds = end && (_noBody || _len == 0);
            await stream.Conn.WriteAsync(stream, Frame(_head!, _headLen, H3FrameType.Headers), fin: headEnds).ConfigureAwait(false);
            if (headEnds) { _ended = true; return; }
        }
        if (_noBody || _len == 0)
        {
            if (end) { _ended = true; await stream.Conn.WriteAsync(stream, default, fin: true).ConfigureAwait(false); }
            return;
        }
        int n = _len;
        _len = 0;
        if (end) _ended = true;
        await stream.Conn.WriteAsync(stream, Frame(_buf!, Room + n, H3FrameType.Data), fin: end).ConfigureAwait(false);
    }
}

/// <summary>The duplex stream a module gets from UpgradeAsync on an HTTP/3 WebSocket (RFC 9220): DATA frames both ways.</summary>
internal sealed class H3TunnelStream : Stream
{
    private readonly H3Stream _s;

    public H3TunnelStream(H3Stream s)
    {
        _s = s;
        s.Body.PrepareTunnel();
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => _s.Body.ReadAsync(buffer, ct);
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) => ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();
    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        if (buffer.IsEmpty) return;
        var hdr = new byte[16];
        int n = H3FrameWriter.Header(hdr, H3FrameType.Data, buffer.Length);
        await _s.Conn.WriteAsync(_s, hdr.AsMemory(0, n), fin: false).ConfigureAwait(false);
        await _s.Conn.WriteAsync(_s, buffer, fin: false).ConfigureAwait(false);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) => WriteAsync(buffer.AsMemory(offset, count), ct).AsTask();
    public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override Task FlushAsync(CancellationToken ct) => Task.CompletedTask;
    public override void Flush() { }
    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
