using System.Buffers;
using Httpgrl.Core.Hosting;
using Httpgrl.Core.Http;

namespace Httpgrl.Core.Http2;

/// <summary>
/// One HTTP/2 request stream: its own deadlines (enforced by the sweeper; an expiry resets the stream, not the
/// connection), its request body and response wire, and its flow-control windows.
/// </summary>
internal sealed class H2Stream : Deadlines
{
    public readonly int Id;
    public readonly Http2Session Session;
    public readonly H2RequestBody Body;
    public readonly H2ResponseWire Wire;
    public HttpContextImpl Ctx = null!;
    /// <summary>What we may still send on this stream (the peer's window). Guarded by the session's lock.</summary>
    public long SendWindow;
    /// <summary>What the peer may still send us on this stream. Reader thread only.</summary>
    public long RecvWindow;
    /// <summary>The peer has sent END_STREAM (or reset it).</summary>
    public bool RemoteClosed;
    /// <summary>We've sent END_STREAM or RST_STREAM.</summary>
    public volatile bool LocalClosed;

    private readonly CancellationTokenSource _cts = new();
    private int _aborted;
    private string? _reason;

    public H2Stream(int id, Http2Session session, long sendWindow, long recvWindow)
    {
        Id = id;
        Session = session;
        SendWindow = sendWindow;
        RecvWindow = recvWindow;
        Body = new H2RequestBody(this);
        Wire = new H2ResponseWire(this);
    }

    public override bool MeasuresSendRate => false; // the connection measures it (its writes), see Http2Session

    public override CancellationToken AbortToken => _cts.Token;
    public override bool IsAborted => Volatile.Read(ref _aborted) != 0;
    public override string? AbortReason => _reason;

    /// <summary>Timed out (the sweeper), cut by the server, or reset by the peer: reset the stream and stop its handler.</summary>
    public override void Abort(string reason, bool graceful = false) => Abort(reason, H2Error.Cancel, sendReset: true);

    public void Abort(string reason, H2Error code, bool sendReset)
    {
        if (Interlocked.Exchange(ref _aborted, 1) != 0) return;
        _reason = reason;
        if (sendReset) Session.ResetLater(this, code);
        try { _cts.Cancel(); } catch (ObjectDisposedException) { }
        Body.Wake();
        Session.WakeWriters();
    }

    public void Dispose() => _cts.Dispose();
}

/// <summary>
/// The request body of a stream: DATA payloads queued by the session's reader, read by the handler. What's read is
/// credited back to the peer (WINDOW_UPDATE), so a handler that reads slowly holds the upload to its window.
/// </summary>
internal sealed class H2RequestBody(H2Stream stream) : RequestBody
{
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
    private long _received, _read;
    /// <summary>The declared content-length, or -1.</summary>
    public long Expected = -1;

    public override bool IsComplete
    {
        get { lock (_lock) return _ended && _queue.Count == 0; }
    }

    public override bool Started => _started;

    /// <summary>HTTP/2 doesn't share a byte stream with the next request: an unread body is ended with RST_STREAM(NO_ERROR) instead.</summary>
    public override ValueTask<bool> DrainAsync(long limit) => ValueTask.FromResult(true);

    /// <summary>Reader thread: a DATA payload. False if the stream must be reset (more than content-length).</summary>
    public bool Deliver(ReadOnlySpan<byte> data, bool end)
    {
        TaskCompletionSource? w;
        lock (_lock)
        {
            if (_ended || _failed) return true;
            _received += data.Length;
            if (Expected >= 0 && (_received > Expected || (end && _received != Expected))) { _failed = true; w = Take(); }
            else
            {
                if (!data.IsEmpty)
                {
                    var b = ArrayPool<byte>.Shared.Rent(data.Length);
                    data.CopyTo(b);
                    _queue.Enqueue(new Chunk(b, data.Length));
                }
                if (end) _ended = true;
                w = Take();
            }
        }
        w?.TrySetResult();
        return !_failed;
    }

    private TaskCompletionSource? Take()
    {
        var w = _waiter;
        _waiter = null;
        return w;
    }

    public void Wake()
    {
        TaskCompletionSource? w;
        lock (_lock) w = Take();
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
            lock (_lock)
            {
                if (_failed) throw new HttpBodyException(400, "request body doesn't match its content-length");
                if (_queue.Count > 0)
                {
                    var c = _queue.Peek();
                    int n = Math.Min(c.Len, buffer.Length);
                    c.Buf.AsSpan(c.Off, n).CopyTo(buffer.Span);
                    c.Off += n;
                    c.Len -= n;
                    if (c.Len == 0) { _queue.Dequeue(); ArrayPool<byte>.Shared.Return(c.Buf); }
                    _read += n;
                    stream.CountBytes(n); // the minimum rate is bytes over time spent waiting for them
                    if (MaxSize > 0 && _read > MaxSize) throw new HttpBodyException(413, "request body too large");
                    stream.Session.Consumed(stream, n);
                    if (_ended && _queue.Count == 0) stream.StopRate();
                    return n;
                }
                if (_ended) { stream.StopRate(); return 0; }
                if (stream.IsAborted) throw new OperationCanceledException("stream reset");
                _waiter ??= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                wait = _waiter.Task;
            }
            stream.ReadOpTimeout = ReadTimeoutMs;
            stream.BeginRead();
            try { await wait.WaitAsync(ct).ConfigureAwait(false); }
            finally { stream.EndRead(0); }
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) => ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();
    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    /// <summary>The stream becomes a tunnel: no body limits, rate or per-read timeout (its idle timeout governs, as on HTTP/1.1).</summary>
    public void PrepareTunnel()
    {
        _started = true;
        MaxSize = 0;
        MinRate = 0;
        ReadTimeoutMs = 0;
        SendContinue = null;
    }

    /// <summary>The stream is done: give back buffers; returns how many received bytes were never read (to credit the connection).</summary>
    public long Release()
    {
        lock (_lock)
        {
            long unread = 0;
            while (_queue.Count > 0)
            {
                var c = _queue.Dequeue();
                unread += c.Len;
                ArrayPool<byte>.Shared.Return(c.Buf);
            }
            _ended = true;
            return unread;
        }
    }
}

/// <summary>
/// A response on an HTTP/2 stream: one HEADERS block (HPACK, no connection-specific fields), then DATA frames within the
/// peer's flow-control windows and frame size. The head is held until the first body bytes or a flush, so a small
/// response goes out as HEADERS plus one DATA frame carrying END_STREAM.
/// </summary>
internal sealed class H2ResponseWire(H2Stream stream) : ResponseWire
{
    private byte[]? _head;
    private int _headLen;
    private bool _headPending, _noBody;
    private byte[]? _buf;
    private int _len;

    public override bool DirectFileSend => false;

    public override void Reset()
    {
        _headPending = _noBody = false;
        _headLen = _len = 0;
    }

    public override void Release()
    {
        if (_buf is { } b) { _buf = null; ArrayPool<byte>.Shared.Return(b); }
        _len = 0;
    }

    private static bool Excluded(string name) =>
        name.Equals("Connection", StringComparison.OrdinalIgnoreCase) || name.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) || name.Equals("Upgrade", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase) || name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Date", StringComparison.OrdinalIgnoreCase) || name.Equals("Server", StringComparison.OrdinalIgnoreCase);

    public override void BeginHead(HttpContextImpl ctx, int status, bool upgrade)
    {
        // An accepted WebSocket over HTTP/2 (RFC 8441) is a 200 on the CONNECT stream, not a 101; the tunnel's bytes are
        // DATA frames, and its end is the stream's END_STREAM.
        if (upgrade && !ctx.Req.ExtendedConnect) throw new InvalidOperationException("101 isn't possible on HTTP/2");
        var resp = ctx.Resp;
        _noBody = upgrade || ctx.Req.IsHead || HttpStatus.HasNoBody(status);
        _head ??= new byte[512];
        _headLen = 0;
        HpackEncoder.Encode(ref _head, ref _headLen, ":status", HttpStatus.Code(upgrade ? 200 : status));
        if (ctx.Loc.Core.Tokens) HpackEncoder.Encode(ref _head, ref _headLen, "server", "httpgrl/" + ServerInfo.Version);
        HpackEncoder.Encode(ref _head, ref _headLen, "date", HttpDate.Value);
        long cl = resp.ContentLength;
        if (cl >= 0 && status >= 200 && status != 204 && status != 304)
            HpackEncoder.Encode(ref _head, ref _headLen, "content-length", cl.ToString(System.Globalization.CultureInfo.InvariantCulture));
        var h = resp.Headers;
        for (int i = 0; i < h.Count; i++)
        {
            var name = h.NameAt(i);
            if (Excluded(name) || (upgrade && name.Equals("Sec-WebSocket-Accept", StringComparison.OrdinalIgnoreCase))) continue;
            HpackEncoder.Encode(ref _head, ref _headLen, name.ToLowerInvariant(), h.ValueAt(i));
        }
        _headPending = true;
    }

    public override ValueTask WriteBodyAsync(ReadOnlyMemory<byte> data)
    {
        _buf ??= ArrayPool<byte>.Shared.Rent(64 << 10);
        if (data.Length <= _buf.Length - _len)
        {
            data.Span.CopyTo(_buf.AsSpan(_len));
            _len += data.Length;
            return _len == _buf.Length ? SendAsync(endStream: false) : ValueTask.CompletedTask;
        }
        return WriteSlowAsync(data);
    }

    private async ValueTask WriteSlowAsync(ReadOnlyMemory<byte> data)
    {
        await SendAsync(endStream: false).ConfigureAwait(false);
        await stream.Session.SendDataAsync(stream, data, endStream: false).ConfigureAwait(false);
    }

    public override ValueTask SendFileAsync(ResponseImpl resp, FileResource file, long offset, long count) => throw new NotSupportedException();

    public override ValueTask FlushAsync() => SendAsync(endStream: false);

    public override ValueTask EndAsync(bool noBody) => SendAsync(endStream: true);

    /// <summary>A 1xx response ahead of the real one (100 Continue).</summary>
    public async ValueTask SendInterimAsync(int status)
    {
        byte[] block = new byte[16];
        int len = 0;
        HpackEncoder.Encode(ref block, ref len, ":status", HttpStatus.Code(status));
        await stream.Session.SendHeadersAsync(stream, block.AsMemory(0, len), endStream: false).ConfigureAwait(false);
    }

    private async ValueTask SendAsync(bool endStream)
    {
        if (stream.LocalClosed) return;
        if (_headPending)
        {
            _headPending = false;
            // A response without a body ends with its HEADERS frame.
            bool headEnds = endStream && (_noBody || _len == 0);
            await stream.Session.SendHeadersAsync(stream, _head.AsMemory(0, _headLen), headEnds).ConfigureAwait(false);
            if (headEnds) return;
        }
        if (_noBody)
        {
            if (endStream) await stream.Session.SendDataAsync(stream, default, endStream: true).ConfigureAwait(false);
            return;
        }
        if (_len > 0 || endStream)
        {
            int n = _len;
            _len = 0;
            await stream.Session.SendDataAsync(stream, _buf is null ? default : _buf.AsMemory(0, n), endStream).ConfigureAwait(false);
        }
    }
}

/// <summary>The duplex stream a module gets from UpgradeAsync on an HTTP/2 WebSocket: DATA frames both ways.</summary>
internal sealed class H2TunnelStream : Stream
{
    private readonly H2Stream _s;

    public H2TunnelStream(H2Stream s)
    {
        _s = s;
        s.Body.PrepareTunnel();
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => _s.Body.ReadAsync(buffer, ct);
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) => ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();
    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) =>
        buffer.IsEmpty ? ValueTask.CompletedTask : _s.Session.SendDataAsync(_s, buffer, endStream: false);
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
