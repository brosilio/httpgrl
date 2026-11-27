using Httpgrl.Core.Hosting;

namespace Httpgrl.Core.Http;

/// <summary>Thrown when the request body violates framing or limits; carries the status to answer with.</summary>
internal sealed class HttpBodyException(int status, string message) : IOException(message)
{
    public int Status { get; } = status;
}

/// <summary>
/// A request body as the core sees it, whatever carried it (HTTP/1.1 framing here; later, a stream's DATA frames).
/// Limits are set per request once the location is known.
/// </summary>
internal abstract class RequestBody : Stream
{
    public long MaxSize;
    public int ReadTimeoutMs;
    public int MinRate;
    /// <summary>HTTP/1.1 only: sent before the first read when the client asked for 100-continue.</summary>
    public Func<ValueTask>? SendContinue;

    /// <summary>True when the whole body has been consumed (or there was none).</summary>
    public abstract bool IsComplete { get; }
    public abstract bool Started { get; }
    /// <summary>Read and discard the rest, up to <paramref name="limit"/> bytes. False if that wasn't possible.</summary>
    public abstract ValueTask<bool> DrainAsync(long limit);

    public override bool CanRead => true;
    public override bool CanWrite => false;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>
/// HTTP/1.1 request body decoder (Content-Length or chunked). Consumes pipelined bytes from the shared input buffer
/// first. Enforces client_max_body_size, client_body_timeout (per read) and client_body_min_rate.
/// </summary>
internal sealed class BodyStream : RequestBody
{
    private enum Mode : byte { None, Length, Chunked }
    private enum Chunk : byte { Size, Data, DataEnd, Trailer, Done }

    private const int MaxChunkLine = 4096;
    private const int MaxTrailer = 8192;
    /// <summary>
    /// Chunk extensions (and whitespace before them) across a whole body. They're ignored, and nothing real sends them,
    /// but each chunk line may carry up to <see cref="MaxChunkLine"/>: uncounted, "1;&lt;4 KiB&gt;" per data byte made
    /// client_max_body_size (and the drain limit) a bound on ~1/4000 of the bytes actually read.
    /// </summary>
    internal const int MaxExtensionBytes = 8192;

    private readonly Deadlines _conn;
    private readonly InputBuffer _in;
    private Stream _transport = Null;
    private Mode _mode;
    private Chunk _chunk;
    private long _remaining;    // Length mode: bytes left; Chunked: bytes left in current chunk
    private long _total;
    private int _trailerBytes;
    private int _extensionBytes;
    private long _framing;      // chunked: size lines, extensions, CRLFs and trailers read so far (wire bytes beyond data)
    private bool _started;

    public BodyStream(Deadlines conn, InputBuffer input)
    {
        _conn = conn;
        _in = input;
    }

    public void Reset(Stream transport, long contentLength, bool chunked)
    {
        _transport = transport;
        _mode = chunked ? Mode.Chunked : contentLength > 0 ? Mode.Length : Mode.None;
        _chunk = Chunk.Size;
        _remaining = contentLength > 0 ? contentLength : 0;
        _total = 0;
        _trailerBytes = 0;
        _extensionBytes = 0;
        _framing = 0;
        _started = false;
        _broken = false;
        SendContinue = null;
    }

    public override bool IsComplete => _mode switch
    {
        Mode.None => true,
        Mode.Length => _remaining == 0,
        _ => _chunk == Chunk.Done,
    };

    public override bool Started => _started;
    public long Remaining => _mode == Mode.Length ? _remaining : -1;

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (buffer.IsEmpty || IsComplete) return 0;
        if (_broken) throw new HttpBodyException(400, "request body reading was abandoned");
        if (!_started) await StartAsync().ConfigureAwait(false);
        _conn.ReadOpTimeout = ReadTimeoutMs;
        _ct = ct;
        int n;
        try { n = _mode == Mode.Length ? await ReadLengthAsync(buffer).ConfigureAwait(false) : await ReadChunkedAsync(buffer).ConfigureAwait(false); }
        catch (OperationCanceledException)
        {
            // The reader gave up on the body (a proxied upstream answered before it was all sent). Its framing state is
            // lost, so the connection can't carry another request: DrainAsync refuses and the session closes it.
            _broken = true;
            _conn.StopRate();
            throw;
        }
        finally { _ct = default; }
        if (IsComplete) _conn.StopRate();
        return n;
    }

    private CancellationToken _ct;
    private bool _broken;

    private async ValueTask StartAsync()
    {
        _started = true;
        if (_mode == Mode.Length && MaxSize > 0 && _remaining > MaxSize)
            throw new HttpBodyException(413, "request body too large");
        _conn.Phase = "request body";
        if (SendContinue is { } send) { SendContinue = null; await send().ConfigureAwait(false); }
        _conn.StartRate(MinRate);
    }

    private async ValueTask<int> ReadLengthAsync(Memory<byte> buffer)
    {
        int want = (int)Math.Min(buffer.Length, _remaining);
        int n;
        if (_in.Count > 0)
        {
            n = Math.Min(want, _in.Count);
            _in.Buf.AsSpan(_in.Start, n).CopyTo(buffer.Span);
            _in.Consume(n);
        }
        else
        {
            n = await _transport.ReadAsync(buffer[..want], _ct).ConfigureAwait(false);
            if (n == 0) throw new HttpBodyException(400, "client closed connection while sending body");
        }
        _remaining -= n;
        return n;
    }

    private async ValueTask<int> ReadChunkedAsync(Memory<byte> buffer)
    {
        while (true)
        {
            switch (_chunk)
            {
                case Chunk.Size:
                {
                    int len = await LineAsync().ConfigureAwait(false);
                    long size = ParseChunkSize(_in.Buf.AsSpan(_in.Start, len - 2));
                    int ext = len - 2 - HexDigits(_in.Buf.AsSpan(_in.Start, len - 2));
                    _in.Consume(len);
                    if (size < 0) throw new HttpBodyException(400, "invalid chunk size");
                    _framing += len;
                    if ((_extensionBytes += ext) > MaxExtensionBytes) throw new HttpBodyException(400, "chunk extensions too large");
                    if (size == 0) { _chunk = Chunk.Trailer; continue; }
                    _total += size;
                    if (MaxSize > 0 && _total > MaxSize) throw new HttpBodyException(413, "request body too large");
                    _remaining = size;
                    _chunk = Chunk.Data;
                    continue;
                }
                case Chunk.Data:
                {
                    if (_in.Count == 0 && await FillAsync().ConfigureAwait(false) == 0)
                        throw new HttpBodyException(400, "client closed connection while sending body");
                    int n = (int)Math.Min(Math.Min(buffer.Length, _remaining), _in.Count);
                    _in.Buf.AsSpan(_in.Start, n).CopyTo(buffer.Span);
                    _in.Consume(n);
                    _remaining -= n;
                    if (_remaining == 0) _chunk = Chunk.DataEnd;
                    return n;
                }
                case Chunk.DataEnd:
                {
                    while (_in.Count < 2)
                        if (await FillAsync().ConfigureAwait(false) == 0) throw new HttpBodyException(400, "truncated chunk");
                    if (_in.Buf[_in.Start] != '\r' || _in.Buf[_in.Start + 1] != '\n') throw new HttpBodyException(400, "missing chunk terminator");
                    _in.Consume(2);
                    _framing += 2;
                    _chunk = Chunk.Size;
                    continue;
                }
                case Chunk.Trailer:
                {
                    int len = await LineAsync().ConfigureAwait(false);
                    _trailerBytes += len;
                    _framing += len;
                    if (_trailerBytes > MaxTrailer) throw new HttpBodyException(431, "trailer too large");
                    // Dropped, but validated: a bare CR (or any CTL) is where parsers disagree about the line structure.
                    if (len > 2 && !ValidTrailer(_in.Buf.AsSpan(_in.Start, len - 2))) throw new HttpBodyException(400, "invalid trailer field");
                    _in.Consume(len);
                    if (len == 2) { _chunk = Chunk.Done; return 0; }
                    continue;
                }
                default:
                    return 0;
            }
        }
    }

    /// <summary>Ensure a full CRLF-terminated line is buffered; returns its length including CRLF.</summary>
    private async ValueTask<int> LineAsync()
    {
        while (true)
        {
            int nl = _in.Data.IndexOf((byte)'\n');
            if (nl >= 0)
            {
                if (nl == 0 || _in.Buf[_in.Start + nl - 1] != '\r') throw new HttpBodyException(400, "bare LF in chunked body");
                return nl + 1;
            }
            if (_in.Count >= MaxChunkLine) throw new HttpBodyException(400, "chunk line too long");
            if (await FillAsync().ConfigureAwait(false) == 0) throw new HttpBodyException(400, "truncated chunked body");
        }
    }

    private async ValueTask<int> FillAsync()
    {
        int n = await _in.FillAsync(_transport, Math.Max(_in.Buf.Length, MaxChunkLine), _ct).ConfigureAwait(false);
        return n < 0 ? throw new HttpBodyException(400, "chunk line too long") : n;
    }

    private static int HexDigits(ReadOnlySpan<byte> line)
    {
        int i = 0;
        while (i < line.Length && char.IsAsciiHexDigit((char)line[i])) i++;
        return i;
    }

    /// <summary>Hex size, optional ";ext" (validated as visible ASCII, otherwise ignored). -1 on error.</summary>
    internal static long ParseChunkSize(ReadOnlySpan<byte> line)
    {
        long size = 0;
        int i = 0, digits = 0;
        for (; i < line.Length; i++)
        {
            int c = line[i], v;
            if ((uint)(c - '0') <= 9) v = c - '0';
            else if ((uint)((c | 0x20) - 'a') <= 5) v = (c | 0x20) - 'a' + 10;
            else break;
            if (++digits > 15) return -1;
            size = (size << 4) | (uint)v;
        }
        if (digits == 0) return -1;
        while (i < line.Length && (line[i] == ' ' || line[i] == '\t')) i++;
        if (i < line.Length)
        {
            if (line[i] != ';') return -1;
            for (; i < line.Length; i++) if ((line[i] < 0x20 && line[i] != '\t') || line[i] == 0x7F) return -1;
        }
        return size;
    }

    /// <summary>A trailer line (without CRLF): token name, ':', value with no control characters but HTAB.</summary>
    internal static bool ValidTrailer(ReadOnlySpan<byte> line)
    {
        int colon = line.IndexOf((byte)':');
        if (colon <= 0) return false;
        foreach (byte b in line[..colon]) if (!HttpChars.IsToken(b)) return false;
        foreach (byte b in line[(colon + 1)..]) if ((b < 0x20 && b != '\t') || b == 0x7F) return false;
        return true;
    }

    /// <summary>
    /// Discard up to <paramref name="limit"/> more bytes of body, counted as read off the wire (chunk framing too, so
    /// the limit bounds the work done). False if the body is larger or broken.
    /// </summary>
    public override async ValueTask<bool> DrainAsync(long limit)
    {
        if (IsComplete) return true;
        if (_broken || (_mode == Mode.Length && _remaining > limit)) return false;
        var tmp = System.Buffers.ArrayPool<byte>.Shared.Rent(8192);
        try
        {
            long seen = 0, framing0 = _framing;
            long savedMax = MaxSize;
            MaxSize = 0;
            if (!_started) { _started = true; _conn.Phase = "request body"; _conn.StartRate(MinRate); }
            _conn.ReadOpTimeout = ReadTimeoutMs;
            while (!IsComplete)
            {
                int n = _mode == Mode.Length ? await ReadLengthAsync(tmp).ConfigureAwait(false) : await ReadChunkedAsync(tmp).ConfigureAwait(false);
                seen += n;
                if (seen + (_framing - framing0) > limit) return false;
            }
            MaxSize = savedMax;
            _conn.StopRate();
            return true;
        }
        catch (HttpBodyException) { return false; }
        finally { System.Buffers.ArrayPool<byte>.Shared.Return(tmp); }
    }

    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) => ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();
}
