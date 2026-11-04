using System.Buffers;
using System.Buffers.Text;

namespace Httpgrl.Core.Http;

/// <summary>
/// HTTP/1.1 response writer. The head is serialized straight into a pooled output buffer and coalesced
/// with the first body bytes; file bodies are pread() into that same buffer (one copy, no extra syscalls).
/// The buffer is only held while a response is in flight.
/// </summary>
internal sealed class ResponseImpl(HttpContextImpl ctx) : HttpResponse
{
    private const int BufSize = 64 << 10;

    private byte[]? _buf;
    private int _len;
    private bool _started, _chunked, _noBody, _inFilters;
    private long _sent;
    private Func<Stream, Stream>? _encoderFactory;
    private Stream? _encoder;
    private Sink? _sink;

    public override bool HasStarted => _started;
    public override long BodyBytesSent => _sent;

    public void Reset()
    {
        Status = 200;
        Headers.Clear();
        ContentLength = -1;
        _started = _chunked = _noBody = _inFilters = false;
        _sent = 0;
        _len = 0;
        ReturnBuffer();
    }

    public override void EncodeBody(Func<Stream, Stream> encoder)
    {
        if (!_inFilters) throw new InvalidOperationException("EncodeBody is only allowed in a header filter");
        _encoderFactory = encoder;
        ContentLength = -1;
    }

    /// <summary>A response that didn't complete: release the encoder's (native) state without writing anything more.</summary>
    private void DropEncoder()
    {
        _encoderFactory = null;
        var e = _encoder;
        _encoder = null;
        if (e is null) return;
        _sink!.Dead = true;
        try { e.Dispose(); } catch (Exception) { /* nothing more can be sent anyway */ }
    }

    /// <summary>Where an encoder writes: the normal framed body path.</summary>
    private sealed class Sink(ResponseImpl r) : Stream
    {
        public bool Dead;
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default) => Dead ? ValueTask.CompletedTask : r.WriteFramedAsync(data);
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) => WriteAsync(buffer.AsMemory(offset, count), ct).AsTask();
        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        public override Task FlushAsync(CancellationToken ct) => Task.CompletedTask; // ResponseImpl.FlushAsync pushes the buffer
        public override void Flush() { }
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    public void ReturnBuffer()
    {
        DropEncoder(); // a response cut short (broken connection) never reached CompleteAsync
        var b = _buf;
        _buf = null;
        if (b is not null) ArrayPool<byte>.Shared.Return(b);
    }

    public override async ValueTask StartAsync()
    {
        if (!_started) BuildHead();
        await FlushBufAsync().ConfigureAwait(false);
    }

    public override async ValueTask FlushAsync()
    {
        if (!_started) BuildHead();
        if (_encoder is not null) await _encoder.FlushAsync().ConfigureAwait(false);
        await FlushBufAsync().ConfigureAwait(false);
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> data)
    {
        if (!_started) BuildHead();
        if (_noBody || data.IsEmpty) return ValueTask.CompletedTask;
        if (_encoder is not null) return _encoder.WriteAsync(data);
        return WriteFramedAsync(data);
    }

    /// <summary>Body bytes as they go on the wire (after any encoder): length-checked, chunk-framed if chunked.</summary>
    private ValueTask WriteFramedAsync(ReadOnlyMemory<byte> data)
    {
        if (data.IsEmpty) return ValueTask.CompletedTask;
        if (ContentLength >= 0 && _sent + data.Length > ContentLength) throw new InvalidOperationException("response body exceeds Content-Length");
        _sent += data.Length;
        if (!_chunked) return AppendAsync(data);
        return WriteChunkAsync(data);
    }

    private async ValueTask WriteChunkAsync(ReadOnlyMemory<byte> data)
    {
        if (_buf!.Length - _len < 32) await FlushBufAsync().ConfigureAwait(false);
        Utf8Formatter.TryFormat((ulong)data.Length, _buf.AsSpan(_len), out int n, new StandardFormat('x'));
        _len += n;
        _buf[_len++] = (byte)'\r';
        _buf[_len++] = (byte)'\n';
        await AppendAsync(data).ConfigureAwait(false);
        if (_buf.Length - _len < 2) await FlushBufAsync().ConfigureAwait(false);
        _buf[_len++] = (byte)'\r';
        _buf[_len++] = (byte)'\n';
    }

    public override async ValueTask SendFileAsync(FileResource file, long offset, long count)
    {
        if (!_started) BuildHead();
        if (_noBody || count <= 0) return;
        if (ContentLength >= 0 && _sent + count > ContentLength) throw new InvalidOperationException("response body exceeds Content-Length");
        if (_chunked || _encoder is not null)
        {
            var tmp = ArrayPool<byte>.Shared.Rent(BufSize / 2);
            try
            {
                while (count > 0)
                {
                    int n = file.Read(tmp.AsSpan(0, (int)Math.Min(tmp.Length, count)), offset);
                    if (n <= 0) throw new IOException("file truncated while sending");
                    await WriteAsync(tmp.AsMemory(0, n)).ConfigureAwait(false);
                    offset += n;
                    count -= n;
                }
            }
            finally { ArrayPool<byte>.Shared.Return(tmp); }
            return;
        }
        var buf = _buf!;
        while (count > 0)
        {
            if (buf.Length - _len < 4096) await FlushBufAsync().ConfigureAwait(false);
            int want = (int)Math.Min(buf.Length - _len, count);
            int n = file.Read(buf.AsSpan(_len, want), offset);
            if (n <= 0) throw new IOException("file truncated while sending");
            _len += n;
            _sent += n;
            offset += n;
            count -= n;
            if (_len == buf.Length) await FlushBufAsync().ConfigureAwait(false);
        }
    }

    /// <summary>Finish the message. Returns false if the declared framing could not be honoured (connection must close).</summary>
    public async ValueTask<bool> CompleteAsync()
    {
        if (!_started)
        {
            if (ContentLength < 0) ContentLength = 0;
            BuildHead();
        }
        if (_encoder is not null)
        {
            var e = _encoder;
            _encoder = null;
            _encoderFactory = null;
            await e.DisposeAsync().ConfigureAwait(false); // writes the encoder's trailer through the sink
        }
        if (_chunked && !_noBody)
        {
            if (_buf!.Length - _len < 5) await FlushBufAsync().ConfigureAwait(false);
            "0\r\n\r\n"u8.CopyTo(_buf.AsSpan(_len));
            _len += 5;
        }
        await FlushBufAsync().ConfigureAwait(false);
        ctx.Conn.StopRate();
        return _noBody || ContentLength < 0 || _sent == ContentLength;
    }

    private async ValueTask AppendAsync(ReadOnlyMemory<byte> data)
    {
        var buf = _buf!;
        if (data.Length <= buf.Length - _len)
        {
            data.Span.CopyTo(buf.AsSpan(_len));
            _len += data.Length;
            return;
        }
        await FlushBufAsync().ConfigureAwait(false);
        if (data.Length >= buf.Length / 2) await ctx.Transport.WriteAsync(data).ConfigureAwait(false);
        else
        {
            data.Span.CopyTo(buf);
            _len = data.Length;
        }
    }

    private ValueTask FlushBufAsync()
    {
        if (_len == 0) return ValueTask.CompletedTask;
        int n = _len;
        _len = 0;
        return ctx.Transport.WriteAsync(_buf.AsMemory(0, n));
    }

    private static bool IsCoreOwned(string name, bool upgrade) =>
        name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Date", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Server", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase)
        || (!upgrade && name.Equals("Connection", StringComparison.OrdinalIgnoreCase));

    private void BuildHead()
    {
        _started = true;
        if (ctx.StatusOverride > 0 && Status == 200) Status = ctx.StatusOverride;
        _inFilters = true;
        foreach (var f in ctx.Rt.Pipeline.HeaderFilters)
        {
            try { f(ctx); }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                ctx.Log.Error("header filter failed", new("conn", ctx.Info.Id), new("error", e.GetType().Name), new("detail", e.Message));
            }
        }
        _inFilters = false;
        int status = Status;
        if (status is < 100 or > 599) throw new InvalidOperationException($"invalid status {status}");
        bool upgrade = status == 101;
        var req = ctx.Req;
        _noBody = req.IsHead || HttpStatus.HasNoBody(status);
        _chunked = false;
        long cl = ContentLength;
        if (!upgrade && cl < 0 && !HttpStatus.HasNoBody(status) && !req.IsHead)
        {
            if (req.VersionValue == HttpVersion.Http11) _chunked = true;
            else ctx.SetKeepAlive(false); // close-delimited
        }

        var core = ctx.Loc.Core;
        conn.WriteOpTimeout = core.SendTimeoutMs;
        conn.Phase = "response";
        conn.StartRate(core.SendMinRateBps);

        int need = 256;
        var h = Headers;
        for (int i = 0; i < h.Count; i++) need += h.NameAt(i).Length + h.ValueAt(i).Length + 4;
        _buf ??= ArrayPool<byte>.Shared.Rent(Math.Max(BufSize, need));
        if (_buf.Length < need)
        {
            ArrayPool<byte>.Shared.Return(_buf);
            _buf = ArrayPool<byte>.Shared.Rent(need);
        }
        var w = new SpanWriter(_buf.AsSpan(_len));
        w.Write(HttpStatus.StatusLine(status));
        if (core.Tokens) w.Write(ServerInfo.HeaderWithVersion);
        w.Write(HttpDate.Header);
        for (int i = 0; i < h.Count; i++)
        {
            var name = h.NameAt(i);
            if (IsCoreOwned(name, upgrade)) continue;
            w.WriteLatin1(name);
            w.Write(": "u8);
            w.WriteLatin1(h.ValueAt(i));
            w.Write("\r\n"u8);
        }
        if (!upgrade)
        {
            if (cl >= 0 && status >= 200 && status != 204 && status != 304)
            {
                w.Write("Content-Length: "u8);
                w.WriteLong(cl);
                w.Write("\r\n"u8);
            }
            else if (_chunked) w.Write("Transfer-Encoding: chunked\r\n"u8);

            if (!ctx.KeepAlive) w.Write("Connection: close\r\n"u8);
            else if (req.VersionValue == HttpVersion.Http10) w.Write("Connection: keep-alive\r\n"u8);
        }
        w.Write("\r\n"u8);
        _len += w.Position;

        if (_encoderFactory is not null && !_noBody && !upgrade)
        {
            _sink ??= new Sink(this);
            _sink.Dead = false;
            _encoder = _encoderFactory(_sink);
        }
        _encoderFactory = null;
    }

    private Hosting.Connection conn => ctx.Conn;
}

public static class ServerInfo
{
    /// <summary>
    /// The semver version from <c>&lt;Version&gt;</c> (pre-release labels included, e.g. 0.2.0-rc.1). Build metadata
    /// (the "+commit" the SDK appends) is dropped: it would put the source revision in every opt-in Server header.
    /// </summary>
    public static readonly string Version = Semver(
        System.Reflection.CustomAttributeExtensions.GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>(typeof(ServerInfo).Assembly)?.InformationalVersion
        ?? typeof(ServerInfo).Assembly.GetName().Version?.ToString(3) ?? "0.0.0");

    internal static string Semver(string v) => v.IndexOf('+') is var plus and >= 0 ? v[..plus] : v;
    internal static readonly byte[] HeaderWithVersion = System.Text.Encoding.ASCII.GetBytes("Server: httpgrl/" + Version + "\r\n");
}

/// <summary>Bounds-checked forward writer over a span (the caller pre-sizes the span).</summary>
internal ref struct SpanWriter(Span<byte> dest)
{
    private readonly Span<byte> _d = dest;
    public int Position;

    public void Write(ReadOnlySpan<byte> s)
    {
        s.CopyTo(_d[Position..]);
        Position += s.Length;
    }

    public void WriteLatin1(string s)
    {
        var d = _d.Slice(Position, s.Length);
        for (int i = 0; i < s.Length; i++) d[i] = (byte)s[i]; // HeaderCollection guarantees <= 0xFF
        Position += s.Length;
    }

    public void WriteLong(long v)
    {
        Utf8Formatter.TryFormat(v, _d[Position..], out int n);
        Position += n;
    }
}
