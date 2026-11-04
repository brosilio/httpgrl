using System.Buffers;
using System.Buffers.Text;

namespace Httpgrl.Core.Http;

/// <summary>
/// The response as modules and the core see it, protocol-neutral: status and headers, header filters, body encoders
/// (compression), Content-Length accounting, HEAD/no-body rules and the response deadlines. How it goes on the wire
/// (HTTP/1.1 status line, chunking, buffering) is the <see cref="ResponseWire"/>'s business.
/// </summary>
internal sealed class ResponseImpl(HttpContextImpl ctx, ResponseWire wire) : HttpResponse
{
    private bool _started, _noBody, _inFilters;
    /// <summary>Body bytes on the wire so far (after any encoder). The wire adds to it on its direct file path.</summary>
    internal long Sent;
    private Func<Stream, Stream>? _encoderFactory;
    private Stream? _encoder;
    private Sink? _sink;

    public override bool HasStarted => _started;
    public override long BodyBytesSent => Sent;

    public void Reset()
    {
        Status = 200;
        Headers.Clear();
        ContentLength = -1;
        _started = _noBody = _inFilters = false;
        Sent = 0;
        ReturnBuffer();
        wire.Reset();
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
        wire.Release();
    }

    public override async ValueTask StartAsync()
    {
        if (!_started) BuildHead();
        await wire.FlushAsync().ConfigureAwait(false);
    }

    public override async ValueTask FlushAsync()
    {
        if (!_started) BuildHead();
        if (_encoder is not null) await _encoder.FlushAsync().ConfigureAwait(false);
        await wire.FlushAsync().ConfigureAwait(false);
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> data)
    {
        if (!_started) BuildHead();
        if (_noBody || data.IsEmpty) return ValueTask.CompletedTask;
        if (_encoder is not null) return _encoder.WriteAsync(data);
        return WriteFramedAsync(data);
    }

    /// <summary>Body bytes as they go on the wire (after any encoder): length-checked, then framed by the wire.</summary>
    private ValueTask WriteFramedAsync(ReadOnlyMemory<byte> data)
    {
        if (data.IsEmpty) return ValueTask.CompletedTask;
        if (ContentLength >= 0 && Sent + data.Length > ContentLength) throw new InvalidOperationException("response body exceeds Content-Length");
        Sent += data.Length;
        return wire.WriteBodyAsync(data);
    }

    public override async ValueTask SendFileAsync(FileResource file, long offset, long count)
    {
        if (!_started) BuildHead();
        if (_noBody || count <= 0) return;
        if (ContentLength >= 0 && Sent + count > ContentLength) throw new InvalidOperationException("response body exceeds Content-Length");
        if (!wire.DirectFileSend || _encoder is not null)
        {
            var tmp = ArrayPool<byte>.Shared.Rent(32 << 10);
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
        await wire.SendFileAsync(this, file, offset, count).ConfigureAwait(false);
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
        await wire.EndAsync(_noBody).ConfigureAwait(false);
        ctx.Timing.StopRate();
        return _noBody || ContentLength < 0 || Sent == ContentLength;
    }

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
        _noBody = ctx.Req.IsHead || HttpStatus.HasNoBody(status);

        var core = ctx.Loc.Core;
        var t = ctx.Timing;
        t.WriteOpTimeout = core.SendTimeoutMs;
        t.Phase = "response";
        if (t.MeasuresSendRate) t.StartRate(core.SendMinRateBps);

        // Advertise HTTP/3 on the other protocols' responses (an explicit add_header Alt-Svc wins).
        if (ctx.ServerRt?.AltSvc is { } alt && ctx.Req.VersionValue < HttpVersion.Http30 && !Headers.Contains("Alt-Svc")) Headers.Set("Alt-Svc", alt);
        wire.BeginHead(ctx, status, upgrade);

        if (_encoderFactory is not null && !_noBody && !upgrade)
        {
            _sink ??= new Sink(this);
            _sink.Dead = false;
            _encoder = _encoderFactory(_sink);
        }
        _encoderFactory = null;
    }
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
