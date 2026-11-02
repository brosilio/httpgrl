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
    private bool _started, _chunked, _noBody;
    private long _sent;

    public override bool HasStarted => _started;
    public override long BodyBytesSent => _sent;

    public void Reset()
    {
        Status = 200;
        Headers.Clear();
        ContentLength = -1;
        _started = _chunked = _noBody = false;
        _sent = 0;
        _len = 0;
        ReturnBuffer();
    }

    public void ReturnBuffer()
    {
        var b = _buf;
        _buf = null;
        if (b is not null) ArrayPool<byte>.Shared.Return(b);
    }

    public override async ValueTask StartAsync()
    {
        if (!_started) BuildHead();
        await FlushBufAsync().ConfigureAwait(false);
    }

    public override ValueTask FlushAsync() => StartAsync();

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> data)
    {
        if (!_started) BuildHead();
        if (_noBody || data.IsEmpty) return ValueTask.CompletedTask;
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
        if (_chunked)
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
    }

    private Hosting.Connection conn => ctx.Conn;
}

public static class ServerInfo
{
    public static readonly string Version = typeof(ServerInfo).Assembly.GetName().Version?.ToString(3) ?? "0";
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
