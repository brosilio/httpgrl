using System.Buffers;
using System.Buffers.Text;

namespace Httpgrl.Core.Http;

/// <summary>How a response is put on the wire. One per exchange (an HTTP/1.1 connection; later, a stream).</summary>
internal abstract class ResponseWire
{
    /// <summary>Decide the framing and serialize the head (status, headers) for <paramref name="ctx"/>'s response.</summary>
    public abstract void BeginHead(HttpContextImpl ctx, int status, bool upgrade);
    /// <summary>Body bytes, already counted and length-checked by the response.</summary>
    public abstract ValueTask WriteBodyAsync(ReadOnlyMemory<byte> data);
    /// <summary>Whether <see cref="SendFileAsync"/> may be used (else file bodies go through <see cref="WriteBodyAsync"/>).</summary>
    public abstract bool DirectFileSend { get; }
    /// <summary>A file body without encoding; adds what it sends to <see cref="ResponseImpl.Sent"/> as it goes.</summary>
    public abstract ValueTask SendFileAsync(ResponseImpl resp, FileResource file, long offset, long count);
    /// <summary>Push everything buffered (the head too, if it hasn't gone yet).</summary>
    public abstract ValueTask FlushAsync();
    /// <summary>End the message (terminating framing, if any) and flush.</summary>
    public abstract ValueTask EndAsync(bool noBody);
    /// <summary>Between responses.</summary>
    public abstract void Reset();
    /// <summary>Give back pooled buffers (a response done or cut short).</summary>
    public abstract void Release();
}

/// <summary>
/// HTTP/1.1 on the wire. The head is serialized straight into a pooled output buffer and coalesced with the first body
/// bytes; file bodies are pread() into that same buffer (one copy, no extra syscalls). The buffer is only held while a
/// response is in flight.
/// </summary>
internal sealed class Http1ResponseWire(Stream transport) : ResponseWire
{
    private const int BufSize = 64 << 10;

    private byte[]? _buf;
    private int _len;
    private bool _chunked;

    public override bool DirectFileSend => !_chunked;

    public override void Reset()
    {
        _chunked = false;
        _len = 0;
    }

    public override void Release()
    {
        var b = _buf;
        _buf = null;
        _len = 0;
        if (b is not null) ArrayPool<byte>.Shared.Return(b);
    }

    private static bool IsCoreOwned(string name, bool upgrade) =>
        name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Date", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Server", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase)
        || (!upgrade && name.Equals("Connection", StringComparison.OrdinalIgnoreCase));

    public override void BeginHead(HttpContextImpl ctx, int status, bool upgrade)
    {
        var req = ctx.Req;
        var resp = ctx.Resp;
        _chunked = false;
        long cl = resp.ContentLength;
        if (!upgrade && cl < 0 && !HttpStatus.HasNoBody(status) && !req.IsHead)
        {
            if (req.VersionValue == HttpVersion.Http11) _chunked = true;
            else ctx.SetKeepAlive(false); // close-delimited
        }

        int need = 256;
        var h = resp.Headers;
        for (int i = 0; i < h.Count; i++) need += h.NameAt(i).Length + h.ValueAt(i).Length + 4;
        _buf ??= ArrayPool<byte>.Shared.Rent(Math.Max(BufSize, need));
        if (_buf.Length < need)
        {
            ArrayPool<byte>.Shared.Return(_buf);
            _buf = ArrayPool<byte>.Shared.Rent(need);
        }
        var w = new SpanWriter(_buf.AsSpan(_len));
        w.Write(HttpStatus.StatusLine(status));
        if (ctx.Loc.Core.Tokens) w.Write(ServerInfo.HeaderWithVersion);
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

    public override ValueTask WriteBodyAsync(ReadOnlyMemory<byte> data) => _chunked ? WriteChunkAsync(data) : AppendAsync(data);

    private async ValueTask WriteChunkAsync(ReadOnlyMemory<byte> data)
    {
        if (_buf!.Length - _len < 32) await FlushAsync().ConfigureAwait(false);
        Utf8Formatter.TryFormat((ulong)data.Length, _buf.AsSpan(_len), out int n, new StandardFormat('x'));
        _len += n;
        _buf[_len++] = (byte)'\r';
        _buf[_len++] = (byte)'\n';
        await AppendAsync(data).ConfigureAwait(false);
        if (_buf.Length - _len < 2) await FlushAsync().ConfigureAwait(false);
        _buf[_len++] = (byte)'\r';
        _buf[_len++] = (byte)'\n';
    }

    public override async ValueTask SendFileAsync(ResponseImpl resp, FileResource file, long offset, long count)
    {
        var buf = _buf!;
        while (count > 0)
        {
            if (buf.Length - _len < 4096) await FlushAsync().ConfigureAwait(false);
            int want = (int)Math.Min(buf.Length - _len, count);
            int n = file.Read(buf.AsSpan(_len, want), offset);
            if (n <= 0) throw new IOException("file truncated while sending");
            _len += n;
            resp.Sent += n;
            offset += n;
            count -= n;
            if (_len == buf.Length) await FlushAsync().ConfigureAwait(false);
        }
    }

    public override async ValueTask EndAsync(bool noBody)
    {
        if (_chunked && !noBody)
        {
            if (_buf!.Length - _len < 5) await FlushAsync().ConfigureAwait(false);
            "0\r\n\r\n"u8.CopyTo(_buf.AsSpan(_len));
            _len += 5;
        }
        await FlushAsync().ConfigureAwait(false);
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
        await FlushAsync().ConfigureAwait(false);
        if (data.Length >= buf.Length / 2) await transport.WriteAsync(data).ConfigureAwait(false);
        else
        {
            data.Span.CopyTo(buf);
            _len = data.Length;
        }
    }

    public override ValueTask FlushAsync()
    {
        if (_len == 0) return ValueTask.CompletedTask;
        int n = _len;
        _len = 0;
        return transport.WriteAsync(_buf.AsMemory(0, n));
    }
}
