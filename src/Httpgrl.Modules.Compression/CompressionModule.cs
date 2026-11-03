using System.Buffers;
using System.IO.Compression;

namespace Httpgrl.Modules.Compression;

public sealed class CompressionConf : ScopeConfig<CompressionConf>
{
    internal bool? Gzip, Brotli, Vary;
    internal int? GzipLevel, BrotliLevel;
    internal long? MinLength;
    internal string[]? Types;

    protected override void Inherit(CompressionConf p)
    {
        Gzip ??= p.Gzip;
        Brotli ??= p.Brotli;
        Vary ??= p.Vary;
        GzipLevel ??= p.GzipLevel;
        BrotliLevel ??= p.BrotliLevel;
        MinLength ??= p.MinLength;
        Types ??= p.Types;
    }
}

/// <summary>
/// Response compression: <c>gzip</c> (ngx_http_gzip_module) and <c>brotli</c> (as the ngx_brotli module), both from the
/// .NET base library. Brotli is preferred when the client accepts both. Compresses 200, 403 and 404 responses (as
/// nginx) whose type is in <c>gzip_types</c> and which aren't already encoded or marked <c>no-transform</c>.
/// Compressed responses get a weak ETag and lose Accept-Ranges (ranges would apply to the encoded bytes).
///
/// Deviations: <c>gzip_vary</c> defaults to <b>on</b> (caches must key on Accept-Encoding, or they serve gzip to
/// clients that can't read it); the default types cover common text formats rather than only text/html;
/// <c>gzip_proxied</c> isn't needed (responses compress whatever the request's Via header says).
/// </summary>
public sealed class CompressionModule : IModule
{
    public const int Order = 200; // after add_header, so its Vary/Content-Encoding edits are final

    private static readonly string[] DefaultTypes =
    [
        "text/html", "text/plain", "text/css", "text/xml", "text/javascript", "text/markdown", "text/csv",
        "application/javascript", "application/json", "application/xml", "application/rss+xml", "application/atom+xml",
        "application/ld+json", "application/manifest+json", "application/wasm", "image/svg+xml",
    ];

    private static readonly string[] Ignored = ["gzip_proxied", "gzip_disable", "gzip_buffers", "gzip_http_version", "gzip_static"];
    private readonly List<(string, SourceLocation)> _ignoredSeen = new();

    public string Name => "http_compression";

    public void Register(IModuleRegistry r)
    {
        var any = ContextKind.HttpAny;
        r.AddDirective(new() { Name = "gzip", Contexts = any, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<CompressionConf>().Gzip = i.Flag(0) });
        r.AddDirective(new() { Name = "brotli", Contexts = any, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<CompressionConf>().Brotli = i.Flag(0) });
        r.AddDirective(new() { Name = "gzip_vary", Contexts = any, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<CompressionConf>().Vary = i.Flag(0) });
        r.AddDirective(new() { Name = "gzip_comp_level", Contexts = any, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<CompressionConf>().GzipLevel = Level(i, 1, 9) });
        r.AddDirective(new() { Name = "brotli_comp_level", Contexts = any, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<CompressionConf>().BrotliLevel = Level(i, 0, 11) });
        r.AddDirective(new() { Name = "gzip_min_length", Contexts = any, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<CompressionConf>().MinLength = i.Size(0) });
        r.AddDirective(new() { Name = "gzip_types", Contexts = any, MinArgs = 1, MaxArgs = -1, Handler = Types });
        r.AddDirective(new() { Name = "brotli_types", Contexts = any, MinArgs = 1, MaxArgs = -1, Handler = Types }); // one list for both
        foreach (var n in Ignored)
            r.AddDirective(new() { Name = n, Contexts = any, MaxArgs = -1, Handler = i => _ignoredSeen.Add((i.Name, i.Source)) });
    }

    private static int Level(DirectiveInvocation i, int min, int max)
    {
        int v = i.Int(0);
        if (v < min || v > max) throw i.Error($"level must be {min}..{max}");
        return v;
    }

    private static void Types(DirectiveInvocation i)
    {
        foreach (var t in i.Args)
            if (t != "*" && (t.IndexOf('/') <= 0 || t.Contains(';'))) throw i.Error($"invalid MIME type \"{t}\"");
        // text/html is always included, as in nginx.
        i.Conf<CompressionConf>().Types = [.. i.Args.Select(a => a.ToLowerInvariant()), "text/html"];
    }

    public void Configure(IModuleSetup setup)
    {
        foreach (var (name, src) in _ignoredSeen)
            setup.Log.Warn(name == "gzip_static"
                ? "directive ignored: precompressed files aren't served yet; responses are compressed on the fly"
                : "directive ignored: not needed here", new("directive", name), new("at", src.ToString()));
        setup.AddHeaderFilter(Filter, Order);
    }

    internal enum Coding : byte { None, Gzip, Brotli }

    private static void Filter(HttpContext ctx)
    {
        var c = ctx.Config<CompressionConf>();
        bool gzip = c.Gzip == true, br = c.Brotli == true;
        if (!gzip && !br) return;
        var resp = ctx.Response;
        if (resp.Status is not (200 or 403 or 404)) return;
        var h = resp.Headers;
        if (!TypeMatches(h.Get("Content-Type"), c.Types ?? DefaultTypes)) return;
        if (h.Get("Content-Encoding") is not null) return;
        if (h.Get("Cache-Control") is { } cc && cc.Contains("no-transform", StringComparison.OrdinalIgnoreCase)) return;

        // The representation varies by Accept-Encoding from here on, whether or not this response gets compressed.
        if (c.Vary != false) AddVary(h);
        if (resp.ContentLength >= 0 && resp.ContentLength < (c.MinLength ?? 256)) return;
        var coding = Negotiate(ctx.Request.Headers.Get("Accept-Encoding"), gzip, br);
        if (coding == Coding.None) return;

        h.Set("Content-Encoding", coding == Coding.Brotli ? "br" : "gzip");
        h.Remove("Accept-Ranges");
        if (h.Get("ETag") is { } etag && !etag.StartsWith("W/", StringComparison.Ordinal)) h.Set("ETag", "W/" + etag);
        int level = coding == Coding.Brotli ? c.BrotliLevel ?? 4 : c.GzipLevel ?? 1;
        resp.EncodeBody(coding == Coding.Brotli
            ? sink => new BrotliEncodeStream(sink, level)
            : sink => new GZipStream(sink, new ZLibCompressionOptions { CompressionLevel = level }, leaveOpen: true));
    }

    private static bool TypeMatches(string? contentType, string[] types)
    {
        if (contentType is null) return false;
        var t = contentType.AsSpan();
        int semi = t.IndexOf(';');
        if (semi >= 0) t = t[..semi];
        t = t.Trim();
        foreach (var x in types)
            if (x == "*" || t.Equals(x, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static void AddVary(HeaderCollection h)
    {
        var v = h.Get("Vary");
        if (v is null) { h.Set("Vary", "Accept-Encoding"); return; }
        foreach (var r in v.AsSpan().Split(','))
        {
            var tok = v.AsSpan()[r].Trim();
            if (tok.Equals("Accept-Encoding", StringComparison.OrdinalIgnoreCase) || tok.SequenceEqual("*")) return;
        }
        h.Set("Vary", v + ", Accept-Encoding");
    }

    /// <summary>
    /// RFC 9110 12.5.3: codings with q=0 are refused; "*" stands for any coding not listed. Brotli wins a tie (it's
    /// smaller at comparable cost); otherwise the higher q wins. Garbage yields no coding, never an error.
    /// </summary>
    internal static Coding Negotiate(string? acceptEncoding, bool gzipOn, bool brOn)
    {
        if (string.IsNullOrEmpty(acceptEncoding)) return Coding.None;
        double gz = -1, brq = -1, star = -1;
        var s = acceptEncoding.AsSpan();
        foreach (var r in s.Split(','))
        {
            var item = s[r].Trim();
            if (item.IsEmpty) continue;
            double q = 1;
            int semi = item.IndexOf(';');
            var name = (semi < 0 ? item : item[..semi]).Trim();
            if (semi >= 0)
            {
                var p = item[(semi + 1)..].Trim();
                if (p.Length < 2 || (p[0] | 0x20) != 'q' || p[1] != '=' || !double.TryParse(p[2..], System.Globalization.NumberStyles.AllowDecimalPoint, System.Globalization.CultureInfo.InvariantCulture, out q) || q is < 0 or > 1)
                    continue; // malformed: ignore this item
            }
            if (name.Equals("gzip", StringComparison.OrdinalIgnoreCase) || name.Equals("x-gzip", StringComparison.OrdinalIgnoreCase)) gz = Math.Max(gz, q);
            else if (name.Equals("br", StringComparison.OrdinalIgnoreCase)) brq = Math.Max(brq, q);
            else if (name.SequenceEqual("*")) star = Math.Max(star, q);
        }
        if (gz < 0) gz = star;
        if (brq < 0) brq = star;
        if (!gzipOn) gz = 0;
        if (!brOn) brq = 0;
        if (brq > 0 && brq >= gz) return Coding.Brotli;
        if (gz > 0) return Coding.Gzip;
        return Coding.None;
    }
}

/// <summary>
/// Streaming brotli with a bounded window (256 KiB) so per-response memory stays small; BrotliStream doesn't expose
/// the window. Flush emits everything written so far (streaming responses keep working).
/// </summary>
internal sealed class BrotliEncodeStream(Stream inner, int quality) : Stream
{
    private const int Window = 18;
    private BrotliEncoder _enc = new(quality, Window);
    private byte[]? _out = ArrayPool<byte>.Shared.Rent(32 << 10);

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        while (true)
        {
            var status = _enc.Compress(data.Span, _out, out int consumed, out int written, isFinalBlock: false);
            if (status == OperationStatus.InvalidData) throw new InvalidOperationException("brotli encoder failed");
            if (written > 0) await inner.WriteAsync(_out.AsMemory(0, written), ct).ConfigureAwait(false);
            data = data[consumed..];
            if (data.IsEmpty && status != OperationStatus.DestinationTooSmall) return;
        }
    }

    public override async Task FlushAsync(CancellationToken ct)
    {
        OperationStatus status;
        do
        {
            status = _enc.Flush(_out, out int written);
            if (written > 0) await inner.WriteAsync(_out.AsMemory(0, written), ct).ConfigureAwait(false);
        } while (status == OperationStatus.DestinationTooSmall);
    }

    public override async ValueTask DisposeAsync()
    {
        if (_out is null) return;
        OperationStatus status;
        do
        {
            status = _enc.Compress(ReadOnlySpan<byte>.Empty, _out, out _, out int written, isFinalBlock: true);
            if (written > 0) await inner.WriteAsync(_out.AsMemory(0, written)).ConfigureAwait(false);
        } while (status == OperationStatus.DestinationTooSmall);
        Release();
    }

    protected override void Dispose(bool disposing)
    {
        Release(); // abandoned response: no trailer, just free the encoder
        base.Dispose(disposing);
    }

    private void Release()
    {
        var b = _out;
        _out = null;
        if (b is null) return;
        _enc.Dispose();
        ArrayPool<byte>.Shared.Return(b);
    }

    public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override void Flush() => FlushAsync().GetAwaiter().GetResult();
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
