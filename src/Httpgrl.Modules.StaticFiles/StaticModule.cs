using System.Globalization;

namespace Httpgrl.Modules.StaticFiles;

/// <summary>
/// Serves regular files (cf. ngx_http_static_module): conditional GET (ETag / If-Modified-Since),
/// single byte ranges, directory-without-slash redirect. Runs last in the content phase.
/// </summary>
public sealed class StaticConf : ScopeConfig<StaticConf>
{
    internal Precompressed? Gzip;
    internal bool? Brotli;
    protected override void Inherit(StaticConf p)
    {
        Gzip ??= p.Gzip;
        Brotli ??= p.Brotli;
    }
}

internal enum Precompressed : byte { Off, On, Always }

public sealed class StaticModule : IModule
{
    public const int Order = 300;
    public string Name => "http_static";

    public void Register(IModuleRegistry r)
    {
        r.AddDirective(new()
        {
            Name = "gzip_static", Contexts = ContextKind.HttpAny, MinArgs = 1, MaxArgs = 1,
            Handler = i => i.Conf<StaticConf>().Gzip = i.Args[0] switch
            {
                "on" => Precompressed.On,
                "off" => Precompressed.Off,
                "always" => Precompressed.Always,
                var a => throw i.Error($"invalid value \"{a}\"; expected on, off or always"),
            },
        });
        r.AddDirective(new() { Name = "brotli_static", Contexts = ContextKind.HttpAny, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<StaticConf>().Brotli = i.Flag(0) });
    }

    /// <summary>
    /// gzip_static / brotli_static: a precompressed sibling (<c>x.br</c>, <c>x.gz</c>) the client accepts, opened through
    /// the core like any file; null to serve the original. Brotli is preferred when both are acceptable.
    /// </summary>
    private static FileResource? OpenPrecompressed(HttpContext ctx, string uri, out string? encoding)
    {
        encoding = null;
        var c = ctx.Config<StaticConf>();
        var gz = c.Gzip ?? Precompressed.Off;
        bool br = c.Brotli == true;
        if (gz == Precompressed.Off && !br) return null;
        AcceptEncoding.AddVary(ctx.Response.Headers);
        var ae = ctx.Request.Headers.Get("Accept-Encoding");
        if (br && AcceptEncoding.Accepts(ae, ContentCoding.Brotli) && AcceptEncoding.Choose(ae, gz != Precompressed.Off, true) == ContentCoding.Brotli
            && ctx.OpenFile(uri + ".br", out var b) == OpenResult.Ok)
        {
            encoding = "br";
            return b;
        }
        if (gz == Precompressed.Always || (gz == Precompressed.On && AcceptEncoding.Accepts(ae, ContentCoding.Gzip)))
        {
            if (ctx.OpenFile(uri + ".gz", out var g) == OpenResult.Ok)
            {
                encoding = "gzip";
                return g;
            }
        }
        return null;
    }

    public void Configure(IModuleSetup setup) => setup.AddHandler(Phase.Content, Handle, Order);

    private static async ValueTask<HandlerResult> Handle(HttpContext ctx)
    {
        var req = ctx.Request;
        var uri = req.Path;
        if (uri.EndsWith('/'))
        {
            // index and autoindex declined: an existing directory is forbidden, anything else is missing.
            return HandlerResult.WithStatus(ctx.Probe(uri) == ResourceKind.Directory ? 403 : 404);
        }
        if (!req.IsGetOrHead)
        {
            ctx.Response.Headers.Set("Allow", "GET, HEAD");
            return HandlerResult.WithStatus(405);
        }

        var opened = OpenPrecompressed(ctx, uri, out var encoding);
        switch (opened is not null ? OpenResult.Ok : ctx.OpenFile(uri, out opened))
        {
            case OpenResult.Ok: break;
            case OpenResult.NotFound: return HandlerResult.WithStatus(404);
            case OpenResult.Forbidden or OpenResult.NotRegularFile: return HandlerResult.WithStatus(403);
            case OpenResult.IsDirectory:
                var location = UrlEncoding.EscapePath(uri) + "/";
                if (req.Query.Length > 0) location += "?" + Redirects.Escape(req.Query); // after an internal redirect the query comes from config
                ctx.Response.Headers.Set("Location", location);
                return HandlerResult.WithStatus(301);
            default: return HandlerResult.WithStatus(500);
        }
        using var file = opened!;

        long length = file.Length;
        var lastModified = file.LastModifiedUtc;
        long mtimeUnix = new DateTimeOffset(lastModified).ToUnixTimeSeconds();
        var etag = "\"" + mtimeUnix.ToString("x", CultureInfo.InvariantCulture) + "-" + length.ToString("x", CultureInfo.InvariantCulture) + "\"";
        var resp = ctx.Response;
        var h = resp.Headers;
        h.Set("Content-Type", encoding is null ? file.ContentType : ctx.ContentTypeFor(uri));
        if (encoding is not null) h.Set("Content-Encoding", encoding);
        h.Set("Last-Modified", lastModified.ToString("r", CultureInfo.InvariantCulture));
        h.Set("ETag", etag);
        h.Set("Accept-Ranges", "bytes");

        if (NotModified(req.Headers, etag, lastModified))
        {
            resp.Status = 304;
            h.Remove("Content-Type");
            resp.ContentLength = 0;
            return HandlerResult.Done;
        }

        long offset = 0, count = length;
        var range = req.Headers.Get("Range");
        if (range is not null && ReferenceEquals(req.Method, HttpMethods.Get) && IfRangeOk(req.Headers.Get("If-Range"), etag, lastModified))
        {
            switch (ParseRange(range, length, out offset, out count))
            {
                case RangeResult.Satisfiable:
                    resp.Status = 206;
                    h.Set("Content-Range", "bytes " + offset.ToString(CultureInfo.InvariantCulture) + "-" + (offset + count - 1).ToString(CultureInfo.InvariantCulture) + "/" + length.ToString(CultureInfo.InvariantCulture));
                    break;
                case RangeResult.Unsatisfiable:
                    h.Set("Content-Range", "bytes */" + length.ToString(CultureInfo.InvariantCulture));
                    return HandlerResult.WithStatus(416);
                default:
                    offset = 0;
                    count = length;
                    break;
            }
        }

        resp.ContentLength = count;
        await resp.SendFileAsync(file, offset, count).ConfigureAwait(false);
        return HandlerResult.Done;
    }

    private static bool NotModified(HeaderCollection h, string etag, DateTime lastModified)
    {
        var inm = h.Get("If-None-Match");
        if (inm is not null) return ETagListMatches(inm, etag); // RFC 9110 13.2.2: If-None-Match wins over If-Modified-Since
        var ims = h.Get("If-Modified-Since");
        return ims is not null
            && DateTime.TryParseExact(ims, "r", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var since)
            && lastModified <= since;
    }

    private static bool ETagListMatches(string header, string etag)
    {
        var s = header.AsSpan();
        var tag = etag.AsSpan();
        foreach (var r in s.Split(','))
        {
            var t = s[r].Trim(" \t");
            if (t.SequenceEqual("*")) return true;
            if (t.StartsWith("W/")) t = t[2..]; // weak comparison
            if (t.SequenceEqual(tag)) return true;
        }
        return false;
    }

    private static bool IfRangeOk(string? ifRange, string etag, DateTime lastModified)
    {
        if (ifRange is null) return true;
        if (ifRange.StartsWith('"')) return ifRange == etag; // strong comparison only
        return DateTime.TryParseExact(ifRange, "r", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) && d == lastModified;
    }

    internal enum RangeResult : byte { Ignore, Satisfiable, Unsatisfiable }

    /// <summary>Single "bytes=" range. Multi-range requests are answered with the full body (RFC-permitted).</summary>
    internal static RangeResult ParseRange(string header, long length, out long offset, out long count)
    {
        offset = 0;
        count = length;
        var s = header.AsSpan().Trim(" \t");
        if (!s.StartsWith("bytes=", StringComparison.OrdinalIgnoreCase)) return RangeResult.Ignore;
        s = s[6..].Trim(" \t");
        if (s.IndexOf(',') >= 0) return RangeResult.Ignore;
        int dash = s.IndexOf('-');
        if (dash < 0) return RangeResult.Ignore;
        var a = s[..dash].Trim(" \t");
        var b = s[(dash + 1)..].Trim(" \t");
        const NumberStyles ns = NumberStyles.None;
        if (a.IsEmpty)
        {
            if (!long.TryParse(b, ns, CultureInfo.InvariantCulture, out long suffix)) return RangeResult.Ignore;
            if (suffix == 0 || length == 0) return RangeResult.Unsatisfiable;
            count = Math.Min(suffix, length);
            offset = length - count;
            return RangeResult.Satisfiable;
        }
        if (!long.TryParse(a, ns, CultureInfo.InvariantCulture, out long first)) return RangeResult.Ignore;
        long last = length - 1;
        if (!b.IsEmpty)
        {
            if (!long.TryParse(b, ns, CultureInfo.InvariantCulture, out last) || last < first) return RangeResult.Ignore;
            last = Math.Min(last, length - 1);
        }
        if (first >= length) return RangeResult.Unsatisfiable;
        offset = first;
        count = last - first + 1;
        return RangeResult.Satisfiable;
    }
}
