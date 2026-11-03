using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Httpgrl.Modules.StaticFiles;

public sealed class AutoIndexConf : ScopeConfig<AutoIndexConf>
{
    public bool? Enabled, ExactSize, LocalTime;
    public bool? Json;
    protected override void Inherit(AutoIndexConf p)
    {
        Enabled ??= p.Enabled;
        ExactSize ??= p.ExactSize;
        LocalTime ??= p.LocalTime;
        Json ??= p.Json;
    }
}

/// <summary>Directory listings in HTML or JSON (cf. ngx_http_autoindex_module). Dotfiles are hidden.</summary>
public sealed class AutoIndexModule : IModule
{
    public const int Order = 200;
    /// <summary>Upper bound on listed entries, so a huge directory can't balloon memory per request.</summary>
    public const int MaxEntries = 50_000;
    public string Name => "http_autoindex";

    public void Register(IModuleRegistry r)
    {
        var ctx = ContextKind.HttpAny;
        r.AddDirective(new() { Name = "autoindex", Contexts = ctx, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<AutoIndexConf>().Enabled = i.Flag(0) });
        r.AddDirective(new() { Name = "autoindex_exact_size", Contexts = ctx, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<AutoIndexConf>().ExactSize = i.Flag(0) });
        r.AddDirective(new() { Name = "autoindex_localtime", Contexts = ctx, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<AutoIndexConf>().LocalTime = i.Flag(0) });
        r.AddDirective(new()
        {
            Name = "autoindex_format", Contexts = ctx, MinArgs = 1, MaxArgs = 1,
            Handler = i => i.Conf<AutoIndexConf>().Json = i.Args[0] switch
            {
                "html" => false,
                "json" => true,
                _ => throw i.Error("supported formats: html, json"),
            },
        });
    }

    public void Configure(IModuleSetup setup) => setup.AddHandler(Phase.Content, Handle, Order);

    private static async ValueTask<HandlerResult> Handle(HttpContext ctx)
    {
        var req = ctx.Request;
        var uri = req.Path;
        if (!uri.EndsWith('/') || !req.IsGetOrHead) return HandlerResult.Declined;
        var conf = ctx.Config<AutoIndexConf>();
        if (conf.Enabled != true) return HandlerResult.Declined;
        var listed = new List<DirectoryEntry>();
        switch (ctx.ListDirectory(uri, MaxEntries, listed, out bool truncated))
        {
            case OpenResult.Ok: break;
            case OpenResult.NotFound or OpenResult.NotRegularFile: return HandlerResult.WithStatus(404);
            case OpenResult.Forbidden: return HandlerResult.WithStatus(403);
            default: return HandlerResult.WithStatus(500);
        }
        listed.RemoveAll(static e => e.Name.StartsWith('.')); // dotfiles stay hidden (in place: no second list)
        listed.Sort(static (a, b) => a.IsDirectory != b.IsDirectory ? (a.IsDirectory ? -1 : 1) : string.CompareOrdinal(a.Name, b.Name));

        // Streamed in small pieces (no Content-Length): a big directory costs a flush buffer, not its whole rendering.
        var resp = ctx.Response;
        resp.Headers.Set("Content-Type", conf.Json == true ? "application/json" : "text/html; charset=utf-8");
        if (conf.Json == true) await RenderJson(resp, listed).ConfigureAwait(false);
        else await RenderHtml(resp, uri, listed, conf, truncated).ConfigureAwait(false);
        return HandlerResult.Done;
    }

    private const int FlushAt = 16 << 10;

    private static async ValueTask RenderJson(HttpResponse resp, List<DirectoryEntry> entries)
    {
        var buf = new ArrayBufferWriter<byte>(FlushAt + 2048);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartArray();
        foreach (var e in entries)
        {
            w.WriteStartObject();
            w.WriteString("name"u8, e.Name);
            w.WriteString("type"u8, e.IsDirectory ? "directory"u8 : "file"u8);
            w.WriteString("mtime"u8, e.LastModifiedUtc.ToString("r", CultureInfo.InvariantCulture));
            if (!e.IsDirectory) w.WriteNumber("size"u8, e.Size);
            w.WriteEndObject();
            if (w.BytesPending + buf.WrittenCount >= FlushAt)
            {
                w.Flush();
                await resp.WriteAsync(buf.WrittenMemory).ConfigureAwait(false);
                buf.ResetWrittenCount();
            }
        }
        w.WriteEndArray();
        w.Flush();
        await resp.WriteAsync(buf.WrittenMemory).ConfigureAwait(false);
    }

    private const int NameWidth = 50;

    private static async ValueTask RenderHtml(HttpResponse resp, string uri, List<DirectoryEntry> entries, AutoIndexConf conf, bool truncated)
    {
        var sb = new StringBuilder(FlushAt + 2048);
        var bytes = new byte[Encoding.UTF8.GetMaxByteCount(FlushAt + 2048)];
        var encoder = Encoding.UTF8.GetEncoder(); // stateful: a surrogate pair split across flushes stays intact
        async ValueTask Flush(bool last)
        {
            if (Encoding.UTF8.GetMaxByteCount(sb.Length) > bytes.Length) bytes = new byte[Encoding.UTF8.GetMaxByteCount(sb.Length)];
            int n = 0;
            foreach (var chunk in sb.GetChunks()) n += encoder.GetBytes(chunk.Span, bytes.AsSpan(n), flush: false);
            if (last) n += encoder.GetBytes([], bytes.AsSpan(n), flush: true);
            sb.Clear();
            if (n > 0) await resp.WriteAsync(bytes.AsMemory(0, n)).ConfigureAwait(false);
        }

        sb.Append("<html>\r\n<head><title>Index of ");
        UrlEncoding.HtmlEscape(sb, uri);
        sb.Append("</title></head>\r\n<body>\r\n<h1>Index of ");
        UrlEncoding.HtmlEscape(sb, uri);
        sb.Append("</h1><hr><pre>");
        if (uri != "/") sb.Append("<a href=\"../\">../</a>\r\n");
        bool exact = conf.ExactSize ?? true;
        bool local = conf.LocalTime == true;
        foreach (var e in entries)
        {
            var display = e.IsDirectory ? e.Name + "/" : e.Name;
            // './' prefix: a name like "javascript:x" must never be read as a URL scheme.
            sb.Append("<a href=\"./");
            UrlEncoding.HtmlEscape(sb, UrlEncoding.EscapePath(e.Name));
            if (e.IsDirectory) sb.Append('/');
            sb.Append("\">");
            var shown = display.Length > NameWidth ? display[..(NameWidth - 3)] + "..>" : display;
            UrlEncoding.HtmlEscape(sb, shown);
            sb.Append("</a>");
            sb.Append(' ', NameWidth + 1 - shown.Length);
            var t = local ? e.LastModifiedUtc.ToLocalTime() : e.LastModifiedUtc;
            sb.Append(t.ToString("dd-MMM-yyyy HH:mm", CultureInfo.InvariantCulture));
            sb.Append(' ');
            var size = e.IsDirectory ? "-" : exact ? e.Size.ToString(CultureInfo.InvariantCulture) : HumanSize(e.Size);
            sb.Append(' ', Math.Max(1, 20 - size.Length)).Append(size).Append("\r\n");
            if (sb.Length >= FlushAt) await Flush(last: false).ConfigureAwait(false);
        }
        if (truncated) sb.Append("(listing truncated)\r\n");
        sb.Append("</pre><hr></body>\r\n</html>\r\n");
        await Flush(last: true).ConfigureAwait(false);
    }

    private static string HumanSize(long n)
    {
        if (n < 1024) return n.ToString(CultureInfo.InvariantCulture);
        string[] units = ["K", "M", "G", "T"];
        double v = n;
        int u = -1;
        while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
        return Math.Round(v).ToString(CultureInfo.InvariantCulture) + units[u];
    }
}
