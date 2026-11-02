namespace Httpgrl.Modules.Headers;

internal sealed record HeaderEntry(string Name, ComplexValue Value, bool Always);

/// <summary>
/// add_header entries. Unlike nginx, inner levels <b>merge</b> with outer ones instead of silently replacing the
/// whole list: a location that adds one header no longer drops the server's HSTS. An inner entry replaces outer
/// entries of the same name; an empty value removes an inherited header.
/// </summary>
public sealed class HeadersConf : ScopeConfig<HeadersConf>
{
    internal List<HeaderEntry>? Own;
    /// <summary>The effective list (outer levels merged with this one), filled in at Inherit/Configure.</summary>
    internal HeaderEntry[]? Effective;

    protected override void Inherit(HeadersConf parent) => Effective = Merge(parent.Effective ?? Clean(parent.Own), Own);

    internal static HeaderEntry[] Clean(List<HeaderEntry>? own) => own is null ? [] : own.FindAll(e => e.Value.Constant != "").ToArray();

    private static HeaderEntry[] Merge(HeaderEntry[] outer, List<HeaderEntry>? own)
    {
        if (own is null) return outer;
        var list = new List<HeaderEntry>();
        foreach (var e in outer)
            if (!own.Exists(o => o.Name.Equals(e.Name, StringComparison.OrdinalIgnoreCase))) list.Add(e);
        list.AddRange(Clean(own));
        return list.ToArray();
    }
}

/// <summary>
/// <c>add_header name value [always];</c> (ngx_http_headers_module). Added to responses with status 200, 201,
/// 204, 206, 301, 302, 303, 304, 307 or 308, or to every response with <c>always</c>. The value may contain
/// variables; an empty result adds nothing. Unlike nginx, the header <b>replaces</b> any header of the same name
/// the response already has (from a handler or an upstream) instead of sending both.
/// </summary>
public sealed class HeadersModule : IModule
{
    public const int Order = 100;

    // Framing and connection management belong to the core; it would ignore them anyway.
    private static readonly string[] CoreOwned = ["Content-Length", "Transfer-Encoding", "Connection", "Keep-Alive", "Upgrade", "TE", "Trailer", "Date", "Server"];

    public string Name => "http_headers";

    public void Register(IModuleRegistry r) => r.AddDirective(new()
    {
        Name = "add_header", Contexts = ContextKind.HttpAny, MinArgs = 2, MaxArgs = 3, Repeatable = true, Handler = AddHeader,
    });

    private static void AddHeader(DirectiveInvocation i)
    {
        var name = i.Args[0];
        if (name.Length == 0) throw i.Error("empty header name");
        foreach (char c in name)
            if (c > 0x7F || !HttpChars.IsToken((byte)c)) throw i.Error($"invalid header name \"{name}\"");
        if (Array.Exists(CoreOwned, n => n.Equals(name, StringComparison.OrdinalIgnoreCase)))
            throw i.Error($"\"{name}\" is managed by the server and can't be set");
        bool always = false;
        if (i.Args.Length == 3)
        {
            if (i.Args[2] != "always") throw i.Error($"invalid parameter \"{i.Args[2]}\"");
            always = true;
        }
        var value = i.Compile(i.Args[1]);
        if (value.Constant is { } k && !Valid(k)) throw i.Error("header value contains CR, LF or NUL");
        (i.Conf<HeadersConf>().Own ??= new()).Add(new HeaderEntry(name, value, always));
    }

    public void Configure(IModuleSetup setup)
    {
        // Scopes whose slot was never inherited into (the first level that sets add_header) have no merged list yet.
        foreach (var kind in new[] { ContextKind.Server, ContextKind.Location })
            foreach (var scope in setup.ScopesOf(kind))
                if (scope.TryGet<HeadersConf>(out var c)) c.Effective ??= HeadersConf.Clean(c.Own);
        setup.AddHeaderFilter(Filter, Order);
    }

    private static void Filter(HttpContext ctx)
    {
        var list = ctx.Config<HeadersConf>().Effective;
        if (list is null || list.Length == 0) return;
        var resp = ctx.Response;
        bool listed = resp.Status is 200 or 201 or 204 or 206 or 301 or 302 or 303 or 304 or 307 or 308;
        var headers = resp.Headers;
        for (int i = 0; i < list.Length; i++)
        {
            var e = list[i];
            if (!e.Always && !listed) continue;
            // First applicable entry of this name: drop what the response already has.
            bool first = true;
            for (int j = 0; j < i && first; j++)
                if ((list[j].Always || listed) && list[j].Name.Equals(e.Name, StringComparison.OrdinalIgnoreCase)) first = false;
            if (first) headers.Remove(e.Name);
            var v = e.Value.Evaluate(ctx);
            if (v.Length == 0) continue;
            if (!Valid(v))
            {
                ctx.Log.Warn("add_header value dropped: contains CR, LF or NUL", new LogField("header", e.Name));
                continue;
            }
            headers.Add(e.Name, v);
        }
    }

    private static bool Valid(string v)
    {
        foreach (char c in v)
            if (c is '\r' or '\n' or '\0' || c > 0xFF) return false;
        return true;
    }
}
