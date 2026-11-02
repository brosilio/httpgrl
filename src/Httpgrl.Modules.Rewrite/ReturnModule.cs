using System.Text;

namespace Httpgrl.Modules.Rewrite;

/// <summary>Not inherited: like nginx, a server-level <c>return</c> runs for every request instead.</summary>
public sealed class ReturnConf : ScopeConfig<ReturnConf>
{
    public bool Set;
    public int Code;
    /// <summary>Body text, or the redirect target for 301/302/303/307/308.</summary>
    public ComplexValue? Text;
    protected override void Inherit(ReturnConf parent) { }
}

/// <summary>
/// <c>return code [text]</c>, <c>return code url</c> (3xx), <c>return url</c> (302), <c>return 444</c> (drop)
/// — cf. ngx_http_rewrite_module. Runs first in the rewrite phase; a server-level return wins over the location's.
/// </summary>
public sealed class ReturnModule : IModule
{
    public const int Order = 0;
    public string Name => "http_return";

    public void Register(IModuleRegistry r) => r.AddDirective(new()
    {
        Name = "return", Contexts = ContextKind.ServerAny, MinArgs = 1, MaxArgs = 2, Handler = Directive,
    });

    private static void Directive(DirectiveInvocation i)
    {
        var c = i.Conf<ReturnConf>();
        c.Set = true;
        var first = i.Args[0];
        if (i.Args.Length == 1 && (first.StartsWith("http://", StringComparison.Ordinal) || first.StartsWith("https://", StringComparison.Ordinal) || first.StartsWith("$scheme", StringComparison.Ordinal)))
        {
            c.Code = 302;
            c.Text = i.Compile(first);
            return;
        }
        int code = i.Int(0);
        if (code != HandlerResult.DropStatus && code is < 200 or > 599) throw i.Error($"invalid return code \"{first}\"");
        if (code == HandlerResult.DropStatus && i.Args.Length > 1) throw i.Error("\"return 444\" closes the connection and cannot carry text");
        if (IsRedirect(code) && i.Args.Length < 2) throw i.Error($"\"return {code}\" needs a URL");
        c.Code = code;
        if (i.Args.Length > 1) c.Text = i.Compile(i.Args[1]);
    }

    public void Configure(IModuleSetup setup) => setup.AddHandler(Phase.Rewrite, Handle, Order);

    private static bool IsRedirect(int code) => code is 301 or 302 or 303 or 307 or 308;

    private static async ValueTask<HandlerResult> Handle(HttpContext ctx)
    {
        var c = ctx.Server.Get<ReturnConf>();
        if (!c.Set) c = ctx.Config<ReturnConf>();
        if (!c.Set) return HandlerResult.Declined;

        if (c.Code == HandlerResult.DropStatus) return HandlerResult.Drop;
        if (IsRedirect(c.Code))
        {
            ctx.Response.Headers.Set("Location", EscapeForHeader(c.Text!.Evaluate(ctx)));
            return HandlerResult.WithStatus(c.Code);
        }
        if (c.Text is null) return HandlerResult.WithStatus(c.Code); // core body; error_page applies, as in nginx

        var body = Encoding.UTF8.GetBytes(c.Text.Evaluate(ctx));
        var resp = ctx.Response;
        resp.Status = c.Code;
        resp.Headers.Set("Content-Type", ctx.ContentTypeFor(""));
        resp.ContentLength = body.Length;
        await resp.WriteAsync(body).ConfigureAwait(false);
        return HandlerResult.Done;
    }

    /// <summary>
    /// Variables like $uri are percent-decoded and may hold CR/LF or non-ASCII. Re-encode those, so
    /// <c>return 301 https://$host$uri</c> can never split the response (a classic nginx misconfiguration).
    /// </summary>
    internal static string EscapeForHeader(string url)
    {
        bool clean = true;
        foreach (char c in url)
            if (c is < (char)0x21 or > (char)0x7E) { clean = false; break; }
        if (clean) return url;
        var sb = new StringBuilder(url.Length + 16);
        foreach (byte b in Encoding.UTF8.GetBytes(url))
        {
            if (b is >= 0x21 and <= 0x7E) sb.Append((char)b);
            else sb.Append('%').Append("0123456789ABCDEF"[b >> 4]).Append("0123456789ABCDEF"[b & 15]);
        }
        return sb.ToString();
    }
}
