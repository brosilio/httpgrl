namespace Httpgrl.Core.Modules;

public sealed class AccessLogConf : ScopeConfig<AccessLogConf>
{
    public bool? Enabled;
    protected override void Inherit(AccessLogConf p) => Enabled ??= p.Enabled;
}

/// <summary>One JSON access record per request (Log phase). Uses only the public module API.</summary>
internal sealed class AccessLogModule : IModule
{
    public string Name => "http_log";

    public void Register(IModuleRegistry r)
    {
        r.AddDirective(new()
        {
            Name = "access_log", Contexts = ContextKind.HttpAny, MinArgs = 1, MaxArgs = -1,
            Handler = i => i.Conf<AccessLogConf>().Enabled = i.Args[0] switch
            {
                "off" => false,
                "stdout" => true,
                _ => throw i.Error("only \"stdout\" or \"off\" are supported; records are JSON on stdout"),
            },
        });
    }

    public void Configure(IModuleSetup setup) => setup.AddHandler(Phase.Log, Log, 0);

    private static ValueTask<HandlerResult> Log(HttpContext ctx)
    {
        if (ctx.Config<AccessLogConf>().Enabled == false || !ctx.Log.IsEnabled(LogLevel.Info)) return HandlerResult.Done;
        var req = ctx.Request;
        ctx.Log.Write(LogLevel.Info, "access",
        [
            new("conn", ctx.Connection.Id),
            new("remote", ctx.Connection.RemoteAddress),
            new("method", req.Method),
            new("uri", req.RawTarget),
            new("proto", req.Version == HttpVersion.Http11 ? "HTTP/1.1" : "HTTP/1.0"),
            new("host", req.Host),
            new("status", (long)ctx.Response.Status),
            new("bytes", ctx.Response.BodyBytesSent),
            new("rt", Math.Round(ctx.Elapsed.TotalSeconds, 6)),
            new("ua", req.Headers.Get("User-Agent")),
            new("referer", req.Headers.Get("Referer")),
            new("tls", ctx.Connection.IsTls),
        ]);
        return HandlerResult.Done;
    }
}
