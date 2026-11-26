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
            Handler = i =>
            {
                i.Conf<AccessLogConf>().Enabled = i.Args[0] != "off";
                // nginx's "access_log /path [format]": records go to stdout as JSON regardless; say so once per directive.
                if (i.Args[0] is not ("off" or "stdout")) _paths.Add((i.Args[0], i.Source));
            },
        });
    }

    private readonly List<(string Path, SourceLocation Source)> _paths = new();

    public void Configure(IModuleSetup setup)
    {
        foreach (var (path, src) in _paths)
            setup.Log.Warn("access_log: records go to stdout as JSON, not to this file (log_format doesn't apply)", new("path", path), new("at", src.ToString()));
        setup.AddHandler(Phase.Log, Log, 0);
    }

    private static ValueTask<HandlerResult> Log(HttpContext ctx)
    {
        if (ctx.Config<AccessLogConf>().Enabled == false || !ctx.Log.IsEnabled(LogLevel.Info)) return HandlerResult.Done;
        var req = ctx.Request;
        ctx.Log.Write(LogLevel.Info, "access",
        [
            new("conn", ctx.Connection.Id),
            new("request_id", req.Id),
            new("remote", ctx.Connection.RemoteAddress),
            new("method", req.Method),
            new("event", "http_access"),
            new("uri", LogPrivacy.PathOnly(req.RawTarget)),
            new("path", req.Path),
            new("query_present", req.Query.Length != 0),
            new("server", ctx.Variable("server_name")),
            new("location", ctx.RouteLabel),
            new("outcome", ctx.ResponseOutcome),
            new("upstream", ctx.Variable("upstream_addr")),
            new("upstream_status", ctx.Variable("upstream_status")),
            new("proto", HttpVersions.Name(req.Version)),
            new("host", req.Host),
            new("status", (long)ctx.Response.Status),
            new("bytes", ctx.Response.BodyBytesSent),
            new("rt", Math.Round(ctx.Elapsed.TotalSeconds, 6)),
            new("ua", req.Headers.Get("User-Agent")),
            new("referer_present", req.Headers.Contains("Referer")),
            new("tls", ctx.Connection.IsTls),
            new("client_verify", ctx.Connection.ClientVerify),
        ]);
        return HandlerResult.Done;
    }
}
