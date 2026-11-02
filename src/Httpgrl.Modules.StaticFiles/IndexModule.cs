namespace Httpgrl.Modules.StaticFiles;

public sealed class IndexConf : ScopeConfig<IndexConf>
{
    public ComplexValue[]? Files;
    protected override void Inherit(IndexConf p) => Files ??= p.Files;
}

/// <summary>
/// For URIs ending in '/', internally redirects to the first existing index file
/// (cf. ngx_http_index_module). A leading-slash entry is an unconditional fallback.
/// </summary>
public sealed class IndexModule : IModule
{
    public const int Order = 100;
    public string Name => "http_index";

    private static readonly ComplexValue[] DefaultFiles = [new("index.html", [new("index.html", null)])];

    public void Register(IModuleRegistry registry)
    {
        registry.AddDirective(new()
        {
            Name = "index", Contexts = ContextKind.HttpAny, MinArgs = 1, MaxArgs = -1,
            Handler = i =>
            {
                var files = new ComplexValue[i.Args.Length];
                for (int k = 0; k < files.Length; k++)
                {
                    if (i.Args[k].Length == 0) throw i.Error("index file name is empty");
                    files[k] = i.Compile(i.Args[k]);
                }
                i.Conf<IndexConf>().Files = files;
            },
        });
    }

    public void Configure(IModuleSetup setup) => setup.AddHandler(Phase.Content, Handle, Order);

    private static ValueTask<HandlerResult> Handle(HttpContext ctx)
    {
        var req = ctx.Request;
        var uri = req.Path;
        if (!uri.EndsWith('/') || !req.IsGetOrHead) return HandlerResult.Declined;

        foreach (var f in ctx.Config<IndexConf>().Files ?? DefaultFiles)
        {
            var name = f.Evaluate(ctx);
            if (name.Length == 0) continue;
            if (name[0] == '/') return HandlerResult.Redirect(name);
            if (name.Contains('/') && name.Contains("..", StringComparison.Ordinal)) continue;
            var candidate = uri + name;
            if (ctx.Probe(candidate) == ResourceKind.File) return HandlerResult.Redirect(candidate);
        }
        return ctx.Probe(uri) == ResourceKind.Directory ? HandlerResult.Declined : HandlerResult.WithStatus(404);
    }
}
