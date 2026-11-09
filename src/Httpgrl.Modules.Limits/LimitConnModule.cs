namespace Httpgrl.Modules.Limits;

internal sealed record ConnZoneDef(string Name, ComplexValue Key, ConnZone State);
internal sealed record ConnSpec(string Zone, int Max, SourceLocation Source);
internal sealed record ConnLimit(ConnZoneDef Zone, int Max);

/// <summary>limit_conn for one block; levels merge as for <see cref="LimitReqConf"/>, and <c>limit_conn off;</c> drops inherited limits.</summary>
public sealed class LimitConnConf : ScopeConfig<LimitConnConf>
{
    internal List<ConnSpec>? Own;
    internal bool Off;
    internal ConnSpec[]? Effective;
    internal ConnLimit[] Bound = [];
    internal int? Status;
    internal bool? DryRun;
    internal LogLevel? Level;

    protected override void Inherit(LimitConnConf p)
    {
        Effective = Limits.Merge(Off ? [] : p.Effective ?? p.Own?.ToArray() ?? [], Own, s => s.Zone);
        Status ??= p.Status;
        DryRun ??= p.DryRun;
        Level ??= p.Level;
    }
}

/// <summary>
/// <c>limit_conn_zone key zone=name:size;</c> and <c>limit_conn zone number;</c> (ngx_http_limit_conn_module): at
/// most <c>number</c> requests in flight per key. A request holds its slot until it ends (a WebSocket for its whole
/// life), and releases it however it ends, including a broken connection. Over the limit: <c>limit_conn_status</c>
/// (default <b>429</b>; nginx: 503). A full zone refuses new keys rather than forgetting live counts.
/// </summary>
public sealed class LimitConnModule : IModule
{
    public const int Order = 1; // after limit_req: a delayed request shouldn't hold a connection slot first

    private readonly Dictionary<string, (string Raw, ComplexValue Key, long Bytes)> _zones = new(StringComparer.Ordinal);
    private readonly object _done = new();
    private readonly object _status = new();

    public string Name => "http_limit_conn";

    public void Register(IModuleRegistry r)
    {
        r.AddDirective(new() { Name = "limit_conn_zone", Contexts = [ContextKind.Http], MinArgs = 2, MaxArgs = 2, Repeatable = true, Handler = Zone });
        r.AddDirective(new() { Name = "limit_conn", Contexts = ContextKind.HttpAny, MinArgs = 1, MaxArgs = 2, Repeatable = true, Handler = Limit });
        r.AddDirective(new() { Name = "limit_conn_status", Contexts = ContextKind.HttpAny, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<LimitConnConf>().Status = Limits.Status(i) });
        r.AddDirective(new() { Name = "limit_conn_dry_run", Contexts = ContextKind.HttpAny, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<LimitConnConf>().DryRun = i.Flag(0) });
        r.AddDirective(new() { Name = "limit_conn_log_level", Contexts = ContextKind.HttpAny, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<LimitConnConf>().Level = Limits.Level(i) });
        r.AddVariable("limit_conn_status", ctx => ctx.Items.TryGetValue(_status, out var s) ? (string?)s : null);
    }

    private void Zone(DirectiveInvocation i)
    {
        if (!i.Args[1].StartsWith("zone=", StringComparison.Ordinal)) throw i.Error($"invalid parameter \"{i.Args[1]}\"; expected zone=name:size");
        var (name, bytes) = Limits.ZoneArg(i, i.Args[1]);
        if (!_zones.TryAdd(name, (i.Args[0], i.Compile(i.Args[0]), bytes))) throw i.Error($"duplicate zone \"{name}\"");
    }

    private static void Limit(DirectiveInvocation i)
    {
        var c = i.Conf<LimitConnConf>();
        if (i.Args is ["off"]) { c.Off = true; return; }
        if (i.Args.Length != 2) throw i.Error("expected \"limit_conn zone number;\" or \"limit_conn off;\"");
        long max = Limits.Count(i, i.Args[1]);
        if (max == 0) throw i.Error("the limit must be at least 1");
        var own = c.Own ??= new();
        if (own.Exists(s => s.Zone == i.Args[0])) throw i.Error($"zone \"{i.Args[0]}\" is already limited here");
        own.Add(new ConnSpec(i.Args[0], (int)max, i.Source));
    }

    public void Configure(IModuleSetup setup)
    {
        var defs = new Dictionary<string, ConnZoneDef>(StringComparer.Ordinal);
        foreach (var (name, z) in _zones)
        {
            // Shared with the configuration being replaced, so requests still running there keep counting.
            var state = setup.Persistent($"limit_conn:{name}:{z.Bytes}:{z.Raw}", () => new ConnZone(z.Bytes));
            defs[name] = new ConnZoneDef(name, z.Key, state);
        }
        foreach (var scope in Limits.Scopes(setup))
        {
            if (!scope.TryGet<LimitConnConf>(out var c)) continue;
            var specs = c.Effective ??= c.Own?.ToArray() ?? [];
            var bound = new ConnLimit[specs.Length];
            for (int k = 0; k < specs.Length; k++)
            {
                var s = specs[k];
                if (!defs.TryGetValue(s.Zone, out var def)) throw new ConfigException($"unknown limit_conn_zone \"{s.Zone}\"", s.Source);
                bound[k] = new ConnLimit(def, s.Max);
            }
            c.Bound = bound;
        }
        setup.AddHandler(Phase.Access, Handle, Order);
    }

    private sealed class Lease(ConnZone zone, string key, Lease? next)
    {
        public readonly ConnZone Zone = zone;
        public readonly string Key = key;
        public readonly Lease? Next = next;

        public static void Release(object? state)
        {
            for (var l = (Lease?)state; l is not null; l = l.Next) l.Zone.Release(l.Key);
        }
    }

    private ValueTask<HandlerResult> Handle(HttpContext ctx)
    {
        var c = ctx.Config<LimitConnConf>();
        var limits = c.Bound;
        if (limits.Length == 0 || !ctx.Items.TryAdd(_done, null)) return new(HandlerResult.Declined);

        Lease? held = null;
        foreach (var l in limits)
        {
            var key = l.Zone.Key.Evaluate(ctx);
            if (key.Length == 0) continue;
            if (l.Zone.State.TryAcquire(key, l.Max))
            {
                held = new Lease(l.Zone.State, key, held);
                continue;
            }
            bool dry = c.DryRun == true;
            ctx.SecurityEvent(dry ? "connection_limit_would_reject" : "connection_limit_exceeded");
            ctx.Items[_status] = dry ? "REJECTED_DRY_RUN" : "REJECTED";
            var level = c.Level ?? LogLevel.Warn;
            if (ctx.Log.IsEnabled(level))
                ctx.Log.Write(level, dry ? "limit_conn would reject (dry run)" : "limit_conn rejected request",
                    [new("zone", l.Zone.Name), new("remote", ctx.Connection.RemoteAddress), new("limit", (long)l.Max), new("uri", ctx.Request.Path)]);
            if (dry) continue;
            Lease.Release(held);
            return new(Limits.Result(c.Status));
        }
        if (held is not null) ctx.OnRequestEnd(Lease.Release, held);
        ctx.Items.TryAdd(_status, "PASSED");
        return new(HandlerResult.Declined);
    }
}
