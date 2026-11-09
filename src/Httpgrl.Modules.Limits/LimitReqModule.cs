namespace Httpgrl.Modules.Limits;

internal sealed record ReqZoneDef(string Name, ComplexValue Key, long Rate, ReqZone State);
internal sealed record ReqSpec(string Zone, long Burst, long Delay, SourceLocation Source);
internal sealed record ReqLimit(ReqZoneDef Zone, long Burst, long Delay);

/// <summary>
/// limit_req for one block. Unlike nginx (where any limit_req at a level discards every inherited one), levels
/// <b>merge</b>: a location adding a limit for its login form keeps the server-wide limit. An inner limit on the
/// same zone replaces the outer one (to change its burst); <c>limit_req off;</c> drops all inherited limits.
/// </summary>
public sealed class LimitReqConf : ScopeConfig<LimitReqConf>
{
    internal List<ReqSpec>? Own;
    internal bool Off;
    internal ReqSpec[]? Effective;
    internal ReqLimit[] Bound = [];
    internal int? Status;
    internal bool? DryRun;
    internal LogLevel? Level;

    protected override void Inherit(LimitReqConf p)
    {
        Effective = Limits.Merge(Off ? [] : p.Effective ?? p.Own?.ToArray() ?? [], Own, s => s.Zone);
        Status ??= p.Status;
        DryRun ??= p.DryRun;
        Level ??= p.Level;
    }
}

/// <summary>
/// <c>limit_req_zone key zone=name:size rate=Nr/s|Nr/m;</c> and <c>limit_req zone=name [burst=n] [nodelay|delay=n];</c>
/// (ngx_http_limit_req_module): nginx's leaky bucket per key. Requests within <c>burst</c> are delayed to the rate
/// (or pass at once with <c>nodelay</c>, or after the first <c>delay=n</c>); beyond it they're rejected with
/// <c>limit_req_status</c> (default <b>429</b>; nginx: 503). An empty key isn't limited (use a <c>map</c> to exempt
/// clients). Counted once per request, whatever internal redirects follow. Zone state survives reloads.
/// </summary>
public sealed class LimitReqModule : IModule
{
    public const int Order = 0; // first in the access phase: reject floods before anything else costs anything

    private readonly Dictionary<string, (string Raw, ComplexValue Key, long Bytes, long Rate)> _zones = new(StringComparer.Ordinal);
    private readonly object _done = new();
    private readonly object _status = new();

    public string Name => "http_limit_req";

    public void Register(IModuleRegistry r)
    {
        r.AddDirective(new() { Name = "limit_req_zone", Contexts = [ContextKind.Http], MinArgs = 3, MaxArgs = 3, Repeatable = true, Handler = Zone });
        r.AddDirective(new() { Name = "limit_req", Contexts = ContextKind.HttpAny, MinArgs = 1, MaxArgs = 4, Repeatable = true, Handler = Limit });
        r.AddDirective(new() { Name = "limit_req_status", Contexts = ContextKind.HttpAny, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<LimitReqConf>().Status = Limits.Status(i) });
        r.AddDirective(new() { Name = "limit_req_dry_run", Contexts = ContextKind.HttpAny, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<LimitReqConf>().DryRun = i.Flag(0) });
        r.AddDirective(new() { Name = "limit_req_log_level", Contexts = ContextKind.HttpAny, MinArgs = 1, MaxArgs = 1, Handler = i => i.Conf<LimitReqConf>().Level = Limits.Level(i) });
        r.AddVariable("limit_req_status", ctx => ctx.Items.TryGetValue(_status, out var s) ? (string?)s : null);
    }

    private void Zone(DirectiveInvocation i)
    {
        string? name = null, rateArg = null;
        long bytes = 0;
        foreach (var a in i.Args.AsSpan(1))
        {
            if (a.StartsWith("zone=", StringComparison.Ordinal)) (name, bytes) = Limits.ZoneArg(i, a);
            else if (a.StartsWith("rate=", StringComparison.Ordinal)) rateArg = a[5..];
            else throw i.Error($"invalid parameter \"{a}\"");
        }
        if (name is null || rateArg is null) throw i.Error("needs zone=name:size and rate=Nr/s");
        long rate = ParseRate(i, rateArg);
        if (!_zones.TryAdd(name, (i.Args[0], i.Compile(i.Args[0]), bytes, rate))) throw i.Error($"duplicate zone \"{name}\"");
    }

    /// <summary>Requests per second × 1000 (nginx's unit), from "10r/s" or "30r/m".</summary>
    private static long ParseRate(DirectiveInvocation i, string s)
    {
        bool perMin = s.EndsWith("r/m", StringComparison.Ordinal);
        if (!perMin && !s.EndsWith("r/s", StringComparison.Ordinal)) throw i.Error($"invalid rate \"{s}\"; expected Nr/s or Nr/m");
        if (!long.TryParse(s.AsSpan(0, s.Length - 3), System.Globalization.NumberStyles.None, null, out long n) || n <= 0 || n > 1_000_000)
            throw i.Error($"invalid rate \"{s}\"");
        long rate = perMin ? n * 1000 / 60 : n * 1000;
        return Math.Max(1, rate);
    }

    private static void Limit(DirectiveInvocation i)
    {
        var c = i.Conf<LimitReqConf>();
        if (i.Args is ["off"]) { c.Off = true; return; }
        string? zone = null;
        long burst = 0, delay = 0;
        bool nodelay = false, delaySet = false;
        foreach (var a in i.Args)
        {
            if (a.StartsWith("zone=", StringComparison.Ordinal)) zone = a[5..];
            else if (a.StartsWith("burst=", StringComparison.Ordinal)) burst = Limits.Count(i, a[6..]);
            else if (a.StartsWith("delay=", StringComparison.Ordinal)) { delay = Limits.Count(i, a[6..]); delaySet = true; }
            else if (a == "nodelay") nodelay = true;
            else throw i.Error($"invalid parameter \"{a}\"");
        }
        if (string.IsNullOrEmpty(zone)) throw i.Error("needs zone=name");
        if (nodelay && delaySet) throw i.Error("\"nodelay\" and \"delay=\" are mutually exclusive");
        var own = c.Own ??= new();
        if (own.Exists(s => s.Zone == zone)) throw i.Error($"zone \"{zone}\" is already limited here");
        own.Add(new ReqSpec(zone, burst * 1000, nodelay ? long.MaxValue : delay * 1000, i.Source));
    }

    public void Configure(IModuleSetup setup)
    {
        var defs = new Dictionary<string, ReqZoneDef>(StringComparer.Ordinal);
        foreach (var (name, z) in _zones)
        {
            // Same name, size and key expression: keep the counters from before the reload.
            var state = setup.Persistent($"limit_req:{name}:{z.Bytes}:{z.Raw}", () => new ReqZone(z.Bytes));
            defs[name] = new ReqZoneDef(name, z.Key, z.Rate, state);
        }
        foreach (var scope in Limits.Scopes(setup))
        {
            if (!scope.TryGet<LimitReqConf>(out var c)) continue;
            var specs = c.Effective ??= c.Own?.ToArray() ?? [];
            var bound = new ReqLimit[specs.Length];
            for (int k = 0; k < specs.Length; k++)
            {
                var s = specs[k];
                if (!defs.TryGetValue(s.Zone, out var def)) throw new ConfigException($"unknown limit_req_zone \"{s.Zone}\"", s.Source);
                bound[k] = new ReqLimit(def, s.Burst, s.Delay);
            }
            c.Bound = bound;
        }
        setup.AddHandler(Phase.Access, Handle, Order);
    }

    private async ValueTask<HandlerResult> Handle(HttpContext ctx)
    {
        var c = ctx.Config<LimitReqConf>();
        var limits = c.Bound;
        if (limits.Length == 0 || !ctx.Items.TryAdd(_done, null)) return HandlerResult.Declined;

        long now = Environment.TickCount64;
        long delayMs = 0;
        string[]? keys = limits.Length > 1 ? new string[limits.Length] : null;
        for (int k = 0; k < limits.Length; k++)
        {
            var l = limits[k];
            var key = l.Zone.Key.Evaluate(ctx);
            if (keys is not null) keys[k] = key;
            if (key.Length == 0) continue;
            if (!l.Zone.State.Account(key, l.Zone.Rate, l.Burst, now, out long excess))
            {
                for (int j = 0; j < k; j++)
                    if (keys![j].Length > 0) limits[j].Zone.State.Refund(keys[j]);
                return Reject(ctx, c, l.Zone.Name, key, excess);
            }
            if (excess > l.Delay) delayMs = Math.Max(delayMs, (excess - l.Delay) * 1000 / l.Zone.Rate);
        }

        if (delayMs == 0)
        {
            ctx.Items[_status] = "PASSED";
            return HandlerResult.Declined;
        }
        var level = Limits.Lower(c.Level ?? LogLevel.Warn);
        if (c.DryRun == true)
        {
            ctx.Items[_status] = "DELAYED_DRY_RUN";
            return HandlerResult.Declined;
        }
        ctx.Items[_status] = "DELAYED";
        if (ctx.Log.IsEnabled(level))
            ctx.Log.Write(level, "limit_req delaying request", [new("remote", ctx.Connection.RemoteAddress), new("delay_ms", delayMs), new("uri", ctx.Request.Path)]);
        try { await Task.Delay(TimeSpan.FromMilliseconds(delayMs), ctx.Aborted).ConfigureAwait(false); }
        catch (OperationCanceledException) { return HandlerResult.Drop; } // the client is gone
        return HandlerResult.Declined;
    }

    private HandlerResult Reject(HttpContext ctx, LimitReqConf c, string zone, string key, long excess)
    {
        bool dry = c.DryRun == true;
        ctx.SecurityEvent(dry ? "rate_limit_would_reject" : "rate_limit_exceeded");
        ctx.Items[_status] = dry ? "REJECTED_DRY_RUN" : "REJECTED";
        var level = c.Level ?? LogLevel.Warn;
        if (ctx.Log.IsEnabled(level))
            ctx.Log.Write(level, dry ? "limit_req would reject (dry run)" : "limit_req rejected request",
                [new("zone", zone), new("remote", ctx.Connection.RemoteAddress), new("excess", excess / 1000.0), new("uri", ctx.Request.Path)]);
        if (dry) return HandlerResult.Declined;
        return Limits.Result(c.Status);
    }
}

/// <summary>Helpers shared by limit_req and limit_conn.</summary>
internal static class Limits
{
    public static T[] Merge<T>(T[] outer, List<T>? own, Func<T, string> zone)
    {
        if (own is null) return outer;
        var list = new List<T>();
        foreach (var e in outer)
            if (!own.Exists(o => zone(o) == zone(e))) list.Add(e);
        list.AddRange(own);
        return list.ToArray();
    }

    public static IEnumerable<IConfigScope> Scopes(IModuleSetup setup)
    {
        foreach (var s in setup.ScopesOf(ContextKind.Server)) yield return s;
        foreach (var s in setup.ScopesOf(ContextKind.Location)) yield return s;
    }

    public static (string Name, long Bytes) ZoneArg(DirectiveInvocation i, string a)
    {
        var v = a[5..];
        int colon = v.IndexOf(':');
        if (colon <= 0) throw i.Error($"invalid zone \"{v}\"; expected name:size");
        if (!ConfigValue.TryParseSize(v.AsSpan(colon + 1), out long bytes) || bytes < ZoneCost.MinSize)
            throw i.Error($"invalid zone size \"{v[(colon + 1)..]}\" (at least 32k)");
        return (v[..colon], bytes);
    }

    public static long Count(DirectiveInvocation i, string s)
    {
        if (!long.TryParse(s, System.Globalization.NumberStyles.None, null, out long n) || n > 1_000_000) throw i.Error($"invalid number \"{s}\"");
        return n;
    }

    public static int Status(DirectiveInvocation i)
    {
        int code = i.Int(0);
        if (code != HandlerResult.DropStatus && code is < 400 or > 599) throw i.Error($"status must be 400..599 or 444, not {code}");
        return code;
    }

    public static HandlerResult Result(int? status) => (status ?? 429) == HandlerResult.DropStatus ? HandlerResult.Drop : HandlerResult.WithStatus(status ?? 429);

    public static LogLevel Level(DirectiveInvocation i) => i.Args[0] switch
    {
        "info" or "notice" => LogLevel.Info,
        "warn" => LogLevel.Warn,
        "error" => LogLevel.Error,
        var a => throw i.Error($"invalid log level \"{a}\"; expected info, notice, warn or error"),
    };

    /// <summary>Delays are logged one level below rejections, as nginx does.</summary>
    public static LogLevel Lower(LogLevel l) => l switch { LogLevel.Error => LogLevel.Warn, LogLevel.Warn => LogLevel.Info, _ => LogLevel.Debug };
}
