namespace Httpgrl;

/// <summary>
/// A compiled-in server module (cf. nginx ngx_module_t). Lifecycle:
/// <list type="number">
/// <item><see cref="Register"/>: declare directives and variables, before any config is parsed.</item>
/// <item>The config is parsed, directive handlers fill <see cref="ScopeConfig{TSelf}"/> slots, scopes are merged and frozen.</item>
/// <item><see cref="Configure"/>: validate the merged config and install request phase handlers.</item>
/// </list>
/// Modules are instantiated once per loaded configuration and must keep no per-request state of their own.
/// </summary>
public interface IModule
{
    string Name { get; }
    void Register(IModuleRegistry registry);
    void Configure(IModuleSetup setup) { }
}

public interface IModuleRegistry
{
    void AddDirective(Directive directive);
    /// <summary>Register <c>$name</c>.</summary>
    void AddVariable(string name, VariableGetter getter);
    /// <summary>Register a family such as <c>$http_*</c>; the getter receives the suffix.</summary>
    void AddVariablePrefix(string prefix, PrefixVariableGetter getter);
}

public interface IModuleSetup
{
    IConfigScope Root { get; }
    ILogger Log { get; }
    /// <summary>All scopes of a kind, in config order (e.g. every location of every server).</summary>
    IEnumerable<IConfigScope> ScopesOf(ContextKind kind);
    /// <summary>Install a phase handler. Lower <paramref name="order"/> runs first.</summary>
    void AddHandler(Phase phase, HttpHandler handler, int order);
}

/// <summary>Request processing phases, in execution order (subset of nginx's).</summary>
public enum Phase
{
    /// <summary>After location selection. May rewrite (internal redirect) or answer.</summary>
    Rewrite,
    /// <summary>Allow/deny decisions.</summary>
    Access,
    /// <summary>Produce the response. Skipped if the location has an exclusive handler (see <see cref="LocationHandlerConf"/>).</summary>
    Content,
    /// <summary>After the response is complete. Return value is ignored.</summary>
    Log,
}

public delegate ValueTask<HandlerResult> HttpHandler(HttpContext ctx);
public delegate string? VariableGetter(HttpContext ctx);
public delegate string? PrefixVariableGetter(HttpContext ctx, string suffix);

public enum HandlerAction : byte
{
    /// <summary>Not mine; try the next handler.</summary>
    Declined,
    /// <summary>The response has been produced.</summary>
    Done,
    /// <summary>Finish with <see cref="HandlerResult.Status"/>; the core renders the body (or an error_page).</summary>
    Status,
    /// <summary>Restart location processing with <see cref="HandlerResult.Uri"/> (path, "path?args", or "@named").</summary>
    InternalRedirect,
}

public readonly struct HandlerResult
{
    public readonly HandlerAction Action;
    public readonly int Status;
    public readonly string? Uri;

    private HandlerResult(HandlerAction a, int status, string? uri) { Action = a; Status = status; Uri = uri; }

    public static readonly HandlerResult Declined = new(HandlerAction.Declined, 0, null);
    public static readonly HandlerResult Done = new(HandlerAction.Done, 0, null);
    public static HandlerResult WithStatus(int status) => new(HandlerAction.Status, status, null);

    /// <summary>nginx's 444: close the connection without sending anything. Logged with status 444.</summary>
    public const int DropStatus = 444;
    public static readonly HandlerResult Drop = new(HandlerAction.Status, DropStatus, null);
    public static HandlerResult Redirect(string uri) => new(HandlerAction.InternalRedirect, 0, uri);

    public static implicit operator ValueTask<HandlerResult>(HandlerResult r) => new(r);
}

/// <summary>
/// Exclusive content handler for one location (cf. nginx clcf->handler, set by e.g. proxy_pass).
/// Not inherited by nested locations.
/// </summary>
public sealed class LocationHandlerConf : ScopeConfig<LocationHandlerConf>
{
    public HttpHandler? Handler;
    public string? Owner;
    protected override void Inherit(LocationHandlerConf parent) { }
}

/// <summary>A string template with $variables, compiled once at config time.</summary>
public sealed class ComplexValue
{
    public readonly struct Part(string? literal, VariableGetter? getter)
    {
        public readonly string? Literal = literal;
        public readonly VariableGetter? Getter = getter;
    }

    private readonly Part[] _parts;
    public string Raw { get; }
    /// <summary>Non-null when the template has no variables.</summary>
    public string? Constant { get; }

    public ComplexValue(string raw, Part[] parts)
    {
        Raw = raw;
        _parts = parts;
        if (parts.Length == 0) Constant = "";
        else if (parts.Length == 1 && parts[0].Getter is null) Constant = parts[0].Literal;
    }

    public string Evaluate(HttpContext ctx)
    {
        if (Constant is not null) return Constant;
        var parts = _parts;
        if (parts.Length == 1) return parts[0].Getter!(ctx) ?? "";
        var sb = new System.Text.StringBuilder(64);
        for (int i = 0; i < parts.Length; i++)
        {
            ref readonly var p = ref parts[i];
            sb.Append(p.Getter is null ? p.Literal : p.Getter(ctx));
        }
        return sb.ToString();
    }

    public override string ToString() => Raw;
}
