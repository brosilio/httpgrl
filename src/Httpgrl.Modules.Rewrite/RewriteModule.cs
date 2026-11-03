using System.Text;
using System.Text.RegularExpressions;

namespace Httpgrl.Modules.Rewrite;

/// <summary>
/// The rewrite script of one block (server, location or if), in config order. Not inherited: as in nginx, a
/// block's rewrite directives belong to it, and the server's run for every request before the location's.
/// </summary>
public sealed class RewriteConf : ScopeConfig<RewriteConf>
{
    internal List<Op>? Script;
    protected override void Inherit(RewriteConf parent) { }
}

internal abstract class Op;

internal sealed class ReturnOp(int code, ComplexValue? text) : Op
{
    public readonly int Code = code;
    /// <summary>Body text, or the redirect target for 301/302/303/307/308.</summary>
    public readonly ComplexValue? Text = text;
}

internal sealed class SetOp(int slot, ComplexValue value) : Op
{
    public readonly int Slot = slot;
    public readonly ComplexValue Value = value;
}

internal sealed class BreakOp : Op
{
    public static readonly BreakOp Instance = new();
}

internal enum RewriteFlag : byte { None, Last, Break, Redirect, Permanent }

internal sealed class RewriteOp(Regex regex, ComplexValue replacement, RewriteFlag flag) : Op
{
    public readonly Regex Regex = regex;
    public readonly ComplexValue Replacement = replacement;
    public readonly RewriteFlag Flag = flag;
}

internal sealed class IfOp(Condition cond, List<Op> body) : Op
{
    public readonly Condition Cond = cond;
    public readonly List<Op> Body = body;
}

/// <summary>
/// ngx_http_rewrite_module's <c>return</c>, <c>set</c>, <c>if</c> and <c>break</c>. The server's script runs first,
/// then the location's, at the start of the rewrite phase; <c>return</c> ends the request, <c>break</c> ends the
/// current block's script.
///
/// Unlike nginx, an <c>if</c> block may contain only these directives (and nested <c>if</c>s): nginx's
/// "if is evil" comes from <c>if</c> being a half-location where other directives behave surprisingly. For a
/// conditional header, upstream or the like, compute a value with <c>map</c> and use it.
/// </summary>
public sealed class RewriteModule : IModule
{
    public const int Order = 0;
    public static readonly ContextKind If = new("if");
    private static readonly ContextKind[] Scripted = [ContextKind.Server, ContextKind.Location, If];

    public string Name => "http_rewrite";

    // User variables ($name from "set"): a slot each in a per-request array.
    private readonly Dictionary<string, int> _slots = new(StringComparer.Ordinal);
    private readonly object _key = new();

    public void Register(IModuleRegistry r)
    {
        r.AddDirective(new() { Name = "return", Contexts = Scripted, MinArgs = 1, MaxArgs = 2, Handler = Return });
        r.AddDirective(new() { Name = "set", Contexts = Scripted, MinArgs = 2, MaxArgs = 2, Repeatable = true, Handler = Set });
        r.AddDirective(new() { Name = "break", Contexts = Scripted, MaxArgs = 0, Handler = i => Append(i, BreakOp.Instance) });
        r.AddDirective(new() { Name = "rewrite", Contexts = Scripted, MinArgs = 2, MaxArgs = 3, Repeatable = true, Handler = Rewrite });
        r.AddDirective(new() { Name = "rewrite_log", Contexts = [ContextKind.Http, ContextKind.Server, ContextKind.Location, If], MinArgs = 1, MaxArgs = 1, Handler = i => i.Flag(0) });
        r.AddDirective(new() { Name = "if", Contexts = Scripted, MinArgs = 1, MaxArgs = -1, Block = If, Repeatable = true, Handler = IfDirective });
    }

    private static void Append(DirectiveInvocation i, Op op) => (i.Conf<RewriteConf>().Script ??= new()).Add(op);

    private static void Return(DirectiveInvocation i)
    {
        var first = i.Args[0];
        if (i.Args.Length == 1 && (first.StartsWith("http://", StringComparison.Ordinal) || first.StartsWith("https://", StringComparison.Ordinal) || first.StartsWith("$scheme", StringComparison.Ordinal)))
        {
            Append(i, new ReturnOp(302, i.Compile(first)));
            return;
        }
        int code = i.Int(0);
        if (code != HandlerResult.DropStatus && code is < 200 or > 599) throw i.Error($"invalid return code \"{first}\"");
        if (code == HandlerResult.DropStatus && i.Args.Length > 1) throw i.Error("\"return 444\" closes the connection and cannot carry text");
        if (IsRedirect(code) && i.Args.Length < 2) throw i.Error($"\"return {code}\" needs a URL");
        Append(i, new ReturnOp(code, i.Args.Length > 1 ? i.Compile(i.Args[1]) : null));
    }

    private void Set(DirectiveInvocation i)
    {
        var name = VariableName(i, i.Args[0]);
        if (!_slots.TryGetValue(name, out int slot))
        {
            _slots[name] = slot = _slots.Count;
            var key = _key;
            i.AddVariable(name, ctx => ctx.Items.TryGetValue(key, out var o) ? ((string?[])o!)[slot] : null);
        }
        Append(i, new SetOp(slot, i.Compile(i.Args[1])));
    }

    internal static string VariableName(DirectiveInvocation i, string arg)
    {
        if (arg.Length < 2 || arg[0] != '$') throw i.Error($"invalid variable name \"{arg}\"");
        foreach (char c in arg.AsSpan(1))
            if (!char.IsAsciiLetterOrDigit(c) && c != '_') throw i.Error($"invalid variable name \"{arg}\"");
        return arg[1..];
    }

    private static void Rewrite(DirectiveInvocation i)
    {
        var flag = i.Args.Length < 3 ? RewriteFlag.None : i.Args[2] switch
        {
            "last" => RewriteFlag.Last,
            "break" => RewriteFlag.Break,
            "redirect" => RewriteFlag.Redirect,
            "permanent" => RewriteFlag.Permanent,
            var f => throw i.Error($"invalid flag \"{f}\"; expected last, break, redirect or permanent"),
        };
        Append(i, new RewriteOp(Regexes.Compile(i.Args[0], ignoreCase: false), i.Compile(i.Args[1]), flag));
    }

    private static void IfDirective(DirectiveInvocation i)
    {
        var body = i.Block!.Get<RewriteConf>().Script ?? new List<Op>();
        Append(i, new IfOp(Condition.Parse(i), body));
    }

    public void Configure(IModuleSetup setup) => setup.AddHandler(Phase.Rewrite, Handle, Order);

    private static bool IsRedirect(int code) => code is 301 or 302 or 303 or 307 or 308;

    /// <summary>How a block's script ended.</summary>
    private enum Flow : byte { Done, Stop, Reselect, Respond }

    /// <summary>What to answer with when a script ends the request (return, or a rewrite redirect).</summary>
    private sealed record Response(ReturnOp? Return, int RedirectStatus = 0, string? Location = null);

    private const int MaxLocationCycles = 10;

    private ValueTask<HandlerResult> Handle(HttpContext ctx)
    {
        // Server level first; the location is (re)chosen by whatever URI it leaves.
        var flow = Run(ctx.Server.Get<RewriteConf>().Script, ctx, serverLevel: true, out var resp);
        if (flow == Flow.Respond) return Respond(ctx, resp!);
        // Location level: a rewrite without a flag, or with "last", sends the request to the location of the new URI,
        // whose own rewrites then run (nginx's rewrite cycle, bounded).
        for (int cycle = 0; !ReferenceEquals(ctx.Location, ctx.Server); cycle++)
        {
            if (cycle == MaxLocationCycles)
            {
                ctx.Log.Error("rewrite cycle", new LogField("uri", ctx.Request.Path));
                return new(HandlerResult.WithStatus(500));
            }
            flow = Run(ctx.Config<RewriteConf>().Script, ctx, serverLevel: false, out resp);
            if (flow == Flow.Respond) return Respond(ctx, resp!);
            if (flow != Flow.Reselect) break;
        }
        return new(HandlerResult.Declined);
    }

    private Flow Run(List<Op>? script, HttpContext ctx, bool serverLevel, out Response? resp)
    {
        resp = null;
        if (script is null) return Flow.Done;
        bool changed = false;
        var flow = Exec(script, ctx, serverLevel, ref changed, out resp);
        if (flow is Flow.Respond or Flow.Reselect) return flow;
        // A URI changed without a flag: choose the location again now (server level: before any location runs;
        // location level: for the next cycle).
        if (changed)
        {
            if (!ctx.SetUri(ctx.Request.Path, ctx.Request.Query, reselectLocation: true)) return Error(ctx, out resp);
            return serverLevel ? Flow.Done : Flow.Reselect;
        }
        return flow;
    }

    private Flow Exec(List<Op> ops, HttpContext ctx, bool serverLevel, ref bool changed, out Response? resp)
    {
        resp = null;
        foreach (var op in ops)
        {
            switch (op)
            {
                case SetOp s:
                    Slots(ctx)[s.Slot] = s.Value.Evaluate(ctx);
                    break;
                case IfOp f when f.Cond.Evaluate(ctx):
                    var inner = Exec(f.Body, ctx, serverLevel, ref changed, out resp);
                    if (inner != Flow.Done) return inner;
                    break;
                case BreakOp:
                    return Flow.Stop;
                case ReturnOp ret:
                    resp = new Response(ret);
                    return Flow.Respond;
                case RewriteOp rw:
                    var m = rw.Regex.Match(ctx.Request.Path);
                    if (!m.Success) break;
                    ctx.SetCaptures(m);
                    var target = rw.Replacement.Evaluate(ctx);
                    var (path, query) = SplitTarget(target, ctx.Request.Query);
                    bool absolute = target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
                    if (absolute || rw.Flag is RewriteFlag.Redirect or RewriteFlag.Permanent)
                    {
                        resp = new Response(null, rw.Flag == RewriteFlag.Permanent ? 301 : 302, query.Length > 0 ? path + "?" + query : path);
                        return Flow.Respond;
                    }
                    switch (rw.Flag)
                    {
                        case RewriteFlag.Last:
                            // Server level: the location search follows anyway. Location level: start a new cycle.
                            if (!ctx.SetUri(path, query, reselectLocation: true)) return Error(ctx, out resp);
                            return serverLevel ? Flow.Stop : Flow.Reselect;
                        case RewriteFlag.Break:
                            // Stays in this location (at server level the location is chosen by the new URI).
                            if (!ctx.SetUri(path, query, reselectLocation: serverLevel)) return Error(ctx, out resp);
                            changed = false;
                            return Flow.Stop;
                        default:
                            if (!ctx.SetUri(path, query, reselectLocation: false)) return Error(ctx, out resp);
                            changed = true;
                            break;
                    }
                    break;
            }
        }
        return Flow.Done;
    }

    /// <summary>
    /// nginx's argument rule: a replacement with its own '?' arguments gets the original ones appended (after '&amp;'),
    /// unless it ends with '?'; one without keeps the original arguments.
    /// </summary>
    internal static (string Path, string Query) SplitTarget(string target, string originalQuery)
    {
        bool drop = target.EndsWith('?');
        if (drop) target = target[..^1];
        int q = target.IndexOf('?');
        if (q < 0) return (target, drop ? "" : originalQuery);
        var own = target[(q + 1)..];
        return (target[..q], drop || originalQuery.Length == 0 ? own : own.Length == 0 ? originalQuery : own + "&" + originalQuery);
    }

    private static Flow Error(HttpContext ctx, out Response? resp)
    {
        ctx.Log.Error("rewrite produced an invalid URI", new LogField("uri", ctx.Request.Path));
        resp = new Response(new ReturnOp(500, null));
        return Flow.Respond;
    }

    private static ValueTask<HandlerResult> Respond(HttpContext ctx, Response r)
    {
        if (r.Return is { } ret) return ReturnAsync(ctx, ret);
        ctx.Response.Headers.Set("Location", EscapeForHeader(r.Location!));
        return new(HandlerResult.WithStatus(r.RedirectStatus));
    }

    private string?[] Slots(HttpContext ctx)
    {
        if (ctx.Items.TryGetValue(_key, out var o)) return (string?[])o!;
        var a = new string?[_slots.Count];
        ctx.Items[_key] = a;
        return a;
    }

    private static async ValueTask<HandlerResult> ReturnAsync(HttpContext ctx, ReturnOp c)
    {
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

/// <summary>
/// An <c>if</c> condition: <c>($var)</c> (true unless empty or "0"), <c>$var = str</c>, <c>$var != str</c>, and
/// regex matches <c>~ ~* !~ !~*</c> (a successful positive match sets <c>$1</c>..<c>$9</c>). nginx's file tests
/// (<c>-f</c>, <c>-d</c>...) are not supported: they operate on filesystem paths, which modules never see. Use
/// <c>try_files</c>.
/// </summary>
internal sealed class Condition
{
    private enum Kind : byte { Truthy, Equal, NotEqual, Match, NotMatch }

    private readonly Kind _kind;
    private readonly ComplexValue _left;
    private readonly ComplexValue? _right;
    private readonly Regex? _regex;

    private Condition(Kind kind, ComplexValue left, ComplexValue? right, Regex? regex)
    {
        _kind = kind;
        _left = left;
        _right = right;
        _regex = regex;
    }

    public bool Evaluate(HttpContext ctx)
    {
        var v = _left.Evaluate(ctx);
        switch (_kind)
        {
            case Kind.Truthy: return v.Length > 0 && v != "0";
            case Kind.Equal: return v == _right!.Evaluate(ctx);
            case Kind.NotEqual: return v != _right!.Evaluate(ctx);
            case Kind.Match:
                var m = _regex!.Match(v);
                if (!m.Success) return false;
                ctx.SetCaptures(m);
                return true;
            default: return !_regex!.IsMatch(v);
        }
    }

    /// <summary>Accepts nginx's spellings: <c>if ($a = b)</c>, <c>if ( $a = b )</c>, <c>if ($a = "b")</c>.</summary>
    public static Condition Parse(DirectiveInvocation i)
    {
        var a = new List<string>(i.Args);
        if (a[0] == "(") a.RemoveAt(0);
        else if (a[0].StartsWith('(')) a[0] = a[0][1..];
        else throw i.Error("condition must be in parentheses");
        if (a.Count == 0) throw i.Error("empty condition");
        if (a[^1] == ")") a.RemoveAt(a.Count - 1);
        else if (a[^1].EndsWith(')')) a[^1] = a[^1][..^1];
        else throw i.Error("missing \")\"");
        if (a.Count == 0 || a[0].Length == 0) throw i.Error("empty condition");

        if (a[0] is "-f" or "!-f" or "-d" or "!-d" or "-e" or "!-e" or "-x" or "!-x")
            throw i.Error($"file tests (\"{a[0]}\") are not supported: modules never see filesystem paths; use try_files");
        if (!a[0].StartsWith('$')) throw i.Error($"the left side of a condition must be a variable, not \"{a[0]}\"");
        var left = i.Compile(a[0]);
        if (a.Count == 1) return new Condition(Kind.Truthy, left, null, null);
        if (a.Count != 3) throw i.Error("invalid condition; expected ($var), ($var = value), ($var != value) or ($var ~ regex)");
        return a[1] switch
        {
            "=" => new Condition(Kind.Equal, left, i.Compile(a[2]), null),
            "!=" => new Condition(Kind.NotEqual, left, i.Compile(a[2]), null),
            "~" => new Condition(Kind.Match, left, null, Regexes.Compile(a[2], ignoreCase: false)),
            "~*" => new Condition(Kind.Match, left, null, Regexes.Compile(a[2], ignoreCase: true)),
            "!~" => new Condition(Kind.NotMatch, left, null, Regexes.Compile(a[2], ignoreCase: false)),
            "!~*" => new Condition(Kind.NotMatch, left, null, Regexes.Compile(a[2], ignoreCase: true)),
            var op => throw i.Error($"unknown operator \"{op}\""),
        };
    }
}

internal static class Regexes
{
    /// <summary>
    /// Linear-time NonBacktracking where the pattern allows (no backreferences or lookarounds); otherwise
    /// backtracking with a 50 ms match timeout. Same policy as the core uses for regex locations.
    /// </summary>
    public static Regex Compile(string pattern, bool ignoreCase)
    {
        var opts = RegexOptions.CultureInvariant | (ignoreCase ? RegexOptions.IgnoreCase : RegexOptions.None);
        try { return new Regex(pattern, opts | RegexOptions.NonBacktracking); }
        catch (NotSupportedException) { return new Regex(pattern, opts, TimeSpan.FromMilliseconds(50)); }
    }
}
