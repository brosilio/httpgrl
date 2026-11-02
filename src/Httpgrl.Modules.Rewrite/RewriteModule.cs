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

    private static void IfDirective(DirectiveInvocation i)
    {
        var body = i.Block!.Get<RewriteConf>().Script ?? new List<Op>();
        Append(i, new IfOp(Condition.Parse(i), body));
    }

    public void Configure(IModuleSetup setup) => setup.AddHandler(Phase.Rewrite, Handle, Order);

    private static bool IsRedirect(int code) => code is 301 or 302 or 303 or 307 or 308;

    private ValueTask<HandlerResult> Handle(HttpContext ctx)
    {
        var ret = Run(ctx.Server.Get<RewriteConf>().Script, ctx);
        if (ret is null && !ReferenceEquals(ctx.Location, ctx.Server)) ret = Run(ctx.Config<RewriteConf>().Script, ctx);
        return ret is null ? new(HandlerResult.Declined) : ReturnAsync(ctx, ret);
    }

    /// <summary>Run one block's script. Returns the <c>return</c> to execute, or null to carry on.</summary>
    private ReturnOp? Run(List<Op>? script, HttpContext ctx)
    {
        if (script is null) return null;
        return Exec(script, ctx, out _);
    }

    private ReturnOp? Exec(List<Op> ops, HttpContext ctx, out bool broke)
    {
        broke = false;
        foreach (var op in ops)
        {
            switch (op)
            {
                case SetOp s:
                    Slots(ctx)[s.Slot] = s.Value.Evaluate(ctx);
                    break;
                case IfOp f when f.Cond.Evaluate(ctx):
                    var r = Exec(f.Body, ctx, out broke);
                    if (r is not null || broke) return r;
                    break;
                case BreakOp:
                    broke = true;
                    return null;
                case ReturnOp ret:
                    return ret;
            }
        }
        return null;
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
