using System.Text.RegularExpressions;

namespace Httpgrl.Modules.Rewrite;

/// <summary>
/// <c>map $source $result { default value; key value; ~regex value; ~*regex value; }</c> (ngx_http_map_module).
/// The source may combine variables (<c>"$host$uri"</c>). Exact keys are matched first (case-sensitively, like
/// nginx without <c>hostnames</c>), then regexes in order (a match sets <c>$1</c>..<c>$9</c> for the value), then
/// <c>default</c> (empty if absent). Values may contain variables. A key starting with <c>~</c> literally is
/// written <c>\~</c>.
///
/// The result is computed when it is used, not cached per request (cf. nginx's <c>volatile</c>, accepted and
/// redundant here). <c>hostnames</c> and <c>include</c> inside a map are not supported.
/// </summary>
public sealed class MapModule : IModule
{
    private static readonly ContextKind MapBlock = new("map");
    private const int MaxDepth = 16;

    [ThreadStatic] private static int t_depth;

    public string Name => "http_map";

    public void Register(IModuleRegistry r) => r.AddDirective(new()
    {
        Name = "map", Contexts = [ContextKind.Http], MinArgs = 2, MaxArgs = 2, Block = MapBlock, RawBlock = true, Repeatable = true,
        Handler = Map,
    });

    private static void Map(DirectiveInvocation i)
    {
        var source = i.Compile(i.Args[0]);
        var name = RewriteModule.VariableName(i, i.Args[1]);
        var exact = new Dictionary<string, ComplexValue>(StringComparer.Ordinal);
        var regexes = new List<(Regex, ComplexValue)>();
        ComplexValue? def = null;
        foreach (var st in i.RawChildren!)
        {
            switch (st.Name)
            {
                case "volatile" when st.Args.Length == 0: continue;
                case "hostnames" when st.Args.Length == 0: throw new ConfigException("\"map\": \"hostnames\" is not supported", st.Source);
                case "include": throw new ConfigException("\"map\": \"include\" inside a map is not supported", st.Source);
            }
            if (st.Args.Length != 1) throw new ConfigException($"\"map\": invalid entry \"{st.Name}\"; expected \"key value;\"", st.Source);
            ComplexValue value;
            try { value = i.Compile(st.Args[0]); }
            catch (ConfigException e) { throw new ConfigException(e.Message, st.Source); }
            var key = st.Name;
            if (key == "default")
            {
                if (def is not null) throw new ConfigException("\"map\": duplicate default", st.Source);
                def = value;
            }
            else if (key.StartsWith('~'))
            {
                bool ci = key.StartsWith("~*", StringComparison.Ordinal);
                try { regexes.Add((Regexes.Compile(key[(ci ? 2 : 1)..], ci), value)); }
                catch (ArgumentException e) { throw new ConfigException($"\"map\": invalid regex \"{key}\": {e.Message}", st.Source); }
            }
            else
            {
                if (key.StartsWith('\\')) key = key[1..]; // \~ and \default are literal keys
                if (!exact.TryAdd(key, value)) throw new ConfigException($"\"map\": duplicate key \"{key}\"", st.Source);
            }
        }
        var regexArr = regexes.ToArray();
        i.AddVariable(name, ctx => Lookup(ctx, source, exact, regexArr, def));
    }

    private static string Lookup(HttpContext ctx, ComplexValue source, Dictionary<string, ComplexValue> exact, (Regex Re, ComplexValue Value)[] regexes, ComplexValue? def)
    {
        // A map whose value (indirectly) uses itself would otherwise recurse until the process dies.
        if (++t_depth > MaxDepth)
        {
            t_depth--;
            throw new InvalidOperationException("map variables reference each other in a cycle");
        }
        try
        {
            var s = source.Evaluate(ctx);
            if (exact.TryGetValue(s, out var v)) return v.Evaluate(ctx);
            foreach (var (re, value) in regexes)
            {
                var m = re.Match(s);
                if (!m.Success) continue;
                ctx.SetCaptures(m);
                return value.Evaluate(ctx);
            }
            return def?.Evaluate(ctx) ?? "";
        }
        finally { t_depth--; }
    }
}
