namespace Httpgrl.Core.Config;

/// <summary>Holds every registered $variable and compiles templates against them.</summary>
internal sealed class VariableRegistry
{
    private readonly Dictionary<string, VariableGetter> _vars = new(StringComparer.Ordinal);
    private readonly List<(string Prefix, PrefixVariableGetter Getter)> _prefixes = new();
    private static readonly VariableGetter[] Captures = MakeCaptures();

    public void Add(string name, VariableGetter g)
    {
        if (!_vars.TryAdd(name, g)) throw new InvalidOperationException($"variable \"${name}\" registered twice");
    }

    public void AddPrefix(string prefix, PrefixVariableGetter g)
    {
        _prefixes.Add((prefix, g));
        _prefixes.Sort((a, b) => b.Prefix.Length.CompareTo(a.Prefix.Length));
    }

    public VariableGetter? Resolve(string name)
    {
        if (_vars.TryGetValue(name, out var g)) return g;
        foreach (var (prefix, pg) in _prefixes)
        {
            if (name.Length > prefix.Length && name.StartsWith(prefix, StringComparison.Ordinal))
            {
                var suffix = name[prefix.Length..];
                return ctx => pg(ctx, suffix);
            }
        }
        return null;
    }

    /// <summary>Uses of names not (yet) registered: the parts array and slot to patch once parsing has ended.</summary>
    private readonly List<(string Name, ComplexValue.Part[] Parts, int Index, SourceLocation? At)> _pending = new();

    /// <summary>
    /// Bind every forward reference (a variable used before the <c>set</c>/<c>map</c> that declares it, as nginx
    /// allows). Patching the compiled parts in place keeps evaluation a direct call.
    /// </summary>
    public void ResolvePending()
    {
        foreach (var (name, parts, index, at) in _pending)
        {
            var g = Resolve(name) ?? throw new ConfigException($"unknown variable \"${name}\"", at);
            parts[index] = new ComplexValue.Part(null, g);
        }
        _pending.Clear();
    }

    public ComplexValue Compile(string raw, SourceLocation? at = null)
    {
        var parts = new List<ComplexValue.Part>();
        var deferred = new List<(string, int)>();
        var lit = new System.Text.StringBuilder();
        int i = 0;
        while (i < raw.Length)
        {
            char c = raw[i];
            if (c != '$') { lit.Append(c); i++; continue; }
            i++;
            if (i >= raw.Length) throw new FormatException($"invalid variable name in \"{raw}\"");
            VariableGetter getter;
            if ((uint)(raw[i] - '0') <= 9)
            {
                getter = Captures[raw[i] - '0'];
                i++;
            }
            else
            {
                bool braced = raw[i] == '{';
                if (braced) i++;
                int start = i;
                while (i < raw.Length && (char.IsAsciiLetterOrDigit(raw[i]) || raw[i] == '_')) i++;
                if (i == start) throw new FormatException($"invalid variable name in \"{raw}\"");
                string name = raw[start..i];
                if (braced)
                {
                    if (i >= raw.Length || raw[i] != '}') throw new FormatException($"missing closing \"}}\" in \"{raw}\"");
                    i++;
                }
                getter = Resolve(name) ?? Unresolved;
                if (lit.Length > 0) { parts.Add(new(lit.ToString(), null)); lit.Clear(); }
                if (ReferenceEquals(getter, Unresolved)) deferred.Add((name, parts.Count));
                parts.Add(new(null, getter));
                continue;
            }
            if (lit.Length > 0) { parts.Add(new(lit.ToString(), null)); lit.Clear(); }
            parts.Add(new(null, getter));
        }
        if (lit.Length > 0) parts.Add(new(lit.ToString(), null));
        var arr = parts.ToArray();
        foreach (var (name, index) in deferred) _pending.Add((name, arr, index, at));
        // ComplexValue keeps this array (not a copy), so ResolvePending's patch is what Evaluate sees.
        return new ComplexValue(raw, arr);
    }

    private static readonly VariableGetter Unresolved = _ => throw new InvalidOperationException("unresolved variable");

    private static VariableGetter[] MakeCaptures()
    {
        var a = new VariableGetter[10];
        for (int n = 0; n < 10; n++)
        {
            int k = n;
            a[n] = ctx => ctx.Capture(k);
        }
        return a;
    }
}
