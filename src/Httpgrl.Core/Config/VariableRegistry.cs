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

    public ComplexValue Compile(string raw)
    {
        var parts = new List<ComplexValue.Part>();
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
                getter = Resolve(name) ?? throw new FormatException($"unknown variable \"${name}\"");
            }
            if (lit.Length > 0) { parts.Add(new(lit.ToString(), null)); lit.Clear(); }
            parts.Add(new(null, getter));
        }
        if (lit.Length > 0) parts.Add(new(lit.ToString(), null));
        return new ComplexValue(raw, parts.ToArray());
    }

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
