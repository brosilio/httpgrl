using System.Diagnostics.CodeAnalysis;

namespace Httpgrl;

/// <summary>A configuration block type (main, http, server, location, or a module-defined one).</summary>
public sealed class ContextKind(string name)
{
    public string Name { get; } = name;

    public static readonly ContextKind Main = new("main");
    public static readonly ContextKind Events = new("events");
    public static readonly ContextKind Http = new("http");
    public static readonly ContextKind Server = new("server");
    public static readonly ContextKind Location = new("location");

    public static readonly ContextKind[] HttpAny = [Http, Server, Location];
    public static readonly ContextKind[] ServerAny = [Server, Location];

    public override string ToString() => Name;
}

public readonly record struct SourceLocation(string File, int Line)
{
    public override string ToString() => $"{File}:{Line}";
}

public sealed class ConfigException(string message, SourceLocation? where = null) : Exception(message)
{
    public SourceLocation? Where { get; } = where;
}

/// <summary>An unparsed statement inside a raw block (e.g. the body of <c>types { }</c>).</summary>
public sealed record RawStatement(string Name, string[] Args, SourceLocation Source);

public delegate void DirectiveHandler(DirectiveInvocation inv);

/// <summary>Declares a configuration directive. Analogous to nginx's ngx_command_t.</summary>
public sealed class Directive
{
    public required string Name { get; init; }
    public required ContextKind[] Contexts { get; init; }
    public int MinArgs { get; init; }
    /// <summary>Maximum argument count; -1 for unbounded.</summary>
    public int MaxArgs { get; init; }
    /// <summary>Non-null when the directive opens a block of this kind.</summary>
    public ContextKind? Block { get; init; }
    /// <summary>Block children are not dispatched as directives but handed over as <see cref="RawStatement"/>s.</summary>
    public bool RawBlock { get; init; }
    /// <summary>May appear more than once in the same block.</summary>
    public bool Repeatable { get; init; }
    public required DirectiveHandler Handler { get; init; }
}

/// <summary>
/// A tree node of parsed configuration. Each module stores its settings in typed
/// <see cref="ScopeConfig{TSelf}"/> slots; after parsing, every slot is inherited top-down.
/// </summary>
public interface IConfigScope
{
    ContextKind Kind { get; }
    IConfigScope? Parent { get; }
    SourceLocation Source { get; }
    /// <summary>Arguments of the directive that opened this block (e.g. <c>["=", "/x"]</c> for a location).</summary>
    IReadOnlyList<string> Args { get; }
    IReadOnlyList<IConfigScope> Children { get; }

    /// <summary>Get-or-create while parsing; after the config is frozen a missing slot yields the type's shared default.</summary>
    T Get<T>() where T : ScopeConfig<T>, new();
    bool TryGet<T>([NotNullWhen(true)] out T? conf) where T : ScopeConfig<T>, new();
}

public abstract class ScopeConfig
{
    public abstract ScopeConfig NewEmpty();
    public abstract void InheritFrom(ScopeConfig parent);
}

/// <summary>
/// Base for module configuration. Fields left unset (null) in a child scope take the parent's value
/// in <see cref="Inherit"/>. Resolve defaults at read time, never in the constructor.
/// </summary>
public abstract class ScopeConfig<TSelf> : ScopeConfig where TSelf : ScopeConfig<TSelf>, new()
{
    /// <summary>Instance returned for scopes that never touched this config. Treat as read-only.</summary>
    public static readonly TSelf Default = new();

    public sealed override ScopeConfig NewEmpty() => new TSelf();
    public sealed override void InheritFrom(ScopeConfig parent) => Inherit((TSelf)parent);
    protected abstract void Inherit(TSelf parent);
}

/// <summary>A single directive occurrence handed to <see cref="Directive.Handler"/>.</summary>
public sealed class DirectiveInvocation(
    string name, string[] args, SourceLocation source, IConfigScope scope,
    IConfigScope? block, RawStatement[]? raw, IConfigServices services)
{
    public string Name { get; } = name;
    public string[] Args { get; } = args;
    public SourceLocation Source { get; } = source;
    /// <summary>The scope the directive appears in.</summary>
    public IConfigScope Scope { get; } = scope;
    /// <summary>The block the directive opened (already parsed), for block directives.</summary>
    public IConfigScope? Block { get; } = block;
    public RawStatement[]? RawChildren { get; } = raw;

    public ConfigException Error(string message) => new($"\"{Name}\": {message}", Source);

    public T Conf<T>() where T : ScopeConfig<T>, new() => Scope.Get<T>();

    /// <summary>Compile a string containing $variables into an evaluable template.</summary>
    public ComplexValue Compile(string raw)
    {
        try { return services.Compile(raw); }
        catch (FormatException e) { throw Error(e.Message); }
    }

    /// <summary>
    /// Read a file at config time (certificates, CA bundles...), relative to the main config's directory.
    /// Modules never touch the filesystem themselves; this is the sanctioned door, and it's closed once the server runs.
    /// </summary>
    public byte[] ReadFile(string path, long maxBytes = 1 << 20)
    {
        try { return services.ReadFile(path, maxBytes); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
        {
            throw Error($"cannot read \"{path}\": {e.Message}");
        }
    }

    public bool Flag(int i) => Args[i] switch
    {
        "on" => true,
        "off" => false,
        _ => throw Error($"invalid value \"{Args[i]}\", expected \"on\" or \"off\""),
    };

    public long Size(int i) => ConfigValue.TryParseSize(Args[i], out var v) ? v : throw Error($"invalid size \"{Args[i]}\"");
    public int Millis(int i) => ConfigValue.TryParseMillis(Args[i], out var v) ? v : throw Error($"invalid time \"{Args[i]}\"");
    public int Int(int i) => int.TryParse(Args[i], System.Globalization.NumberStyles.None, null, out var v) ? v : throw Error($"invalid number \"{Args[i]}\"");
}

/// <summary>Parser-provided services for directive handlers (implemented by the core).</summary>
public interface IConfigServices
{
    ComplexValue Compile(string raw);
    byte[] ReadFile(string path, long maxBytes);
}

public static class ConfigValue
{
    /// <summary>nginx sizes: 1024, 8k, 1m, 1g (case-insensitive).</summary>
    public static bool TryParseSize(ReadOnlySpan<char> s, out long value)
    {
        value = 0;
        if (s.IsEmpty) return false;
        long mul = 1;
        switch (s[^1] | 0x20)
        {
            case 'k': mul = 1L << 10; s = s[..^1]; break;
            case 'm': mul = 1L << 20; s = s[..^1]; break;
            case 'g': mul = 1L << 30; s = s[..^1]; break;
        }
        if (!long.TryParse(s, System.Globalization.NumberStyles.None, null, out var n)) return false;
        if (n > long.MaxValue / mul) return false;
        value = n * mul;
        return true;
    }

    /// <summary>nginx times: "30" (seconds), 500ms, 10s, 5m, 1h, 1d, and sequences such as "1m30s".</summary>
    public static bool TryParseMillis(ReadOnlySpan<char> s, out int ms)
    {
        ms = 0;
        if (s.IsEmpty) return false;
        long total = 0;
        int i = 0;
        while (i < s.Length)
        {
            long n = 0;
            int start = i;
            while (i < s.Length && (uint)(s[i] - '0') <= 9)
            {
                n = n * 10 + (s[i] - '0');
                if (n > int.MaxValue) return false;
                i++;
            }
            if (i == start) return false;
            long unit = 1000;
            if (i < s.Length)
            {
                if (s[i] == 'm' && i + 1 < s.Length && s[i + 1] == 's') { unit = 1; i += 2; }
                else
                {
                    unit = s[i] switch { 's' => 1000, 'm' => 60_000, 'h' => 3_600_000, 'd' => 86_400_000, _ => -1 };
                    if (unit < 0) return false;
                    i++;
                }
            }
            else if (start != 0) return false; // trailing bare number after a unit, e.g. "1m30"
            total += n * unit;
            if (total > int.MaxValue) return false;
        }
        ms = (int)total;
        return true;
    }
}
