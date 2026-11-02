using System.Diagnostics.CodeAnalysis;

namespace Httpgrl.Core.Config;

internal sealed class ConfigScope(ContextKind kind, ConfigScope? parent, string[] args, SourceLocation source) : IConfigScope
{
    private readonly Dictionary<Type, ScopeConfig> _confs = new();
    private readonly List<ConfigScope> _children = new();
    private bool _frozen;

    /// <summary>Non-repeatable directives already seen in this block (includes share the block).</summary>
    internal readonly HashSet<string> Seen = new(StringComparer.Ordinal);

    public ContextKind Kind { get; } = kind;
    public IConfigScope? Parent { get; } = parent;
    public SourceLocation Source { get; } = source;
    public IReadOnlyList<string> Args { get; } = args;
    public IReadOnlyList<IConfigScope> Children => _children;
    internal List<ConfigScope> ChildList => _children;

    internal void AddChild(ConfigScope child) => _children.Add(child);

    public T Get<T>() where T : ScopeConfig<T>, new()
    {
        if (_confs.TryGetValue(typeof(T), out var c)) return (T)c;
        if (_frozen) return ScopeConfig<T>.Default;
        var n = new T();
        _confs.Add(typeof(T), n);
        return n;
    }

    public bool TryGet<T>([NotNullWhen(true)] out T? conf) where T : ScopeConfig<T>, new()
    {
        if (_confs.TryGetValue(typeof(T), out var c)) { conf = (T)c; return true; }
        conf = null;
        return false;
    }

    /// <summary>Inherit every config slot top-down, then freeze the whole tree.</summary>
    internal void MergeAndFreeze()
    {
        foreach (var child in _children)
        {
            foreach (var (type, conf) in _confs)
            {
                if (!child._confs.TryGetValue(type, out var cc))
                {
                    cc = conf.NewEmpty();
                    child._confs.Add(type, cc);
                }
                cc.InheritFrom(conf);
            }
            child.MergeAndFreeze();
        }
        _frozen = true;
    }

    internal IEnumerable<ConfigScope> Descendants(ContextKind kind)
    {
        foreach (var c in _children)
        {
            if (c.Kind == kind) yield return c;
            foreach (var d in c.Descendants(kind)) yield return d;
        }
    }
}
