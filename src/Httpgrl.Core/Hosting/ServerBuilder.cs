using Httpgrl.Core.Config;
using Httpgrl.Core.Logging;
using Httpgrl.Core.Modules;
using Httpgrl.Core.Pipeline;

namespace Httpgrl.Core.Hosting;

/// <summary>
/// Loads a configuration: registers modules, parses, merges, lets modules configure, compiles routing.
/// Everything a running server needs is produced here, so a config that loads is a config that runs.
/// </summary>
public static class ServerBuilder
{
    /// <summary>Load a configuration file. <paramref name="modules"/> is called again on every reload (fresh module state).</summary>
    public static HttpServer Load(string configPath, Func<IModule[]> modules, JsonLogger log)
    {
        var full = Path.GetFullPath(configPath);
        var prefix = Path.GetDirectoryName(full)!;
        return new HttpServer(() => Build(modules(), log, prefix, p => p.ParseFile(full)), log);
    }

    public static HttpServer LoadText(string text, string prefix, Func<IModule[]> modules, JsonLogger log) =>
        new(() => BuildText(text, prefix, modules(), log), log);

    internal static HttpRuntime BuildText(string text, string prefix, IEnumerable<IModule> modules, JsonLogger log) =>
        Build(modules, log, prefix, p => p.ParseText(text, Path.Combine(prefix, "<inline>"), prefix));

    /// <summary>Everything a running server needs. Side-effect free: a failed build (e.g. on reload) changes nothing.</summary>
    private static HttpRuntime Build(IEnumerable<IModule> extra, JsonLogger log, string prefix, Func<ConfigParser, ConfigScope> parse)
    {
        IModule[] modules = [new HttpCoreModule(prefix), new SslModule(), new AccessLogModule(), .. extra];

        var registry = new Registry();
        foreach (var m in modules)
        {
            registry.Owner = m.Name;
            m.Register(registry);
        }

        var root = parse(new ConfigParser(registry.Directives, registry.Vars));
        root.MergeAndFreeze();

        var main = root.Get<MainConf>();

        var setup = new Setup(root, log);
        foreach (var m in modules) m.Configure(setup);

        var bindings = RoutingBuilder.Build(root, log);
        var events = root.Children.FirstOrDefault(c => c.Kind == ContextKind.Events)?.Get<EventsConf>() ?? EventsConf.Default;

        var rt = new HttpRuntime
        {
            Log = log,
            Vars = registry.Vars,
            Pipeline = setup.BuildPipeline(),
            Bindings = bindings,
            DefaultRoot = Path.Combine(prefix, "html"),
            Main = main,
            Events = events,
            Modules = modules,
        };
        return rt;
    }

    private sealed class Registry : IModuleRegistry
    {
        public readonly Dictionary<string, List<Directive>> Directives = new(StringComparer.Ordinal);
        private readonly Dictionary<Directive, string> _owners = new();
        public readonly VariableRegistry Vars = new();
        public string Owner = "";

        public void AddDirective(Directive d)
        {
            if (d.RawBlock && d.Block is null) throw new InvalidOperationException($"directive \"{d.Name}\": RawBlock requires Block");
            if (!Directives.TryGetValue(d.Name, out var list)) Directives[d.Name] = list = new List<Directive>(1);
            foreach (var other in list)
                foreach (var ctx in d.Contexts)
                    if (Array.IndexOf(other.Contexts, ctx) >= 0)
                        throw new InvalidOperationException($"directive \"{d.Name}\" in \"{ctx}\" from module \"{Owner}\" is already defined by \"{_owners[other]}\"");
            list.Add(d);
            _owners[d] = Owner;
        }

        public void AddVariable(string name, VariableGetter getter) => Vars.Add(name, getter);
        public void AddVariablePrefix(string prefix, PrefixVariableGetter getter) => Vars.AddPrefix(prefix, getter);
    }

    private sealed class Setup(ConfigScope root, ILogger log) : IModuleSetup
    {
        private readonly List<(Phase Phase, int Order, int Seq, HttpHandler Handler)> _handlers = new();

        public IConfigScope Root => root;
        public ILogger Log => log;
        public IEnumerable<IConfigScope> ScopesOf(ContextKind kind) => root.Descendants(kind);

        public void AddHandler(Phase phase, HttpHandler handler, int order) => _handlers.Add((phase, order, _handlers.Count, handler));

        public RequestPipeline BuildPipeline()
        {
            HttpHandler[] Of(Phase p)
            {
                var l = _handlers.FindAll(h => h.Phase == p);
                l.Sort((a, b) => a.Order != b.Order ? a.Order.CompareTo(b.Order) : a.Seq.CompareTo(b.Seq));
                return l.ConvertAll(h => h.Handler).ToArray();
            }
            return new RequestPipeline(Of(Phase.Rewrite), Of(Phase.Access), Of(Phase.Content), Of(Phase.Log));
        }
    }
}
