using System.Net;
using System.Net.Sockets;

namespace Httpgrl.Modules.Access;

internal readonly record struct Rule(bool Allow, IPNetwork? Net, bool Unix, bool All);

/// <summary>
/// allow/deny rules of one block, in order. As in nginx, a level with its own rules replaces the inherited list
/// (an ordered list can't be merged meaningfully); a level without rules inherits its parent's.
/// </summary>
public sealed class AccessConf : ScopeConfig<AccessConf>
{
    internal List<Rule>? Rules;
    internal Rule[] Effective = [];

    protected override void Inherit(AccessConf parent) => Rules ??= parent.Rules;
}

/// <summary>
/// <c>allow address | CIDR | unix: | all;</c> and <c>deny ...;</c> (ngx_http_access_module). The first rule that
/// matches the client address decides; no match allows. A denied request gets a 403 (so <c>error_page 403 =444</c>
/// drops it). IPv4 clients reaching an IPv6 socket as <c>::ffff:a.b.c.d</c> are matched as IPv4.
/// </summary>
public sealed class AccessModule : IModule
{
    public const int Order = 10; // after limit_req/limit_conn, as nginx's access phase follows preaccess

    public string Name => "http_access";

    public void Register(IModuleRegistry r)
    {
        r.AddDirective(new() { Name = "allow", Contexts = ContextKind.HttpAny, MinArgs = 1, MaxArgs = 1, Repeatable = true, Handler = i => Add(i, true) });
        r.AddDirective(new() { Name = "deny", Contexts = ContextKind.HttpAny, MinArgs = 1, MaxArgs = 1, Repeatable = true, Handler = i => Add(i, false) });
    }

    private static void Add(DirectiveInvocation i, bool allow)
    {
        var a = i.Args[0];
        Rule rule;
        if (a == "all") rule = new Rule(allow, null, false, true);
        else if (a == "unix:") rule = new Rule(allow, null, true, false);
        else
        {
            if (!a.Contains('/')) a += IPAddress.TryParse(a, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6 ? "/128" : "/32";
            if (!IPNetwork.TryParse(a, out var net)) throw i.Error($"invalid address or network \"{i.Args[0]}\"");
            // Host bits set (192.168.1.1/24): nginx warns and masks, and so does IPNetwork. An ACL that doesn't mean
            // what it says is an error here.
            if (!IPAddress.Parse(a.AsSpan(0, a.IndexOf('/'))).Equals(net.BaseAddress))
                throw i.Error($"\"{i.Args[0]}\" has host bits set; did you mean {net}?");
            if (net.BaseAddress.IsIPv4MappedToIPv6) throw i.Error($"write IPv4-mapped addresses as IPv4: \"{i.Args[0]}\"");
            rule = new Rule(allow, net, false, false);
        }
        (i.Conf<AccessConf>().Rules ??= new()).Add(rule);
    }

    public void Configure(IModuleSetup setup)
    {
        foreach (var kind in new[] { ContextKind.Server, ContextKind.Location })
            foreach (var scope in setup.ScopesOf(kind))
                if (scope.TryGet<AccessConf>(out var c)) c.Effective = c.Rules?.ToArray() ?? [];
        setup.AddHandler(Phase.Access, Handle, Order);
    }

    private static ValueTask<HandlerResult> Handle(HttpContext ctx)
    {
        var rules = ctx.Config<AccessConf>().Effective;
        if (rules.Length == 0) return new(HandlerResult.Declined);
        IPAddress? ip = ctx.Connection.Remote is IPEndPoint ep ? (ep.Address.IsIPv4MappedToIPv6 ? ep.Address.MapToIPv4() : ep.Address) : null;
        foreach (var r in rules)
        {
            bool match = r.All || (r.Unix ? ip is null : ip is not null && r.Net!.Value.Contains(ip));
            if (!match) continue;
            if (r.Allow) return new(HandlerResult.Declined);
            ctx.SecurityEvent("access_denied");
            if (ctx.Log.IsEnabled(LogLevel.Info))
                ctx.Log.Info("access forbidden by rule", new("remote", ctx.Connection.RemoteAddress), new("uri", ctx.Request.Path));
            return new(HandlerResult.WithStatus(403));
        }
        return new(HandlerResult.Declined);
    }
}
