using System.Net;
using System.Text.RegularExpressions;

namespace Httpgrl.Core.Modules;

/// <summary>Inheritable http/server/location settings of the core module.</summary>
public sealed class HttpCoreConf : ScopeConfig<HttpCoreConf>
{
    public ComplexValue? Root;
    /// <summary>Full path the mapped file must stay inside of (constant prefix of root/alias).</summary>
    public string? RootBase;
    public ComplexValue? Alias;
    public string? AliasBase;
    /// <summary>The location that declared the alias (its pattern is what the alias replaces).</summary>
    public IConfigScope? AliasOwner;
    public TryFilesSpec? TryFiles; // not inherited
    public bool Internal;          // not inherited
    public Dictionary<int, ErrorPage>? ErrorPages;
    public string? DefaultType;
    public Dictionary<string, string>? Types;
    public Dictionary<string, string>.AlternateLookup<ReadOnlySpan<char>>? TypesLookup;

    public int? KeepaliveTimeout, KeepaliveRequests, ClientHeaderTimeout, ClientBodyTimeout, SendTimeout, SslHandshakeTimeout;
    public int? BodyMinRate, SendMinRate;
    public long? ClientMaxBodySize;
    public int? LargeHeaderCount, LargeHeaderSize;
    public bool? ServerTokens;
    public bool? UnderscoresInHeaders;
    public bool? Http2;
    public int? Http2MaxConcurrentStreams;
    /// <summary>disable_symlinks: null/off; "" = check from "/"; otherwise an absolute prefix, or "$document_root".</summary>
    public string? DisableSymlinksFrom;
    public bool? DisableSymlinks;

    public int KeepaliveTimeoutMs => KeepaliveTimeout ?? 60_000;
    public int KeepaliveRequestsMax => KeepaliveRequests ?? 1000;
    public int ClientHeaderTimeoutMs => ClientHeaderTimeout ?? 10_000;
    public int ClientBodyTimeoutMs => ClientBodyTimeout ?? 30_000;
    public int SendTimeoutMs => SendTimeout ?? 30_000;
    public int SslHandshakeTimeoutMs => SslHandshakeTimeout ?? 10_000;
    public int BodyMinRateBps => BodyMinRate ?? 256;
    public int SendMinRateBps => SendMinRate ?? 256;
    public long MaxBodySize => ClientMaxBodySize ?? (1 << 20);
    public int HeaderLineMax => LargeHeaderSize ?? 8192;
    public int HeaderTotalMax => (LargeHeaderCount ?? 4) * HeaderLineMax;
    /// <summary>Off by default: no Server header and no product name in core error pages.</summary>
    public bool Tokens => ServerTokens ?? false;
    /// <summary>http2 on: offered by ALPN (never by default).</summary>
    public bool Http2Enabled => Http2 ?? false;
    public int Http2MaxStreams => Http2MaxConcurrentStreams ?? 128;
    public string DefaultContentType => DefaultType ?? "text/plain";

    protected override void Inherit(HttpCoreConf p)
    {
        if (Root is null && Alias is null)
        {
            Root = p.Root; RootBase = p.RootBase;
            Alias = p.Alias; AliasBase = p.AliasBase; AliasOwner = p.AliasOwner;
        }
        ErrorPages ??= p.ErrorPages;
        DefaultType ??= p.DefaultType;
        if (Types is null) { Types = p.Types; TypesLookup = p.TypesLookup; }
        KeepaliveTimeout ??= p.KeepaliveTimeout;
        KeepaliveRequests ??= p.KeepaliveRequests;
        ClientHeaderTimeout ??= p.ClientHeaderTimeout;
        ClientBodyTimeout ??= p.ClientBodyTimeout;
        SendTimeout ??= p.SendTimeout;
        SslHandshakeTimeout ??= p.SslHandshakeTimeout;
        BodyMinRate ??= p.BodyMinRate;
        SendMinRate ??= p.SendMinRate;
        ClientMaxBodySize ??= p.ClientMaxBodySize;
        LargeHeaderCount ??= p.LargeHeaderCount;
        LargeHeaderSize ??= p.LargeHeaderSize;
        ServerTokens ??= p.ServerTokens;
        UnderscoresInHeaders ??= p.UnderscoresInHeaders;
        Http2 ??= p.Http2;
        Http2MaxConcurrentStreams ??= p.Http2MaxConcurrentStreams;
        if (DisableSymlinks is null) { DisableSymlinks = p.DisableSymlinks; DisableSymlinksFrom = p.DisableSymlinksFrom; }
    }
}

/// <summary>Override: -1 keep the code, 0 use the target's status, else that code. A null Uri with Override 444 means "drop".</summary>
public sealed record ErrorPage(ComplexValue? Uri, int Override)
{
    public bool IsDrop => Uri is null;
}

public sealed record TryFilesSpec(ComplexValue[] Files, ComplexValue? Fallback, int FallbackStatus);

/// <summary>Per-server: listen sockets and names. Not inherited.</summary>
public sealed class ServerConf : ScopeConfig<ServerConf>
{
    public readonly List<ListenSpec> Listens = new();
    public readonly List<string> Names = new();
    protected override void Inherit(ServerConf parent) { }
}

public sealed record ListenSpec(EndPoint EndPoint, bool IsWildcard, bool Ssl, bool DefaultServer, int Backlog, bool ReusePort, SourceLocation Source, bool ProxyProtocol = false)
{
    public string Key => EndPoint switch
    {
        IPEndPoint ip => (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{ip.Address}]" : ip.Address.ToString()) + ":" + ip.Port,
        _ => EndPoint.ToString() ?? "",
    };
}

public enum LocationKind : byte { Exact, Prefix, PrefixNoRegex, Regex, Named }

/// <summary>Parsed <c>location</c> arguments. Not inherited.</summary>
public sealed class LocationDef : ScopeConfig<LocationDef>
{
    public LocationKind Kind;
    public string Pattern = "";
    public Regex? Regex;
    public bool Defined;
    protected override void Inherit(LocationDef parent) { }
}

/// <summary>main-level settings.</summary>
public sealed class MainConf : ScopeConfig<MainConf>
{
    public int? ShutdownTimeout;
    public int? ReloadDrainTimeout;
    public LogLevel? LogLevel;
    public int ShutdownTimeoutMs => ShutdownTimeout ?? 10_000;
    /// <summary>After a reload, how long connections may stay on the old configuration (tunnels, long polls).</summary>
    public int ReloadDrainTimeoutMs => ReloadDrainTimeout ?? 60_000;
    protected override void Inherit(MainConf parent) { }
}

public sealed class EventsConf : ScopeConfig<EventsConf>
{
    public int? WorkerConnections;
    public int? ConnectionsPerClient;
    public int MaxConnections => WorkerConnections ?? 16384;
    public int PerClient => ConnectionsPerClient ?? 256;
    protected override void Inherit(EventsConf parent) { }
}
