using System.Diagnostics;
using System.Text.RegularExpressions;
using Httpgrl.Core.Hosting;
using Httpgrl.Core.Pipeline;

namespace Httpgrl.Core.Http;

internal sealed class RequestImpl : HttpRequest
{
    public string MethodValue = HttpMethods.Get;
    public string RawTargetValue = "";
    /// <summary>$request_uri: the origin-form path and query of the target (the scheme and authority of an absolute-form one dropped).</summary>
    public string RequestUriValue = "";
    public string PathValue = "/";
    public string QueryValue = "";
    public string HostValue = "";
    public HttpVersion VersionValue = HttpVersion.Http11;
    public long ContentLengthValue = -1;
    public bool ChunkedValue;
    public bool ExpectContinue, ConnClose, ConnKeepAlive, ConnUpgrade;
    /// <summary>An HTTP/2 extended CONNECT for a WebSocket (RFC 8441), presented to modules as an HTTP/1.1 upgrade request.</summary>
    public bool ExtendedConnect;
    public readonly HeaderCollection HeaderList = new();
    public RequestBody BodyValue = null!;

    public override string Method => MethodValue;
    public override string RawTarget => RawTargetValue;
    public override string Path => PathValue;
    public override string Query => QueryValue;
    public override HttpVersion Version => VersionValue;
    public override HeaderCollection Headers => HeaderList;
    public override string Host => HostValue;
    public override long ContentLength => ContentLengthValue;
    public override bool IsChunked => ChunkedValue;
    public override Stream Body => BodyValue;

    public void Reset()
    {
        MethodValue = HttpMethods.Get;
        RawTargetValue = "";
        RequestUriValue = "";
        PathValue = "/";
        QueryValue = "";
        HostValue = "";
        VersionValue = HttpVersion.Http11;
        ContentLengthValue = -1;
        ChunkedValue = ExpectContinue = ConnClose = ConnKeepAlive = ConnUpgrade = ExtendedConnect = false;
        HeaderList.Clear();
        _id = null;
    }

    private string? _id;
    public override string Id => _id ??= NewId();

    private static string NewId()
    {
        Span<byte> b = stackalloc byte[16];
        System.Security.Cryptography.RandomNumberGenerator.Fill(b);
        return Convert.ToHexStringLower(b);
    }
}

/// <summary>
/// One request exchange, reset between requests. Protocol-neutral: what's specific to how the request arrived comes
/// from its exchange: the timing record the sweeper enforces (the connection, for HTTP/1.1), the body, the response
/// wire, and (HTTP/1.1 only) how an upgrade takes over the transport.
/// </summary>
internal sealed class HttpContextImpl : HttpContext
{
    public readonly RequestImpl Req = new();
    public readonly ResponseImpl Resp;
    public readonly Deadlines Timing;
    public readonly ConnectionInfo Info;
    public readonly HttpRuntime Rt;
    public readonly RequestBody BodyReader;
    /// <summary>The raw duplex stream after a 101, or null where the protocol can't upgrade this way.</summary>
    public Func<Stream>? Upgrader;

    public ServerRt ServerRt = null!;
    public LocationRt Loc = null!;
    public Match? LocMatch;
    public bool Internal, InErrorPage, Upgraded, Broken, Dropped;
    public bool ResponseComplete, RequestPending;
    public int StatusOverride, Redirects;
    private bool _keepAlive;
    private long _start;

    public HttpContextImpl(HttpRuntime rt, ConnectionInfo info, Deadlines timing, RequestBody body, ResponseWire wire)
    {
        Rt = rt;
        Info = info;
        Timing = timing;
        BodyReader = body;
        Req.BodyValue = body;
        Resp = new ResponseImpl(this, wire);
    }

    public override HttpRequest Request => Req;
    public override HttpResponse Response => Resp;
    public override ConnectionInfo Connection => Info;
    public override ILogger Log => Rt.Log;
    public override string ResponseOutcome => Dropped ? "dropped" : ResponseComplete ? "complete" : "incomplete";
    public override string RouteLabel => Loc?.Name ?? "";
    public override IConfigScope Server => ServerRt.Scope;
    public override IConfigScope Location => Loc.Scope;
    public override bool IsInternal => Internal;
    public override CancellationToken Aborted => Timing.AbortToken;
    public override CancellationToken ConfigurationRetired => Rt.RetiredToken;
    /// <summary>Modules may only turn keep-alive off; the core decides whether it was allowed at all.</summary>
    public override bool KeepAlive { get => _keepAlive; set { if (!value) _keepAlive = false; } }
    public override TimeSpan Elapsed => Stopwatch.GetElapsedTime(_start);

    public void BeginRequest()
    {
        _start = Stopwatch.GetTimestamp();
        ResponseComplete = false;
        RequestPending = true;
        Loc = null!;
        ServerRt = null!;
        Req.Reset();
        Resp.Reset();
        ResetItems();
        LocMatch = null;
        Internal = InErrorPage = Upgraded = Broken = Dropped = false;
        StatusOverride = Redirects = 0;
        _keepAlive = false;
    }

    public void SetKeepAlive(bool v) => _keepAlive = v;

    public void SelectLocation(LocationRt loc, Match? m)
    {
        Loc = loc;
        LocMatch = m;
        var core = loc.Core;
        BodyReader.MaxSize = core.MaxBodySize;
        BodyReader.ReadTimeoutMs = core.ClientBodyTimeoutMs;
        BodyReader.MinRate = core.BodyMinRateBps;
    }

    public override ResourceKind Probe(string uriPath) =>
        MapPath(uriPath) is { } p ? Files.LocalFiles.Probe(p, NoSymlinksFrom(p)) : ResourceKind.Missing;

    /// <summary>disable_symlinks: the prefix of <paramref name="full"/> in which symlinks are still followed, or null when off.</summary>
    private string? NoSymlinksFrom(string full)
    {
        var core = Loc.Core;
        if (core.DisableSymlinks != true) return null;
        var from = core.DisableSymlinksFrom!;
        if (from == "$document_root") from = DocumentRoot() ?? "";
        from = from.TrimEnd('/');
        // A prefix that isn't one (e.g. an alias outside it) checks the whole path: stricter, never looser.
        return from.Length > 0 && full.StartsWith(from + "/", StringComparison.Ordinal) ? from : "";
    }

    public override OpenResult OpenFile(string uriPath, out FileResource? file)
    {
        file = null;
        if (MapPath(uriPath) is not { } p) { this.SecurityEvent("filesystem_mapping_denied"); return OpenResult.NotFound; }
        var r = Files.LocalFiles.Open(p, NoSymlinksFrom(p), out var handle, out long length, out var mtime);
        if (r == OpenResult.Forbidden) this.SecurityEvent("filesystem_access_denied");
        if (r == OpenResult.Ok) file = new Files.LocalFileResource(handle!, length, mtime, ContentTypeFor(p));
        return r;
    }

    public override OpenResult ListDirectory(string uriPath, int maxEntries, List<DirectoryEntry> entries, out bool truncated)
    {
        truncated = false;
        return MapPath(uriPath) is { } p ? Files.LocalFiles.List(p, NoSymlinksFrom(p), maxEntries, entries, out truncated) : OpenResult.NotFound;
    }

    /// <summary>
    /// URI path → filesystem path via the location's root/alias, contained within it. Null if it can't be mapped
    /// safely. Core-only: modules get resources through Probe/OpenFile/ListDirectory.
    /// </summary>
    internal string? MapPath(string uriPath)
    {
        var loc = Loc;
        var core = loc.Core;
        if (core.Alias is { } alias)
            return Map(uriPath, alias.Evaluate(this), isAlias: true, loc.AliasPrefixLength, core.AliasBase);
        if (core.Root is { } root)
            return Map(uriPath, root.Evaluate(this), isAlias: false, -1, core.RootBase);
        return Map(uriPath, Rt.DefaultRoot, isAlias: false, -1, Rt.DefaultRoot);
    }

    /// <summary>
    /// The mapping itself, pure (fuzzed). <paramref name="value"/> is the evaluated root/alias; <paramref name="baseDir"/>
    /// its constant leading directory, which the result must stay inside. A value that begins with a variable has no
    /// constant part: then the value itself must be an absolute path without dot segments, and is the boundary. Without
    /// that, "root $doc;" with a $doc built from the request would let "../" through to the filesystem.
    /// </summary>
    internal static string? Map(string uriPath, string value, bool isAlias, int aliasPrefixLength, string? baseDir)
    {
        if (!FsGuard.IsSafe(uriPath)) return null;
        if (baseDir is null)
        {
            if (!System.IO.Path.IsPathFullyQualified(value) || HasDotSegmentOrControl(value)) return null;
            baseDir = value;
        }
        string joined;
        if (isAlias) joined = aliasPrefixLength < 0 ? value : value + uriPath.AsSpan(Math.Min(aliasPrefixLength, uriPath.Length)).ToString();
        else joined = string.Concat(value.AsSpan().TrimEnd('/'), uriPath);
        string full;
        try { full = System.IO.Path.GetFullPath(joined); }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
        if (uriPath.EndsWith('/') && !System.IO.Path.EndsInDirectorySeparator(full)) full += System.IO.Path.DirectorySeparatorChar;
        return FsGuard.IsContained(full, baseDir) ? full : null;
    }

    private static bool HasDotSegmentOrControl(string path)
    {
        foreach (char c in path) if (c < 0x20 || c == 0x7f) return true;
        foreach (var r in path.AsSpan().SplitAny('/', System.IO.Path.DirectorySeparatorChar))
        {
            var seg = path.AsSpan()[r];
            if (seg is "." or "..") return true;
        }
        return false;
    }

    public string? DocumentRoot()
    {
        var core = Loc.Core;
        if (core.Alias is { } a) return a.Evaluate(this);
        return core.Root?.Evaluate(this) ?? Rt.DefaultRoot;
    }

    public override bool HasErrorPage(int status) => Loc.Core.ErrorPages?.ContainsKey(status) == true;

    public override string ContentTypeFor(string fileName)
    {
        var core = Loc.Core;
        var span = fileName.AsSpan();
        int slash = span.LastIndexOfAny('/', System.IO.Path.DirectorySeparatorChar);
        int dot = span.LastIndexOf('.');
        if (dot > slash && dot + 1 < span.Length)
        {
            var ext = span[(dot + 1)..];
            var lookup = core.TypesLookup ?? Modules.HttpCoreModule.BuiltinLookup;
            if (lookup.TryGetValue(ext, out var t)) return t;
        }
        return core.DefaultContentType;
    }

    public override string? Variable(string name) => Rt.Vars.Resolve(name)?.Invoke(this);

    public override void SetCaptures(Match match) => LocMatch = match;

    public override bool SetUri(string path, string query, bool reselectLocation)
    {
        var p = UriNormalizer.NormalizeDecoded(path);
        if (p is null) return false;
        Req.PathValue = p;
        Req.QueryValue = EscapeQuery(query);
        if (reselectLocation)
        {
            Internal = true;
            var loc = ServerRt.Find(p, out var m);
            SelectLocation(loc, m);
        }
        return true;
    }

    /// <summary>A query built from decoded parts may hold spaces, CR/LF or non-ASCII: encode what can't go on a request line.</summary>
    internal static string EscapeQuery(string q)
    {
        bool clean = true;
        foreach (char c in q) if (c is <= ' ' or >= (char)0x7f or '#') { clean = false; break; }
        if (clean) return q;
        var sb = new System.Text.StringBuilder(q.Length + 16);
        foreach (byte b in System.Text.Encoding.UTF8.GetBytes(q))
        {
            if (b is > (byte)' ' and < 0x7f and not (byte)'#') sb.Append((char)b);
            else sb.Append('%').Append("0123456789ABCDEF"[b >> 4]).Append("0123456789ABCDEF"[b & 15]);
        }
        return sb.ToString();
    }

    public Hosting.ConnectionManager? Mgr;
    public override ServerStats Stats() => Mgr?.Stats() ?? default;

    private List<(Action<object?> Callback, object? State)>? _onEnd;

    public override void OnRequestEnd(Action<object?> callback, object? state) => (_onEnd ??= new()).Add((callback, state));

    /// <summary>Run and clear the request-end callbacks. Safe to call more than once.</summary>
    public void EndRequest()
    {
        var list = _onEnd;
        if (list is null || list.Count == 0) return;
        for (int i = 0; i < list.Count; i++)
        {
            try { list[i].Callback(list[i].State); }
            catch (Exception e) { Log.Error("request-end callback failed", new("error", e.GetType().Name), new("detail", e.Message)); }
        }
        list.Clear();
    }

    public override string? Capture(int n)
    {
        var m = LocMatch;
        if (m is null || (uint)n >= (uint)m.Groups.Count) return null;
        var g = m.Groups[n];
        return g.Success ? g.Value : null;
    }

    public override async ValueTask<Stream> UpgradeAsync(int idleTimeoutMs)
    {
        if (Resp.HasStarted) throw new InvalidOperationException("response already started");
        if (Resp.Status != 101) throw new InvalidOperationException("upgrade requires status 101");
        if (idleTimeoutMs <= 0) throw new ArgumentOutOfRangeException(nameof(idleTimeoutMs));
        // HTTP/1.1 hands over its connection; HTTP/2 only an extended CONNECT stream (a WebSocket, RFC 8441).
        var upgrader = (Req.VersionValue < HttpVersion.Http20 || Req.ExtendedConnect ? Upgrader : null)
            ?? throw new NotSupportedException("this request can't be upgraded");
        Upgraded = true;
        _keepAlive = false;
        await Resp.StartAsync().ConfigureAwait(false);
        var t = Timing;
        t.StopRate();
        t.Phase = "upgraded";
        // Bidirectional idle: every completed op on this socket (client reads AND writes carrying the other
        // direction's traffic) pushes the deadline out; a stalled write still dies on its own op deadline.
        t.ReadOpTimeout = 0;
        t.WriteOpTimeout = idleTimeoutMs;
        t.IdleRefreshMs = idleTimeoutMs;
        t.BaseDeadline = Environment.TickCount64 + idleTimeoutMs;
        return upgrader();
    }
}

/// <summary>Raw duplex stream after a 101: drains already-buffered client bytes first.</summary>
internal sealed class UpgradedStream(InputBuffer input, Stream transport) : Stream
{
    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (input.Count > 0)
        {
            int n = Math.Min(buffer.Length, input.Count);
            input.Buf.AsSpan(input.Start, n).CopyTo(buffer.Span);
            input.Consume(n);
            return new ValueTask<int>(n);
        }
        return transport.ReadAsync(buffer, ct);
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) => transport.WriteAsync(buffer, ct);
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) => ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) => WriteAsync(buffer.AsMemory(offset, count), ct).AsTask();
    public override Task FlushAsync(CancellationToken ct) => transport.FlushAsync(ct);
    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer, offset, count, default).GetAwaiter().GetResult();
    public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer, offset, count, default).GetAwaiter().GetResult();
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}

/// <summary>Filesystem-facing URI checks. Windows paths have aliases (ADS, 8.3-ish trailing dots, device names) that Unix doesn't.</summary>
internal static class FsGuard
{
    private static readonly bool Windows = OperatingSystem.IsWindows();

    public static bool IsSafe(string uri)
    {
        if (!Windows) return true;
        var s = uri.AsSpan();
        foreach (char c in s)
            if (c < 0x20 || c is '\\' or ':' or '*' or '?' or '"' or '<' or '>' or '|') return false;
        foreach (var r in s.Split('/'))
        {
            var seg = s[r];
            if (seg.IsEmpty) continue;
            if (seg[^1] is '.' or ' ') return false;
            int dot = seg.IndexOf('.');
            var stem = (dot < 0 ? seg : seg[..dot]).TrimEnd(' ');
            if (IsDevice(stem)) return false;
        }
        return true;
    }

    private static bool IsDevice(ReadOnlySpan<char> s)
    {
        if (s.Length == 3)
            return s.Equals("CON", StringComparison.OrdinalIgnoreCase) || s.Equals("PRN", StringComparison.OrdinalIgnoreCase)
                || s.Equals("AUX", StringComparison.OrdinalIgnoreCase) || s.Equals("NUL", StringComparison.OrdinalIgnoreCase);
        if (s.Length == 4 && (s.StartsWith("COM", StringComparison.OrdinalIgnoreCase) || s.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)))
            return char.IsAsciiDigit(s[3]) || s[3] is '¹' or '²' or '³';
        if (s.Length == 6) return s.Equals("CONIN$", StringComparison.OrdinalIgnoreCase);
        if (s.Length == 7) return s.Equals("CONOUT$", StringComparison.OrdinalIgnoreCase);
        return false;
    }

    public static bool IsContained(string full, string baseDir)
    {
        var b = baseDir.AsSpan();
        while (b.Length > 1 && (b[^1] == '/' || b[^1] == System.IO.Path.DirectorySeparatorChar)) b = b[..^1];
        var f = full.AsSpan();
        if (!f.StartsWith(b, PathCmp.Mode)) return false;
        if (f.Length == b.Length) return true;
        if (b.Length == 1 && (b[0] == '/' || b[0] == System.IO.Path.DirectorySeparatorChar)) return true;
        char next = f[b.Length];
        return next == '/' || next == System.IO.Path.DirectorySeparatorChar;
    }
}
