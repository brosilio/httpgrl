using System.Diagnostics;
using System.Text.RegularExpressions;
using Httpgrl.Core.Hosting;
using Httpgrl.Core.Pipeline;

namespace Httpgrl.Core.Http;

internal sealed class RequestImpl : HttpRequest
{
    public string MethodValue = HttpMethods.Get;
    public string RawTargetValue = "";
    public string PathValue = "/";
    public string QueryValue = "";
    public string HostValue = "";
    public HttpVersion VersionValue = HttpVersion.Http11;
    public long ContentLengthValue = -1;
    public bool ChunkedValue;
    public bool ExpectContinue, ConnClose, ConnKeepAlive, ConnUpgrade;
    public readonly HeaderCollection HeaderList = new();
    public BodyStream BodyValue = null!;

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
        PathValue = "/";
        QueryValue = "";
        HostValue = "";
        VersionValue = HttpVersion.Http11;
        ContentLengthValue = -1;
        ChunkedValue = ExpectContinue = ConnClose = ConnKeepAlive = ConnUpgrade = false;
        HeaderList.Clear();
    }
}

/// <summary>One per connection, reset between requests.</summary>
internal sealed class HttpContextImpl : HttpContext
{
    public readonly RequestImpl Req = new();
    public readonly ResponseImpl Resp;
    public readonly Connection Conn;
    public readonly ConnectionInfo Info;
    public readonly HttpRuntime Rt;
    public readonly InputBuffer Input;
    public readonly BodyStream BodyReader;
    public Stream Transport = Stream.Null;

    public ServerRt ServerRt = null!;
    public LocationRt Loc = null!;
    public Match? LocMatch;
    public bool Internal, InErrorPage, Upgraded, Broken, Dropped;
    public int StatusOverride, Redirects;
    private bool _keepAlive;
    private long _start;

    public HttpContextImpl(HttpRuntime rt, Connection conn, ConnectionInfo info, InputBuffer input)
    {
        Rt = rt;
        Conn = conn;
        Info = info;
        Input = input;
        BodyReader = new BodyStream(conn, input);
        Req.BodyValue = BodyReader;
        Resp = new ResponseImpl(this);
    }

    public override HttpRequest Request => Req;
    public override HttpResponse Response => Resp;
    public override ConnectionInfo Connection => Info;
    public override ILogger Log => Rt.Log;
    public override IConfigScope Server => ServerRt.Scope;
    public override IConfigScope Location => Loc.Scope;
    public override bool IsInternal => Internal;
    public override CancellationToken Aborted => Conn.AbortToken;
    /// <summary>Modules may only turn keep-alive off; the core decides whether it was allowed at all.</summary>
    public override bool KeepAlive { get => _keepAlive; set { if (!value) _keepAlive = false; } }
    public override TimeSpan Elapsed => Stopwatch.GetElapsedTime(_start);

    public void BeginRequest()
    {
        _start = Stopwatch.GetTimestamp();
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
        MapPath(uriPath) is { } p ? Files.LocalFiles.Probe(p) : ResourceKind.Missing;

    public override OpenResult OpenFile(string uriPath, out FileResource? file)
    {
        file = null;
        if (MapPath(uriPath) is not { } p) return OpenResult.NotFound;
        var r = Files.LocalFiles.Open(p, out var handle, out long length, out var mtime);
        if (r == OpenResult.Ok) file = new Files.LocalFileResource(handle!, length, mtime, ContentTypeFor(p));
        return r;
    }

    public override OpenResult ListDirectory(string uriPath, int maxEntries, List<DirectoryEntry> entries, out bool truncated)
    {
        truncated = false;
        return MapPath(uriPath) is { } p ? Files.LocalFiles.List(p, maxEntries, entries, out truncated) : OpenResult.NotFound;
    }

    /// <summary>
    /// URI path → filesystem path via the location's root/alias, contained within it. Null if it can't be mapped
    /// safely. Core-only: modules get resources through Probe/OpenFile/ListDirectory.
    /// </summary>
    internal string? MapPath(string uriPath)
    {
        if (!FsGuard.IsSafe(uriPath)) return null;
        var loc = Loc;
        var core = loc.Core;
        string joined;
        string? baseDir;
        if (core.Alias is { } alias)
        {
            var a = alias.Evaluate(this);
            if (loc.AliasPrefixLength < 0) joined = a;
            else joined = a + uriPath.AsSpan(Math.Min(loc.AliasPrefixLength, uriPath.Length)).ToString();
            baseDir = core.AliasBase;
        }
        else
        {
            var r = core.Root is { } root ? root.Evaluate(this) : Rt.DefaultRoot;
            joined = string.Concat(r.AsSpan().TrimEnd('/'), uriPath);
            baseDir = core.Root is null ? Rt.DefaultRoot : core.RootBase;
        }
        string full;
        try { full = System.IO.Path.GetFullPath(joined); }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
        if (uriPath.EndsWith('/') && !System.IO.Path.EndsInDirectorySeparator(full)) full += System.IO.Path.DirectorySeparatorChar;
        if (baseDir is not null && !FsGuard.IsContained(full, baseDir)) return null;
        return full;
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
        Upgraded = true;
        _keepAlive = false;
        await Resp.StartAsync().ConfigureAwait(false);
        Conn.StopRate();
        Conn.Phase = "upgraded";
        // Bidirectional idle: every completed op on this socket (client reads AND writes carrying the other
        // direction's traffic) pushes the deadline out; a stalled write still dies on its own op deadline.
        Conn.ReadOpTimeout = 0;
        Conn.WriteOpTimeout = idleTimeoutMs;
        Conn.IdleRefreshMs = idleTimeoutMs;
        Conn.BaseDeadline = Environment.TickCount64 + idleTimeoutMs;
        return new UpgradedStream(Input, Transport);
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
