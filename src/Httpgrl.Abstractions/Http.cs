using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace Httpgrl;

public enum HttpVersion : byte { Http10 = 10, Http11 = 11 }

public static class HttpMethods
{
    // Parsed request methods are interned to these instances.
    public const string Get = "GET", Head = "HEAD", Post = "POST", Put = "PUT", Delete = "DELETE",
        Options = "OPTIONS", Patch = "PATCH", Trace = "TRACE", Connect = "CONNECT";
}

/// <summary>Per-request state handed to every phase handler. Valid only until the handler chain completes.</summary>
public abstract class HttpContext
{
    public abstract HttpRequest Request { get; }
    public abstract HttpResponse Response { get; }
    public abstract ConnectionInfo Connection { get; }
    public abstract ILogger Log { get; }

    /// <summary>The selected server block.</summary>
    public abstract IConfigScope Server { get; }
    /// <summary>The selected location block (the server scope when no location matched).</summary>
    public abstract IConfigScope Location { get; }
    public T Config<T>() where T : ScopeConfig<T>, new() => Location.Get<T>();

    /// <summary>True once the request went through an internal redirect (try_files, index, error_page...).</summary>
    public abstract bool IsInternal { get; }
    /// <summary>Signalled when the client connection is torn down (timeout, reset, shutdown).</summary>
    public abstract CancellationToken Aborted { get; }
    /// <summary>Time since the request head was received.</summary>
    public abstract TimeSpan Elapsed { get; }
    /// <summary>Set false to close the connection after this response.</summary>
    public abstract bool KeepAlive { get; set; }

    // ---- Resources on disk ----
    // Modules name resources by (validated) request path only; the core maps them through the location's
    // root/alias, enforces containment and opens them safely. Filesystem paths never reach a module.

    /// <summary>What <paramref name="uriPath"/> names under this location's root/alias.</summary>
    public abstract ResourceKind Probe(string uriPath);
    /// <summary>Open the regular file <paramref name="uriPath"/> names. Dispose the result.</summary>
    public abstract OpenResult OpenFile(string uriPath, out FileResource? file);
    /// <summary>
    /// Entries of the directory <paramref name="uriPath"/> names (without "." and ".."), at most
    /// <paramref name="maxEntries"/>. Symlinks are reported as their targets; broken ones are skipped.
    /// </summary>
    public abstract OpenResult ListDirectory(string uriPath, int maxEntries, List<DirectoryEntry> entries, out bool truncated);
    /// <summary>True if the current location maps <paramref name="status"/> to an error_page (incl. the 444 drop shorthand).</summary>
    public abstract bool HasErrorPage(int status);
    /// <summary>MIME type for a file name by extension, per the location's <c>types</c>/<c>default_type</c>.</summary>
    public abstract string ContentTypeFor(string fileName);
    public abstract string? Variable(string name);
    /// <summary>Regex capture (0..9) from the last successful match: the location's, or a later one set by a module (e.g. <c>if</c>, <c>map</c>). Null if none.</summary>
    public abstract string? Capture(int n);
    /// <summary>Make <paramref name="match"/> the source of <c>$1</c>..<c>$9</c> from now on (nginx: the last regex that matched wins).</summary>
    public abstract void SetCaptures(Match match);

    /// <summary>
    /// Send the response head (Status must be 101) and take over the raw connection. The returned stream
    /// carries any bytes the client already pipelined. The connection is closed when the handler returns.
    /// The connection is closed once no data has moved in either direction for <paramref name="idleTimeoutMs"/>
    /// (a quiet client doesn't kill a server-push tunnel), and any single write stalling that long kills it too.
    /// </summary>
    public abstract ValueTask<Stream> UpgradeAsync(int idleTimeoutMs);

    private Dictionary<object, object?>? _items;
    /// <summary>Scratch space for modules, keyed by a private object.</summary>
    public Dictionary<object, object?> Items => _items ??= new();
    protected void ResetItems() => _items?.Clear();
}

public abstract class HttpRequest
{
    public abstract string Method { get; }
    /// <summary>Request target exactly as received (Latin-1 decoded).</summary>
    public abstract string RawTarget { get; }
    /// <summary>Percent-decoded, dot-segment-resolved, slash-merged path. Changes on internal redirects.</summary>
    public abstract string Path { get; }
    /// <summary>Query string without the '?', still encoded. Empty if none.</summary>
    public abstract string Query { get; }
    public abstract HttpVersion Version { get; }
    public abstract HeaderCollection Headers { get; }
    /// <summary>Validated, lower-cased host without port.</summary>
    public abstract string Host { get; }
    /// <summary>-1 when absent (or chunked).</summary>
    public abstract long ContentLength { get; }
    public abstract bool IsChunked { get; }
    /// <summary>Body stream enforcing size limits and timeouts. Reading it sends "100 Continue" if the client expects it.</summary>
    public abstract Stream Body { get; }

    public bool HasBody => ContentLength > 0 || IsChunked;
    public bool IsGetOrHead => ReferenceEquals(Method, HttpMethods.Get) || ReferenceEquals(Method, HttpMethods.Head);
    public bool IsHead => ReferenceEquals(Method, HttpMethods.Head);
}

public abstract class HttpResponse
{
    public int Status { get; set; } = 200;
    /// <summary>
    /// Response headers. Framing headers (Content-Length, Transfer-Encoding, Connection, Date, Server)
    /// are owned by the core and ignored here; use <see cref="ContentLength"/>.
    /// </summary>
    public HeaderCollection Headers { get; } = new();
    /// <summary>-1: unknown (chunked on HTTP/1.1, close-delimited on 1.0).</summary>
    public long ContentLength { get; set; } = -1;

    public abstract bool HasStarted { get; }
    public abstract long BodyBytesSent { get; }

    /// <summary>Send the head now (otherwise sent with the first body write or at completion).</summary>
    public abstract ValueTask StartAsync();
    /// <summary>Buffered (coalesced up to 64 KiB); call <see cref="FlushAsync"/> to push data out now.</summary>
    public abstract ValueTask WriteAsync(ReadOnlyMemory<byte> data);
    /// <summary>Send the head if needed and everything buffered so far (streaming: SSE, long polls, proxied bodies).</summary>
    public abstract ValueTask FlushAsync();
    public abstract ValueTask SendFileAsync(FileResource file, long offset, long count);
}

public sealed class ConnectionInfo(long id, EndPoint? remote, EndPoint? local, bool isTls)
{
    public long Id { get; } = id;
    public EndPoint? Remote { get; } = remote;
    public EndPoint? Local { get; } = local;
    public bool IsTls { get; } = isTls;
    public string? TlsServerName { get; private set; }
    public string? TlsProtocol { get; private set; }
    /// <summary>The certificate the client presented (only when <c>ssl_verify_client</c> is not off).</summary>
    public X509Certificate2? ClientCertificate { get; private set; }
    /// <summary>
    /// The client certificate verdict as in nginx's <c>$ssl_client_verify</c>: "SUCCESS", "FAILED:reason" (only
    /// reachable with <c>optional_no_ca</c>) or "NONE"; null when client certificates aren't requested.
    /// </summary>
    public string? ClientVerify { get; private set; }
    /// <summary>True only when a client certificate was presented and chains to a trusted CA.</summary>
    public bool ClientVerified => ClientVerify == "SUCCESS";
    public int Requests { get; private set; }

    public string RemoteAddress => Remote switch { IPEndPoint ip => ip.Address.ToString(), null => "", var e => e.ToString() ?? "" };
    public int RemotePort => Remote is IPEndPoint ip ? ip.Port : 0;
    public string LocalAddress => Local switch { IPEndPoint ip => ip.Address.ToString(), null => "", var e => e.ToString() ?? "" };
    public int LocalPort => Local is IPEndPoint ip ? ip.Port : 0;

    // Core-only: a module must not be able to rewrite the connection's TLS identity.
    internal void SetTls(string? sni, string protocol, X509Certificate2? clientCert, string? clientVerify)
    {
        TlsServerName = sni;
        TlsProtocol = protocol;
        ClientCertificate = clientCert;
        ClientVerify = clientVerify;
    }
    internal void CountRequest() => Requests++;
}

/// <summary>Ordered, case-insensitive header list. Flat arrays, linear lookup (headers are few).</summary>
public sealed class HeaderCollection
{
    private string[] _names = new string[16];
    private string[] _values = new string[16];
    private int _count;

    public int Count => _count;
    public string NameAt(int i) => (uint)i < (uint)_count ? _names[i] : throw new IndexOutOfRangeException();
    public string ValueAt(int i) => (uint)i < (uint)_count ? _values[i] : throw new IndexOutOfRangeException();

    public string? this[string name]
    {
        get => Get(name);
        set { if (value is null) Remove(name); else Set(name, value); }
    }

    public string? Get(string name)
    {
        for (int i = 0; i < _count; i++)
            if (string.Equals(_names[i], name, StringComparison.OrdinalIgnoreCase)) return _values[i];
        return null;
    }

    public int CountOf(string name)
    {
        int n = 0;
        for (int i = 0; i < _count; i++)
            if (string.Equals(_names[i], name, StringComparison.OrdinalIgnoreCase)) n++;
        return n;
    }

    public bool Contains(string name) => Get(name) is not null;

    /// <summary>Append. Throws on CR/LF/NUL or invalid names (response splitting).</summary>
    public void Add(string name, string value)
    {
        Validate(name, value);
        AddUnchecked(name, value);
    }

    /// <summary>Replace all values of <paramref name="name"/>.</summary>
    public void Set(string name, string value)
    {
        Validate(name, value);
        for (int i = 0; i < _count; i++)
        {
            if (!string.Equals(_names[i], name, StringComparison.OrdinalIgnoreCase)) continue;
            _values[i] = value;
            int w = i + 1;
            for (int r = i + 1; r < _count; r++)
            {
                if (string.Equals(_names[r], name, StringComparison.OrdinalIgnoreCase)) continue;
                _names[w] = _names[r]; _values[w] = _values[r]; w++;
            }
            Array.Clear(_names, w, _count - w); Array.Clear(_values, w, _count - w);
            _count = w;
            return;
        }
        AddUnchecked(name, value);
    }

    public bool Remove(string name)
    {
        int w = 0;
        for (int r = 0; r < _count; r++)
        {
            if (string.Equals(_names[r], name, StringComparison.OrdinalIgnoreCase)) continue;
            _names[w] = _names[r]; _values[w] = _values[r]; w++;
        }
        bool removed = w != _count;
        Array.Clear(_names, w, _count - w); Array.Clear(_values, w, _count - w);
        _count = w;
        return removed;
    }

    public void Clear()
    {
        Array.Clear(_names, 0, _count); Array.Clear(_values, 0, _count);
        _count = 0;
    }

    /// <summary>For the request parser, which has already validated name and value byte-wise.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AddUnchecked(string name, string value)
    {
        if (_count == _names.Length)
        {
            Array.Resize(ref _names, _count * 2);
            Array.Resize(ref _values, _count * 2);
        }
        _names[_count] = name;
        _values[_count] = value;
        _count++;
    }

    private static void Validate(string name, string value)
    {
        if (name.Length == 0) throw new ArgumentException("empty header name");
        foreach (char c in name)
            if (!HttpChars.IsToken(c)) throw new ArgumentException($"invalid header name \"{name}\"");
        foreach (char c in value)
            if (c is '\r' or '\n' or '\0' || c > 0xFF) throw new ArgumentException($"invalid character in header \"{name}\"");
    }
}

public static class HttpChars
{
    // RFC 9110 tchar.
    private static ReadOnlySpan<byte> TokenTable =>
    [
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,1,0,1,1,1,1,1,0,0,1,1,0,1,1,0, 1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,
        0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,0,0,0,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,0,1,0,1,0,
    ];

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool IsToken(int c) => (uint)c < 128 && TokenTable[c] != 0;
}
