using System.Net;
using System.Net.Security;
using System.Net.Sockets;

namespace Httpgrl.Modules.Proxy;

internal sealed class UpstreamServer(EndPoint endPoint, string name, int weight, int maxFails, int failTimeoutMs, bool backup, bool down)
{
    public readonly EndPoint EndPoint = endPoint;
    public readonly string Name = name;
    public readonly int Weight = weight;
    public readonly int MaxFails = maxFails;
    public readonly int FailTimeoutMs = failTimeoutMs;
    public readonly bool Backup = backup;
    public readonly bool Down = down;
    public readonly string Display = endPoint.ToString() ?? name;

    // Guarded by the group lock.
    internal int Fails;
    internal long FailedAt;
    internal int CurrentWeight;
    internal readonly List<UpstreamConn> Idle = new();

    internal bool Available(long now) => !Down && (MaxFails == 0 || Fails < MaxFails || now - FailedAt > FailTimeoutMs);
}

/// <summary>
/// A set of peers: smooth weighted round-robin (nginx's algorithm), passive health checks
/// (max_fails within fail_timeout), backups, and a per-peer pool of idle keep-alive connections.
/// </summary>
internal sealed class UpstreamGroup
{
    private readonly UpstreamServer[] _primary;
    private readonly UpstreamServer[] _backup;
    private readonly object _lock = new();
    public readonly string Name;
    public readonly int KeepAlive, KeepAliveTimeoutMs, KeepAliveRequests;
    public int Count => _primary.Length + _backup.Length;

    public UpstreamGroup(string name, List<UpstreamServer> servers, int keepAlive, int keepAliveTimeoutMs, int keepAliveRequests)
    {
        Name = name;
        _primary = servers.FindAll(s => !s.Backup).ToArray();
        _backup = servers.FindAll(s => s.Backup).ToArray();
        KeepAlive = keepAlive;
        KeepAliveTimeoutMs = keepAliveTimeoutMs;
        KeepAliveRequests = keepAliveRequests;
    }

    public UpstreamServer? Pick(List<UpstreamServer> tried)
    {
        long now = Environment.TickCount64;
        lock (_lock)
        {
            return PickFrom(_primary, tried, now, true) ?? PickFrom(_backup, tried, now, true)
                // Everyone is marked failed: rather than refuse outright, try the untried anyway (nginx does too).
                ?? PickFrom(_primary, tried, now, false) ?? PickFrom(_backup, tried, now, false);
        }
    }

    private static UpstreamServer? PickFrom(UpstreamServer[] peers, List<UpstreamServer> tried, long now, bool healthyOnly)
    {
        UpstreamServer? best = null;
        int total = 0;
        foreach (var s in peers)
        {
            if (s.Down || tried.Contains(s) || (healthyOnly && !s.Available(now))) continue;
            s.CurrentWeight += s.Weight;
            total += s.Weight;
            if (best is null || s.CurrentWeight > best.CurrentWeight) best = s;
        }
        if (best is not null) best.CurrentWeight -= total;
        return best;
    }

    public void Fail(UpstreamServer s)
    {
        lock (_lock)
        {
            long now = Environment.TickCount64;
            if (now - s.FailedAt > s.FailTimeoutMs) s.Fails = 0;
            s.Fails++;
            s.FailedAt = now;
        }
    }

    public void Success(UpstreamServer s)
    {
        lock (_lock) s.Fails = 0;
    }

    /// <summary>
    /// Most recently used idle connection that is still healthy and was established under the same TLS identity
    /// (null for plaintext), or null. Two locations may share a peer with different proxy_ssl_name / trust
    /// settings: a connection verified under one must never serve the other.
    /// </summary>
    public UpstreamConn? TakeIdle(UpstreamServer s, object? identity)
    {
        if (KeepAlive <= 0) return null;
        long now = Environment.TickCount64;
        while (true)
        {
            UpstreamConn? c = null;
            lock (_lock)
            {
                var idle = s.Idle;
                for (int i = idle.Count - 1; i >= 0; i--)
                {
                    if (!ReferenceEquals(idle[i].Identity, identity)) continue;
                    c = idle[i];
                    idle.RemoveAt(i);
                    break;
                }
            }
            if (c is null) return null;
            if (now - c.IdleSince <= KeepAliveTimeoutMs && c.IsReusable()) return c;
            c.Dispose();
        }
    }

    private volatile bool _retired;

    /// <summary>No more pooling: close idle connections now, and any connection handed back later.</summary>
    public void Retire()
    {
        _retired = true;
        var all = new List<UpstreamConn>();
        lock (_lock)
            foreach (var s in _primary.Concat(_backup)) { all.AddRange(s.Idle); s.Idle.Clear(); }
        foreach (var c in all) c.Dispose();
    }

    public void ReturnIdle(UpstreamConn c)
    {
        if (_retired || KeepAlive <= 0 || c.Requests >= KeepAliveRequests || !c.IsReusable()) { c.Dispose(); return; }
        c.IdleSince = Environment.TickCount64;
        UpstreamConn? evicted = null;
        lock (_lock)
        {
            var idle = c.Server.Idle;
            if (_retired) evicted = c;
            else
            {
                idle.Add(c);
                if (idle.Count > KeepAlive) { evicted = idle[0]; idle.RemoveAt(0); }
            }
        }
        evicted?.Dispose();
    }
}

/// <summary>One connection to a peer, with its read buffer and per-operation timeouts (one reusable CTS).</summary>
internal sealed class UpstreamConn : IDisposable
{
    public readonly UpstreamServer Server;
    public readonly Socket Socket;
    public Stream Stream;
    public byte[] Buf;
    public int Start, End;
    public int Requests;
    public long IdleSince;
    /// <summary>The TLS options this connection was verified under (null: plaintext). Pool reuse requires a match.</summary>
    public readonly object? Identity;
    private readonly CancellationTokenSource _cts = new();
    private int _disposed;

    private UpstreamConn(UpstreamServer server, Socket socket, Stream stream, int bufSize, object? identity)
    {
        Server = server;
        Identity = identity;
        Socket = socket;
        Stream = stream;
        // Not pooled on purpose: Dispose can race an in-flight read (client abort), and a buffer handed back
        // to the pool while the kernel may still write into it would corrupt someone else's data.
        Buf = new byte[bufSize];
    }

    public int Buffered => End - Start;

    public static async Task<UpstreamConn> ConnectAsync(UpstreamServer s, ProxyTarget t, int timeoutMs, int bufSize, CancellationToken abort)
    {
        var ep = s.EndPoint;
        var socket = ep is UnixDomainSocketEndPoint
            ? new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified)
            : new Socket(ep.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(abort);
        cts.CancelAfter(timeoutMs);
        try
        {
            await socket.ConnectAsync(ep, cts.Token).ConfigureAwait(false);
            Stream stream = new NetworkStream(socket, ownsSocket: true);
            if (t.Tls)
            {
                var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
                await ssl.AuthenticateAsClientAsync(t.Ssl!, cts.Token).ConfigureAwait(false);
                stream = ssl;
            }
            return new UpstreamConn(s, socket, stream, bufSize, t.Ssl);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>A pooled connection is reusable only if the peer hasn't closed it or sent anything unsolicited.</summary>
    public bool IsReusable()
    {
        if (Volatile.Read(ref _disposed) != 0 || Buffered != 0) return false;
        try { return Socket.Connected && !Socket.Poll(0, SelectMode.SelectRead); }
        catch (Exception e) when (e is SocketException or ObjectDisposedException) { return false; }
    }

    public async ValueTask<int> ReadAsync(Memory<byte> into, int timeoutMs)
    {
        if (timeoutMs > 0) _cts.CancelAfter(timeoutMs);
        try { return await Stream.ReadAsync(into, timeoutMs > 0 ? _cts.Token : default).ConfigureAwait(false); }
        finally { if (timeoutMs > 0) _cts.TryReset(); }
    }

    public async ValueTask WriteAsync(ReadOnlyMemory<byte> data, int timeoutMs)
    {
        _cts.CancelAfter(timeoutMs);
        try { await Stream.WriteAsync(data, _cts.Token).ConfigureAwait(false); }
        finally { _cts.TryReset(); }
    }

    /// <summary>Read more into the buffer (compacting first). 0 on EOF; throws if the buffer is full.</summary>
    public async ValueTask<int> FillAsync(int timeoutMs)
    {
        if (Start > 0 && Start == End) Start = End = 0;
        if (End == Buf.Length)
        {
            if (Start == 0) throw new UpstreamException("upstream line too long");
            Buffer.BlockCopy(Buf, Start, Buf, 0, End - Start);
            End -= Start;
            Start = 0;
        }
        int n = await ReadAsync(Buf.AsMemory(End), timeoutMs).ConfigureAwait(false);
        End += n;
        return n;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try { Stream.Dispose(); } catch (Exception e) when (e is IOException or ObjectDisposedException or SocketException) { }
        _cts.Dispose();
    }
}

/// <summary>The upstream misbehaved (protocol violation, premature close, oversized header): answer 502.</summary>
internal sealed class UpstreamException(string message) : Exception(message);
