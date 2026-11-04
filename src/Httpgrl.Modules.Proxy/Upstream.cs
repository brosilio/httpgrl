using System.Net;
using System.Net.Security;
using System.Net.Sockets;

namespace Httpgrl.Modules.Proxy;

internal sealed class UpstreamServer(EndPoint endPoint, string name, int weight, int maxFails, int failTimeoutMs, bool backup, bool down)
{
    /// <summary>The single peer of a tunnel upstream: whoever has connections parked.</summary>
    public static UpstreamServer ForTunnel(string name) => new(new TunnelPeer(name), name, 1, 0, 10_000, false, false);

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
    /// <summary>DNS no longer returns this address: finish what's in flight, pool nothing more.</summary>
    internal volatile bool Removed;
    /// <summary>Failed its active health check: never picked until it passes again.</summary>
    internal volatile bool CheckFailed;
    internal int CheckFails, CheckPasses; // owned by the health checker

    internal bool Available(long now) => !Down && (MaxFails == 0 || Fails < MaxFails || now - FailedAt > FailTimeoutMs);
}

/// <summary>
/// A set of peers: smooth weighted round-robin (nginx's algorithm), passive health checks
/// (max_fails within fail_timeout), backups, and a per-peer pool of idle keep-alive connections.
/// </summary>
/// <summary>A configured peer that names a host: re-resolved periodically into zero or more <see cref="UpstreamServer"/>s.</summary>
internal sealed record ResolvableSpec(string Address, string Host, int Port, int Weight, int MaxFails, int FailTimeoutMs, bool Backup, bool Down);

internal sealed class UpstreamGroup
{
    private UpstreamServer[] _primary;
    private UpstreamServer[] _backup;
    private readonly object _lock = new();
    public readonly string Name;
    public readonly int KeepAlive, KeepAliveTimeoutMs, KeepAliveRequests;
    /// <summary>Peers given by hostname (re-resolved); IP literals and unix sockets are fixed.</summary>
    public readonly ResolvableSpec[] Resolvable;
    public int Count { get { lock (_lock) return _primary.Length + _backup.Length; } }

    public UpstreamGroup(string name, List<UpstreamServer> servers, int keepAlive, int keepAliveTimeoutMs, int keepAliveRequests, ResolvableSpec[]? resolvable = null)
    {
        Name = name;
        _primary = servers.FindAll(s => !s.Backup).ToArray();
        _backup = servers.FindAll(s => s.Backup).ToArray();
        KeepAlive = keepAlive;
        KeepAliveTimeoutMs = keepAliveTimeoutMs;
        KeepAliveRequests = keepAliveRequests;
        Resolvable = resolvable ?? [];
    }

    /// <summary>
    /// Replace the peers of one resolvable spec with <paramref name="addresses"/>. Peers whose address is unchanged
    /// are kept (with their failure counts and idle connections); removed ones close their idle connections.
    /// Returns whether anything changed.
    /// </summary>
    public bool Update(ResolvableSpec spec, IPAddress[] addresses)
    {
        var dropped = new List<UpstreamConn>();
        lock (_lock)
        {
            var all = new List<UpstreamServer>(_primary.Length + _backup.Length);
            all.AddRange(_primary);
            all.AddRange(_backup);
            var mine = all.FindAll(s => s.Name == spec.Address);
            var wanted = new HashSet<IPAddress>(addresses);
            if (mine.Count == wanted.Count && mine.TrueForAll(s => s.EndPoint is IPEndPoint ip && wanted.Contains(ip.Address))) return false;
            var next = all.FindAll(s => s.Name != spec.Address);
            foreach (var a in addresses)
            {
                var keep = mine.Find(s => s.EndPoint is IPEndPoint ip && ip.Address.Equals(a));
                next.Add(keep ?? new UpstreamServer(new IPEndPoint(a, spec.Port), spec.Address, spec.Weight, spec.MaxFails, spec.FailTimeoutMs, spec.Backup, spec.Down));
            }
            foreach (var s in mine)
            {
                if (next.Contains(s)) continue;
                s.Removed = true;
                dropped.AddRange(s.Idle);
                s.Idle.Clear();
            }
            _primary = next.FindAll(s => !s.Backup).ToArray();
            _backup = next.FindAll(s => s.Backup).ToArray();
        }
        foreach (var c in dropped) c.Dispose();
        return true;
    }

    public UpstreamServer[] Snapshot()
    {
        lock (_lock) return [.. _primary, .. _backup];
    }

    public string Describe()
    {
        lock (_lock) return string.Join(", ", _primary.Concat(_backup).Select(s => s.Display));
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
            if (s.Down || s.CheckFailed || tried.Contains(s) || (healthyOnly && !s.Available(now))) continue;
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
        if (Tunnel is { } pool) return pool.TakeIdle();
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
        Tunnel?.Retire();
        var all = new List<UpstreamConn>();
        lock (_lock)
            foreach (var s in _primary.Concat(_backup)) { all.AddRange(s.Idle); s.Idle.Clear(); }
        foreach (var c in all) c.Dispose();
    }

    /// <summary>Set for <c>upstream { tunnel; }</c>: connections come from agents, not from connecting.</summary>
    public TunnelPool? Tunnel { get; init; }

    public void ReturnIdle(UpstreamConn c)
    {
        if (Tunnel is { } pool)
        {
            if (_retired || c.Requests >= KeepAliveRequests || !c.IsReusable()) c.Dispose();
            else pool.Park(c);
            return;
        }
        if (_retired || c.Server.Removed || KeepAlive <= 0 || c.Requests >= KeepAliveRequests || !c.IsReusable()) { c.Dispose(); return; }
        c.IdleSince = Environment.TickCount64;
        UpstreamConn? evicted = null;
        lock (_lock)
        {
            var idle = c.Server.Idle;
            if (_retired || c.Server.Removed) evicted = c;
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
    /// <summary>Null for a tunnel connection (an upgraded client stream we don't own the socket of).</summary>
    public readonly Socket? Socket;
    public Stream Stream;
    public byte[] Buf;
    public int Start, End;
    public int Requests;
    public long IdleSince;
    /// <summary>The TLS options this connection was verified under (null: plaintext). Pool reuse requires a match.</summary>
    public readonly object? Identity;
    // Reads and writes time out separately: while a request body uploads, the response head is read at the same time.
    private readonly CancellationTokenSource _readCts = new(), _writeCts = new();
    private int _disposed;
    private Action? _onDispose;
    /// <summary>
    /// Tunnel connections, while parked: a read is kept pending so a connection the agent closed (or that died) leaves
    /// the pool at once. The next request's first read takes over its result (the agent sends nothing unprompted).
    /// </summary>
    private Task<int>? _watch;

    /// <summary>A parked agent connection (tunnel upstreams). <paramref name="onDispose"/> runs once, when it's done.</summary>
    public static UpstreamConn ForTunnel(UpstreamServer server, Stream stream, int bufSize, Action onDispose) =>
        new(server, null, stream, bufSize, null) { _onDispose = onDispose };

    /// <summary>Start watching a parked tunnel connection; <paramref name="fired"/> runs if anything arrives (or it breaks) before it's used.</summary>
    public void StartWatch(Action<UpstreamConn> fired)
    {
        Start = End = 0;
        Task<int> w;
        try { w = Stream.ReadAsync(Buf.AsMemory()).AsTask(); }
        catch (Exception e) when (e is IOException or ObjectDisposedException or InvalidOperationException) { w = Task.FromException<int>(e); }
        _watch = w;
        w.ContinueWith(static (t, st) =>
        {
            _ = t.Exception; // observed: a broken parked connection is routine
            var (c, f) = ((UpstreamConn, Action<UpstreamConn>))st!;
            f(c);
        }, (this, fired), CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    /// <summary>True if the watch read has completed: the parked connection is closed or misbehaved.</summary>
    public bool WatchFired => _watch is { IsCompleted: true };

    private UpstreamConn(UpstreamServer server, Socket? socket, Stream stream, int bufSize, object? identity)
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
        if (Socket is null) return !WatchFired;
        try { return Socket.Connected && !Socket.Poll(0, SelectMode.SelectRead); }
        catch (Exception e) when (e is SocketException or ObjectDisposedException) { return false; }
    }

    public async ValueTask<int> ReadAsync(Memory<byte> into, int timeoutMs)
    {
        if (_watch is { } w)
        {
            // The watch read went into the start of Buf; the first read of a response always asks for exactly there.
            _watch = null;
            if (!System.Runtime.InteropServices.MemoryMarshal.TryGetArray<byte>(into, out var seg) || seg.Array != Buf || seg.Offset != 0)
                throw new InvalidOperationException("first read of a parked connection must fill the buffer from its start");
            try { return timeoutMs > 0 ? await w.WaitAsync(TimeSpan.FromMilliseconds(timeoutMs)).ConfigureAwait(false) : await w.ConfigureAwait(false); }
            catch (TimeoutException) { throw new OperationCanceledException("read timed out"); }
        }
        if (timeoutMs > 0) _readCts.CancelAfter(timeoutMs);
        try { return await Stream.ReadAsync(into, timeoutMs > 0 ? _readCts.Token : default).ConfigureAwait(false); }
        finally { if (timeoutMs > 0) _readCts.TryReset(); }
    }

    public async ValueTask WriteAsync(ReadOnlyMemory<byte> data, int timeoutMs)
    {
        _writeCts.CancelAfter(timeoutMs);
        try { await Stream.WriteAsync(data, _writeCts.Token).ConfigureAwait(false); }
        finally { _writeCts.TryReset(); }
    }

    /// <summary>Abandon the write in flight (and any later one): the connection won't be reused.</summary>
    public void CancelWrites()
    {
        try { _writeCts.Cancel(); } catch (ObjectDisposedException) { }
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
        try { Stream.Dispose(); } catch (Exception e) when (e is IOException or ObjectDisposedException or SocketException or InvalidOperationException) { }
        _readCts.Dispose();
        _writeCts.Dispose();
        _onDispose?.Invoke();
    }
}

/// <summary>The upstream misbehaved (protocol violation, premature close, oversized header): answer 502.</summary>
internal sealed class UpstreamException(string message) : Exception(message)
{
    /// <summary>The connection closed before a single byte of response: what a pooled connection the peer dropped looks like.</summary>
    public bool ClosedEarly { get; init; }
}

/// <summary>
/// Re-resolves the hostnames of upstream peers every interval (system resolver: /etc/hosts, nsswitch, DNS). A failed
/// or empty answer keeps the previous addresses. Started on first use, so a configuration that never goes live
/// starts nothing; stopped when the configuration is retired.
/// </summary>
internal sealed class DnsRefresher(List<UpstreamGroup> groups, int intervalMs, Func<string, CancellationToken, Task<IPAddress[]>> resolve, ILogger log)
{
    private const int LookupTimeoutMs = 10_000;
    private int _started;
    private readonly CancellationTokenSource _stop = new();

    public void EnsureStarted()
    {
        if (Volatile.Read(ref _started) != 0 || Interlocked.Exchange(ref _started, 1) != 0) return;
        _ = Task.Run(LoopAsync);
    }

    private async Task LoopAsync()
    {
        while (true)
        {
            try { await Task.Delay(intervalMs, _stop.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
            await RefreshAsync().ConfigureAwait(false);
        }
    }

    public async Task RefreshAsync()
    {
        foreach (var g in groups)
        {
            foreach (var spec in g.Resolvable)
            {
                if (_stop.IsCancellationRequested) return;
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                cts.CancelAfter(LookupTimeoutMs);
                try
                {
                    var addrs = await resolve(spec.Host, cts.Token).ConfigureAwait(false);
                    if (addrs.Length == 0)
                    {
                        log.Warn("upstream host resolved to nothing; keeping previous addresses", new("upstream", g.Name), new("host", spec.Host));
                        continue;
                    }
                    if (g.Update(spec, addrs)) log.Info("upstream addresses changed", new("upstream", g.Name), new("host", spec.Host), new("peers", g.Describe()));
                }
                catch (OperationCanceledException) when (_stop.IsCancellationRequested) { return; }
                catch (Exception e) when (e is System.Net.Sockets.SocketException or OperationCanceledException or ArgumentException)
                {
                    log.Warn("upstream DNS refresh failed; keeping previous addresses", new("upstream", g.Name), new("host", spec.Host), new("error", e.Message));
                }
            }
        }
    }

    public void Stop()
    {
        try { _stop.Cancel(); } catch (ObjectDisposedException) { }
    }
}

internal sealed record HealthCheckSpec(string Uri, int IntervalMs, int TimeoutMs, int Fails, int Passes, int StatusMin, int StatusMax, string? Host);

/// <summary>
/// Active health checks for one upstream group: every interval, a GET of the check URI on each peer (in parallel), over
/// the scheme and TLS settings the group is proxied with. A peer that fails <c>fails</c> checks in a row is taken out
/// of rotation; <c>passes</c> good checks bring it back. Started on first use, stopped with its configuration.
/// </summary>
internal sealed class HealthChecker(UpstreamGroup group, HealthCheckSpec spec, ProxyTarget target, ILogger log)
{
    private int _started;
    private readonly CancellationTokenSource _stop = new();
    private readonly byte[] _request = System.Text.Encoding.ASCII.GetBytes(
        $"GET {spec.Uri} HTTP/1.1\r\nHost: {spec.Host ?? target.HostHeader}\r\nUser-Agent: httpgrl-health-check\r\nConnection: close\r\n\r\n");

    public void EnsureStarted()
    {
        if (Volatile.Read(ref _started) != 0 || Interlocked.Exchange(ref _started, 1) != 0) return;
        _ = Task.Run(LoopAsync);
    }

    private async Task LoopAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            var peers = group.Snapshot();
            var checks = new Task[peers.Length];
            for (int k = 0; k < peers.Length; k++) checks[k] = CheckAsync(peers[k]);
            await Task.WhenAll(checks).ConfigureAwait(false);
            try { await Task.Delay(spec.IntervalMs, _stop.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
        }
    }

    private async Task CheckAsync(UpstreamServer s)
    {
        if (s.Down || s.Removed) return;
        string? failure = null;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
        cts.CancelAfter(spec.TimeoutMs);
        UpstreamConn? conn = null;
        try
        {
            conn = await UpstreamConn.ConnectAsync(s, target, spec.TimeoutMs, 8192, cts.Token).ConfigureAwait(false);
            await conn.WriteAsync(_request, spec.TimeoutMs).ConfigureAwait(false);
            var r = await UpstreamResponse.ReadAsync(conn, 8192, spec.TimeoutMs, requestWasHead: false).ConfigureAwait(false);
            if (r.Status < spec.StatusMin || r.Status > spec.StatusMax) failure = $"status {r.Status}";
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { return; }
        catch (Exception e) when (e is System.Net.Sockets.SocketException or IOException or OperationCanceledException or UpstreamException or System.Security.Authentication.AuthenticationException)
        {
            failure = e is OperationCanceledException ? "timed out" : e.Message;
        }
        finally { conn?.Dispose(); }

        if (failure is null)
        {
            s.CheckFails = 0;
            if (s.CheckFailed && ++s.CheckPasses >= spec.Passes)
            {
                s.CheckFailed = false;
                log.Info("upstream peer passed its health check; back in rotation", new("upstream", group.Name), new("peer", s.Display));
            }
            return;
        }
        s.CheckPasses = 0;
        if (!s.CheckFailed && ++s.CheckFails >= spec.Fails)
        {
            s.CheckFailed = true;
            log.Warn("upstream peer failed its health check; out of rotation", new("upstream", group.Name), new("peer", s.Display), new("reason", failure));
        }
    }

    public void Stop()
    {
        try { _stop.Cancel(); } catch (ObjectDisposedException) { }
    }
}
