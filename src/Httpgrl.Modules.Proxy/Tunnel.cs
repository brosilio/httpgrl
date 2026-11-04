using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace Httpgrl.Modules.Proxy;

/// <summary>The peer address of a tunnel upstream (for logs and $upstream_addr): there's nothing to connect to.</summary>
internal sealed class TunnelPeer(string name) : EndPoint
{
    public override string ToString() => "tunnel:" + name;
}

/// <summary>
/// Connections agents have parked for one <c>upstream { tunnel; }</c>. A request takes the most recently parked one,
/// or waits up to proxy_connect_timeout for an agent to park one (its pool refills as soon as one is taken). While
/// parked, each connection has a read pending, so one the agent closes leaves at once. <see cref="Max"/> bounds
/// parked plus serving connections: an agent (or a stolen certificate) can't pile up connections without limit.
/// </summary>
internal sealed class TunnelPool(string name, int max)
{
    public readonly string Name = name;
    public readonly int Max = max;
    public readonly UpstreamServer Server = UpstreamServer.ForTunnel(name);
    private readonly object _lock = new();
    private readonly List<UpstreamConn> _idle = new();
    private readonly LinkedList<TaskCompletionSource<UpstreamConn?>> _waiters = new();
    private int _total;
    private bool _retired;
    /// <summary>When the pool last had no connections at all (0: it has some). Fail fast once it's been empty a while.</summary>
    private long _emptySince = Environment.TickCount64;

    /// <summary>Room for one more agent connection? Pair with <see cref="Unreserve"/> when it ends.</summary>
    public bool TryReserve()
    {
        lock (_lock)
        {
            if (_retired || _total >= Max) return false;
            _total++;
            _emptySince = 0;
            return true;
        }
    }

    public void Unreserve()
    {
        lock (_lock)
            if (--_total == 0) _emptySince = Environment.TickCount64;
    }

    /// <summary>Make <paramref name="c"/> available: to a waiting request, or parked (watched) for the next one.</summary>
    public void Park(UpstreamConn c)
    {
        lock (_lock)
        {
            if (!_retired)
            {
                c.Start = c.End = 0;
                while (_waiters.First is { } w)
                {
                    _waiters.RemoveFirst();
                    if (w.Value.TrySetResult(c)) return;
                }
                _idle.Add(c);
                c.StartWatch(OnWatchFired); // may fire at once (synchronously) on a broken stream: it takes the lock again
                return;
            }
        }
        c.Dispose();
    }

    private void OnWatchFired(UpstreamConn c)
    {
        bool mine;
        lock (_lock) mine = _idle.Remove(c);
        if (mine) c.Dispose(); // still parked: the agent closed it (or sent something it shouldn't have)
    }

    /// <summary>The most recently parked live connection, or null.</summary>
    public UpstreamConn? TakeIdle()
    {
        while (true)
        {
            UpstreamConn? c;
            lock (_lock)
            {
                if (_idle.Count == 0) return null;
                c = _idle[^1];
                _idle.RemoveAt(_idle.Count - 1);
            }
            if (c.IsReusable()) return c;
            c.Dispose();
        }
    }

    /// <summary>
    /// Wait for an agent to park a connection. Null on timeout, on <paramref name="ct"/>, or at once if the pool has had
    /// no connections for longer than the wait itself (the agent is down: don't hold every request for the timeout).
    /// </summary>
    public async Task<UpstreamConn?> WaitAsync(int timeoutMs, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<UpstreamConn?>(TaskCreationOptions.RunContinuationsAsynchronously);
        LinkedListNode<TaskCompletionSource<UpstreamConn?>> node;
        while (true)
        {
            UpstreamConn? parked = null;
            lock (_lock)
            {
                if (_retired) return null;
                // Under the same lock that registers the waiter: a connection parked after the caller found the pool
                // empty would otherwise sit idle while this request waits for the next one.
                if (_idle.Count > 0)
                {
                    parked = _idle[^1];
                    _idle.RemoveAt(_idle.Count - 1);
                }
                else
                {
                    if (_emptySince != 0 && Environment.TickCount64 - _emptySince > timeoutMs) return null;
                    node = _waiters.AddLast(tcs);
                    break;
                }
            }
            if (parked.IsReusable()) return parked;
            parked.Dispose();
        }
        try { await tcs.Task.WaitAsync(TimeSpan.FromMilliseconds(timeoutMs), ct).ConfigureAwait(false); }
        catch (Exception e) when (e is TimeoutException or OperationCanceledException) { }
        lock (_lock) if (node.List is not null) _waiters.Remove(node);
        if (tcs.TrySetResult(null)) return null; // gave up before anyone handed us a connection
        var c = tcs.Task.Result;
        if (c is not null && ct.IsCancellationRequested) { Park(c); return null; } // not ours to use any more
        return c;
    }

    /// <summary>Configuration replaced or shutting down: close parked connections (agents redial into the new one).</summary>
    public void Retire()
    {
        List<UpstreamConn> idle;
        List<TaskCompletionSource<UpstreamConn?>> waiters;
        lock (_lock)
        {
            if (_retired) return;
            _retired = true;
            idle = [.. _idle];
            _idle.Clear();
            waiters = [.. _waiters];
            _waiters.Clear();
        }
        foreach (var c in idle) c.Dispose();
        foreach (var w in waiters) w.TrySetResult(null);
    }

    internal (int Idle, int Total) Counts()
    {
        lock (_lock) return (_idle.Count, _total);
    }
}

/// <summary>tunnel_accept: settings of one accepting location.</summary>
internal sealed record TunnelAcceptSpec(string Upstream, string ClientName, int IdleTimeoutMs, SourceLocation Source)
{
    public TunnelPool? Pool { get; set; }
}

/// <summary>
/// The remote side of a reverse tunnel. An agent's request to a <c>tunnel_accept</c> location (over mTLS) is answered
/// with 101 and the connection is parked in the tunnel upstream's pool; from then on we send requests down it and the
/// agent answers them. The handler holds the client connection open until the parked connection is done with.
/// </summary>
internal static class TunnelAcceptor
{
    public const string Protocol = "httpgrl-tunnel";

    public static async ValueTask<HandlerResult> AcceptAsync(HttpContext ctx, TunnelAcceptSpec spec)
    {
        var req = ctx.Request;
        var pool = spec.Pool!;
        // Only an agent may park, and only under its own name: a client certificate from the configured CA isn't
        // enough on its own, or any certificate holder could take over (or squat) any tunnel.
        if (!ctx.Connection.ClientVerified || ctx.Connection.ClientCertificate is not { } cert || !NamedFor(cert, spec.ClientName))
        {
            ctx.Log.Warn("tunnel connection refused: no verified client certificate for this tunnel",
                new("tunnel", spec.Upstream), new("remote", ctx.Connection.RemoteAddress), new("expected", spec.ClientName),
                new("subject", ctx.Connection.ClientCertificate?.Subject));
            return HandlerResult.WithStatus(403);
        }
        if (!ReferenceEquals(req.Method, HttpMethods.Get) || req.Version != HttpVersion.Http11 || req.HasBody
            || !string.Equals(req.Headers.Get("Upgrade")?.Trim(), Protocol, StringComparison.OrdinalIgnoreCase)
            || !HasToken(req.Headers, "Connection", "upgrade"))
            return HandlerResult.WithStatus(400);
        if (!pool.TryReserve())
        {
            ctx.Log.Warn("tunnel connection refused: pool full", new("tunnel", spec.Upstream), new("max", (long)pool.Max));
            return HandlerResult.WithStatus(503);
        }

        Stream stream;
        try
        {
            ctx.Response.Status = 101;
            ctx.Response.Headers.Set("Connection", "upgrade");
            ctx.Response.Headers.Set("Upgrade", Protocol);
            stream = await ctx.UpgradeAsync(spec.IdleTimeoutMs).ConfigureAwait(false);
        }
        catch
        {
            pool.Unreserve();
            throw;
        }

        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var conn = UpstreamConn.ForTunnel(pool.Server, stream, 64 << 10, () => { pool.Unreserve(); done.TrySetResult(); });
        // Torn down (idle timeout, shutdown) or replaced by a reload: let go. A connection serving a request at reload
        // finishes it, then isn't parked again (the old pool is retired).
        using (ctx.Aborted.Register(static c => ((UpstreamConn)c!).Dispose(), conn))
        using (ctx.ConfigurationRetired.Register(static p => ((TunnelPool)p!).Retire(), pool))
        {
            ctx.Log.Debug("tunnel connection parked", new("tunnel", spec.Upstream), new("remote", ctx.Connection.RemoteAddress));
            pool.Park(conn);
            await done.Task.ConfigureAwait(false);
        }
        return HandlerResult.Done;
    }

    /// <summary>The certificate's CN or one of its DNS names is <paramref name="name"/>.</summary>
    internal static bool NamedFor(X509Certificate2 cert, string name)
    {
        if (string.Equals(cert.GetNameInfo(X509NameType.SimpleName, false), name, StringComparison.OrdinalIgnoreCase)) return true;
        foreach (var ext in cert.Extensions)
        {
            if (ext is not X509SubjectAlternativeNameExtension san) continue;
            foreach (var dns in san.EnumerateDnsNames())
                if (string.Equals(dns, name, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static bool HasToken(HeaderCollection h, string header, string token)
    {
        for (int i = 0; i < h.Count; i++)
        {
            if (!h.NameAt(i).Equals(header, StringComparison.OrdinalIgnoreCase)) continue;
            var v = h.ValueAt(i);
            foreach (var r in v.AsSpan().Split(','))
                if (v.AsSpan()[r].Trim(" \t").Equals(token, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }
}
