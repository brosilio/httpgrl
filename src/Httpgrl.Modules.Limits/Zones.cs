namespace Httpgrl.Modules.Limits;

/// <summary>
/// Accounting shared by everything that limits per key. A zone's size is a memory budget, as in nginx: every entry
/// is charged a fixed overhead plus its key, so long keys (say, a header) can't make a zone grow past its size.
/// Sharded by the (randomized) string hash so one lock isn't a global point of contention.
/// </summary>
internal static class ZoneCost
{
    public const int Shards = 16;
    /// <summary>Entry, list node and dictionary slot, roughly (nginx charges ~64 bytes plus the key).</summary>
    public const long Overhead = 128;
    public const long MinSize = 32 * 1024;

    public static long Of(string key) => Overhead + 2L * key.Length;
    public static int Shard(string key) => (int)((uint)key.GetHashCode() % Shards);
}

/// <summary>limit_req state: nginx's leaky bucket per key, in milli-requests. Least recently used keys are forgotten when full.</summary>
internal sealed class ReqZone(long bytes)
{
    private sealed class Entry(string key)
    {
        public readonly string Key = key;
        public long Excess;
        public long Last;
    }

    private sealed class Shard(long budget)
    {
        public readonly Dictionary<string, LinkedListNode<Entry>> Map = new(StringComparer.Ordinal);
        public readonly LinkedList<Entry> Lru = new();
        public readonly long Budget = budget;
        public long Used;
    }

    private readonly Shard[] _shards = MakeShards(bytes / ZoneCost.Shards);

    private static Shard[] MakeShards(long budget)
    {
        var a = new Shard[ZoneCost.Shards];
        for (int i = 0; i < a.Length; i++) a[i] = new Shard(budget);
        return a;
    }

    /// <summary>
    /// Charge one request to <paramref name="key"/>. Returns false (and charges nothing) when the bucket would overflow
    /// <paramref name="burst"/>; <paramref name="excess"/> is the resulting backlog either way.
    /// </summary>
    public bool Account(string key, long rate, long burst, long now, out long excess)
    {
        var sh = _shards[ZoneCost.Shard(key)];
        lock (sh)
        {
            if (sh.Map.TryGetValue(key, out var node))
            {
                var e = node.Value;
                long ms = Math.Max(0, now - e.Last);
                // ngx_http_limit_req_lookup: drain at `rate` since the last accepted request, then add this one.
                excess = Math.Max(0, e.Excess - rate * ms / 1000 + 1000);
                if (node != sh.Lru.First) { sh.Lru.Remove(node); sh.Lru.AddFirst(node); }
                if (excess > burst) return false;
                e.Excess = excess;
                e.Last = now;
                return true;
            }
            long cost = ZoneCost.Of(key);
            if (cost > sh.Budget) { excess = 0; return false; } // can't be tracked at all: fail closed
            while (sh.Used + cost > sh.Budget && sh.Lru.Last is { } old)
            {
                sh.Lru.RemoveLast();
                sh.Map.Remove(old.Value.Key);
                sh.Used -= ZoneCost.Of(old.Value.Key);
            }
            var n = sh.Lru.AddFirst(new Entry(key) { Last = now });
            sh.Map[key] = n;
            sh.Used += cost;
            excess = 0;
            return true;
        }
    }

    /// <summary>Bytes charged across all shards (tests, diagnostics).</summary>
    internal long Used
    {
        get
        {
            long n = 0;
            foreach (var sh in _shards) lock (sh) n += sh.Used;
            return n;
        }
    }

    /// <summary>Undo one charge (another limit of the same request rejected it).</summary>
    public void Refund(string key)
    {
        var sh = _shards[ZoneCost.Shard(key)];
        lock (sh)
            if (sh.Map.TryGetValue(key, out var node)) node.Value.Excess = Math.Max(0, node.Value.Excess - 1000);
    }
}

/// <summary>limit_conn state: in-flight requests per key. Keys at zero are removed; a full zone refuses new keys (fails closed, as nginx).</summary>
internal sealed class ConnZone(long bytes)
{
    private sealed class Shard(long budget)
    {
        public readonly Dictionary<string, int> Map = new(StringComparer.Ordinal);
        public readonly long Budget = budget;
        public long Used;
    }

    private readonly Shard[] _shards = MakeShards(bytes / ZoneCost.Shards);

    private static Shard[] MakeShards(long budget)
    {
        var a = new Shard[ZoneCost.Shards];
        for (int i = 0; i < a.Length; i++) a[i] = new Shard(budget);
        return a;
    }

    public bool TryAcquire(string key, int max)
    {
        var sh = _shards[ZoneCost.Shard(key)];
        lock (sh)
        {
            if (sh.Map.TryGetValue(key, out int n))
            {
                if (n >= max) return false;
                sh.Map[key] = n + 1;
                return true;
            }
            long cost = ZoneCost.Of(key);
            if (sh.Used + cost > sh.Budget) return false;
            sh.Map[key] = 1;
            sh.Used += cost;
            return true;
        }
    }

    public void Release(string key)
    {
        var sh = _shards[ZoneCost.Shard(key)];
        lock (sh)
        {
            if (!sh.Map.TryGetValue(key, out int n)) return;
            if (n > 1) { sh.Map[key] = n - 1; return; }
            sh.Map.Remove(key);
            sh.Used -= ZoneCost.Of(key);
        }
    }

    /// <summary>For tests and diagnostics.</summary>
    public int Count(string key)
    {
        var sh = _shards[ZoneCost.Shard(key)];
        lock (sh) return sh.Map.TryGetValue(key, out int n) ? n : 0;
    }
}
