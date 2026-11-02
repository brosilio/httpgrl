namespace Httpgrl.Core.Hosting;

/// <summary>
/// Fixed slot table of live connections with global and per-client caps, plus the sweeper that enforces
/// every deadline. When full, the longest-idle keep-alive connection is evicted to admit a new one.
/// </summary>
internal sealed class ConnectionManager : IDisposable
{
    public const int SweepIntervalMs = 250;
    private const int RateGraceMs = 5000;

    private readonly Connection?[] _slots;
    private readonly int[] _free;
    private int _freeCount;
    private readonly Dictionary<IpKey, int> _perIp = new();
    private readonly int _perIpMax;
    private readonly object _lock = new();
    private readonly Thread _sweeper;
    private readonly ILogger _log;
    private volatile bool _stopping;
    private volatile bool _disposed;
    private long _nextId;
    private int _active;

    public ConnectionManager(int max, int perIpMax, ILogger log)
    {
        _slots = new Connection?[max];
        _free = new int[max];
        for (int i = 0; i < max; i++) _free[i] = max - 1 - i;
        _freeCount = max;
        _perIpMax = perIpMax;
        _log = log;
        _sweeper = new Thread(SweepLoop) { IsBackground = true, Name = "conn-sweeper" };
        _sweeper.Start();
    }

    public int Active => Volatile.Read(ref _active);
    public bool Stopping => _stopping;

    public long NextId() => Interlocked.Increment(ref _nextId);

    /// <summary>Admit or refuse. On refusal the caller closes the socket.</summary>
    public bool TryAdmit(Connection c, out string? refusal)
    {
        Connection? evict = null;
        lock (_lock)
        {
            if (_stopping) { refusal = "shutting down"; return false; }
            _perIp.TryGetValue(c.IpKey, out int n);
            if (_perIpMax > 0 && n >= _perIpMax) { refusal = "per-client connection limit"; return false; }
            if (_freeCount == 0)
            {
                evict = OldestIdleLocked();
                if (evict is null) { refusal = "connection limit"; return false; }
                ReleaseLocked(evict);
            }
            int slot = _free[--_freeCount];
            _slots[slot] = c;
            c.Slot = slot;
            _perIp[c.IpKey] = n + 1;
            _active++;
        }
        evict?.Abort("evicted idle connection");
        refusal = null;
        return true;
    }

    public void Release(Connection c)
    {
        lock (_lock) ReleaseLocked(c);
    }

    private void ReleaseLocked(Connection c)
    {
        int slot = c.Slot;
        if (slot < 0 || !ReferenceEquals(_slots[slot], c)) return;
        _slots[slot] = null;
        c.Slot = -1;
        _free[_freeCount++] = slot;
        _active--;
        if (_perIp.TryGetValue(c.IpKey, out int n))
        {
            if (n <= 1) _perIp.Remove(c.IpKey);
            else _perIp[c.IpKey] = n - 1;
        }
    }

    private Connection? OldestIdleLocked()
    {
        Connection? best = null;
        var slots = _slots;
        for (int i = 0; i < slots.Length; i++)
        {
            var c = slots[i];
            if (c is null || !c.Idle) continue;
            if (best is null || c.IdleSince < best.IdleSince) best = c;
        }
        return best;
    }

    /// <summary>Stop admitting; idle connections are closed on the next sweep.</summary>
    public void BeginShutdown() => _stopping = true;

    public void AbortAll(string reason)
    {
        foreach (var c in Snapshot()) c.Abort(reason);
    }

    private List<Connection> Snapshot()
    {
        var list = new List<Connection>();
        lock (_lock)
            foreach (var c in _slots)
                if (c is not null) list.Add(c);
        return list;
    }

    private void SweepLoop()
    {
        var doomed = new List<(Connection, string)>();
        while (!_disposed)
        {
            Thread.Sleep(SweepIntervalMs);
            Http.HttpDate.Tick();
            long now = Environment.TickCount64;
            bool stopping = _stopping;
            var slots = _slots;
            // Unlocked scan: slots only ever hold fully-constructed connections; a stale read is harmless.
            for (int i = 0; i < slots.Length; i++)
            {
                var c = Volatile.Read(ref slots[i]);
                if (c is null) continue;
                string? why = null;
                long b = Volatile.Read(ref c.BaseDeadline);
                long o = Volatile.Read(ref c.OpDeadline);
                if (stopping && c.Idle) why = "shutdown";
                else if (b != 0 && now > b) why = c.Phase + " timeout";
                else if (o != 0 && now > o) why = c.Phase + " i/o timeout";
                else if (c.MinRate > 0)
                {
                    long busy = c.RateBusyMs;
                    long started = Volatile.Read(ref c.OpStartedAt);
                    if (started != 0) busy += now - started;
                    if (busy > RateGraceMs && c.RateBytes * 1000 < (long)c.MinRate * busy) why = c.Phase + " below minimum rate";
                }
                if (why is not null) doomed.Add((c, why));
            }
            foreach (var (c, why) in doomed)
            {
                if (why != "shutdown") _log.Info("connection aborted", new("conn", c.Id), new("reason", why));
                c.Abort(why);
            }
            doomed.Clear();
        }
    }

    public void Dispose() => _disposed = true;
}
