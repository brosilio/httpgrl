namespace Httpgrl.Core.Hosting;

/// <summary>
/// The timing record the sweeper enforces: phase deadlines, per-operation read/write deadlines, minimum transfer rate.
/// All times are absolute <see cref="Environment.TickCount64"/> milliseconds, stamped by the owner and read by the
/// sweeper. A connection is one; a multiplexed protocol's streams will be others, each with its own deadlines, so one
/// slow stream is cut without its connection.
/// </summary>
internal abstract class Deadlines
{
    /// <summary>Phase deadline independent of I/O (TLS handshake, whole request head, keep-alive idle). 0 = none.</summary>
    public long BaseDeadline;
    /// <summary>Deadlines of the in-flight read and write (independent: upgraded tunnels do both at once). 0 = none.</summary>
    public long ReadDeadline;
    public long WriteDeadline;
    public int ReadOpTimeout;
    public int WriteOpTimeout;

    // Minimum transfer rate over time spent blocked in I/O (slow-read / slow-body defence).
    public int MinRate;
    public long RateBytes;
    public long RateBusyMs;
    public long ReadStartedAt;
    public long WriteStartedAt;

    /// <summary>When set (upgraded tunnels), each completed I/O op moves <see cref="BaseDeadline"/> this far out.</summary>
    public int IdleRefreshMs;

    public volatile bool Idle;
    public long IdleSince;
    public volatile string? Phase;

    public void SetIdle(int timeoutMs)
    {
        long now = Environment.TickCount64;
        IdleSince = now;
        BaseDeadline = timeoutMs > 0 ? now + timeoutMs : 0;
        Phase = "keepalive";
        Idle = true;
    }

    public void SetActive() => Idle = false;

    public void StartRate(int minRate)
    {
        RateBytes = 0;
        RateBusyMs = 0;
        MinRate = minRate;
    }

    public void StopRate() => MinRate = 0;

    // Called by the transport around every socket operation. Reads and writes keep separate state, so a read
    // completing can never clear (or a read's start overwrite) the deadline of a write stalled at the same time.
    public void BeginRead() => Begin(ref ReadStartedAt, ref ReadDeadline, ReadOpTimeout);
    public void EndRead(int bytes) => End(ref ReadStartedAt, ref ReadDeadline, bytes);
    public void BeginWrite() => Begin(ref WriteStartedAt, ref WriteDeadline, WriteOpTimeout);
    public void EndWrite(int bytes) => End(ref WriteStartedAt, ref WriteDeadline, bytes);

    private static void Begin(ref long startedAt, ref long deadline, int timeoutMs)
    {
        long now = Environment.TickCount64;
        Volatile.Write(ref startedAt, now);
        Volatile.Write(ref deadline, timeoutMs > 0 ? now + timeoutMs : 0);
    }

    private void End(ref long startedAt, ref long deadline, int bytes)
    {
        long now = Environment.TickCount64;
        Volatile.Write(ref deadline, 0);
        if (IdleRefreshMs > 0) BaseDeadline = now + IdleRefreshMs;
        if (MinRate > 0)
        {
            Interlocked.Add(ref RateBusyMs, now - startedAt);
            Interlocked.Add(ref RateBytes, bytes);
        }
        Volatile.Write(ref startedAt, 0);
    }

    /// <summary>Signalled when this record's owner is torn down (timeout, reset, shutdown).</summary>
    public abstract CancellationToken AbortToken { get; }
    public abstract bool IsAborted { get; }
    public abstract string? AbortReason { get; }
    /// <summary>Tear the owner down; what the sweeper calls when a deadline passes. Safe from any thread, any number of times.</summary>
    public abstract void Abort(string reason, bool graceful = false);
}
