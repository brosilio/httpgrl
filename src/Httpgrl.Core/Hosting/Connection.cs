using System.Net;
using System.Net.Sockets;

namespace Httpgrl.Core.Hosting;

/// <summary>
/// Kernel-ish connection record. All timing is absolute <see cref="Environment.TickCount64"/> milliseconds,
/// written by the owning session and read by the sweeper; aborting closes the socket, which faults
/// whatever I/O is pending.
/// </summary>
internal sealed class Connection
{
    public readonly long Id;
    public readonly Socket Socket;
    public readonly IpKey IpKey;
    public readonly long AcceptedAt;
    public int Slot = -1;
    /// <summary>The configuration this connection runs under (set before admission).</summary>
    public Pipeline.HttpRuntime? Generation;
    /// <summary>Accepted on a TLS listener (its handshake ties it to the configuration it was made under).</summary>
    public bool Tls;

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

    private int _aborted;
    private CancellationTokenSource? _cts;
    public string? AbortReason { get; private set; }
    public bool IsAborted => Volatile.Read(ref _aborted) != 0;

    public Connection(long id, Socket socket, IpKey key)
    {
        Id = id;
        Socket = socket;
        IpKey = key;
        AcceptedAt = Environment.TickCount64;
    }

    public CancellationToken AbortToken
    {
        get
        {
            var cts = _cts;
            if (cts is null)
            {
                cts = new CancellationTokenSource();
                if (Interlocked.CompareExchange(ref _cts, cts, null) is { } existing) { cts.Dispose(); cts = existing; }
                if (IsAborted) cts.Cancel();
            }
            return cts.Token;
        }
    }

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

    /// <summary>Hard close: RST, no lingering. Safe to call from any thread, any number of times.</summary>
    /// <summary>
    /// Close now. Default is a reset (linger 0: nothing lingers in the kernel for a client we're punishing);
    /// <paramref name="graceful"/> sends a FIN instead, for idle connections we close on our own account
    /// (reload, shutdown), so clients see an ordinary keep-alive close and retry.
    /// </summary>
    public void Abort(string reason, bool graceful = false)
    {
        if (Interlocked.Exchange(ref _aborted, 1) != 0) return;
        AbortReason = reason;
        try
        {
            // .NET closes abortively when a receive is pending, so a graceful close must shutdown() first.
            if (graceful) Socket.Shutdown(SocketShutdown.Both);
            else Socket.LingerState = new LingerOption(true, 0);
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException) { }
        Socket.Dispose();
        try { _cts?.Cancel(); } catch (ObjectDisposedException) { }
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _aborted, 1);
        Socket.Dispose();
        try { _cts?.Cancel(); } catch (ObjectDisposedException) { }
        _cts?.Dispose();
    }
}

/// <summary>Per-client accounting key: an IPv4 address, or an IPv6 /64 (one end-site).</summary>
internal readonly record struct IpKey(ulong Hi, ulong Lo)
{
    public static IpKey From(EndPoint? ep)
    {
        if (ep is not IPEndPoint ip) return default;
        var a = ip.Address;
        if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
        Span<byte> b = stackalloc byte[16];
        if (a.AddressFamily == AddressFamily.InterNetwork)
        {
            a.TryWriteBytes(b, out _);
            return new IpKey(0, 0x1_0000_0000UL | System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(b));
        }
        a.TryWriteBytes(b, out _);
        return new IpKey(System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(b), 0);
    }
}
