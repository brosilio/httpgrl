using System.Net;
using System.Net.Sockets;

namespace Httpgrl.Core.Hosting;

/// <summary>
/// Kernel-ish connection record. All timing is absolute <see cref="Environment.TickCount64"/> milliseconds,
/// written by the owning session and read by the sweeper; aborting closes the socket, which faults
/// whatever I/O is pending.
/// </summary>
internal sealed class Connection : Deadlines
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

    private int _aborted;
    private CancellationTokenSource? _cts;
    public override string? AbortReason => _abortReason;
    private string? _abortReason;
    public override bool IsAborted => Volatile.Read(ref _aborted) != 0;

    public Connection(long id, Socket socket, IpKey key)
    {
        Id = id;
        Socket = socket;
        IpKey = key;
        AcceptedAt = Environment.TickCount64;
    }

    public override CancellationToken AbortToken
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

    /// <summary>Hard close: RST, no lingering. Safe to call from any thread, any number of times.</summary>
    /// <summary>
    /// Close now. Default is a reset (linger 0: nothing lingers in the kernel for a client we're punishing);
    /// <paramref name="graceful"/> sends a FIN instead, for idle connections we close on our own account
    /// (reload, shutdown), so clients see an ordinary keep-alive close and retry.
    /// </summary>
    public override void Abort(string reason, bool graceful = false)
    {
        if (Interlocked.Exchange(ref _aborted, 1) != 0) return;
        _abortReason = reason;
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
