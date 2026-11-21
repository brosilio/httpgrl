using System.Diagnostics;

namespace Httpgrl.Quic;

/// <summary>
/// The clock the endpoints drive connections with: microseconds, monotonic. A <see cref="QuicConnection"/> never reads
/// a clock itself; whoever drives one passes "now" in, so a game loop or a test can use its own (any monotonic
/// microsecond count that's always positive: 0 means "no deadline").
/// </summary>
public static class QuicClock
{
    private static readonly long Start = Stopwatch.GetTimestamp();

    /// <summary>
    /// Microseconds since the process first used QUIC, plus one second: always positive, and divided before it's
    /// multiplied (ticks × 10^6 overflows a long after a few hours of uptime at nanosecond resolution).
    /// </summary>
    public static long Now()
    {
        long t = Stopwatch.GetTimestamp() - Start, f = Stopwatch.Frequency;
        return 1_000_000 + t / f * 1_000_000 + t % f * 1_000_000 / f;
    }
}

/// <summary>
/// Runs work on the thread that owns a connection (an endpoint's): the only thread that may touch it. Protocols built
/// on a connection (HTTP/3) post through this from other threads.
/// </summary>
public interface IQuicDispatcher
{
    /// <summary>
    /// Do <paramref name="work"/> on <paramref name="connection"/> from any thread: on its owner's thread, if the
    /// connection still exists; then send whatever it produced.
    /// </summary>
    void Run(QuicConnection connection, Action<QuicConnection> work);
}
