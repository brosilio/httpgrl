namespace Httpgrl.Quic;

public enum QuicLogLevel : byte { Warn, Error }

/// <summary>
/// Where the endpoint reports what goes wrong outside any one connection's protocol (application exceptions, socket
/// trouble, security refusals). Called on the endpoint's thread: an implementation must not block. Messages and keys
/// are constants; values may come from the network, so an implementation must escape them.
/// </summary>
public interface IQuicLog
{
    void Write(QuicLogLevel level, string message, ReadOnlySpan<(string Key, string? Value)> fields);
}

internal static class QuicLogExtensions
{
    public static void Warn(this IQuicLog l, string msg, params ReadOnlySpan<(string Key, string? Value)> f) => l.Write(QuicLogLevel.Warn, msg, f);
    public static void Error(this IQuicLog l, string msg, params ReadOnlySpan<(string Key, string? Value)> f) => l.Write(QuicLogLevel.Error, msg, f);
}

/// <summary>Discards everything.</summary>
public sealed class NullQuicLog : IQuicLog
{
    public static readonly NullQuicLog Instance = new();
    public void Write(QuicLogLevel level, string message, ReadOnlySpan<(string Key, string? Value)> fields) { }
}

/// <summary>
/// A client's address as the per-client connection limit counts it: an IPv4 address, or an IPv6 /64 (one subscriber's
/// usual allocation). The server's TCP limits use the same rule (its IpKey); keep the two identical.
/// </summary>
internal readonly record struct ClientKey(ulong Hi, ulong Lo)
{
    public static ClientKey From(System.Net.EndPoint? ep)
    {
        if (ep is not System.Net.IPEndPoint ip) return default;
        var a = ip.Address;
        if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
        Span<byte> b = stackalloc byte[16];
        if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            a.TryWriteBytes(b, out _);
            return new ClientKey(0, 0x1_0000_0000UL | System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(b));
        }
        a.TryWriteBytes(b, out _);
        return new ClientKey(System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(b), 0);
    }
}
