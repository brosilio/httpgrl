using System.Buffers.Binary;
using System.Net;

namespace Httpgrl.Core.Http;

/// <summary>What a PROXY protocol header said. Addresses are null for LOCAL (v2) / UNKNOWN (v1) and non-IP families.</summary>
internal readonly record struct ProxyHeader(IPEndPoint? Source, IPEndPoint? Destination);

/// <summary>
/// PROXY protocol v1 (text) and v2 (binary), as sent by HAProxy, load balancers and TCP relays in front of us
/// (https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt). Strict: exact syntax, bounded lengths, no
/// leniency an attacker reaching the socket directly could exploit. Only listeners configured with
/// <c>proxy_protocol</c> parse it, and there the header is mandatory.
/// </summary>
internal static class ProxyProtocol
{
    public const int V1Max = 107;
    /// <summary>v2 headers may carry TLVs; nothing legitimate needs more than this (nginx caps lower still).</summary>
    public const int V2Max = 16 + 1024;
    private static ReadOnlySpan<byte> V2Signature => [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];

    /// <summary>
    /// Parse a header at the start of <paramref name="data"/>. Returns its length (header found), 0 (need more bytes)
    /// or -1 (invalid: close the connection).
    /// </summary>
    public static int TryParse(ReadOnlySpan<byte> data, out ProxyHeader header)
    {
        header = default;
        if (data.IsEmpty) return 0;
        if (data[0] == (byte)'P') return ParseV1(data, out header);
        if (data[0] == 0x0D) return ParseV2(data, out header);
        return -1;
    }

    private static int ParseV1(ReadOnlySpan<byte> data, out ProxyHeader header)
    {
        header = default;
        var prefix = "PROXY "u8;
        int n = Math.Min(data.Length, prefix.Length);
        if (!data[..n].SequenceEqual(prefix[..n])) return -1;
        int eol = data[..Math.Min(data.Length, V1Max)].IndexOf("\r\n"u8);
        if (eol < 0) return data.Length >= V1Max ? -1 : 0;
        var line = data[prefix.Length..eol];
        // "UNKNOWN" may be followed by anything (the spec says receivers ignore the rest).
        if (line.StartsWith("UNKNOWN"u8)) return eol + 2;
        // Exactly five fields separated by single spaces.
        Span<Range> parts = stackalloc Range[5];
        int count = 0, start = 0;
        for (int i = 0; i <= line.Length; i++)
        {
            if (i < line.Length && line[i] != ' ') continue;
            if (i == start || count == 5) return -1;
            parts[count++] = start..i;
            start = i + 1;
        }
        if (count != 5) return -1;
        var family = line[parts[0]];
        bool v4 = family.SequenceEqual("TCP4"u8), v6 = family.SequenceEqual("TCP6"u8);
        if (!v4 && !v6) return -1;
        if (!ParseIp(line[parts[1]], v4, out var src) || !ParseIp(line[parts[2]], v4, out var dst)) return -1;
        if (!ParsePort(line[parts[3]], out int sport) || !ParsePort(line[parts[4]], out int dport)) return -1;
        header = new ProxyHeader(new IPEndPoint(src, sport), new IPEndPoint(dst, dport));
        return eol + 2;
    }

    private static bool ParseIp(ReadOnlySpan<byte> s, bool v4, out IPAddress ip)
    {
        ip = IPAddress.None;
        if (s.IsEmpty || s.Length > 45) return false;
        foreach (byte b in s)
            if (!(char.IsAsciiHexDigit((char)b) || b is (byte)'.' or (byte)':')) return false;
        Span<char> c = stackalloc char[s.Length];
        for (int i = 0; i < s.Length; i++) c[i] = (char)s[i];
        if (!IPAddress.TryParse(c, out var parsed)) return false;
        if (v4 != (parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)) return false;
        ip = parsed;
        return true;
    }

    /// <summary>Decimal 0..65535, no sign, no leading zeros (as the spec requires).</summary>
    private static bool ParsePort(ReadOnlySpan<byte> s, out int port)
    {
        port = 0;
        if (s.IsEmpty || s.Length > 5 || (s.Length > 1 && s[0] == '0')) return false;
        foreach (byte b in s)
        {
            if ((uint)(b - '0') > 9) return false;
            port = port * 10 + (b - '0');
        }
        return port <= 65535;
    }

    private static int ParseV2(ReadOnlySpan<byte> data, out ProxyHeader header)
    {
        header = default;
        int n = Math.Min(data.Length, V2Signature.Length);
        if (!data[..n].SequenceEqual(V2Signature[..n])) return -1;
        if (data.Length < 16) return 0;
        byte verCmd = data[12], famProto = data[13];
        int len = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(14, 2));
        if ((verCmd >> 4) != 2) return -1;
        int cmd = verCmd & 0x0F;
        if (cmd > 1) return -1;
        if (16 + len > V2Max) return -1;
        if (data.Length < 16 + len) return 0;
        var body = data.Slice(16, len);
        if (cmd == 0) return 16 + len; // LOCAL: health checks from the proxy itself; addresses ignored
        int family = famProto >> 4, proto = famProto & 0x0F;
        if (proto is not (0 or 1 or 2)) return -1;  // UNSPEC, STREAM, DGRAM
        switch (family)
        {
            case 1: // AF_INET
                if (len < 12) return -1;
                header = new ProxyHeader(
                    new IPEndPoint(new IPAddress(body[..4]), BinaryPrimitives.ReadUInt16BigEndian(body.Slice(8, 2))),
                    new IPEndPoint(new IPAddress(body.Slice(4, 4)), BinaryPrimitives.ReadUInt16BigEndian(body.Slice(10, 2))));
                break;
            case 2: // AF_INET6
                if (len < 36) return -1;
                header = new ProxyHeader(
                    new IPEndPoint(new IPAddress(body[..16]), BinaryPrimitives.ReadUInt16BigEndian(body.Slice(32, 2))),
                    new IPEndPoint(new IPAddress(body.Slice(16, 16)), BinaryPrimitives.ReadUInt16BigEndian(body.Slice(34, 2))));
                break;
            case 0 or 3: break; // UNSPEC, AF_UNIX: no IP addresses to report
            default: return -1;
        }
        return 16 + len; // TLVs after the addresses are skipped
    }
}

/// <summary>A stream that first yields bytes already read (what followed the PROXY header), then reads on.</summary>
internal sealed class PrefixedStream(ReadOnlyMemory<byte> prefix, Stream inner) : Stream
{
    private ReadOnlyMemory<byte> _prefix = prefix;

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (_prefix.IsEmpty) return inner.ReadAsync(buffer, ct);
        int n = Math.Min(buffer.Length, _prefix.Length);
        _prefix[..n].CopyTo(buffer);
        _prefix = _prefix[n..];
        return ValueTask.FromResult(n);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) => ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();
    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) => inner.WriteAsync(buffer, ct);
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) => inner.WriteAsync(buffer, offset, count, ct);
    public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
    public override Task FlushAsync(CancellationToken ct) => inner.FlushAsync(ct);
    public override void Flush() => inner.Flush();
    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
    public override ValueTask DisposeAsync() => inner.DisposeAsync();
}
