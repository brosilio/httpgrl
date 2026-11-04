using System.Buffers.Binary;

namespace Httpgrl.Core.Quic;

/// <summary>QUIC variable-length integers (RFC 9000 16): 1, 2, 4 or 8 bytes, the top two bits giving the length.</summary>
internal static class VarInt
{
    public const ulong Max = (1UL << 62) - 1;

    public static int Size(ulong v) => v < 1UL << 6 ? 1 : v < 1UL << 14 ? 2 : v < 1UL << 30 ? 4 : 8;

    /// <summary>Write <paramref name="v"/> (at most <see cref="Max"/>) in its shortest form; the bytes written.</summary>
    public static int Write(Span<byte> d, ulong v)
    {
        if (v < 1UL << 6) { d[0] = (byte)v; return 1; }
        if (v < 1UL << 14) { BinaryPrimitives.WriteUInt16BigEndian(d, (ushort)(v | 0x4000)); return 2; }
        if (v < 1UL << 30) { BinaryPrimitives.WriteUInt32BigEndian(d, (uint)v | 0x8000_0000); return 4; }
        if (v > Max) throw new ArgumentOutOfRangeException(nameof(v));
        BinaryPrimitives.WriteUInt64BigEndian(d, v | 0xC000_0000_0000_0000);
        return 8;
    }

    /// <summary>Write <paramref name="v"/> in exactly <paramref name="size"/> bytes (for lengths filled in afterwards).</summary>
    public static void WriteFixed(Span<byte> d, ulong v, int size)
    {
        switch (size)
        {
            case 1: if (v >= 1UL << 6) throw new ArgumentOutOfRangeException(nameof(v)); d[0] = (byte)v; break;
            case 2: if (v >= 1UL << 14) throw new ArgumentOutOfRangeException(nameof(v)); BinaryPrimitives.WriteUInt16BigEndian(d, (ushort)(v | 0x4000)); break;
            case 4: if (v >= 1UL << 30) throw new ArgumentOutOfRangeException(nameof(v)); BinaryPrimitives.WriteUInt32BigEndian(d, (uint)v | 0x8000_0000); break;
            case 8: if (v > Max) throw new ArgumentOutOfRangeException(nameof(v)); BinaryPrimitives.WriteUInt64BigEndian(d, v | 0xC000_0000_0000_0000); break;
            default: throw new ArgumentOutOfRangeException(nameof(size));
        }
    }

    /// <summary>Read one; false if <paramref name="s"/> is too short. Non-minimal encodings are legal (RFC 9000 16).</summary>
    public static bool TryRead(ReadOnlySpan<byte> s, out ulong v, out int len)
    {
        v = 0;
        len = 0;
        if (s.IsEmpty) return false;
        int n = 1 << (s[0] >> 6);
        if (s.Length < n) return false;
        len = n;
        v = n switch
        {
            1 => (ulong)(s[0] & 0x3F),
            2 => (ulong)(BinaryPrimitives.ReadUInt16BigEndian(s) & 0x3FFF),
            4 => BinaryPrimitives.ReadUInt32BigEndian(s) & 0x3FFF_FFFF,
            _ => BinaryPrimitives.ReadUInt64BigEndian(s) & 0x3FFF_FFFF_FFFF_FFFF,
        };
        return true;
    }
}

/// <summary>
/// A cursor over untrusted bytes. Running out of input is a <see cref="QuicException"/> with the code given at
/// construction (FRAME_ENCODING_ERROR for frames, TRANSPORT_PARAMETER_ERROR for transport parameters).
/// </summary>
internal ref struct QuicReader(ReadOnlySpan<byte> s, QuicError error)
{
    private readonly ReadOnlySpan<byte> _s = s;
    private int _p;

    public readonly int Position => _p;
    public readonly int Remaining => _s.Length - _p;
    public readonly bool End => _p >= _s.Length;
    public readonly ReadOnlySpan<byte> Rest => _s[_p..];

    public ulong VarInt(ulong frameType = 0)
    {
        if (!Quic.VarInt.TryRead(_s[_p..], out var v, out int n)) throw new QuicException(error, "truncated integer", frameType);
        _p += n;
        return v;
    }

    /// <summary>A varint at most <paramref name="max"/>, as an int (lengths).</summary>
    public int Length(int max, ulong frameType = 0)
    {
        ulong v = VarInt(frameType);
        if (v > (ulong)max) throw new QuicException(error, "length out of range", frameType);
        return (int)v;
    }

    public byte Byte(ulong frameType = 0)
    {
        if (_p >= _s.Length) throw new QuicException(error, "truncated", frameType);
        return _s[_p++];
    }

    public ReadOnlySpan<byte> Bytes(int n, ulong frameType = 0)
    {
        if (n < 0 || n > _s.Length - _p) throw new QuicException(error, "truncated", frameType);
        var r = _s.Slice(_p, n);
        _p += n;
        return r;
    }
}
