using System.Buffers.Binary;

namespace Httpgrl.Quic;

/// <summary>A connection ID as a dictionary key without allocating: up to 20 bytes in three words.</summary>
internal readonly record struct CidKey(ulong A, ulong B, uint C, byte Len)
{
    public static CidKey From(ReadOnlySpan<byte> cid)
    {
        Span<byte> b = stackalloc byte[24];
        b.Clear();
        cid[..Math.Min(cid.Length, 20)].CopyTo(b);
        return new(BinaryPrimitives.ReadUInt64LittleEndian(b), BinaryPrimitives.ReadUInt64LittleEndian(b[8..]), BinaryPrimitives.ReadUInt32LittleEndian(b[16..]), (byte)cid.Length);
    }
}
