using System.Net.Sockets;
using Httpgrl.Core.Hosting;

namespace Httpgrl.Core.Http;

/// <summary>
/// Raw socket stream that stamps every operation into the <see cref="Connection"/> so the sweeper can
/// enforce per-op timeouts and minimum rates. Sits below TLS, so ciphertext is what gets measured.
/// </summary>
internal sealed class TransportStream(Connection conn) : Stream
{
    private readonly Socket _s = conn.Socket;

    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        conn.BeginOp(conn.ReadOpTimeout);
        int n = 0;
        try { return n = await _s.ReceiveAsync(buffer, SocketFlags.None, ct).ConfigureAwait(false); }
        finally { conn.EndOp(n); }
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        while (!buffer.IsEmpty)
        {
            conn.BeginOp(conn.WriteOpTimeout);
            int n = 0;
            try { n = await _s.SendAsync(buffer, SocketFlags.None, ct).ConfigureAwait(false); }
            finally { conn.EndOp(n); }
            if (n <= 0) throw new IOException("connection closed during send");
            buffer = buffer[n..];
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        WriteAsync(buffer.AsMemory(offset, count), ct).AsTask();

    public override int Read(byte[] buffer, int offset, int count)
    {
        conn.BeginOp(conn.ReadOpTimeout);
        int n = 0;
        try { return n = _s.Receive(buffer, offset, count, SocketFlags.None); }
        finally { conn.EndOp(n); }
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        conn.BeginOp(conn.WriteOpTimeout);
        try { _s.Send(buffer, offset, count, SocketFlags.None); }
        finally { conn.EndOp(count); }
    }

    public override Task FlushAsync(CancellationToken ct) => Task.CompletedTask;
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}

/// <summary>Growable receive buffer for the request head; pipelined leftovers stay in [Start, End).</summary>
internal sealed class InputBuffer : IDisposable
{
    public byte[] Buf;
    public int Start;
    public int End;
    /// <summary>Head terminator search resumes here (avoids rescanning on every fill).</summary>
    public int Scan;

    public InputBuffer(int initial) => Buf = System.Buffers.ArrayPool<byte>.Shared.Rent(initial);

    public int Count => End - Start;
    public ReadOnlySpan<byte> Data => Buf.AsSpan(Start, End - Start);

    public void Consume(int n)
    {
        Start += n;
        Scan = Start;
        if (Start == End) { Start = End = Scan = 0; }
    }

    /// <summary>Read more bytes. Returns 0 on EOF, -1 when <paramref name="limit"/> buffered bytes are already held.</summary>
    public async ValueTask<int> FillAsync(Stream s, int limit)
    {
        if (End == Buf.Length)
        {
            int count = Count;
            if (count >= limit) return -1;
            if (Start > 0)
            {
                Buffer.BlockCopy(Buf, Start, Buf, 0, count);
                Scan -= Start;
                Start = 0;
                End = count;
            }
            if (End == Buf.Length)
            {
                var bigger = System.Buffers.ArrayPool<byte>.Shared.Rent(Math.Min(Buf.Length * 2, Math.Max(limit, Buf.Length)));
                Buffer.BlockCopy(Buf, 0, bigger, 0, End);
                System.Buffers.ArrayPool<byte>.Shared.Return(Buf);
                Buf = bigger;
            }
        }
        int max = Math.Min(Buf.Length - End, Math.Max(limit - Count, 1));
        int n = await s.ReadAsync(Buf.AsMemory(End, max)).ConfigureAwait(false);
        End += n;
        return n;
    }

    public void Dispose()
    {
        var b = Buf;
        Buf = [];
        if (b.Length > 0) System.Buffers.ArrayPool<byte>.Shared.Return(b);
    }
}
