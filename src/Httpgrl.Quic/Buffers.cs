using System.Buffers;

namespace Httpgrl.Quic;

/// <summary>Disjoint, sorted, half-open ranges [Start, End) of non-negative integers: received packet numbers, stream bytes.</summary>
internal sealed class RangeSet
{
    private readonly List<(long Start, long End)> _r = new();

    public int Count => _r.Count;
    public bool IsEmpty => _r.Count == 0;
    public (long Start, long End) this[int i] => _r[i];
    /// <summary>One past the highest value held.</summary>
    public long Max => _r.Count == 0 ? 0 : _r[^1].End;

    public void Clear() => _r.Clear();

    /// <summary>Add [start, end); true if any of it was new.</summary>
    public bool Add(long start, long end)
    {
        if (end <= start) return false;
        int n = _r.Count;
        // Fast path: at or after the end (packet numbers and in-order data).
        if (n == 0 || start > _r[n - 1].End)
        {
            _r.Add((start, end));
            return true;
        }
        if (start >= _r[n - 1].Start)
        {
            var last = _r[n - 1];
            if (end <= last.End) return false;
            _r[n - 1] = (last.Start, end);
            return true;
        }
        // General case: find the first range whose End >= start, merge everything [start, end) touches.
        int i = 0, lo = 0, hi = n - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >> 1;
            if (_r[mid].End < start) lo = mid + 1; else hi = mid - 1;
        }
        i = lo;
        if (i < n && _r[i].Start <= start && _r[i].End >= end) return false;
        long s = start, e = end;
        int j = i;
        while (j < n && _r[j].Start <= end)
        {
            s = Math.Min(s, _r[j].Start);
            e = Math.Max(e, _r[j].End);
            j++;
        }
        _r.RemoveRange(i, j - i);
        _r.Insert(i, (s, e));
        return true;
    }

    public bool Contains(long v)
    {
        int lo = 0, hi = _r.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >> 1;
            if (_r[mid].End <= v) lo = mid + 1;
            else if (_r[mid].Start > v) hi = mid - 1;
            else return true;
        }
        return false;
    }

    /// <summary>Remove [start, end) from the set.</summary>
    public void Remove(long start, long end)
    {
        if (end <= start) return;
        for (int i = 0; i < _r.Count; i++)
        {
            var (s, e) = _r[i];
            if (e <= start) continue;
            if (s >= end) break;
            if (s < start && e > end)
            {
                _r[i] = (s, start);
                _r.Insert(i + 1, (end, e));
                return;
            }
            if (s < start) _r[i] = (s, start);
            else if (e > end) { _r[i] = (end, e); return; }
            else { _r.RemoveAt(i); i--; }
        }
    }

    /// <summary>Forget everything below <paramref name="v"/>.</summary>
    public void RemoveBelow(long v)
    {
        int k = 0;
        while (k < _r.Count && _r[k].End <= v) k++;
        if (k > 0) _r.RemoveRange(0, k);
        if (_r.Count > 0 && _r[0].Start < v) _r[0] = (v, _r[0].End);
    }

    /// <summary>Keep only the <paramref name="max"/> highest ranges (ACK frames needn't describe ancient history).</summary>
    public void KeepHighest(int max)
    {
        if (_r.Count > max) _r.RemoveRange(0, _r.Count - max);
    }

    /// <summary>The end of the run starting at <paramref name="v"/>: <paramref name="v"/> itself if it isn't held.</summary>
    public long RunFrom(long v)
    {
        foreach (var (s, e) in _r)
        {
            if (s > v) break;
            if (e > v) return e;
        }
        return v;
    }

    /// <summary>The first range at or after <paramref name="v"/> (clipped to start at it), or false.</summary>
    public bool FirstFrom(long v, out long start, out long end)
    {
        foreach (var (s, e) in _r)
        {
            if (e <= v) continue;
            start = Math.Max(s, v);
            end = e;
            return true;
        }
        start = end = 0;
        return false;
    }
}

/// <summary>
/// The sending half of a byte stream (a QUIC stream or a level's CRYPTO stream). Data stays until acknowledged;
/// losses come back as ranges to resend (QUIC retransmits information, not packets).
/// </summary>
internal sealed class SendBuffer
{
    private byte[] _buf = [];
    private long _base;          // offset of _buf[_head]; everything below is acknowledged
    private int _head, _len;     // live bytes: _buf[_head .. _head + _len)
    private long _sent;          // the next never-sent offset
    private readonly RangeSet _acked = new(), _lost = new();
    private long _finAt = -1;    // the final size, once the writer finished
    private bool _finSent, _finAcked, _finLost;

    /// <summary>One past the last byte written.</summary>
    public long End => _base + _len;
    public long Sent => _sent;
    public long Acked => _base;
    public bool Finished => _finAt >= 0;
    /// <summary>Finished, and everything up to and including the FIN acknowledged (until then the writer may add more).</summary>
    public bool AllAcked => Finished && _finAcked && _base == _finAt;
    public int Buffered => _len;

    public void Write(ReadOnlySpan<byte> data)
    {
        if (Finished) throw new InvalidOperationException("stream already finished");
        if (data.IsEmpty) return;
        if (_head + _len + data.Length > _buf.Length)
        {
            if (_len + data.Length <= _buf.Length / 2 && _head > 0)
            {
                Buffer.BlockCopy(_buf, _head, _buf, 0, _len);
                _head = 0;
            }
            else
            {
                var nb = ArrayPool<byte>.Shared.Rent(Math.Max(_len + data.Length, Math.Max(4096, _buf.Length * 2)));
                Buffer.BlockCopy(_buf, _head, nb, 0, _len);
                if (_buf.Length > 0) ArrayPool<byte>.Shared.Return(_buf);
                _buf = nb;
                _head = 0;
            }
        }
        data.CopyTo(_buf.AsSpan(_head + _len));
        _len += data.Length;
    }

    public void Finish()
    {
        if (!Finished) _finAt = End;
    }

    /// <summary>Whether anything is waiting: a lost range, unsent data under <paramref name="limit"/>, or a FIN to (re)send.</summary>
    public bool HasData(long limit) =>
        !_lost.IsEmpty || (_sent < End && _sent < limit) || (Finished && (!_finSent || _finLost) && !_finAcked && _sent >= _finAt);

    /// <summary>
    /// The next chunk to send, at most <paramref name="max"/> bytes: lost data first, then new data below
    /// <paramref name="limit"/> (flow control). <paramref name="fin"/>: the chunk ends the stream. False: nothing to send.
    /// </summary>
    public bool Next(int max, long limit, out long offset, out ReadOnlySpan<byte> data, out bool fin)
    {
        fin = false;
        data = default;
        offset = 0;
        if (_lost.FirstFrom(_base, out long ls, out long le))
        {
            int n = (int)Math.Min(le - ls, max);
            offset = ls;
            data = _buf.AsSpan(_head + (int)(ls - _base), n);
            fin = Finished && ls + n == _finAt && ls + n >= _sent;
            return true;
        }
        long avail = Math.Min(End, Math.Max(limit, _sent)) - _sent;
        if (avail > 0)
        {
            int n = (int)Math.Min(avail, max);
            offset = _sent;
            data = _buf.AsSpan(_head + (int)(_sent - _base), n);
            fin = Finished && _sent + n == _finAt;
            return true;
        }
        if (Finished && _sent >= _finAt && !_finAcked && (!_finSent || _finLost))
        {
            offset = _finAt; // an empty frame carrying only the FIN
            fin = true;
            return true;
        }
        return false;
    }

    /// <summary>Record that [offset, offset + length) (and the FIN) went out in a packet.</summary>
    public void OnSent(long offset, int length, bool fin)
    {
        _lost.Remove(offset, offset + length);
        if (offset + length > _sent) _sent = offset + length;
        if (fin) { _finSent = true; _finLost = false; }
    }

    public void OnAcked(long offset, int length, bool fin)
    {
        if (fin) _finAcked = true;
        if (length == 0) return;
        _acked.Add(offset, offset + length);
        _lost.Remove(offset, offset + length);
        long newBase = _acked.RunFrom(_base);
        if (newBase > _base)
        {
            int n = (int)(newBase - _base);
            _head += n;
            _len -= n;
            _base = newBase;
            _acked.RemoveBelow(_base);
            if (_len == 0) _head = 0;
        }
    }

    public void OnLost(long offset, int length, bool fin)
    {
        if (fin && !_finAcked) _finLost = true;
        long s = Math.Max(offset, _base), e = offset + length;
        if (s >= e) return;
        _lost.Add(s, e);
        // Don't resend what was acknowledged by another packet meanwhile.
        for (int i = 0; i < _acked.Count; i++) _lost.Remove(_acked[i].Start, _acked[i].End);
    }

    /// <summary>Drop everything (stream reset, keys discarded).</summary>
    public void Release()
    {
        if (_buf.Length > 0) ArrayPool<byte>.Shared.Return(_buf);
        _buf = [];
        _head = _len = 0;
        _lost.Clear();
        _acked.Clear();
    }
}

/// <summary>
/// The receiving half of a byte stream: reassembles out-of-order data up to a limit (flow control or the CRYPTO
/// buffer cap) and hands it out in order. Enforces final-size rules (RFC 9000 4.5).
/// </summary>
internal sealed class RecvBuffer
{
    private byte[] _buf = [];
    private long _read;              // offset of _buf[0]: everything below has been read
    private readonly RangeSet _have = new();
    public long FinalSize { get; private set; } = -1;

    public long ReadOffset => _read;
    /// <summary>The highest offset received (for flow control accounting).</summary>
    public long Highest { get; private set; }
    /// <summary>Bytes readable now, in order.</summary>
    public int Readable => (int)(_have.RunFrom(_read) - _read);
    /// <summary>Everything up to the final size has been read.</summary>
    public bool Complete => FinalSize >= 0 && _read == FinalSize;
    public bool FinKnown => FinalSize >= 0;

    /// <summary>
    /// Data at <paramref name="offset"/>. <paramref name="limit"/>: the highest offset allowed (exclusive). Returns
    /// false if the frame is a duplicate entirely below what's been read.
    /// </summary>
    public bool Write(long offset, ReadOnlySpan<byte> data, bool fin, long limit, ulong frameType)
    {
        long end = offset + data.Length;
        if (FinalSize >= 0 && (end > FinalSize || (fin && end != FinalSize)))
            throw new QuicException(QuicError.FinalSizeError, "data beyond, or a different, final size", frameType);
        if (fin)
        {
            if (end < Highest) throw new QuicException(QuicError.FinalSizeError, "final size below data already received", frameType);
            FinalSize = end;
        }
        if (end > limit) throw new QuicException(frameType == QuicFrameType.Crypto ? QuicError.CryptoBufferExceeded : QuicError.FlowControlError, "data beyond the receive limit", frameType);
        if (end > Highest) Highest = end;
        if (end <= _read) return false;
        int skip = (int)Math.Max(0, _read - offset);
        long from = offset + skip;
        int need = (int)(end - _read);
        if (need > _buf.Length)
        {
            var nb = ArrayPool<byte>.Shared.Rent(Math.Max(need, Math.Max(4096, _buf.Length * 2)));
            int keep = (int)Math.Min(_have.Max - _read, _buf.Length);
            if (keep > 0) Buffer.BlockCopy(_buf, 0, nb, 0, keep);
            if (_buf.Length > 0) ArrayPool<byte>.Shared.Return(_buf);
            _buf = nb;
        }
        data[skip..].CopyTo(_buf.AsSpan((int)(from - _read)));
        _have.Add(from, end);
        return true;
    }

    /// <summary>A RESET_STREAM's final size: the same rules (it may not shrink below what arrived, nor change).</summary>
    public void SetFinalSize(long size, ulong frameType)
    {
        if ((FinalSize >= 0 && FinalSize != size) || size < Highest) throw new QuicException(QuicError.FinalSizeError, "reset with a different final size", frameType);
        FinalSize = size;
        Highest = size;
    }

    /// <summary>Copy readable bytes out; the count.</summary>
    public int Read(Span<byte> dest)
    {
        int n = Math.Min(Readable, dest.Length);
        if (n == 0) return 0;
        _buf.AsSpan(0, n).CopyTo(dest);
        Consume(n);
        return n;
    }

    /// <summary>The readable bytes, in place (valid until the next call).</summary>
    public ReadOnlySpan<byte> Peek() => _buf.AsSpan(0, Readable);

    public void Consume(int n)
    {
        int held = (int)Math.Min(_have.Max - _read, _buf.Length);
        Buffer.BlockCopy(_buf, n, _buf, 0, held - n);
        _read += n;
        _have.RemoveBelow(_read);
    }

    public void Release()
    {
        if (_buf.Length > 0) ArrayPool<byte>.Shared.Return(_buf);
        _buf = [];
        _have.Clear();
    }
}
