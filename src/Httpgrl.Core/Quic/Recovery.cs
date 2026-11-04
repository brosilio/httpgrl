namespace Httpgrl.Core.Quic;

/// <summary>What a sent packet carried that matters if it's acknowledged or lost (RFC 9000 13.3).</summary>
internal enum SentKind : byte
{
    Crypto,          // A = offset, B = length (the packet's space is the level)
    Stream,          // Id, A = offset, B = length, Fin
    MaxData,
    MaxStreamData,   // Id
    MaxStreamsBidi,
    MaxStreamsUni,
    HandshakeDone,
    NewConnectionId, // A = sequence number
    RetireConnectionId, // A = sequence number
    ResetStream,     // Id
    StopSending,     // Id
    Ack,             // A = the largest packet number it acknowledged
    DataBlocked,
    StreamDataBlocked, // Id
    NewToken,
    Ping,
    PathChallenge,
}

internal struct SentFrame
{
    public SentKind Kind;
    public bool Fin;
    public long Id, A, B;
}

internal enum CongestionControl : byte
{
    NewReno,
    /// <summary>RFC 9438: better on long, fast paths; Reno-friendly where Reno would do better.</summary>
    Cubic,
}

internal sealed class SentPacket
{
    public long Pn;
    public long TimeSent;
    public int Size;
    public bool AckEliciting, InFlight;
    /// <summary>Sent while the congestion window was what limited us (only then may an ACK of it grow the window).</summary>
    public bool WindowLimited;
    public readonly List<SentFrame> Frames = new(4);

    public void Reset()
    {
        Frames.Clear();
        AckEliciting = InFlight = WindowLimited = false;
    }
}

/// <summary>
/// Unacknowledged packets of one space, indexed by packet number: packet numbers are consecutive, so a ring of
/// slots from the oldest outstanding one makes acknowledging a packet O(1), however large the window.
/// </summary>
internal sealed class SentPackets
{
    private SentPacket?[] _ring = new SentPacket?[64];
    private int _head;          // slot of _base
    private long _base;         // packet number of the oldest slot
    private int _span;          // slots in use, from _base to the newest packet sent
    public int Count { get; private set; }

    public void Add(SentPacket p)
    {
        if (_span == 0) { _base = p.Pn; _head = 0; }
        long at = p.Pn - _base;
        if (at < _span) throw new InvalidOperationException("packet numbers must increase");
        while (at >= _ring.Length) Grow();
        _ring[(_head + (int)at) & (_ring.Length - 1)] = p;
        _span = (int)at + 1;
        Count++;
    }

    private void Grow()
    {
        var n = new SentPacket?[_ring.Length * 2];
        for (int i = 0; i < _span; i++) n[i] = _ring[(_head + i) & (_ring.Length - 1)];
        _ring = n;
        _head = 0;
    }

    public SentPacket? Get(long pn)
    {
        long at = pn - _base;
        return at < 0 || at >= _span ? null : _ring[(_head + (int)at) & (_ring.Length - 1)];
    }

    public SentPacket? Remove(long pn)
    {
        long at = pn - _base;
        if (at < 0 || at >= _span) return null;
        ref var slot = ref _ring[(_head + (int)at) & (_ring.Length - 1)];
        var p = slot;
        if (p is null) return null;
        slot = null;
        Count--;
        // Drop empty slots at the front, so the window starts at the oldest outstanding packet.
        while (_span > 0 && _ring[_head] is null)
        {
            _head = (_head + 1) & (_ring.Length - 1);
            _base++;
            _span--;
        }
        return p;
    }

    /// <summary>The oldest outstanding packet, or null.</summary>
    public SentPacket? Oldest => _span > 0 ? _ring[_head] : null;
    /// <summary>The lowest and one past the highest packet number in the window (outstanding packets lie between).</summary>
    public long First => _base;
    public long End => _base + _span;

    public void Clear()
    {
        Array.Clear(_ring);
        _span = Count = 0;
        _head = 0;
    }

    public IEnumerable<SentPacket> All()
    {
        for (int i = 0; i < _span; i++)
            if (_ring[(_head + i) & (_ring.Length - 1)] is { } p) yield return p;
    }
}

/// <summary>
/// Loss detection and congestion control (RFC 9002), for one connection's three packet number spaces: RTT
/// estimation, ACK processing, packet- and time-threshold loss, the probe timeout, and NewReno with persistent
/// congestion. Times are microseconds on the connection's clock.
/// </summary>
internal sealed class Recovery
{
    public const long Granularity = 1_000, InitialRtt = 333_000;
    public const int PacketThreshold = 3, PersistentCongestionThreshold = 3;

    public sealed class Space
    {
        /// <summary>Unacknowledged packets, by packet number.</summary>
        public readonly SentPackets Sent = new();
        public long LargestAcked = -1;
        public long LossTime;
        public long LastAckElicitingSent;
        public int AckElicitingInFlight;
        public bool Discarded;
        /// <summary>One past the highest packet number sent.</summary>
        public long NextPn;
        /// <summary>Recently acknowledged packet numbers (for the persistent-congestion check).</summary>
        public readonly RangeSet AckedPns = new();
    }

    public readonly Space[] Spaces = [new(), new(), new()];

    public long LatestRtt, SmoothedRtt = InitialRtt, RttVar = InitialRtt / 2, MinRtt;
    public bool HasRttSample;
    /// <summary>The peer's max_ack_delay, applied to the application space once the handshake is confirmed.</summary>
    public long MaxAckDelay = 25_000;
    public int PtoCount;

    // NewReno (RFC 9002 7).
    public readonly int MaxDatagramSize;
    public long Cwnd, Ssthresh = long.MaxValue, BytesInFlight;
    private long _recoveryStart = -1;
    private long _firstRttSampleTime;
    public long MinWindow => 2L * MaxDatagramSize;
    /// <summary>Counters for logs and tests.</summary>
    public long LostPackets, CongestionEvents, PersistentCongestions;

    public readonly CongestionControl Algorithm;

    // CUBIC (RFC 9438), in bytes: the window before the last reduction, the time to regain it, the epoch's start,
    // and the Reno-friendly estimate.
    public const double CubicC = 0.4, CubicBeta = 0.7;
    private double _wMax, _wLastMax, _k, _wEst;
    private long _epochStart = -1;

    public Recovery(int maxDatagramSize = 1200, CongestionControl algorithm = CongestionControl.Cubic)
    {
        MaxDatagramSize = maxDatagramSize;
        Algorithm = algorithm;
        Cwnd = InitialWindow;
    }

    public long InitialWindow => Math.Min(10L * MaxDatagramSize, Math.Max(14720, 2L * MaxDatagramSize));

    public bool CanSend(int bytes) => BytesInFlight + bytes <= Cwnd;

    public void OnPacketSent(int space, SentPacket p)
    {
        var s = Spaces[space];
        s.Sent.Add(p);
        s.NextPn = p.Pn + 1;
        if (p.InFlight)
        {
            if (p.AckEliciting)
            {
                s.LastAckElicitingSent = p.TimeSent;
                s.AckElicitingInFlight++;
            }
            BytesInFlight += p.Size;
            // Half the window in use counts as window-limited: an application that never fills it (interactive
            // traffic) mustn't inflate it without bound.
            p.WindowLimited = BytesInFlight * 2 >= Cwnd;
        }
    }

    /// <summary>
    /// Process an ACK's ranges (largest first, inclusive). Newly acknowledged packets go to <paramref name="acked"/>,
    /// packets declared lost to <paramref name="lost"/>, both removed from tracking. False if the ACK acknowledges a
    /// packet number we never sent (a PROTOCOL_VIOLATION for the caller).
    /// </summary>
    public bool OnAck(int space, List<(long Smallest, long Largest)> ranges, long ackDelay, long now, bool handshakeConfirmed,
        List<SentPacket> acked, List<SentPacket> lost)
    {
        var s = Spaces[space];
        long largest = ranges[0].Largest;
        if (largest >= s.NextPn) return false; // acknowledges a packet never sent
        foreach (var (lo, hi) in ranges) s.AckedPns.Add(lo, hi + 1);
        s.AckedPns.KeepHighest(64);
        bool newLargest = largest > s.LargestAcked;
        if (newLargest) s.LargestAcked = largest;

        // Collect newly acknowledged packets: each range, clipped to what's outstanding, slot by slot.
        int start = acked.Count;
        foreach (var (lo, hi) in ranges)
        {
            long from = Math.Max(lo, s.Sent.First), to = Math.Min(hi, s.Sent.End - 1);
            for (long pn = to; pn >= from; pn--)
                if (s.Sent.Remove(pn) is { } p) acked.Add(p);
        }
        if (acked.Count == start) return true;

        // An RTT sample, if the largest acknowledged is newly acknowledged and ack-eliciting (RFC 9002 5.1).
        SentPacket? top = null;
        bool anyAckEliciting = false;
        for (int i = start; i < acked.Count; i++)
        {
            var p = acked[i];
            if (p.Pn == largest) top = p;
            anyAckEliciting |= p.AckEliciting;
        }
        if (top is not null && anyAckEliciting && newLargest)
        {
            LatestRtt = Math.Max(now - top.TimeSent, 1);
            UpdateRtt(space == 2 && handshakeConfirmed ? Math.Min(ackDelay, MaxAckDelay) : (space == 2 ? ackDelay : 0), now);
        }

        DetectLost(space, now, lost);
        for (int i = start; i < acked.Count; i++) OnAcked(s, acked[i], now);
        // Reset the backoff: the peer is responding (a client still validating the server's address keeps it).
        PtoCount = 0;
        return true;
    }

    private void UpdateRtt(long ackDelay, long now)
    {
        if (!HasRttSample)
        {
            HasRttSample = true;
            _firstRttSampleTime = now;
            MinRtt = LatestRtt;
            SmoothedRtt = LatestRtt;
            RttVar = LatestRtt / 2;
            return;
        }
        MinRtt = Math.Min(MinRtt, LatestRtt);
        long adjusted = LatestRtt >= MinRtt + ackDelay ? LatestRtt - ackDelay : LatestRtt;
        RttVar = (3 * RttVar + Math.Abs(SmoothedRtt - adjusted)) / 4;
        SmoothedRtt = (7 * SmoothedRtt + adjusted) / 8;
    }

    private void OnAcked(Space s, SentPacket p, long now)
    {
        if (!p.InFlight) return;
        if (p.AckEliciting) s.AckElicitingInFlight--;
        BytesInFlight -= p.Size;
        // No growth for packets sent before the current recovery period began, nor when the window wasn't the limit.
        if (p.TimeSent <= _recoveryStart || !p.WindowLimited) return;
        if (Cwnd < Ssthresh) { Cwnd += p.Size; return; } // slow start, for both
        if (Algorithm == CongestionControl.NewReno) { Cwnd += (long)MaxDatagramSize * p.Size / Cwnd; return; }
        CubicGrow(p.Size, now);
    }

    /// <summary>Congestion avoidance under CUBIC (RFC 9438 4.2-4.4).</summary>
    private void CubicGrow(int acked, long now)
    {
        double mss = MaxDatagramSize;
        if (_epochStart < 0)
        {
            // A new epoch (after slow start, or the first ACK after a reduction).
            _epochStart = now;
            if (_wMax <= Cwnd) { _wMax = Cwnd; _k = 0; }
            else _k = Math.Cbrt((_wMax - Cwnd) / mss / CubicC);
            _wEst = Cwnd;
        }
        double t = (now - _epochStart + SmoothedRtt) / 1e6; // the window one RTT from now
        double target = (CubicC * Math.Pow(t - _k, 3)) * mss + _wMax;
        // The Reno-friendly estimate grows like Reno would with CUBIC's beta (alpha = 3(1 - beta)/(1 + beta)).
        _wEst += 3 * (1 - CubicBeta) / (1 + CubicBeta) * mss * acked / Cwnd;
        if (target < _wEst) { Cwnd = (long)Math.Max(Cwnd, _wEst); return; }
        target = Math.Clamp(target, Cwnd, 1.5 * Cwnd);
        Cwnd += (long)Math.Max(1, (target - Cwnd) * acked / Cwnd);
    }

    /// <summary>Declare packets lost by the packet or time threshold (RFC 9002 6.1), and react as a congestion event.</summary>
    public void DetectLost(int space, long now, List<SentPacket> lost)
    {
        var s = Spaces[space];
        s.LossTime = 0;
        if (s.LargestAcked < 0) return;
        long lossDelay = Math.Max(9 * Math.Max(LatestRtt, SmoothedRtt) / 8, Granularity);
        long lostSendTime = now - lossDelay;
        int start = lost.Count;
        long end = Math.Min(s.LargestAcked, s.Sent.End - 1);
        for (long pn = s.Sent.First; pn <= end; pn++)
        {
            var p = s.Sent.Get(pn);
            if (p is null) continue;
            if (p.TimeSent <= lostSendTime || s.LargestAcked >= p.Pn + PacketThreshold)
            {
                s.Sent.Remove(pn);
                lost.Add(p);
            }
            else if (s.LossTime == 0 || p.TimeSent + lossDelay < s.LossTime) s.LossTime = p.TimeSent + lossDelay;
        }
        if (lost.Count > start) OnLost(s, lost, start, now);
    }

    private void OnLost(Space s, List<SentPacket> lost, int start, long now)
    {
        long latestLost = 0, firstAckEliciting = long.MaxValue, lastAckEliciting = 0;
        long firstPn = long.MaxValue, lastPn = -1;
        int ackElicitingLost = 0;
        for (int i = start; i < lost.Count; i++)
        {
            var p = lost[i];
            LostPackets++;
            if (!p.InFlight) continue;
            BytesInFlight -= p.Size;
            if (p.AckEliciting)
            {
                s.AckElicitingInFlight--;
                ackElicitingLost++;
                firstAckEliciting = Math.Min(firstAckEliciting, p.TimeSent);
                lastAckEliciting = Math.Max(lastAckEliciting, p.TimeSent);
                firstPn = Math.Min(firstPn, p.Pn);
                lastPn = Math.Max(lastPn, p.Pn);
            }
            latestLost = Math.Max(latestLost, p.TimeSent);
        }
        if (latestLost == 0) return;
        OnCongestionEvent(latestLost, now);
        // Persistent congestion (7.6): ack-eliciting losses spanning the threshold, after the first RTT sample, with
        // nothing in between acknowledged (they're the oldest outstanding: nothing below them is still in flight).
        if (HasRttSample && ackElicitingLost >= 2 && firstAckEliciting > _firstRttSampleTime)
        {
            long duration = (SmoothedRtt + Math.Max(4 * RttVar, Granularity) + MaxAckDelay) * PersistentCongestionThreshold;
            bool contiguous = !(s.AckedPns.FirstFrom(firstPn, out long a, out _) && a <= lastPn);
            if (lastAckEliciting - firstAckEliciting > duration && contiguous)
            {
                PersistentCongestions++;
                Cwnd = MinWindow;
                _recoveryStart = -1;
                _epochStart = -1;
                _wMax = _wLastMax = 0;
            }
        }
    }

    private void OnCongestionEvent(long sentTime, long now)
    {
        if (sentTime <= _recoveryStart) return; // already in recovery for this
        CongestionEvents++;
        _recoveryStart = now;
        if (Algorithm == CongestionControl.Cubic)
        {
            // Fast convergence: below the last maximum, let go of more (RFC 9438 4.7).
            _wMax = Cwnd < _wLastMax ? Cwnd * (1 + CubicBeta) / 2 : Cwnd;
            _wLastMax = Cwnd;
            _epochStart = -1;
            Ssthresh = Math.Max((long)(Cwnd * CubicBeta), MinWindow);
        }
        else Ssthresh = Math.Max(Cwnd / 2, MinWindow);
        Cwnd = Ssthresh;
    }

    /// <summary>A new path (RFC 9000 9.4): congestion control and the RTT estimate start over; what's in flight stays counted.</summary>
    public void ResetForNewPath()
    {
        Cwnd = InitialWindow;
        Ssthresh = long.MaxValue;
        _epochStart = -1;
        _wMax = _wLastMax = 0;
        _recoveryStart = -1;
        HasRttSample = false;
        LatestRtt = MinRtt = 0;
        SmoothedRtt = InitialRtt;
        RttVar = InitialRtt / 2;
        PtoCount = 0;
    }

    /// <summary>Forget a space whose keys are discarded (RFC 9002 6.4): its packets no longer count in flight.</summary>
    public void Discard(int space)
    {
        var s = Spaces[space];
        foreach (var p in s.Sent.All())
            if (p.InFlight) BytesInFlight -= p.Size;
        s.Sent.Clear();
        s.LossTime = 0;
        s.AckElicitingInFlight = 0;
        s.Discarded = true;
        PtoCount = 0;
    }

    /// <summary>
    /// When the loss-detection timer fires, and for which space (RFC 9002 A.8): the earliest loss time, else the
    /// probe timeout. 0: no timer. <paramref name="amplificationBlocked"/>: a server that may not send anyway.
    /// <paramref name="peerValidatedUs"/>: our address is validated, or we're the server (no anti-deadlock probe).
    /// </summary>
    public long Deadline(bool handshakeConfirmed, bool amplificationBlocked, bool peerValidatedUs, out int space, out bool pto)
    {
        space = -1;
        pto = false;
        long earliest = 0;
        for (int i = 0; i < 3; i++)
        {
            var s = Spaces[i];
            if (s.LossTime != 0 && (earliest == 0 || s.LossTime < earliest))
            {
                earliest = s.LossTime;
                space = i;
            }
        }
        if (earliest != 0) return earliest;
        if (amplificationBlocked) return 0;
        pto = true;
        long duration = (SmoothedRtt + Math.Max(4 * RttVar, Granularity)) << Math.Min(PtoCount, 16);
        bool anyInFlight = Spaces[0].AckElicitingInFlight + Spaces[1].AckElicitingInFlight + Spaces[2].AckElicitingInFlight > 0;
        if (!anyInFlight)
        {
            if (peerValidatedUs) return 0;
            // A client's anti-deadlock probe: Handshake if it has keys for it, else Initial (the caller decides).
            space = Spaces[0].Discarded ? 1 : 0;
            return LastSendTime + duration;
        }
        for (int i = 0; i < 3; i++)
        {
            var s = Spaces[i];
            if (s.AckElicitingInFlight == 0) continue;
            long d = duration;
            if (i == 2)
            {
                if (!handshakeConfirmed) break; // no application-data probes before the handshake is confirmed
                d += MaxAckDelay << Math.Min(PtoCount, 16);
            }
            long t = s.LastAckElicitingSent + d;
            if (earliest == 0 || t < earliest)
            {
                earliest = t;
                space = i;
            }
        }
        return earliest;
    }

    /// <summary>When we last sent anything ack-eliciting (the anti-deadlock probe counts from it).</summary>
    public long LastSendTime => Math.Max(Spaces[0].LastAckElicitingSent, Math.Max(Spaces[1].LastAckElicitingSent, Spaces[2].LastAckElicitingSent));

    // Pacing (RFC 9002 7.7): a token bucket filled at N × cwnd / smoothed RTT, holding at most the initial window,
    // so a large window doesn't go out as one burst. N is 2 in slow start and 1.25 after.
    private double _tokens = -1;
    private long _tokensAt;

    /// <summary>When a packet of <paramref name="size"/> may go out: now or later (the caller waits until then).</summary>
    public long PacedAt(long now, int size)
    {
        Refill(now);
        if (_tokens >= size) return now;
        double rate = PacingRate;
        return now + (long)Math.Ceiling((size - _tokens) / rate);
    }

    public void OnPaced(long now, int size)
    {
        Refill(now);
        _tokens -= size;
    }

    /// <summary>Bytes per microsecond.</summary>
    private double PacingRate => (Cwnd < Ssthresh ? 2.0 : 1.25) * Cwnd / Math.Max(SmoothedRtt, Granularity);

    private void Refill(long now)
    {
        double cap = InitialWindow;
        if (_tokens < 0) { _tokens = cap; _tokensAt = now; return; }
        if (now > _tokensAt) _tokens = Math.Min(cap, _tokens + (now - _tokensAt) * PacingRate);
        _tokensAt = now;
    }

    /// <summary>The probe timeout without backoff, for the closing and draining periods (3 × PTO).</summary>
    public long Pto => SmoothedRtt + Math.Max(4 * RttVar, Granularity) + MaxAckDelay;
}
