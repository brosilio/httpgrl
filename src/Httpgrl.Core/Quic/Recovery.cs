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

internal sealed class SentPacket
{
    public long Pn;
    public long TimeSent;
    public int Size;
    public bool AckEliciting, InFlight;
    public readonly List<SentFrame> Frames = new(4);

    public void Reset()
    {
        Frames.Clear();
        AckEliciting = InFlight = false;
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
        /// <summary>Unacknowledged packets, ascending packet number.</summary>
        public readonly List<SentPacket> Sent = new();
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

    public Recovery(int maxDatagramSize = 1200)
    {
        MaxDatagramSize = maxDatagramSize;
        Cwnd = Math.Min(10L * maxDatagramSize, Math.Max(14720, 2L * maxDatagramSize));
    }

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

        // Collect newly acknowledged packets: walk both lists from the top.
        int start = acked.Count;
        int r = 0;
        for (int i = s.Sent.Count - 1; i >= 0 && r < ranges.Count; i--)
        {
            var p = s.Sent[i];
            while (r < ranges.Count && p.Pn < ranges[r].Smallest) r++;
            if (r < ranges.Count && p.Pn <= ranges[r].Largest)
            {
                acked.Add(p);
                s.Sent.RemoveAt(i);
            }
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
        for (int i = start; i < acked.Count; i++) OnAcked(s, acked[i]);
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

    private void OnAcked(Space s, SentPacket p)
    {
        if (!p.InFlight) return;
        if (p.AckEliciting) s.AckElicitingInFlight--;
        BytesInFlight -= p.Size;
        // No growth for packets sent before the current recovery period began.
        if (p.TimeSent <= _recoveryStart) return;
        if (Cwnd < Ssthresh) Cwnd += p.Size;
        else Cwnd += (long)MaxDatagramSize * p.Size / Cwnd;
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
        for (int i = 0; i < s.Sent.Count; i++)
        {
            var p = s.Sent[i];
            if (p.Pn > s.LargestAcked) break;
            if (p.TimeSent <= lostSendTime || s.LargestAcked >= p.Pn + PacketThreshold)
            {
                lost.Add(p);
                s.Sent.RemoveAt(i);
                i--;
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
            }
        }
    }

    private void OnCongestionEvent(long sentTime, long now)
    {
        if (sentTime <= _recoveryStart) return; // already in recovery for this
        CongestionEvents++;
        _recoveryStart = now;
        Ssthresh = Math.Max(Cwnd / 2, MinWindow);
        Cwnd = Ssthresh;
    }

    /// <summary>A new path (RFC 9000 9.4): congestion control and the RTT estimate start over; what's in flight stays counted.</summary>
    public void ResetForNewPath()
    {
        Cwnd = Math.Min(10L * MaxDatagramSize, Math.Max(14720, 2L * MaxDatagramSize));
        Ssthresh = long.MaxValue;
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
        foreach (var p in s.Sent)
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

    /// <summary>The probe timeout without backoff, for the closing and draining periods (3 × PTO).</summary>
    public long Pto => SmoothedRtt + Math.Max(4 * RttVar, Granularity) + MaxAckDelay;
}
