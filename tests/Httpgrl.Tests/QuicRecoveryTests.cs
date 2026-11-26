using Httpgrl.Quic;

namespace Httpgrl.Tests;

/// <summary>QUIC's bookkeeping: range sets, send/receive buffers, and RFC 9002 loss detection and congestion control.</summary>
internal static class QuicRecoveryTests
{
    private static string S(RangeSet r)
    {
        var parts = new List<string>();
        for (int i = 0; i < r.Count; i++) parts.Add($"[{r[i].Start},{r[i].End})");
        return string.Join(" ", parts);
    }

    private static SentPacket P(long pn, long t, int size = 1200, bool ackEliciting = true) =>
        new() { Pn = pn, TimeSent = t, Size = size, AckEliciting = ackEliciting, InFlight = true };

    public static void Register()
    {
        T.Add("quic ranges: merging, splitting, trimming", () =>
        {
            var r = new RangeSet();
            T.True(r.Add(10, 20));
            T.True(r.Add(30, 40));
            T.True(r.Add(0, 5));
            T.True(!r.Add(12, 18));
            T.Eq("[0,5) [10,20) [30,40)", S(r));
            T.True(r.Add(5, 10)); // adjacent ranges merge
            T.Eq("[0,20) [30,40)", S(r));
            T.True(r.Add(15, 35));
            T.Eq("[0,40)", S(r));
            r.Remove(10, 12);
            T.Eq("[0,10) [12,40)", S(r));
            T.True(r.Contains(9) && !r.Contains(10) && !r.Contains(11) && r.Contains(12) && !r.Contains(40));
            T.Eq(10L, r.RunFrom(0));
            T.Eq(11L, r.RunFrom(11));
            r.RemoveBelow(15);
            T.Eq("[15,40)", S(r));
            r.Add(50, 51); r.Add(60, 61); r.Add(70, 71);
            r.KeepHighest(2);
            T.Eq("[60,61) [70,71)", S(r));
            T.True(r.FirstFrom(62, out long a, out long b) && a == 70 && b == 71);
        });

        T.Add("quic send buffer: flow-control limits, lost data first, acknowledged prefix released, FIN carried and resent", () =>
        {
            var sb = new SendBuffer();
            var data = new byte[10_000];
            for (int i = 0; i < data.Length; i++) data[i] = (byte)i;
            sb.Write(data);
            T.True(sb.Next(1000, 2500, out long off, out var chunk, out bool fin) && off == 0 && chunk.Length == 1000 && !fin);
            sb.OnSent(0, 1000, false);
            T.True(sb.Next(1000, 2500, out off, out chunk, out _) && off == 1000 && chunk.Length == 1000);
            sb.OnSent(1000, 1000, false);
            T.True(sb.Next(1000, 2500, out off, out chunk, out _) && off == 2000 && chunk.Length == 500); // the limit
            sb.OnSent(2000, 500, false);
            T.True(!sb.Next(1000, 2500, out _, out _, out _));
            // The middle chunk is lost, the first acknowledged: the loss goes first, and the acked prefix is freed.
            sb.OnLost(1000, 1000, false);
            sb.OnAcked(0, 1000, false);
            T.Eq(1000L, sb.Acked);
            T.True(sb.Next(600, 2500, out off, out chunk, out _) && off == 1000 && chunk.Length == 600 && chunk[0] == data[1000]);
            sb.OnSent(1000, 600, false);
            T.True(sb.Next(600, 2500, out off, out chunk, out _) && off == 1600 && chunk.Length == 400);
            sb.OnSent(1600, 400, false);
            sb.OnAcked(2000, 500, false);
            sb.OnAcked(1000, 1000, false);
            T.Eq(2500L, sb.Acked);
            // Finish: the last chunk carries the FIN; if it's lost, the FIN comes back with it.
            sb.Finish();
            T.True(sb.Next(10_000, 20_000, out off, out chunk, out fin) && off == 2500 && chunk.Length == 7500 && fin);
            sb.OnSent(2500, 7500, true);
            T.True(!sb.HasData(20_000));
            sb.OnLost(2500, 7500, true);
            T.True(sb.Next(10_000, 20_000, out off, out chunk, out fin) && off == 2500 && chunk.Length == 7500 && fin);
            sb.OnSent(2500, 7500, true);
            sb.OnAcked(2500, 7500, true);
            T.True(sb.AllAcked);
            // A FIN on its own, after all the data went out.
            var empty = new SendBuffer();
            empty.Write([1, 2, 3]);
            T.True(empty.Next(100, 100, out _, out _, out fin) && !fin);
            empty.OnSent(0, 3, false);
            empty.Finish();
            T.True(empty.Next(100, 100, out off, out chunk, out fin) && off == 3 && chunk.IsEmpty && fin);
        });

        T.Add("quic receive buffer: reassembly, limits, and final-size rules", () =>
        {
            var rb = new RecvBuffer();
            T.True(rb.Write(5, "fgh"u8, false, 100, QuicFrameType.Stream));
            T.Eq(0, rb.Readable);
            T.True(rb.Write(0, "abcde"u8, false, 100, QuicFrameType.Stream));
            T.Eq(8, rb.Readable);
            rb.Write(3, "defgh"u8, false, 100, QuicFrameType.Stream); // an overlapping retransmission changes nothing
            var buf = new byte[16];
            int n = rb.Read(buf);
            T.Eq(8, n);
            T.Eq("abcdefgh", System.Text.Encoding.ASCII.GetString(buf, 0, n));
            T.True(!rb.Write(0, "abc"u8, false, 100, QuicFrameType.Stream)); // all old
            T.True(rb.Write(8, "ij"u8, true, 100, QuicFrameType.Stream));
            T.Eq(10L, rb.FinalSize);
            rb.Read(buf);
            T.True(rb.Complete);

            QuicError Fails(Action a)
            {
                try { a(); } catch (QuicException e) { return e.Code; }
                throw new Exception("accepted");
            }
            var f = new RecvBuffer();
            f.Write(0, "abcd"u8, true, 100, QuicFrameType.Stream);
            T.Eq(QuicError.FinalSizeError, Fails(() => f.Write(2, "cdef"u8, false, 100, QuicFrameType.Stream))); // beyond the final size
            T.Eq(QuicError.FinalSizeError, Fails(() => f.Write(0, "ab"u8, true, 100, QuicFrameType.Stream))); // a different final size
            T.Eq(QuicError.FinalSizeError, Fails(() => f.SetFinalSize(5, QuicFrameType.ResetStream)));
            var g = new RecvBuffer();
            g.Write(0, "abcdef"u8, false, 100, QuicFrameType.Stream);
            T.Eq(QuicError.FinalSizeError, Fails(() => g.Write(0, "abc"u8, true, 100, QuicFrameType.Stream))); // final size below what arrived
            T.Eq(QuicError.FlowControlError, Fails(() => g.Write(98, "abc"u8, false, 100, QuicFrameType.Stream)));
            T.Eq(QuicError.CryptoBufferExceeded, Fails(() => new RecvBuffer().Write(90, new byte[20], false, 100, QuicFrameType.Crypto)));
        });

        T.Add("quic recovery: RTT estimation (RFC 9002 5) and ack delay applied only to application data", () =>
        {
            var r = new Recovery();
            var acked = new List<SentPacket>();
            var lost = new List<SentPacket>();
            r.OnPacketSent(0, P(0, 0));
            T.True(r.OnAck(0, [(0, 0)], 0, 100_000, false, acked, lost));
            T.Eq(100_000L, r.SmoothedRtt);
            T.Eq(50_000L, r.RttVar);
            T.Eq(100_000L, r.MinRtt);
            // A second sample of 200 ms with 50 ms of ack delay in application data: capped at the peer's
            // max_ack_delay (25 ms), so adjusted to 175 ms; then with a larger max_ack_delay, the whole 50 ms.
            r.OnPacketSent(2, P(0, 1_000_000));
            T.True(r.OnAck(2, [(0, 0)], 50_000, 1_200_000, true, acked, lost));
            T.Eq(200_000L, r.LatestRtt);
            T.Eq((7 * 100_000L + 175_000) / 8, r.SmoothedRtt);
            long srtt = r.SmoothedRtt, rttvar = r.RttVar;
            r.MaxAckDelay = 100_000;
            r.OnPacketSent(2, P(1, 2_000_000));
            T.True(r.OnAck(2, [(1, 1)], 50_000, 2_200_000, true, acked, lost));
            T.Eq((7 * srtt + 150_000) / 8, r.SmoothedRtt);
            T.Eq((3 * rttvar + Math.Abs(srtt - 150_000)) / 4, r.RttVar);
            // ACKing a packet never sent is refused.
            T.True(!r.OnAck(2, [(5, 5)], 0, 1_300_000, true, acked, lost));
        });

        T.Add("quic recovery: packet- and time-threshold loss, one congestion event per recovery period, PTO backoff", () =>
        {
            var r = new Recovery(1200, CongestionControl.NewReno);
            var acked = new List<SentPacket>();
            var lost = new List<SentPacket>();
            long cwnd0 = r.Cwnd;
            T.Eq(12_000L, cwnd0); // min(10 × 1200, max(14720, 2400))
            for (int pn = 0; pn < 6; pn++) r.OnPacketSent(2, P(pn, pn * 1000));
            T.Eq(7200L, r.BytesInFlight);
            // 4 and 5 acknowledged: 0, 1 and 2 are 3 or more below the largest, lost at once; 3 waits for the time threshold.
            T.True(r.OnAck(2, [(4, 5)], 0, 50_000, true, acked, lost));
            T.Eq("0 1 2", string.Join(" ", lost.Select(p => p.Pn)));
            T.Eq(1L, r.CongestionEvents);
            T.Eq(cwnd0 / 2, r.Cwnd);
            T.True(r.Spaces[2].LossTime > 50_000);
            long loss = r.Deadline(true, false, true, out int space, out bool pto);
            T.True(!pto && space == 2 && loss == r.Spaces[2].LossTime);
            lost.Clear();
            r.DetectLost(2, loss, lost);
            T.Eq("3", string.Join(" ", lost.Select(p => p.Pn)));
            T.Eq(1L, r.CongestionEvents); // sent before the recovery period began: no second reduction
            T.Eq(0L, r.BytesInFlight);

            // PTO: with nothing lost-pending, the timer is the probe timeout, doubling with each one fired.
            r.OnPacketSent(2, P(6, 100_000));
            long t1 = r.Deadline(true, false, true, out space, out pto);
            T.True(pto && space == 2);
            r.PtoCount = 1;
            long t2 = r.Deadline(true, false, true, out _, out _);
            T.True(t2 - 100_000 > 2 * (t1 - 100_000) - 30_000);
            // Application-data probes wait for the handshake to be confirmed; an amplification-blocked server has no timer.
            T.Eq(0L, r.Deadline(false, false, true, out _, out _));
            T.Eq(0L, r.Deadline(true, true, true, out _, out _));
        });

        T.Add("quic cubic: 0.7x on loss with fast convergence; the cubic curve regains the old maximum near K; no growth when app-limited", () =>
        {
            var r = new Recovery(1200, CongestionControl.Cubic);
            var acked = new List<SentPacket>();
            var lost = new List<SentPacket>();
            long now = 0, pn = 0;
            // Get an RTT sample of 100 ms and leave slow start with a loss at a 120-packet window.
            r.Cwnd = 144_000;
            r.Ssthresh = 144_000;
            void Round(int packets)
            {
                long sent = now;
                long first = pn;
                for (int i = 0; i < packets; i++) r.OnPacketSent(2, P(pn++, sent));
                now += 100_000;
                acked.Clear();
                r.OnAck(2, [(first, pn - 1)], 0, now, true, acked, lost);
            }
            Round(1);
            // A loss: pn 0..3 sent, 3 acknowledged later than... use the packet threshold.
            for (int i = 0; i < 4; i++) r.OnPacketSent(2, P(pn++, now));
            now += 100_000;
            lost.Clear();
            r.OnAck(2, [(pn - 1, pn - 1)], 0, now, true, acked, lost);
            T.Eq(1L, r.CongestionEvents);
            T.Eq((long)(144_000 * 0.7), r.Cwnd);
            // A second loss below the previous maximum (in a new recovery period): fast convergence lowers the target further.
            long w1 = r.Cwnd;
            now += 1_000;
            for (int i = 0; i < 4; i++) r.OnPacketSent(2, P(pn++, now));
            now += 100_000;
            r.OnAck(2, [(pn - 1, pn - 1)], 0, now, true, acked, lost);
            T.Eq(2L, r.CongestionEvents);
            T.Eq((long)(w1 * 0.7), r.Cwnd);
            // Congestion avoidance with the window full every RTT: concave growth back toward the maximum
            // (w1 * 1.7 / 2 after fast convergence), reached around K = cbrt(Wmax(1 - beta)/C) seconds.
            double wMax = w1 * (1 + 0.7) / 2;
            double k = Math.Cbrt(wMax * 0.3 / 1200 / 0.4);
            long start = now;
            long atK = 0;
            while (now - start < (long)(k * 1e6) + 200_000)
            {
                Round((int)(r.Cwnd / 1200));
                if (atK == 0 && now - start >= (long)(k * 1e6)) atK = r.Cwnd;
            }
            T.True(Math.Abs(atK - wMax) < wMax * 0.15);

            // App-limited: a window barely used never grows.
            var a = new Recovery(1200, CongestionControl.Cubic);
            long w0 = a.Cwnd;
            long t = 0;
            for (int i = 0; i < 50; i++)
            {
                a.OnPacketSent(2, P(i, t));
                t += 50_000;
                a.OnAck(2, [(i, i)], 0, t, true, acked, lost);
            }
            T.Eq(w0, a.Cwnd);
        });

        T.Add("quic recovery: persistent congestion collapses the window; discarding a space forgets its packets", () =>
        {
            var r = new Recovery();
            var acked = new List<SentPacket>();
            var lost = new List<SentPacket>();
            r.OnPacketSent(2, P(0, 0));
            r.OnAck(2, [(0, 0)], 0, 10_000, true, acked, lost); // RTT 10 ms
            // Packets 1..4 sent over 2 s, all lost; 5 acknowledged long after.
            for (int pn = 1; pn <= 4; pn++) r.OnPacketSent(2, P(pn, 20_000 + pn * 500_000));
            r.OnPacketSent(2, P(5, 2_100_000));
            r.OnAck(2, [(5, 5)], 0, 2_120_000, true, acked, lost);
            T.Eq(4, lost.Count);
            T.Eq(1L, r.PersistentCongestions);
            T.Eq(r.MinWindow + 1200, r.Cwnd); // collapsed to the minimum, then grown by the packet this ACK acknowledged

            var d = new Recovery();
            d.OnPacketSent(0, P(0, 0));
            d.OnPacketSent(0, P(1, 0));
            T.Eq(2400L, d.BytesInFlight);
            d.Discard(0);
            T.Eq(0L, d.BytesInFlight);
            T.Eq(0, d.Spaces[0].Sent.Count);
        });
    }
}
