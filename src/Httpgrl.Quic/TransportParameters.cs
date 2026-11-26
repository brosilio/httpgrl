namespace Httpgrl.Quic;

/// <summary>
/// QUIC transport parameters (RFC 9000 18, RFC 9221 3), carried in the TLS handshake. Parsing is strict: a duplicate,
/// a value out of range, or a parameter the sender's role mayn't send is a TRANSPORT_PARAMETER_ERROR. Unknown
/// parameters are ignored (that's how the extension point and greasing work).
/// </summary>
internal sealed class TransportParameters
{
    public const ulong OriginalDcidId = 0x00, MaxIdleTimeoutId = 0x01, StatelessResetTokenId = 0x02, MaxUdpPayloadSizeId = 0x03,
        InitialMaxDataId = 0x04, InitialMaxStreamDataBidiLocalId = 0x05, InitialMaxStreamDataBidiRemoteId = 0x06,
        InitialMaxStreamDataUniId = 0x07, InitialMaxStreamsBidiId = 0x08, InitialMaxStreamsUniId = 0x09,
        AckDelayExponentId = 0x0a, MaxAckDelayId = 0x0b, DisableActiveMigrationId = 0x0c, PreferredAddressId = 0x0d,
        ActiveConnectionIdLimitId = 0x0e, InitialScidId = 0x0f, RetryScidId = 0x10, MaxDatagramFrameSizeId = 0x20;

    public byte[]? OriginalDcid;
    public ulong MaxIdleTimeoutMs;
    public byte[]? StatelessResetToken;
    public ulong MaxUdpPayloadSize = 65527;
    public ulong InitialMaxData;
    public ulong InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote, InitialMaxStreamDataUni;
    public ulong InitialMaxStreamsBidi, InitialMaxStreamsUni;
    public ulong AckDelayExponent = 3;
    public ulong MaxAckDelayMs = 25;
    public bool DisableActiveMigration;
    /// <summary>A server's preferred address, kept raw: we neither send one nor migrate to one.</summary>
    public byte[]? PreferredAddress;
    public ulong ActiveConnectionIdLimit = 2;
    public byte[]? InitialScid;
    public byte[]? RetryScid;
    /// <summary>0 = DATAGRAM frames not supported by the sender (RFC 9221 3).</summary>
    public ulong MaxDatagramFrameSize;

    /// <summary>Parse the peer's parameters. <paramref name="fromServer"/>: who sent them (servers may send more).</summary>
    public static TransportParameters Parse(ReadOnlySpan<byte> data, bool fromServer)
    {
        var tp = new TransportParameters();
        var r = new QuicReader(data, QuicError.TransportParameterError);
        ulong seen = 0; // the known parameters (all below 64) we've had
        while (!r.End)
        {
            ulong id = r.VarInt();
            int len = r.Length(r.Remaining);
            var v = r.Bytes(len);
            if (id < 64)
            {
                if ((seen & 1UL << (int)id) != 0) throw Error("duplicate transport parameter");
                seen |= 1UL << (int)id;
            }
            switch (id)
            {
                case OriginalDcidId: ServerOnly(fromServer); tp.OriginalDcid = Cid(v); break;
                case MaxIdleTimeoutId: tp.MaxIdleTimeoutMs = Int(v); break;
                case StatelessResetTokenId:
                    ServerOnly(fromServer);
                    if (v.Length != 16) throw Error("stateless_reset_token length");
                    tp.StatelessResetToken = v.ToArray();
                    break;
                case MaxUdpPayloadSizeId:
                    tp.MaxUdpPayloadSize = Int(v);
                    if (tp.MaxUdpPayloadSize < 1200) throw Error("max_udp_payload_size below 1200");
                    break;
                case InitialMaxDataId: tp.InitialMaxData = Int(v); break;
                case InitialMaxStreamDataBidiLocalId: tp.InitialMaxStreamDataBidiLocal = Int(v); break;
                case InitialMaxStreamDataBidiRemoteId: tp.InitialMaxStreamDataBidiRemote = Int(v); break;
                case InitialMaxStreamDataUniId: tp.InitialMaxStreamDataUni = Int(v); break;
                case InitialMaxStreamsBidiId:
                    tp.InitialMaxStreamsBidi = Int(v);
                    if (tp.InitialMaxStreamsBidi > 1UL << 60) throw Error("initial_max_streams_bidi beyond 2^60");
                    break;
                case InitialMaxStreamsUniId:
                    tp.InitialMaxStreamsUni = Int(v);
                    if (tp.InitialMaxStreamsUni > 1UL << 60) throw Error("initial_max_streams_uni beyond 2^60");
                    break;
                case AckDelayExponentId:
                    tp.AckDelayExponent = Int(v);
                    if (tp.AckDelayExponent > 20) throw Error("ack_delay_exponent above 20");
                    break;
                case MaxAckDelayId:
                    tp.MaxAckDelayMs = Int(v);
                    if (tp.MaxAckDelayMs >= 1 << 14) throw Error("max_ack_delay of 2^14 or more");
                    break;
                case DisableActiveMigrationId:
                    if (v.Length != 0) throw Error("disable_active_migration with a value");
                    tp.DisableActiveMigration = true;
                    break;
                case PreferredAddressId:
                    ServerOnly(fromServer);
                    tp.PreferredAddress = v.ToArray();
                    break;
                case ActiveConnectionIdLimitId:
                    tp.ActiveConnectionIdLimit = Int(v);
                    if (tp.ActiveConnectionIdLimit < 2) throw Error("active_connection_id_limit below 2");
                    break;
                case InitialScidId: tp.InitialScid = Cid(v); break;
                case RetryScidId: ServerOnly(fromServer); tp.RetryScid = Cid(v); break;
                case MaxDatagramFrameSizeId: tp.MaxDatagramFrameSize = Int(v); break;
            }
        }
        // Every endpoint states the connection ID it chose (RFC 9000 7.3).
        if (tp.InitialScid is null) throw Error("initial_source_connection_id missing");
        if (fromServer && tp.OriginalDcid is null) throw Error("original_destination_connection_id missing");
        return tp;
    }

    private static QuicException Error(string why) => new(QuicError.TransportParameterError, why);

    private static void ServerOnly(bool fromServer)
    {
        if (!fromServer) throw Error("a server-only transport parameter from a client");
    }

    private static ulong Int(ReadOnlySpan<byte> v)
    {
        if (!VarInt.TryRead(v, out ulong x, out int n) || n != v.Length) throw Error("malformed integer parameter");
        return x;
    }

    private static byte[] Cid(ReadOnlySpan<byte> v)
    {
        if (v.Length > Packets.MaxCidLength) throw Error("connection ID too long");
        return v.ToArray();
    }

    /// <summary>Encode ours. Defaults are omitted, as are client-only absences; the bytes written.</summary>
    public int Write(Span<byte> d)
    {
        int p = 0;
        void Bytes(ulong id, ReadOnlySpan<byte> v, Span<byte> d)
        {
            p += VarInt.Write(d[p..], id);
            p += VarInt.Write(d[p..], (ulong)v.Length);
            v.CopyTo(d[p..]);
            p += v.Length;
        }
        void Int(ulong id, ulong v, Span<byte> d)
        {
            p += VarInt.Write(d[p..], id);
            p += VarInt.Write(d[p..], (ulong)VarInt.Size(v));
            p += VarInt.Write(d[p..], v);
        }
        if (OriginalDcid is not null) Bytes(OriginalDcidId, OriginalDcid, d);
        if (MaxIdleTimeoutMs != 0) Int(MaxIdleTimeoutId, MaxIdleTimeoutMs, d);
        if (StatelessResetToken is not null) Bytes(StatelessResetTokenId, StatelessResetToken, d);
        if (MaxUdpPayloadSize != 65527) Int(MaxUdpPayloadSizeId, MaxUdpPayloadSize, d);
        if (InitialMaxData != 0) Int(InitialMaxDataId, InitialMaxData, d);
        if (InitialMaxStreamDataBidiLocal != 0) Int(InitialMaxStreamDataBidiLocalId, InitialMaxStreamDataBidiLocal, d);
        if (InitialMaxStreamDataBidiRemote != 0) Int(InitialMaxStreamDataBidiRemoteId, InitialMaxStreamDataBidiRemote, d);
        if (InitialMaxStreamDataUni != 0) Int(InitialMaxStreamDataUniId, InitialMaxStreamDataUni, d);
        if (InitialMaxStreamsBidi != 0) Int(InitialMaxStreamsBidiId, InitialMaxStreamsBidi, d);
        if (InitialMaxStreamsUni != 0) Int(InitialMaxStreamsUniId, InitialMaxStreamsUni, d);
        if (AckDelayExponent != 3) Int(AckDelayExponentId, AckDelayExponent, d);
        if (MaxAckDelayMs != 25) Int(MaxAckDelayId, MaxAckDelayMs, d);
        if (DisableActiveMigration) Bytes(DisableActiveMigrationId, default, d);
        if (ActiveConnectionIdLimit != 2) Int(ActiveConnectionIdLimitId, ActiveConnectionIdLimit, d);
        if (InitialScid is not null) Bytes(InitialScidId, InitialScid, d);
        if (RetryScid is not null) Bytes(RetryScidId, RetryScid, d);
        if (MaxDatagramFrameSize != 0) Int(MaxDatagramFrameSizeId, MaxDatagramFrameSize, d);
        return p;
    }

    public byte[] ToArray()
    {
        Span<byte> buf = stackalloc byte[512];
        int n = Write(buf);
        return buf[..n].ToArray();
    }
}
