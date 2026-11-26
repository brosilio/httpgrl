using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Httpgrl.Quic;

/// <summary>The AEADs QUIC packets are protected with (RFC 9001 5).</summary>
public enum QuicCipher : byte
{
    Aes128Gcm,
    Aes256Gcm,
    /// <summary>For clients without AES hardware. Header protection is raw ChaCha20 (from OpenSSL, see ChaChaMask).</summary>
    ChaCha20,
}

/// <summary>
/// QUIC's key schedule (RFC 9001 5): TLS 1.3's HKDF-Expand-Label with QUIC's labels, and the Initial secrets derived
/// from the client's first destination connection ID. All cryptography is .NET's (OpenSSL underneath).
/// </summary>
internal static class QuicKeys
{
    private static ReadOnlySpan<byte> InitialSaltV1 => [0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a];

    public static HashAlgorithmName Hash(QuicCipher c) => c == QuicCipher.Aes256Gcm ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;
    public static int KeyLength(QuicCipher c) => c == QuicCipher.Aes128Gcm ? 16 : 32;
    public static int SecretLength(QuicCipher c) => c == QuicCipher.Aes256Gcm ? 48 : 32;

    /// <summary>HKDF-Expand-Label(secret, label, "", output.Length) of TLS 1.3 (RFC 8446 7.1), with no context.</summary>
    public static void ExpandLabel(HashAlgorithmName hash, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label, Span<byte> output)
    {
        // HkdfLabel: uint16 length, opaque label<7..255> = "tls13 " + label, opaque context<0..255> = "".
        Span<byte> info = stackalloc byte[2 + 1 + 6 + label.Length + 1];
        BinaryPrimitives.WriteUInt16BigEndian(info, (ushort)output.Length);
        info[2] = (byte)(6 + label.Length);
        "tls13 "u8.CopyTo(info[3..]);
        label.CopyTo(info[9..]);
        info[^1] = 0;
        HKDF.Expand(hash, secret, output, info);
    }

    /// <summary>The client's and server's Initial secrets for a connection the client opened to <paramref name="dcid"/> (RFC 9001 5.2).</summary>
    public static (byte[] Client, byte[] Server) InitialSecrets(ReadOnlySpan<byte> dcid)
    {
        Span<byte> initial = stackalloc byte[32];
        HKDF.Extract(HashAlgorithmName.SHA256, dcid, InitialSaltV1, initial);
        var client = new byte[32];
        var server = new byte[32];
        ExpandLabel(HashAlgorithmName.SHA256, initial, "client in"u8, client);
        ExpandLabel(HashAlgorithmName.SHA256, initial, "server in"u8, server);
        CryptographicOperations.ZeroMemory(initial);
        return (client, server);
    }

    /// <summary>The next generation's secret, for a key update (RFC 9001 6.1).</summary>
    public static byte[] NextSecret(QuicCipher c, ReadOnlySpan<byte> secret)
    {
        var next = new byte[SecretLength(c)];
        ExpandLabel(Hash(c), secret, "quic ku"u8, next);
        return next;
    }
}

/// <summary>
/// One direction's packet protection at one encryption level: AEAD over the payload with the packet number in the
/// nonce, and header protection over the first byte and the packet number (RFC 9001 5.3, 5.4).
/// </summary>
internal sealed class PacketKeys : IDisposable
{
    public const int TagLength = 16;
    public const int SampleLength = 16;

    private readonly AesGcm? _aead;
    private readonly ChaCha20Poly1305? _chacha;
    private readonly Aes? _hp;
    // One reusable ECB encryptor: .NET's one-shot EncryptEcb sets up a cipher context per call, which costs more than
    // the packet's AES-GCM (one 16-byte block per packet, here).
    private readonly ICryptoTransform? _hpEncryptor;
    private readonly ChaChaMask? _hpChaCha;
    private readonly byte[] _sample = new byte[SampleLength];
    private readonly byte[] _iv = new byte[12];
    private readonly byte[] _mask = new byte[SampleLength];

    public QuicCipher Cipher { get; }
    /// <summary>Packets sealed with this key, against the AEAD's confidentiality limit (RFC 9001 6.6).</summary>
    public long Sealed { get; private set; }
    /// <summary>Packets that failed to open with this key, against the integrity limit.</summary>
    public long Forged { get; private set; }

    /// <summary>AES-GCM's limits (RFC 9001 6.6): update keys before 2^23 packets; give up after 2^52 forgeries.</summary>
    public const long ConfidentialityLimit = 1L << 23, IntegrityLimit = 1L << 52;
    /// <summary>The integrity limit for this key's AEAD: ChaCha20-Poly1305's is 2^36 (its confidentiality limit is beyond reach).</summary>
    public long ForgeryLimit => Cipher == QuicCipher.ChaCha20 ? 1L << 36 : IntegrityLimit;

    public PacketKeys(QuicCipher cipher, ReadOnlySpan<byte> secret) : this(cipher, secret, null) { }

    private PacketKeys(QuicCipher cipher, ReadOnlySpan<byte> secret, byte[]? hpKey)
    {
        Cipher = cipher;
        var hash = QuicKeys.Hash(cipher);
        int keyLen = QuicKeys.KeyLength(cipher);
        Span<byte> key = stackalloc byte[keyLen];
        QuicKeys.ExpandLabel(hash, secret, "quic key"u8, key);
        QuicKeys.ExpandLabel(hash, secret, "quic iv"u8, _iv);
        if (hpKey is null)
        {
            hpKey = new byte[keyLen];
            QuicKeys.ExpandLabel(hash, secret, "quic hp"u8, hpKey);
        }
        _hpKey = hpKey;
        if (cipher == QuicCipher.ChaCha20)
        {
            _chacha = new ChaCha20Poly1305(key);
            _hpChaCha = new ChaChaMask(hpKey);
        }
        else
        {
            _aead = new AesGcm(key, TagLength);
            _hp = Aes.Create();
            _hp.Key = hpKey;
            _hp.Mode = CipherMode.ECB;
            _hp.Padding = PaddingMode.None;
            _hpEncryptor = _hp.CreateEncryptor();
        }
        CryptographicOperations.ZeroMemory(key);
    }

    private readonly byte[] _hpKey;

    /// <summary>
    /// The next generation's keys after a key update (RFC 9001 6): new AEAD key and IV from
    /// <paramref name="nextSecret"/>, the same header-protection key (it never changes).
    /// </summary>
    public PacketKeys NextGeneration(ReadOnlySpan<byte> nextSecret) => new(Cipher, nextSecret, (byte[])_hpKey.Clone());

    /// <summary>For tests: the derived IV.</summary>
    internal ReadOnlySpan<byte> Iv => _iv;

    private void Nonce(Span<byte> nonce, long pn)
    {
        _iv.CopyTo(nonce);
        Span<byte> p = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(p, pn);
        for (int i = 0; i < 8; i++) nonce[4 + i] ^= p[i];
    }

    /// <summary>The header-protection mask for a 16-byte sample.</summary>
    public void Mask(ReadOnlySpan<byte> sample, Span<byte> mask)
    {
        if (_hpChaCha is not null) { _hpChaCha.Mask(sample[..SampleLength], mask[..5]); return; }
        sample[..SampleLength].CopyTo(_sample);
        _hpEncryptor!.TransformBlock(_sample, 0, SampleLength, _mask, 0);
        _mask.AsSpan(0, 5).CopyTo(mask);
    }

    /// <summary>
    /// Protect a packet in place. <paramref name="packet"/> holds the header (packet number written in clear, in
    /// <paramref name="pnLength"/> bytes at <paramref name="pnOffset"/>) then the plaintext payload, then 16 spare
    /// bytes for the tag. Afterwards it's the packet as sent.
    /// </summary>
    public void Seal(Span<byte> packet, int pnOffset, int pnLength, long pn)
    {
        int headerLen = pnOffset + pnLength;
        int payloadLen = packet.Length - headerLen - TagLength;
        Span<byte> nonce = stackalloc byte[12];
        Nonce(nonce, pn);
        var payload = packet.Slice(headerLen, payloadLen);
        if (_chacha is not null) _chacha.Encrypt(nonce, payload, payload, packet.Slice(headerLen + payloadLen, TagLength), packet[..headerLen]);
        else _aead!.Encrypt(nonce, payload, payload, packet.Slice(headerLen + payloadLen, TagLength), packet[..headerLen]);
        Sealed++;

        // Header protection, sampled 4 bytes after the start of the packet number (RFC 9001 5.4.2).
        Span<byte> mask = stackalloc byte[5];
        Mask(packet.Slice(pnOffset + 4, SampleLength), mask);
        packet[0] ^= (byte)(mask[0] & ((packet[0] & 0x80) != 0 ? 0x0F : 0x1F));
        for (int i = 0; i < pnLength; i++) packet[pnOffset + i] ^= mask[1 + i];
    }

    /// <summary>
    /// Remove header protection in place, revealing the first byte's low bits and the packet number. Returns the
    /// packet number's length; the truncated number is in <paramref name="truncated"/>. The packet must be at least
    /// <paramref name="pnOffset"/> + 4 + 16 bytes (the parser guarantees it for long headers).
    /// </summary>
    public int Unmask(Span<byte> packet, int pnOffset, out ulong truncated)
    {
        Span<byte> mask = stackalloc byte[5];
        Mask(packet.Slice(pnOffset + 4, SampleLength), mask);
        packet[0] ^= (byte)(mask[0] & ((packet[0] & 0x80) != 0 ? 0x0F : 0x1F));
        int pnLength = (packet[0] & 0x03) + 1;
        truncated = 0;
        for (int i = 0; i < pnLength; i++)
        {
            packet[pnOffset + i] ^= mask[1 + i];
            truncated = truncated << 8 | packet[pnOffset + i];
        }
        return pnLength;
    }

    /// <summary>
    /// Decrypt a payload in place (after <see cref="Unmask"/>): the header is <paramref name="packet"/>[..headerLength],
    /// the ciphertext and tag the rest. False if it doesn't authenticate (drop the packet, RFC 9001 5.5).
    /// </summary>
    public bool Open(Span<byte> packet, int headerLength, long pn)
    {
        int ctLen = packet.Length - headerLength - TagLength;
        if (ctLen < 0) return false;
        Span<byte> nonce = stackalloc byte[12];
        Nonce(nonce, pn);
        var ct = packet.Slice(headerLength, ctLen);
        try
        {
            if (_chacha is not null) _chacha.Decrypt(nonce, ct, packet.Slice(headerLength + ctLen, TagLength), ct, packet[..headerLength]);
            else _aead!.Decrypt(nonce, ct, packet.Slice(headerLength + ctLen, TagLength), ct, packet[..headerLength]);
            return true;
        }
        catch (AuthenticationTagMismatchException)
        {
            Forged++;
            return false;
        }
    }

    public void Dispose()
    {
        _aead?.Dispose();
        _chacha?.Dispose();
        _hpEncryptor?.Dispose();
        _hp?.Dispose();
        _hpChaCha?.Dispose();
        CryptographicOperations.ZeroMemory(_iv);
        CryptographicOperations.ZeroMemory(_hpKey);
    }
}

/// <summary>The Retry integrity tag (RFC 9001 5.8): AES-128-GCM under a fixed key over the Retry pseudo-packet.</summary>
internal static class RetryIntegrity
{
    private static ReadOnlySpan<byte> Key => [0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e];
    private static ReadOnlySpan<byte> Nonce => [0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb];

    /// <summary>The tag for <paramref name="retry"/> (the packet without its tag), sent to a client that used <paramref name="originalDcid"/>.</summary>
    public static void Tag(ReadOnlySpan<byte> retry, ReadOnlySpan<byte> originalDcid, Span<byte> tag)
    {
        Span<byte> pseudo = stackalloc byte[1 + originalDcid.Length + retry.Length];
        pseudo[0] = (byte)originalDcid.Length;
        originalDcid.CopyTo(pseudo[1..]);
        retry.CopyTo(pseudo[(1 + originalDcid.Length)..]);
        using var gcm = new AesGcm(Key, PacketKeys.TagLength);
        gcm.Encrypt(Nonce, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag, pseudo);
    }

    /// <summary>Whether a whole Retry packet (tag last) is genuine for <paramref name="originalDcid"/> (a client's check).</summary>
    public static bool Verify(ReadOnlySpan<byte> packet, ReadOnlySpan<byte> originalDcid)
    {
        if (packet.Length < PacketKeys.TagLength + 7) return false;
        Span<byte> tag = stackalloc byte[PacketKeys.TagLength];
        Tag(packet[..^PacketKeys.TagLength], originalDcid, tag);
        return CryptographicOperations.FixedTimeEquals(tag, packet[^PacketKeys.TagLength..]);
    }
}
