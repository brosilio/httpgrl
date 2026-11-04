using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace Httpgrl.Core.Quic;

/// <summary>QUIC encryption levels, numbered as OpenSSL's protection levels (OSSL_RECORD_PROTECTION_LEVEL_*).</summary>
internal enum QuicLevel : byte
{
    Initial = 0,
    ZeroRtt = 1,
    Handshake = 2,
    OneRtt = 3,
}

/// <summary>What a <see cref="QuicTls"/> asks of its connection. Called synchronously, from inside <see cref="QuicTls.Advance"/>.</summary>
internal interface IQuicTlsHost
{
    /// <summary>Handshake bytes to send in CRYPTO frames at <paramref name="level"/>.</summary>
    void OnCryptoData(QuicLevel level, ReadOnlySpan<byte> data);
    /// <summary>A new secret: for sending (<paramref name="write"/>) or receiving packets at <paramref name="level"/>.</summary>
    void OnSecret(QuicLevel level, bool write, QuicCipher cipher, ReadOnlySpan<byte> secret);
    /// <summary>
    /// The peer's transport parameters (raw). A server returns its own, to go in its reply; a client returns null
    /// (it sent its own up front). Throw a <see cref="QuicException"/> to refuse them.
    /// </summary>
    byte[]? OnPeerTransportParameters(ReadOnlySpan<byte> raw);
}

/// <summary>
/// The TLS 1.3 handshake for QUIC, run by the system OpenSSL through its third-party QUIC TLS API (OpenSSL 3.5,
/// SSL_set_quic_tls_cbs). OpenSSL does the handshake and certificate work; we move CRYPTO bytes and receive the
/// traffic secrets. All of HTTP/3's native interop is in this file.
///
/// A connection's QuicTls is used by one thread at a time (the connection's), and OpenSSL calls back only from inside
/// our calls to it, on that thread. Buffers OpenSSL may read later (records, transport parameters) live in native
/// memory we own until it's done with them.
/// </summary>
internal sealed unsafe partial class QuicTls : IDisposable
{
    private const string LibSsl = "libssl.so.3", LibCrypto = "libcrypto.so.3";

    // OSSL_FUNC_SSL_QUIC_TLS_* (core_dispatch.h).
    private const int CryptoSendId = 2001, CryptoRecvRcdId = 2002, CryptoReleaseRcdId = 2003, YieldSecretId = 2004, GotTransportParamsId = 2005, AlertId = 2006;
    private const int SslErrorWantRead = 2, SslErrorZeroReturn = 6;
    private const int SslCtrlSetTlsextServernameCb = 53, SslCtrlSetTlsextHostname = 55;
    private const int TlsextErrOk = 0, TlsextErrAlertFatal = 2, TlsextErrNoAck = 3;
    private const int AlertUnrecognizedName = 112, AlertNoApplicationProtocol = 120;
    public const string CipherSuites = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";

    [LibraryImport(LibSsl)] private static partial IntPtr TLS_method();
    [LibraryImport(LibSsl)] private static partial IntPtr SSL_CTX_new(IntPtr method);
    [LibraryImport(LibSsl)] private static partial void SSL_CTX_free(IntPtr ctx);
    [LibraryImport(LibSsl, StringMarshalling = StringMarshalling.Utf8)] private static partial int SSL_CTX_set_ciphersuites(IntPtr ctx, string str);
    [LibraryImport(LibSsl, StringMarshalling = StringMarshalling.Utf8)] private static partial int SSL_CTX_use_certificate_chain_file(IntPtr ctx, string file);
    [LibraryImport(LibSsl, StringMarshalling = StringMarshalling.Utf8)] private static partial int SSL_CTX_use_PrivateKey_file(IntPtr ctx, string file, int type);
    [LibraryImport(LibSsl)] private static partial int SSL_CTX_check_private_key(IntPtr ctx);
    [LibraryImport(LibSsl, StringMarshalling = StringMarshalling.Utf8)] private static partial int SSL_CTX_load_verify_locations(IntPtr ctx, string? file, string? path);
    [LibraryImport(LibSsl)] private static partial void SSL_CTX_set_verify(IntPtr ctx, int mode, IntPtr callback);
    [LibraryImport(LibSsl)] private static partial void SSL_CTX_set_alpn_select_cb(IntPtr ctx, IntPtr cb, IntPtr arg);
    [LibraryImport(LibSsl)] private static partial nint SSL_CTX_callback_ctrl(IntPtr ctx, int cmd, IntPtr fp);
    [LibraryImport(LibSsl)] private static partial IntPtr SSL_new(IntPtr ctx);
    [LibraryImport(LibSsl)] private static partial void SSL_free(IntPtr ssl);
    [LibraryImport(LibSsl)] private static partial void SSL_set_accept_state(IntPtr ssl);
    [LibraryImport(LibSsl)] private static partial void SSL_set_connect_state(IntPtr ssl);
    [LibraryImport(LibSsl)] private static partial int SSL_set_quic_tls_cbs(IntPtr ssl, IntPtr dispatch, IntPtr arg);
    [LibraryImport(LibSsl)] private static partial int SSL_set_quic_tls_transport_params(IntPtr ssl, byte* p, nuint len);
    [LibraryImport(LibSsl)] private static partial int SSL_do_handshake(IntPtr ssl);
    [LibraryImport(LibSsl)] private static partial int SSL_read_ex(IntPtr ssl, byte* buf, nuint num, nuint* read);
    [LibraryImport(LibSsl)] private static partial int SSL_get_error(IntPtr ssl, int ret);
    [LibraryImport(LibSsl)] private static partial int SSL_set_ex_data(IntPtr ssl, int idx, IntPtr data);
    [LibraryImport(LibSsl)] private static partial IntPtr SSL_get_ex_data(IntPtr ssl, int idx);
    [LibraryImport(LibSsl)] private static partial IntPtr SSL_set_SSL_CTX(IntPtr ssl, IntPtr ctx);
    [LibraryImport(LibSsl)] private static partial IntPtr SSL_get_servername(IntPtr ssl, int type);
    [LibraryImport(LibSsl)] private static partial void SSL_get0_alpn_selected(IntPtr ssl, byte** data, uint* len);
    [LibraryImport(LibSsl)] private static partial int SSL_set_alpn_protos(IntPtr ssl, byte* protos, uint len);
    [LibraryImport(LibSsl)] private static partial int SSL_select_next_proto(byte** outp, byte* outlen, byte* server, uint serverLen, byte* client, uint clientLen);
    [LibraryImport(LibSsl)] private static partial nint SSL_ctrl(IntPtr ssl, int cmd, nint larg, IntPtr parg);
    [LibraryImport(LibSsl, StringMarshalling = StringMarshalling.Utf8)] private static partial int SSL_set1_host(IntPtr ssl, string host);
    [LibraryImport(LibSsl)] private static partial IntPtr SSL_get_current_cipher(IntPtr ssl);
    [LibraryImport(LibSsl)] private static partial ushort SSL_CIPHER_get_protocol_id(IntPtr cipher);
    [LibraryImport(LibCrypto)] private static partial nuint ERR_get_error();
    [LibraryImport(LibCrypto)] private static partial void ERR_error_string_n(nuint e, byte* buf, nuint len);
    [LibraryImport(LibCrypto)] private static partial void ERR_clear_error();

    /// <summary>Null if QUIC TLS works here; otherwise why not (not Linux, or an OpenSSL without the QUIC TLS API).</summary>
    public static string? Unavailable => _unavailable.Value;

    private static readonly Lazy<string?> _unavailable = new(() =>
    {
        if (!OperatingSystem.IsLinux()) return "HTTP/3 is only implemented on Linux";
        if (!NativeLibrary.TryLoad(LibSsl, out var lib)) return "libssl.so.3 not found";
        if (!NativeLibrary.TryGetExport(lib, "SSL_set_quic_tls_cbs", out _)) return "the system OpenSSL has no QUIC TLS API (needs OpenSSL 3.5 or newer)";
        return null;
    });

    // The dispatch table OpenSSL calls through: one for every connection (the connection is the callbacks' "arg").
    private static readonly IntPtr Dispatch = MakeDispatch();

    private static IntPtr MakeDispatch()
    {
        // struct ossl_dispatch_st { int function_id; void (*function)(void); }, terminated by { 0, NULL }.
        var t = (byte*)NativeMemory.AllocZeroed((nuint)(7 * 16));
        void Entry(int i, int id, IntPtr fn)
        {
            *(int*)(t + i * 16) = id;
            *(IntPtr*)(t + i * 16 + 8) = fn;
        }
        Entry(0, CryptoSendId, (IntPtr)(delegate* unmanaged<IntPtr, byte*, nuint, nuint*, IntPtr, int>)&CryptoSendCb);
        Entry(1, CryptoRecvRcdId, (IntPtr)(delegate* unmanaged<IntPtr, byte**, nuint*, IntPtr, int>)&CryptoRecvRcdCb);
        Entry(2, CryptoReleaseRcdId, (IntPtr)(delegate* unmanaged<IntPtr, nuint, IntPtr, int>)&CryptoReleaseRcdCb);
        Entry(3, YieldSecretId, (IntPtr)(delegate* unmanaged<IntPtr, uint, int, byte*, nuint, IntPtr, int>)&YieldSecretCb);
        Entry(4, GotTransportParamsId, (IntPtr)(delegate* unmanaged<IntPtr, byte*, nuint, IntPtr, int>)&GotTransportParamsCb);
        Entry(5, AlertId, (IntPtr)(delegate* unmanaged<IntPtr, byte, IntPtr, int>)&AlertCb);
        return (IntPtr)t;
    }

    private readonly IQuicTlsHost _host;
    private readonly Func<string?, QuicTlsContext?>? _selectServer;
    private IntPtr _ssl;
    private GCHandle _self;
    private readonly bool _isServer;

    // Received, in-order CRYPTO data waiting for OpenSSL, per level; and the record OpenSSL holds right now.
    private readonly List<byte>[] _pending = [new(), new(), new(), new()];
    private byte* _rcd;
    private int _rcdCapacity;
    private byte* _ourParams;
    private QuicLevel _readLevel = QuicLevel.Initial, _writeLevel = QuicLevel.Initial;

    public bool HandshakeComplete { get; private set; }
    /// <summary>Set when a call failed: the CONNECTION_CLOSE code (CRYPTO_ERROR + alert where TLS sent one) and why.</summary>
    public QuicError? Error { get; private set; }
    public string? ErrorReason { get; private set; }
    public string? ServerName { get; private set; }
    public string? Alpn { get; private set; }
    /// <summary>The context SNI selected (a server's), or the one it started with.</summary>
    public QuicTlsContext Context { get; private set; }

    /// <summary>A server-side handshake. <paramref name="selectServer"/> maps the client's SNI (or null) to a context, or null to refuse.</summary>
    public static QuicTls Server(QuicTlsContext initial, Func<string?, QuicTlsContext?> selectServer, IQuicTlsHost host) =>
        new(initial, host, server: true, selectServer, sni: null, alpn: null, transportParameters: null);

    /// <summary>A client-side handshake (tests and interop tooling): SNI, ALPN offered, and our transport parameters.</summary>
    public static QuicTls Client(QuicTlsContext ctx, string sni, string[] alpn, byte[] transportParameters, IQuicTlsHost host) =>
        new(ctx, host, server: false, null, sni, alpn, transportParameters);

    private QuicTls(QuicTlsContext ctx, IQuicTlsHost host, bool server, Func<string?, QuicTlsContext?>? selectServer, string? sni, string[]? alpn, byte[]? transportParameters)
    {
        _host = host;
        _isServer = server;
        _selectServer = selectServer;
        Context = ctx;
        _ssl = SSL_new(ctx.Handle);
        if (_ssl == IntPtr.Zero) throw new InvalidOperationException("SSL_new failed: " + LastError());
        _self = GCHandle.Alloc(this, GCHandleType.Weak); // the connection holds us during every call into OpenSSL
        var self = GCHandle.ToIntPtr(_self);
        SSL_set_ex_data(_ssl, 0, self);
        if (SSL_set_quic_tls_cbs(_ssl, Dispatch, self) != 1) throw new InvalidOperationException("SSL_set_quic_tls_cbs failed: " + LastError());
        if (server) SSL_set_accept_state(_ssl);
        else
        {
            SSL_set_connect_state(_ssl);
            var name = Marshal.StringToCoTaskMemUTF8(sni);
            try { SSL_ctrl(_ssl, SslCtrlSetTlsextHostname, 0, name); }
            finally { Marshal.FreeCoTaskMem(name); }
            if (ctx.VerifyPeer && SSL_set1_host(_ssl, sni!) != 1) throw new InvalidOperationException("SSL_set1_host failed");
            var wire = QuicTlsContext.AlpnWire(alpn!);
            fixed (byte* w = wire)
                if (SSL_set_alpn_protos(_ssl, w, (uint)wire.Length) != 0) throw new InvalidOperationException("SSL_set_alpn_protos failed");
            SetOurParameters(transportParameters!);
        }
    }

    private void SetOurParameters(byte[] p)
    {
        if (_ourParams != null) NativeMemory.Free(_ourParams);
        _ourParams = (byte*)NativeMemory.Alloc((nuint)Math.Max(p.Length, 1));
        p.CopyTo(new Span<byte>(_ourParams, p.Length));
        if (SSL_set_quic_tls_transport_params(_ssl, _ourParams, (nuint)p.Length) != 1) throw new QuicException(QuicError.InternalError, "SSL_set_quic_tls_transport_params failed");
    }

    /// <summary>
    /// CRYPTO data the peer sent at <paramref name="level"/>, in order and new (the connection reassembles). Data at a
    /// level below the one TLS now reads is a PROTOCOL_VIOLATION (RFC 9001 4.1.3). Then call <see cref="Advance"/>.
    /// </summary>
    public void Receive(QuicLevel level, ReadOnlySpan<byte> data)
    {
        if (level < _readLevel) throw new QuicException(QuicError.ProtocolViolation, "CRYPTO data at an encryption level already left behind", QuicFrameType.Crypto);
        var q = _pending[(int)level];
        foreach (byte b in data) q.Add(b);
    }

    /// <summary>Bytes received at a level and not yet taken by TLS (bounded by the connection's CRYPTO buffer limit).</summary>
    public int Pending(QuicLevel level) => _pending[(int)level].Count;

    /// <summary>
    /// Let TLS make progress with what it has: the handshake, or post-handshake messages. False if the connection
    /// must close (see <see cref="Error"/>).
    /// </summary>
    public bool Advance()
    {
        if (Error is not null) return false;
        ERR_clear_error();
        int r;
        if (!HandshakeComplete)
        {
            r = SSL_do_handshake(_ssl);
            if (r == 1)
            {
                HandshakeComplete = true;
                byte* a;
                uint alen;
                SSL_get0_alpn_selected(_ssl, &a, &alen);
                if (alen == 0)
                {
                    // ALPN is mandatory in QUIC (RFC 9001 8.1).
                    Fail(QuicError.CryptoError + AlertNoApplicationProtocol, "no application protocol negotiated");
                    return false;
                }
                Alpn = Encoding.ASCII.GetString(a, (int)alen);
                if (_isServer) ServerName = Marshal.PtrToStringUTF8(SSL_get_servername(_ssl, 0));
                return Error is null;
            }
        }
        else
        {
            nuint n;
            byte dummy;
            r = SSL_read_ex(_ssl, &dummy, 0, &n);
            if (r == 1) return Error is null;
        }
        int e = SSL_get_error(_ssl, r);
        if (e == SslErrorWantRead) return Error is null;
        if (e == SslErrorZeroReturn) { Fail(QuicError.ProtocolViolation, "TLS closed the connection"); return false; }
        Fail(Error ?? QuicError.CryptoError + 80 /* internal_error */, ErrorReason ?? "TLS error: " + LastError());
        return false;
    }

    private void Fail(QuicError code, string reason)
    {
        Error ??= code;
        ErrorReason ??= reason;
    }

    private static string LastError()
    {
        nuint e = ERR_get_error();
        if (e == 0) return "unknown";
        byte* buf = stackalloc byte[256];
        ERR_error_string_n(e, buf, 256);
        return Marshal.PtrToStringUTF8((IntPtr)buf) ?? "unknown";
    }

    private static QuicTls? From(IntPtr arg) =>
        arg == IntPtr.Zero ? null : GCHandle.FromIntPtr(arg).Target as QuicTls;

    // ---- callbacks: never let an exception reach OpenSSL; a failure returns 0 and records why ----

    [UnmanagedCallersOnly]
    private static int CryptoSendCb(IntPtr ssl, byte* buf, nuint len, nuint* consumed, IntPtr arg)
    {
        var t = From(arg);
        if (t is null) return 0;
        try
        {
            t._host.OnCryptoData(t._writeLevel, new ReadOnlySpan<byte>(buf, checked((int)len)));
            *consumed = len;
            return 1;
        }
        catch (Exception e) { t.CallbackFailed(e); return 0; }
    }

    [UnmanagedCallersOnly]
    private static int CryptoRecvRcdCb(IntPtr ssl, byte** buf, nuint* read, IntPtr arg)
    {
        var t = From(arg);
        if (t is null) return 0;
        try
        {
            var q = t._pending[(int)t._readLevel];
            if (q.Count == 0)
            {
                *buf = null;
                *read = 0;
                return 1;
            }
            if (t._rcdCapacity < q.Count)
            {
                if (t._rcd != null) NativeMemory.Free(t._rcd);
                t._rcdCapacity = Math.Max(q.Count, 4096);
                t._rcd = (byte*)NativeMemory.Alloc((nuint)t._rcdCapacity);
            }
            CollectionsMarshal.AsSpan(q).CopyTo(new Span<byte>(t._rcd, q.Count));
            *buf = t._rcd;
            *read = (nuint)q.Count;
            q.Clear(); // OpenSSL takes the whole record (release always reports its full size)
            return 1;
        }
        catch (Exception e) { t.CallbackFailed(e); return 0; }
    }

    [UnmanagedCallersOnly]
    private static int CryptoReleaseRcdCb(IntPtr ssl, nuint len, IntPtr arg) => From(arg) is null ? 0 : 1;

    [UnmanagedCallersOnly]
    private static int YieldSecretCb(IntPtr ssl, uint level, int direction, byte* secret, nuint len, IntPtr arg)
    {
        var t = From(arg);
        if (t is null) return 0;
        try
        {
            if (level is not (2 or 3)) throw new QuicException(QuicError.InternalError, "unexpected TLS protection level " + level);
            var lvl = (QuicLevel)level;
            QuicCipher cipher;
            IntPtr c = SSL_get_current_cipher(ssl);
            ushort id = c != IntPtr.Zero ? SSL_CIPHER_get_protocol_id(c) : (ushort)0;
            cipher = id switch
            {
                0x1301 => QuicCipher.Aes128Gcm,
                0x1302 => QuicCipher.Aes256Gcm,
                0 when len == 32 => QuicCipher.Aes128Gcm,
                0 when len == 48 => QuicCipher.Aes256Gcm,
                _ => throw new QuicException(QuicError.InternalError, $"unsupported TLS cipher suite 0x{id:x4}"),
            };
            if ((int)len != QuicKeys.SecretLength(cipher)) throw new QuicException(QuicError.InternalError, "secret length doesn't match the cipher suite");
            bool write = direction == 1;
            if (write) t._writeLevel = lvl;
            else
            {
                // Keys change at a message boundary: anything still unread at the old level is out of place.
                if (t._pending[(int)t._readLevel].Count > 0) throw new QuicException(QuicError.ProtocolViolation, "CRYPTO data left over at a key change");
                t._readLevel = lvl;
            }
            t._host.OnSecret(lvl, write, cipher, new ReadOnlySpan<byte>(secret, (int)len));
            return 1;
        }
        catch (Exception e) { t.CallbackFailed(e); return 0; }
    }

    [UnmanagedCallersOnly]
    private static int GotTransportParamsCb(IntPtr ssl, byte* p, nuint len, IntPtr arg)
    {
        var t = From(arg);
        if (t is null) return 0;
        try
        {
            var ours = t._host.OnPeerTransportParameters(new ReadOnlySpan<byte>(p, checked((int)len)));
            if (t._isServer)
            {
                if (ours is null) throw new QuicException(QuicError.InternalError, "no transport parameters to answer with");
                t.SetOurParameters(ours);
            }
            return 1;
        }
        catch (Exception e) { t.CallbackFailed(e); return 0; }
    }

    [UnmanagedCallersOnly]
    private static int AlertCb(IntPtr ssl, byte alert, IntPtr arg)
    {
        var t = From(arg);
        if (t is null) return 0;
        t.Fail(QuicError.CryptoError + alert, "TLS alert " + alert);
        return 1;
    }

    private void CallbackFailed(Exception e)
    {
        if (e is QuicException q) Fail(q.Code, q.Message);
        else Fail(QuicError.InternalError, e.GetType().Name + ": " + e.Message);
    }

    // SNI: switch to the server's context before the certificate is chosen (the classic servername callback).
    [UnmanagedCallersOnly]
    internal static int ServernameCb(IntPtr ssl, int* alert, IntPtr arg)
    {
        try
        {
            var t = From(SSL_get_ex_data(ssl, 0));
            if (t?._selectServer is null) return TlsextErrNoAck;
            var name = Marshal.PtrToStringUTF8(SSL_get_servername(ssl, 0));
            var ctx = t._selectServer(name);
            if (ctx is null)
            {
                *alert = AlertUnrecognizedName;
                t.Fail(QuicError.CryptoError + AlertUnrecognizedName, "no server for this name");
                return TlsextErrAlertFatal;
            }
            if (!ReferenceEquals(ctx, t.Context))
            {
                SSL_set_SSL_CTX(ssl, ctx.Handle);
                t.Context = ctx;
            }
            return TlsextErrOk;
        }
        catch (Exception)
        {
            *alert = 80; // internal_error
            return TlsextErrAlertFatal;
        }
    }

    // ALPN: the server's first protocol the client offers; none in common is fatal (no_application_protocol).
    [UnmanagedCallersOnly]
    internal static int AlpnSelectCb(IntPtr ssl, byte** outp, byte* outlen, byte* inp, uint inlen, IntPtr arg)
    {
        int len = *(int*)arg;
        byte* ours = (byte*)arg + 4;
        return SSL_select_next_proto(outp, outlen, ours, (uint)len, inp, inlen) == 1 ? TlsextErrOk : TlsextErrAlertFatal;
    }

    internal static IntPtr NewContext(bool server, string[] alpn, out IntPtr alpnArg)
    {
        alpnArg = IntPtr.Zero;
        var ctx = SSL_CTX_new(TLS_method());
        if (ctx == IntPtr.Zero) throw new InvalidOperationException("SSL_CTX_new failed: " + LastError());
        if (SSL_CTX_set_ciphersuites(ctx, CipherSuites) != 1)
        {
            SSL_CTX_free(ctx);
            throw new InvalidOperationException("SSL_CTX_set_ciphersuites failed: " + LastError());
        }
        if (server)
        {
            var wire = QuicTlsContext.AlpnWire(alpn);
            var a = (byte*)NativeMemory.Alloc((nuint)(4 + wire.Length));
            *(int*)a = wire.Length;
            wire.CopyTo(new Span<byte>(a + 4, wire.Length));
            alpnArg = (IntPtr)a;
            SSL_CTX_set_alpn_select_cb(ctx, (IntPtr)(delegate* unmanaged<IntPtr, byte**, byte*, byte*, uint, IntPtr, int>)&AlpnSelectCb, alpnArg);
            SSL_CTX_callback_ctrl(ctx, SslCtrlSetTlsextServernameCb, (IntPtr)(delegate* unmanaged<IntPtr, int*, IntPtr, int>)&ServernameCb);
        }
        return ctx;
    }

    internal static void LoadCertificate(IntPtr ctx, string certFile, string keyFile)
    {
        ERR_clear_error();
        if (SSL_CTX_use_certificate_chain_file(ctx, certFile) != 1) throw new InvalidOperationException($"can't load {certFile}: {LastError()}");
        if (SSL_CTX_use_PrivateKey_file(ctx, keyFile, 1 /* SSL_FILETYPE_PEM */) != 1) throw new InvalidOperationException($"can't load {keyFile}: {LastError()}");
        if (SSL_CTX_check_private_key(ctx) != 1) throw new InvalidOperationException($"{keyFile} doesn't match {certFile}");
    }

    internal static void LoadVerify(IntPtr ctx, string caFile)
    {
        ERR_clear_error();
        if (SSL_CTX_load_verify_locations(ctx, caFile, null) != 1) throw new InvalidOperationException($"can't load {caFile}: {LastError()}");
        SSL_CTX_set_verify(ctx, 1 /* SSL_VERIFY_PEER */, IntPtr.Zero);
    }

    internal static void FreeContext(IntPtr ctx, IntPtr alpnArg)
    {
        SSL_CTX_free(ctx);
        if (alpnArg != IntPtr.Zero) NativeMemory.Free((void*)alpnArg);
    }

    public void Dispose()
    {
        if (_ssl != IntPtr.Zero)
        {
            SSL_free(_ssl);
            _ssl = IntPtr.Zero;
        }
        if (_self.IsAllocated) _self.Free();
        if (_rcd != null) { NativeMemory.Free(_rcd); _rcd = null; }
        if (_ourParams != null) { NativeMemory.Free(_ourParams); _ourParams = null; }
        GC.SuppressFinalize(this);
    }

    // A connection dropped without Dispose mustn't leak the SSL or native buffers. Unreachable means no one is
    // calling into OpenSSL with it, so freeing here can't race.
    ~QuicTls()
    {
        if (_ssl != IntPtr.Zero) SSL_free(_ssl);
        if (_self.IsAllocated) _self.Free();
        if (_rcd != null) NativeMemory.Free(_rcd);
        if (_ourParams != null) NativeMemory.Free(_ourParams);
    }
}

/// <summary>
/// An OpenSSL context for QUIC: one per server{} (its certificate, AES-GCM suites, ALPN), or a client's (its CA).
/// Built at configuration time; disposed with the configuration.
/// </summary>
internal sealed class QuicTlsContext : IDisposable
{
    internal IntPtr Handle { get; private set; }
    private readonly IntPtr _alpnArg;
    public bool VerifyPeer { get; }

    private QuicTlsContext(IntPtr handle, IntPtr alpnArg, bool verify)
    {
        Handle = handle;
        _alpnArg = alpnArg;
        VerifyPeer = verify;
    }

    /// <summary>A server context: the PEM certificate chain and key (the ssl_certificate files), offering <paramref name="alpn"/>.</summary>
    public static QuicTlsContext Server(string certFile, string keyFile, string[] alpn)
    {
        var ctx = QuicTls.NewContext(server: true, alpn, out var arg);
        try { QuicTls.LoadCertificate(ctx, certFile, keyFile); }
        catch
        {
            QuicTls.FreeContext(ctx, arg);
            throw;
        }
        return new QuicTlsContext(ctx, arg, verify: false);
    }

    /// <summary>A client context, verifying the server against <paramref name="caFile"/> (or nothing, for interop probes).</summary>
    public static QuicTlsContext Client(string? caFile)
    {
        var ctx = QuicTls.NewContext(server: false, [], out _);
        if (caFile is not null)
        {
            try { QuicTls.LoadVerify(ctx, caFile); }
            catch
            {
                QuicTls.FreeContext(ctx, IntPtr.Zero);
                throw;
            }
        }
        return new QuicTlsContext(ctx, IntPtr.Zero, verify: caFile is not null);
    }

    /// <summary>ALPN's wire format: each protocol as a length byte and its name.</summary>
    internal static byte[] AlpnWire(string[] protocols)
    {
        var b = new List<byte>();
        foreach (var p in protocols)
        {
            if (p.Length is 0 or > 255) throw new ArgumentException("ALPN protocol length", nameof(protocols));
            b.Add((byte)p.Length);
            b.AddRange(Encoding.ASCII.GetBytes(p));
        }
        return [.. b];
    }

    public void Dispose()
    {
        if (Handle == IntPtr.Zero) return;
        QuicTls.FreeContext(Handle, _alpnArg);
        Handle = IntPtr.Zero;
    }
}
