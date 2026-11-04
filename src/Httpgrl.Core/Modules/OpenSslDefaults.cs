using System.IO.Pipelines;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Httpgrl.Core.Modules;

/// <summary>
/// Strict cipher suites without losing TLS session resumption, through OpenSSL's public API only.
///
/// .NET on Linux caches one OpenSSL SSL_CTX per server certificate context, and that cache is where resumable sessions
/// live, but it refuses to cache when a CipherSuitesPolicy is set. With no policy it leaves the suites to OpenSSL
/// ("let OpenSSL choose"), and OpenSSL applies its process-wide <c>system_default</c> configuration to every SSL_CTX it
/// creates. So we load our own system_default (AEAD-only) into OpenSSL from memory, once, before any context exists:
/// servers on the default list need no policy, and their sessions resume. Then we check it took, with real in-memory
/// handshakes against a throwaway certificate: a CBC suite must be refused, a GCM suite accepted. If anything is off
/// (no OpenSSL 3, a load error, the check failing) the caller uses a CipherSuitesPolicy instead: same suites, no
/// resumption. Http1Session also checks every negotiated suite against the server's list and drops a connection
/// outside it, so a surprise fails closed.
///
/// It's process-wide and fixed (always the default list, whatever the configuration says), so it can't differ between
/// configurations and a reload never changes it. It also applies to our outgoing TLS (proxy upstreams, tunnels).
/// </summary>
internal static partial class OpenSslDefaults
{
    private const string LibCrypto = "libcrypto.so.3";

    [LibraryImport(LibCrypto, EntryPoint = "NCONF_new")] private static partial IntPtr NconfNew(IntPtr method);
    [LibraryImport(LibCrypto, EntryPoint = "NCONF_free")] private static partial void NconfFree(IntPtr conf);
    [LibraryImport(LibCrypto, EntryPoint = "NCONF_load_bio")] private static partial int NconfLoadBio(IntPtr conf, IntPtr bio, out nint errorLine);
    [LibraryImport(LibCrypto, EntryPoint = "CONF_modules_load")] private static partial int ConfModulesLoad(IntPtr conf, IntPtr appName, nuint flags);
    [LibraryImport(LibCrypto, EntryPoint = "BIO_new_mem_buf")] private static partial IntPtr BioNewMemBuf(byte[] buf, int len);
    [LibraryImport(LibCrypto, EntryPoint = "BIO_free")] private static partial int BioFree(IntPtr bio);
    [LibraryImport(LibCrypto, EntryPoint = "ERR_clear_error")] private static partial void ErrClearError();

    private static readonly object Gate = new();
    private static string? _result;
    private static bool _done;
    private static string _tls12 = "", _tls13 = "";

    /// <summary>
    /// Load the default suites (OpenSSL syntax) into OpenSSL's process-wide default, once. Null if that's in force
    /// (verified), else why not. Later calls return the first outcome.
    /// </summary>
    public static string? Ensure(string tls12, string tls13)
    {
        lock (Gate)
        {
            if (!_done)
            {
                _tls12 = tls12;
                _tls13 = tls13;
                _result = Install();
                _done = true;
            }
            return _result;
        }
    }

    private static string? Install()
    {
        if (!OperatingSystem.IsLinux()) return "only implemented for OpenSSL on Linux";
        try
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var req = new CertificateRequest("CN=httpgrl-cipher-check", key, HashAlgorithmName.SHA256);
            using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddMinutes(5));
            // Initialise .NET's OpenSSL first, so its own initialisation (and the system openssl.cnf) can't come after ours.
            var context = SslStreamCertificateContext.Create(cert, null, offline: true);

            var text = $"openssl_conf = httpgrl_init\n[httpgrl_init]\nssl_conf = httpgrl_ssl\n[httpgrl_ssl]\nsystem_default = httpgrl_default\n"
                + $"[httpgrl_default]\nCipherString = {_tls12}\nCiphersuites = {_tls13}\n";
            var bytes = System.Text.Encoding.ASCII.GetBytes(text);
            IntPtr conf = NconfNew(IntPtr.Zero), bio = BioNewMemBuf(bytes, bytes.Length);
            try
            {
                if (conf == IntPtr.Zero || bio == IntPtr.Zero) return "OpenSSL couldn't allocate a configuration";
                if (NconfLoadBio(conf, bio, out var line) != 1) return $"OpenSSL rejected the configuration (line {line})";
                if (ConfModulesLoad(conf, IntPtr.Zero, 0) != 1) return "OpenSSL couldn't apply the configuration";
            }
            finally
            {
                if (bio != IntPtr.Zero) BioFree(bio);
                if (conf != IntPtr.Zero) NconfFree(conf);
                ErrClearError();
            }

            // Verify on a fresh, policy-less server context: what our servers will use.
            var options = new SslServerAuthenticationOptions
            {
                ServerCertificateContext = context,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ApplicationProtocols = [SslApplicationProtocol.Http11],
            };
            if (Probe(options, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) != TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
                return "an allowed suite was refused after loading the default";
            if (Probe(options, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256) is not null)
                return "a CBC suite was still accepted (is .NET using a different libssl?)";
            return null;
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or CryptographicException
                                      or AuthenticationException or IOException or PlatformNotSupportedException)
        {
            return e.GetType().Name + ": " + e.Message;
        }
    }

    /// <summary>One TLS 1.2 handshake offering only <paramref name="suite"/>: the negotiated suite, or null if refused.</summary>
    private static TlsCipherSuite? Probe(SslServerAuthenticationOptions options, TlsCipherSuite suite)
    {
        var a = new Pipe();
        var b = new Pipe();
        var serverSide = new DuplexStream(a.Reader.AsStream(), b.Writer.AsStream());
        var clientSide = new DuplexStream(b.Reader.AsStream(), a.Writer.AsStream());
        using var server = new SslStream(serverSide, leaveInnerStreamOpen: false);
        using var client = new SslStream(clientSide, false, (_, _, _, _) => true);
        var co = new SslClientAuthenticationOptions { TargetHost = "check.invalid", EnabledSslProtocols = SslProtocols.Tls12 };
        if (!OperatingSystem.IsWindows()) co.CipherSuitesPolicy = new CipherSuitesPolicy([suite]);
        var s = server.AuthenticateAsServerAsync(options);
        var c = client.AuthenticateAsClientAsync(co);
        // A refusal on one side must not leave the other waiting for bytes that never come.
        Task.WaitAny([s, c], TimeSpan.FromSeconds(10));
        if (s.IsFaulted || c.IsFaulted) { serverSide.Dispose(); clientSide.Dispose(); }
        try { Task.WaitAll([s, c], TimeSpan.FromSeconds(10)); }
        catch (AggregateException) { return null; }
        return s.IsCompletedSuccessfully && c.IsCompletedSuccessfully ? client.NegotiatedCipherSuite : null;
    }

    private sealed class DuplexStream(Stream read, Stream write) : Stream
    {
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => read.ReadAsync(buffer, ct);
        public override Task<int> ReadAsync(byte[] b, int o, int c, CancellationToken ct) => read.ReadAsync(b, o, c, ct);
        public override int Read(byte[] b, int o, int c) => read.Read(b, o, c);
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        {
            await write.WriteAsync(buffer, ct).ConfigureAwait(false);
            await write.FlushAsync(ct).ConfigureAwait(false);
        }
        public override Task WriteAsync(byte[] b, int o, int c, CancellationToken ct) => WriteAsync(b.AsMemory(o, c), ct).AsTask();
        public override void Write(byte[] b, int o, int c) { write.Write(b, o, c); write.Flush(); }
        public override Task FlushAsync(CancellationToken ct) => write.FlushAsync(ct);
        public override void Flush() => write.Flush();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing) { read.Dispose(); write.Dispose(); }
            base.Dispose(disposing);
        }
    }
}
