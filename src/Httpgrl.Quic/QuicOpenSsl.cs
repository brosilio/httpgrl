using System.Reflection;
using System.Runtime.InteropServices;

namespace Httpgrl.Quic;

/// <summary>
/// Which OpenSSL (3.5 or newer, for its QUIC TLS API) the built-in TLS provider loads. By default the platform's usual
/// names: <c>libssl.so.3</c> on Linux and the BSDs, <c>libssl.3.dylib</c> on macOS, <c>libssl-3-x64.dll</c> (or
/// <c>-arm64</c>) on Windows, each with its libcrypto. An application that ships its own OpenSSL, or keeps it somewhere
/// else, calls <see cref="UseLibraries"/> before its first QUIC connection. Platforms without OpenSSL supply their own
/// <see cref="QuicTlsContext"/> instead.
/// </summary>
public static class QuicOpenSsl
{
    private static readonly object Gate = new();
    private static string? _ssl, _crypto;
    private static bool _installed, _used;
    private static IntPtr _sslHandle, _cryptoHandle;

    /// <summary>
    /// Load these files (names, or paths) instead of the platform's defaults. Call it before the first QUIC
    /// connection: once OpenSSL is loaded it can't change, and this throws <see cref="InvalidOperationException"/>.
    /// </summary>
    public static void UseLibraries(string libssl, string libcrypto)
    {
        ArgumentException.ThrowIfNullOrEmpty(libssl);
        ArgumentException.ThrowIfNullOrEmpty(libcrypto);
        lock (Gate)
        {
            if (_used) throw new InvalidOperationException("OpenSSL is already loaded");
            _ssl = libssl;
            _crypto = libcrypto;
        }
    }

    /// <summary>The libssl and libcrypto this process loads (or will).</summary>
    public static (string Ssl, string Crypto) Names
    {
        get
        {
            lock (Gate) return (_ssl ?? DefaultSsl, _crypto ?? DefaultCrypto);
        }
    }

    private static string Arch => RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "arm64" : "x64";

    private static string DefaultSsl =>
        OperatingSystem.IsWindows() ? $"libssl-3-{Arch}.dll" : OperatingSystem.IsMacOS() ? "libssl.3.dylib" : "libssl.so.3";

    private static string DefaultCrypto =>
        OperatingSystem.IsWindows() ? $"libcrypto-3-{Arch}.dll" : OperatingSystem.IsMacOS() ? "libcrypto.3.dylib" : "libcrypto.so.3";

    /// <summary>Route this assembly's [LibraryImport("libssl"/"libcrypto")] to the chosen files. Once, from QuicTls's static constructor.</summary>
    internal static void Install()
    {
        lock (Gate)
        {
            if (_installed) return;
            _installed = true;
            NativeLibrary.SetDllImportResolver(typeof(QuicOpenSsl).Assembly, Resolve);
        }
    }

    private static IntPtr Resolve(string name, Assembly assembly, DllImportSearchPath? path) => Load(name) ?? IntPtr.Zero;

    /// <summary>The handle of libssl or libcrypto (by our logical names), loading it on first use; null if it can't be.</summary>
    internal static IntPtr? Load(string logical)
    {
        lock (Gate)
        {
            _used = true;
            bool ssl = logical == QuicTls.LibSsl;
            if (!ssl && logical != QuicTls.LibCrypto) return null;
            ref IntPtr h = ref ssl ? ref _sslHandle : ref _cryptoHandle;
            if (h != IntPtr.Zero) return h;
            // libcrypto first: libssl depends on it, and a path given for it must win over whatever libssl would pull in.
            if (ssl && _cryptoHandle == IntPtr.Zero && NativeLibrary.TryLoad(_crypto ?? DefaultCrypto, out var c)) _cryptoHandle = c;
            if (!NativeLibrary.TryLoad(ssl ? _ssl ?? DefaultSsl : _crypto ?? DefaultCrypto, out var lib)) return null;
            h = lib;
            return h;
        }
    }
}
