namespace Httpgrl.Core.Http3;

/// <summary>Whether this server can serve HTTP/3 here (docs/plan-http2-http3.md, decision 4).</summary>
internal static class Http3Support
{
    /// <summary>
    /// Null when it can; otherwise why not. The QUIC library itself loads OpenSSL on any platform, but the server's
    /// HTTP/3 is only exercised (and supported) on Linux.
    /// </summary>
    public static string? Unavailable => OperatingSystem.IsLinux() ? QuicTlsContext.Unavailable : "HTTP/3 is only implemented on Linux";
}
