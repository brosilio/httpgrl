using System.Net;
using System.Net.Sockets;
using Httpgrl.Core.Http;
using Httpgrl.Core.Pipeline;

namespace Httpgrl.Core.Hosting;

/// <summary>Owns listening sockets, accept loops and the connection table for one loaded configuration.</summary>
public sealed class HttpServer : IAsyncDisposable
{
    private readonly HttpRuntime _rt;
    private readonly ConnectionManager _mgr;
    private readonly List<(Socket Socket, ListenBinding Binding)> _listeners = new();
    private readonly List<Task> _loops = new();
    private volatile bool _stopping;

    internal HttpServer(HttpRuntime rt)
    {
        _rt = rt;
        _mgr = new ConnectionManager(rt.Events.MaxConnections, rt.Events.PerClient, rt.Log);
    }

    /// <summary>Actual bound endpoints (port 0 resolved), in binding order.</summary>
    public IReadOnlyList<EndPoint> EndPoints => _listeners.ConvertAll(l => l.Socket.LocalEndPoint!);

    public int ActiveConnections => _mgr.Active;

    public void Start()
    {
        foreach (var b in _rt.Bindings)
        {
            Socket s;
            try { s = Bind(b); }
            catch (SocketException e)
            {
                foreach (var (ls, _) in _listeners) ls.Dispose();
                _listeners.Clear();
                throw new IOException($"cannot listen on {b}: {e.Message}", e);
            }
            _listeners.Add((s, b));
            _rt.Log.Info("listening", new("addr", s.LocalEndPoint?.ToString() ?? b.ToString()), new("ssl", b.Ssl));
        }
        int loops = Math.Clamp(Environment.ProcessorCount / 2, 1, 4);
        foreach (var (s, b) in _listeners)
            for (int i = 0; i < loops; i++)
                _loops.Add(Task.Run(() => AcceptLoop(s, b)));
    }

    private static Socket Bind(ListenBinding b)
    {
        Socket s;
        if (b.EndPoint is UnixDomainSocketEndPoint u)
        {
            var path = u.ToString();
            if (File.Exists(path) && new FileInfo(path).Length == 0) File.Delete(path); // stale socket from a previous run
            s = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        }
        else
        {
            var ip = (IPEndPoint)b.EndPoint;
            s = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            if (ip.AddressFamily == AddressFamily.InterNetworkV6) s.DualMode = false; // [::] and 0.0.0.0 bind independently, as in nginx
            if (OperatingSystem.IsWindows()) s.ExclusiveAddressUse = true;
            else SetReuseAddrOnly(s);
            if (b.ReusePort) SetReusePort(s);
        }
        try
        {
            s.Bind(b.EndPoint);
            s.Listen(b.Backlog);
        }
        catch
        {
            s.Dispose();
            throw;
        }
        return s;
    }

    /// <summary>
    /// SO_REUSEADDR (fast restart over TIME_WAIT) without SO_REUSEPORT. .NET's ReuseAddress sets both on Unix,
    /// which would let another process silently bind the same port and steal connections.
    /// </summary>
    private static void SetReuseAddrOnly(Socket s)
    {
        Span<byte> one = [1, 0, 0, 0];
        if (OperatingSystem.IsLinux()) s.SetRawSocketOption(1, 2, one);                 // SOL_SOCKET, SO_REUSEADDR
        else if (OperatingSystem.IsMacOS() || OperatingSystem.IsFreeBSD()) s.SetRawSocketOption(0xffff, 0x4, one);
    }

    /// <summary>Explicit <c>listen ... reuseport</c>: several sockets (processes) share the port, the kernel balances accepts.</summary>
    private static void SetReusePort(Socket s)
    {
        Span<byte> one = [1, 0, 0, 0];
        if (OperatingSystem.IsLinux()) s.SetRawSocketOption(1, 15, one);                // SOL_SOCKET, SO_REUSEPORT
        else if (OperatingSystem.IsMacOS() || OperatingSystem.IsFreeBSD()) s.SetRawSocketOption(0xffff, 0x200, one);
    }

    private async Task AcceptLoop(Socket listener, ListenBinding binding)
    {
        while (!_stopping)
        {
            Socket s;
            try { s = await listener.AcceptAsync().ConfigureAwait(false); }
            catch (ObjectDisposedException) { return; }
            catch (SocketException e)
            {
                if (_stopping) return;
                // EMFILE/ENFILE and friends: back off rather than spin.
                _rt.Log.Warn("accept failed", new LogField("error", e.SocketErrorCode.ToString()));
                await Task.Delay(100).ConfigureAwait(false);
                continue;
            }

            EndPoint? remote;
            try { remote = s.RemoteEndPoint; }
            catch (SocketException) { s.Dispose(); continue; }
            var conn = new Connection(_mgr.NextId(), s, IpKey.From(remote));
            if (!_mgr.TryAdmit(conn, out var why))
            {
                _rt.Log.Debug("connection refused", new("remote", remote?.ToString()), new("reason", why));
                conn.Abort(why!);
                continue;
            }
            if (s.AddressFamily != AddressFamily.Unix) s.NoDelay = true;
            var session = new Http1Session(conn, binding, _rt, _mgr);
            ThreadPool.UnsafeQueueUserWorkItem(static x => _ = x.RunAsync(), session, preferLocal: false);
        }
    }

    /// <summary>Stop accepting, let in-flight requests finish (idle keep-alives close at once), then cut the rest.</summary>
    public async Task StopAsync(int timeoutMs)
    {
        if (_stopping) return;
        _stopping = true;
        _mgr.BeginShutdown();
        foreach (var (s, b) in _listeners)
        {
            s.Dispose();
            if (b.EndPoint is UnixDomainSocketEndPoint u) try { File.Delete(u.ToString()); } catch (IOException) { }
        }
        long deadline = Environment.TickCount64 + timeoutMs;
        while (_mgr.Active > 0 && Environment.TickCount64 < deadline) await Task.Delay(50).ConfigureAwait(false);
        if (_mgr.Active > 0)
        {
            _rt.Log.Warn("shutdown timeout, aborting connections", new LogField("count", (long)_mgr.Active));
            _mgr.AbortAll("shutdown");
        }
        try { await Task.WhenAll(_loops).ConfigureAwait(false); } catch (Exception) { /* loops end on listener disposal */ }
        _mgr.Dispose();
    }

    public int ShutdownTimeoutMs => _rt.Main.ShutdownTimeoutMs;

    public async ValueTask DisposeAsync() => await StopAsync(0).ConfigureAwait(false);
}
