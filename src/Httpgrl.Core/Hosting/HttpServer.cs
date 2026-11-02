using System.Net;
using System.Net.Sockets;
using Httpgrl.Core.Http;
using Httpgrl.Core.Pipeline;

namespace Httpgrl.Core.Hosting;

/// <summary>
/// Owns listening sockets, accept loops and the connection table. The configuration ("generation") can be
/// replaced at runtime with <see cref="ReloadAsync"/>: listeners are kept, opened or closed to match, new
/// connections get the new generation, and existing ones finish on the generation they started with.
/// </summary>
public sealed class HttpServer : IAsyncDisposable
{
    private readonly Func<HttpRuntime> _load;
    private readonly Logging.JsonLogger _log;
    private HttpRuntime _rt = null!;
    private ConnectionManager _mgr = null!;
    /// <summary>Keyed by endpoint (see <see cref="ListenBinding.ToString"/>).</summary>
    private readonly Dictionary<string, Listener> _listeners = new(StringComparer.Ordinal);
    private readonly List<Task> _loops = new();
    private readonly SemaphoreSlim _reloadLock = new(1, 1);
    private volatile bool _stopping;

    /// <summary>One listening socket. Its binding and generation are swapped together on reload.</summary>
    private sealed class Listener(Socket socket, ListenBinding binding, HttpRuntime rt)
    {
        public readonly Socket Socket = socket;
        public volatile State Current = new(binding, rt);
        public sealed record State(ListenBinding Binding, HttpRuntime Rt);
    }

    internal HttpServer(Func<HttpRuntime> load, Logging.JsonLogger log)
    {
        _load = load;
        _log = log;
        _rt = load(); // configuration errors surface here, before anything is bound
    }

    /// <summary>Actual bound endpoints (port 0 resolved), in binding order.</summary>
    public IReadOnlyList<EndPoint> EndPoints
    {
        get { lock (_listeners) return _rt.Bindings.ConvertAll(b => _listeners[b.ToString()].Socket.LocalEndPoint!); }
    }

    public int ActiveConnections => _mgr.Active;

    public void Start()
    {
        _log.MinLevel = _rt.Main.LogLevel ?? LogLevel.Info;
        _mgr = new ConnectionManager(_rt.Events.MaxConnections, _rt.Events.PerClient, _rt.Log);
        var opened = OpenNew(_rt);
        lock (_listeners)
            foreach (var (key, s, b) in opened) _listeners[key] = new Listener(s, b, _rt);
        StartLoops(opened);
    }

    /// <summary>
    /// Re-read the configuration and switch to it. On any failure (config error, unreadable certificate, port
    /// in use) the running configuration stays as it was. Returns whether the new configuration is live.
    /// </summary>
    public Task<bool> ReloadAsync() => ReloadAsync(_load);

    internal async Task<bool> ReloadAsync(Func<HttpRuntime> load)
    {
        await _reloadLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_stopping) return false;
            HttpRuntime next;
            try { next = load(); }
            catch (Exception e) when (e is ConfigException or InvalidOperationException or IOException)
            {
                var at = (e as ConfigException)?.Where?.ToString();
                _rt.Log.Error("reload failed, keeping the running configuration", new("error", e.Message), new("at", at));
                return false;
            }

            List<(string Key, Socket Socket, ListenBinding Binding)> opened;
            try { opened = OpenNew(next); }
            catch (IOException e)
            {
                next.Retire();
                _rt.Log.Error("reload failed, keeping the running configuration", new LogField("error", e.Message));
                return false;
            }

            var prev = _rt;
            var closing = new List<(Socket, ListenBinding)>();
            lock (_listeners)
            {
                var wanted = new HashSet<string>(StringComparer.Ordinal);
                foreach (var b in next.Bindings)
                {
                    var key = b.ToString();
                    wanted.Add(key);
                    if (!_listeners.TryGetValue(key, out var l)) continue;
                    var old = l.Current.Binding;
                    if (old.ReusePort != b.ReusePort || old.Backlog != b.Backlog)
                        _rt.Log.Warn("listen option change needs a restart; keeping the socket as it is", new LogField("addr", key));
                    l.Current = new Listener.State(b, next);
                }
                foreach (var (key, l) in _listeners)
                    if (!wanted.Contains(key)) closing.Add((l.Socket, l.Current.Binding));
                foreach (var (_, b) in closing) _listeners.Remove(b.ToString());
                foreach (var (key, sock, b) in opened) _listeners[key] = new Listener(sock, b, next);
                _rt = next;
            }
            StartLoops(opened);
            foreach (var (sock, b) in closing)
            {
                _rt.Log.Info("stopped listening", new LogField("addr", b.ToString()));
                CloseListener(sock, b);
            }

            _log.MinLevel = next.Main.LogLevel ?? LogLevel.Info;
            if (next.Events.MaxConnections != prev.Events.MaxConnections)
                _rt.Log.Warn("worker_connections change needs a restart", new LogField("running", (long)prev.Events.MaxConnections));
            _mgr.PerClientMax = next.Events.PerClient;
            prev.Retire(Environment.TickCount64 + next.Main.ReloadDrainTimeoutMs);
            _mgr.RetireIdle(); // old idle keep-alives close now; busy ones finish their request first
            _rt.Log.Info("configuration reloaded", new LogField("listeners", (long)next.Bindings.Count));
            return true;
        }
        finally { _reloadLock.Release(); }
    }

    /// <summary>Bind every binding of <paramref name="rt"/> that isn't already open. All or nothing.</summary>
    private List<(string Key, Socket Socket, ListenBinding Binding)> OpenNew(HttpRuntime rt)
    {
        var opened = new List<(string, Socket, ListenBinding)>();
        foreach (var b in rt.Bindings)
        {
            var key = b.ToString();
            lock (_listeners) if (_listeners.ContainsKey(key)) continue;
            Socket s;
            try { s = Bind(b); }
            catch (Exception e) when (e is SocketException or IOException or UnauthorizedAccessException)
            {
                foreach (var (_, os, ob) in opened) CloseListener(os, ob);
                throw new IOException($"cannot listen on {b}: {e.Message}", e);
            }
            opened.Add((key, s, b));
            rt.Log.Info("listening", new("addr", s.LocalEndPoint?.ToString() ?? key), new("ssl", b.Ssl));
        }
        return opened;
    }

    private void StartLoops(List<(string Key, Socket Socket, ListenBinding Binding)> opened)
    {
        int loops = Math.Clamp(Environment.ProcessorCount / 2, 1, 4);
        foreach (var (key, _, _) in opened)
        {
            Listener l;
            lock (_listeners) l = _listeners[key];
            for (int i = 0; i < loops; i++) _loops.Add(Task.Run(() => AcceptLoop(l)));
        }
    }

    private static void CloseListener(Socket s, ListenBinding b)
    {
        s.Dispose();
        if (b.EndPoint is UnixDomainSocketEndPoint u) try { File.Delete(u.ToString()); } catch (IOException) { }
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

    private async Task AcceptLoop(Listener listener)
    {
        while (!_stopping)
        {
            Socket s;
            try { s = await listener.Socket.AcceptAsync().ConfigureAwait(false); }
            catch (ObjectDisposedException) { return; }
            catch (SocketException e)
            {
                if (_stopping || !listener.Socket.IsBound) return;
                // EMFILE/ENFILE and friends: back off rather than spin.
                _rt.Log.Warn("accept failed", new LogField("error", e.SocketErrorCode.ToString()));
                await Task.Delay(100).ConfigureAwait(false);
                continue;
            }

            EndPoint? remote;
            try { remote = s.RemoteEndPoint; }
            catch (SocketException) { s.Dispose(); continue; }
            var conn = new Connection(_mgr.NextId(), s, IpKey.From(remote));
            // Pin a generation; a reload between reading and pinning just means we read again.
            Listener.State st;
            while (!(st = listener.Current).Rt.TryAcquire()) { }
            conn.Generation = st.Rt;
            if (!_mgr.TryAdmit(conn, out var why))
            {
                st.Rt.Release();
                st.Rt.Log.Debug("connection refused", new("remote", remote?.ToString()), new("reason", why));
                conn.Abort(why!);
                continue;
            }
            if (s.AddressFamily != AddressFamily.Unix) s.NoDelay = true;
            var session = new Http1Session(conn, st.Binding, st.Rt, _mgr);
            ThreadPool.UnsafeQueueUserWorkItem(static x => _ = x.RunAsync(), session, preferLocal: false);
        }
    }

    /// <summary>Stop accepting, let in-flight requests finish (idle keep-alives close at once), then cut the rest.</summary>
    public async Task StopAsync(int timeoutMs)
    {
        if (_stopping) return;
        await _reloadLock.WaitAsync().ConfigureAwait(false);
        try
        {
            _stopping = true;
            if (_mgr is null) { _rt.Retire(); return; } // never started
            _mgr.BeginShutdown();
            lock (_listeners)
            {
                foreach (var (_, l) in _listeners) CloseListener(l.Socket, l.Current.Binding);
                _listeners.Clear();
            }
            long deadline = Environment.TickCount64 + timeoutMs;
            while (_mgr.Active > 0 && Environment.TickCount64 < deadline) await Task.Delay(50).ConfigureAwait(false);
            if (_mgr.Active > 0)
            {
                _rt.Log.Warn("shutdown timeout, aborting connections", new LogField("count", (long)_mgr.Active));
                _mgr.AbortAll("shutdown");
            }
            try { await Task.WhenAll(_loops).ConfigureAwait(false); } catch (Exception) { /* loops end on listener disposal */ }
            _rt.Retire();
            _mgr.Dispose();
        }
        finally { _reloadLock.Release(); }
    }

    public int ShutdownTimeoutMs => _rt.Main.ShutdownTimeoutMs;

    public async ValueTask DisposeAsync() => await StopAsync(0).ConfigureAwait(false);
}
