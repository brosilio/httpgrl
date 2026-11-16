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
    private readonly Func<IReadOnlyDictionary<string, object>, HttpRuntime> _load;
    private readonly Logging.JsonLogger _log;
    private HttpRuntime _rt = null!;
    private ConnectionManager _mgr = null!;
    /// <summary>Keyed by endpoint (see <see cref="ListenBinding.ToString"/>).</summary>
    private readonly Dictionary<string, Listener> _listeners = new(StringComparer.Ordinal);
    /// <summary><c>listen tunnel:NAME</c> bindings, keyed by tunnel name. Guarded by <see cref="_listeners"/>.</summary>
    private readonly Dictionary<string, TunnelDialer> _tunnels = new(StringComparer.Ordinal);
    private readonly List<Task> _loops = new();
    private readonly SemaphoreSlim _reloadLock = new(1, 1);
    private volatile bool _stopping;

    /// <summary>One listening socket. Its binding and generation are swapped together on reload.</summary>
    private sealed class Listener(Socket socket, ListenBinding binding, HttpRuntime rt)
    {
        public readonly Socket Socket = socket;
        /// <summary>A quic listener's HTTP/3 side (null for TCP).</summary>
        public Quic.QuicEndpoint? Endpoint;
        public Http3.Http3Application? App;
        public volatile State Current = new(binding, rt);
        /// <summary>Set when a reload drops this address: its connections can't move to a newer configuration.</summary>
        public volatile bool Closed;
        public (ListenBinding, HttpRuntime)? Now() => Closed ? null : (Current.Binding, Current.Rt);
        public sealed record State(ListenBinding Binding, HttpRuntime Rt);
    }

    internal HttpServer(Func<IReadOnlyDictionary<string, object>, HttpRuntime> load, Logging.JsonLogger log)
    {
        _load = load;
        _log = log;
        _rt = load(new Dictionary<string, object>()); // configuration errors surface here, before anything is bound
    }

    /// <summary>Actual bound endpoints (port 0 resolved), in binding order.</summary>
    public IReadOnlyList<EndPoint> EndPoints
    {
        get { lock (_listeners) return _rt.Bindings.FindAll(b => b.Tunnel is null).ConvertAll(b => _listeners[b.ToString()].Socket.LocalEndPoint!); }
    }

    public int ActiveConnections => _mgr.Active;

    /// <summary>Bound quic (HTTP/3) endpoints, for tests.</summary>
    internal IReadOnlyList<EndPoint> QuicEndPoints
    {
        get { lock (_listeners) return _listeners.Values.Where(l => l.Endpoint is not null).Select(l => l.Socket.LocalEndPoint!).ToList(); }
    }

    /// <summary>Open HTTP/3 connections across quic listeners, for tests.</summary>
    internal int QuicConnections
    {
        get { lock (_listeners) return _listeners.Values.Sum(l => l.Endpoint?.Connections ?? 0); }
    }

    public void Start()
    {
        _log.MinLevel = _rt.Main.LogLevel ?? LogLevel.Info;
        _mgr = new ConnectionManager(_rt.Events.MaxConnections, _rt.Events.PerClient, _rt.Log) { DroppedLogLines = () => _log.DroppedTotal };
        var opened = OpenNew(_rt);
        lock (_listeners)
            foreach (var (key, s, b) in opened) _listeners[key] = new Listener(s, b, _rt);
        StartLoops(opened);
        SyncTunnels(_rt);
    }

    /// <summary>Tunnel dialers for <paramref name="rt"/>: kept (and switched over) while a tunnel's identity is unchanged, else replaced.</summary>
    private void SyncTunnels(HttpRuntime rt)
    {
        var start = new List<TunnelDialer>();
        var stop = new List<TunnelDialer>();
        lock (_listeners)
        {
            var wanted = new HashSet<string>(StringComparer.Ordinal);
            foreach (var b in rt.Bindings)
            {
                if (b.Tunnel is not { } spec) continue;
                wanted.Add(spec.Name);
                if (_tunnels.TryGetValue(spec.Name, out var d))
                {
                    if (d.Spec.Identity == spec.Identity) { d.Update(b, rt); continue; }
                    // New remote, certificate or trust: connections made under the old settings mustn't carry on.
                    stop.Add(d);
                }
                var nd = new TunnelDialer(b, rt, _mgr);
                _tunnels[spec.Name] = nd;
                start.Add(nd);
            }
            foreach (var (name, d) in _tunnels)
                if (!wanted.Contains(name)) stop.Add(d);
            foreach (var d in stop)
                if (_tunnels.TryGetValue(d.Spec.Name, out var cur) && ReferenceEquals(cur, d)) _tunnels.Remove(d.Spec.Name);
        }
        foreach (var d in stop) d.Close();
        foreach (var d in start)
        {
            rt.Log.Info("tunnel started", new("tunnel", d.Spec.Name), new("remote", d.Spec.Host + ":" + d.Spec.Port), new("pool", (long)d.Spec.Pool));
            d.Start();
        }
    }

    /// <summary>Idle and total connections of a tunnel (tests).</summary>
    internal (int Idle, int Total)? TunnelCounts(string name)
    {
        lock (_listeners) return _tunnels.TryGetValue(name, out var d) ? d.Counts() : null;
    }

    /// <summary>
    /// Re-read the configuration and switch to it. On any failure (config error, unreadable certificate, port
    /// in use) the running configuration stays as it was. Returns whether the new configuration is live.
    /// </summary>
    public Task<bool> ReloadAsync() => ReloadAsync(_load);

    internal async Task<bool> ReloadAsync(Func<IReadOnlyDictionary<string, object>, HttpRuntime> load)
    {
        await _reloadLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_stopping) return false;
            HttpRuntime next;
            try { next = load(_rt.Persistent); }
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
                    if (b.Tunnel is not null) continue;
                    var key = b.ToString();
                    wanted.Add(key);
                    if (!_listeners.TryGetValue(key, out var l)) continue;
                    var old = l.Current.Binding;
                    if (old.ReusePort != b.ReusePort || old.Backlog != b.Backlog)
                        _rt.Log.Warn("listen option change needs a restart; keeping the socket as it is", new LogField("addr", key));
                    l.Current = new Listener.State(b, next);
                    if (l.App is not null)
                    {
                        l.App.Update(b, next);
                        l.Endpoint!.Update(QuicOptions(b, next));
                    }
                }
                foreach (var (key, l) in _listeners)
                    if (!wanted.Contains(key)) closing.Add((l.Socket, l.Current.Binding));
                foreach (var (_, b) in closing)
                {
                    var gone = _listeners[b.ToString()];
                    gone.Closed = true;
                    gone.Endpoint?.Dispose(); // its connections end with the socket
                    _listeners.Remove(b.ToString());
                }
                foreach (var (key, sock, b) in opened) _listeners[key] = new Listener(sock, b, next);
                _rt = next;
            }
            StartLoops(opened);
            SyncTunnels(next);
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
            _mgr.CountReload();
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
            if (b.Tunnel is not null) continue; // dialed, not bound
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
            rt.Log.Info("listening", new("addr", s.LocalEndPoint?.ToString() ?? key), new("ssl", b.Ssl), new("quic", b.Quic));
        }
        return opened;
    }

    private void StartLoops(List<(string Key, Socket Socket, ListenBinding Binding)> opened)
    {
        int loops = Math.Clamp(Environment.ProcessorCount / 2, 1, 4);
        foreach (var (key, _, b) in opened)
        {
            Listener l;
            lock (_listeners) l = _listeners[key];
            if (b.Quic) { StartQuic(l); continue; }
            for (int i = 0; i < loops; i++) _loops.Add(Task.Run(() => AcceptLoop(l)));
        }
    }

    /// <summary>A quic listener: HTTP/3 on its UDP socket, one endpoint thread, following reloads.</summary>
    private void StartQuic(Listener l)
    {
        var (b, rt) = (l.Current.Binding, l.Current.Rt);
        var app = new Http3.Http3Application(_mgr);
        app.Update(b, rt);
        var ep = new Quic.QuicEndpoint(l.Socket, null, _ => null, app, new Logging.QuicLogAdapter(rt.Log), QuicOptions(b, rt));
        app.Attach(ep);
        l.App = app;
        l.Endpoint = ep;
        ep.Start();
    }

    private static Quic.QuicEndpointOptions QuicOptions(ListenBinding b, HttpRuntime rt)
    {
        var core = b.Hosts.Default.Root.Core;
        return new Quic.QuicEndpointOptions
        {
            Retry = core.QuicRetryEnabled,
            Gso = core.QuicGsoEnabled,
            MaxConnections = rt.Events.MaxConnections,
            MaxConnectionsPerClient = rt.Events.PerClient,
        };
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
        else if (b.Quic)
        {
            var ip = (IPEndPoint)b.EndPoint;
            s = new Socket(ip.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            if (ip.AddressFamily == AddressFamily.InterNetworkV6) s.DualMode = false;
            if (OperatingSystem.IsWindows()) s.ExclusiveAddressUse = true;
            else SetReuseAddrOnly(s);
            if (b.ReusePort) SetReusePort(s);
            s.ReceiveBufferSize = Math.Max(s.ReceiveBufferSize, 4 << 20);
            s.SendBufferSize = Math.Max(s.SendBufferSize, 4 << 20);
            try { s.Bind(b.EndPoint); }
            catch { s.Dispose(); throw; }
            return s;
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
                // A reload that drops this address closes the socket under the pending accept: that's the end, not an error.
                if (_stopping || listener.Closed || !listener.Socket.IsBound || e.SocketErrorCode == SocketError.OperationAborted) return;
                // EMFILE/ENFILE and friends: back off rather than spin.
                _rt.Log.Warn("accept failed", new LogField("error", e.SocketErrorCode.ToString()));
                await Task.Delay(100).ConfigureAwait(false);
                continue;
            }

            EndPoint? remote;
            try { remote = s.RemoteEndPoint; }
            catch (SocketException) { s.Dispose(); continue; }
            _mgr.CountAccepted();
            var conn = new Connection(_mgr.NextId(), s, IpKey.From(remote));
            // Pin a generation; a reload between reading and pinning just means we read again.
            // A listener a reload dropped keeps its last (now retired) state forever: give up on it rather than spin.
            Listener.State st;
            bool pinned;
            while (!(pinned = (st = listener.Current).Rt.TryAcquire()) && !listener.Closed && !_stopping) { }
            if (!pinned) { s.Dispose(); return; }
            conn.Generation = st.Rt;
            conn.Tls = st.Binding.Ssl;
            if (!_mgr.TryAdmit(conn, out var why))
            {
                st.Rt.Release();
                st.Rt.Log.Debug("connection refused", new("remote", remote?.ToString()), new("reason", why));
                conn.Abort(why!);
                continue;
            }
            if (s.AddressFamily != AddressFamily.Unix) s.NoDelay = true;
            var session = new Http1Session(conn, st.Binding, st.Rt, _mgr, listener.Now);
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
            _rt.SignalRetiring(); // long-lived handlers (parked tunnel connections) wind down instead of holding up the exit
            List<TunnelDialer> dialers;
            List<Listener> quic;
            lock (_listeners)
            {
                quic = _listeners.Values.Where(l => l.Endpoint is not null).ToList();
                foreach (var (_, l) in _listeners) if (l.Endpoint is null) CloseListener(l.Socket, l.Current.Binding);
                _listeners.Clear();
                dialers = [.. _tunnels.Values];
                _tunnels.Clear();
            }
            foreach (var d in dialers) d.Close();
            long deadline = Environment.TickCount64 + timeoutMs;
            // HTTP/3: GOAWAY everywhere, requests finish (within the timeout), then the sockets close.
            foreach (var l in quic) { var app = l.App!; l.Endpoint!.Post(app.GoAwayAll); }
            while (quic.Exists(l => l.Endpoint!.Connections > 0) && Environment.TickCount64 < deadline) await Task.Delay(50).ConfigureAwait(false);
            foreach (var l in quic) { l.Endpoint!.Dispose(); CloseListener(l.Socket, l.Current.Binding); }
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
