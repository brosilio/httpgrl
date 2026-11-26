using System.Net.Sockets;
using Httpgrl.Core.Hosting;
using Httpgrl.Core.Http;
using Httpgrl.Core.Http2;
using Httpgrl.Core.Modules;
using Httpgrl.Core.Pipeline;
using Httpgrl.Http3;
using Httpgrl.HttpFields;
using Httpgrl.Quic;

namespace Httpgrl.Core.Http3;

/// <summary>
/// The server's side of one HTTP/3 connection: the protocol is <see cref="Http3ServerConnection"/>'s; this maps its
/// requests onto the request pipeline (the same lifecycle as HTTP/1.1 and HTTP/2), follows reloads, and logs. It runs
/// on the endpoint's thread, except the handler-facing methods, which say so.
/// </summary>
internal sealed class Http3Connection : IHttp3ServerHandler
{
    public readonly QuicConnection Q;
    public readonly Http3ServerConnection H;
    private readonly QuicEndpoint _ep;
    private readonly HttpRuntime _rt;
    private readonly VirtualHosts _hosts;
    private readonly ConnectionManager _mgr;
    private readonly ConnectionInfo _info;
    private readonly HttpCoreConf _core;
    private readonly ILogger _log;
    private readonly long _id;
    private readonly RequestHead _head;
    private readonly CancellationTokenRegistration _retired;

    public Http3Connection(QuicConnection q, QuicEndpoint ep, HttpRuntime rt, VirtualHosts hosts, ConnectionManager mgr, HttpCoreConf core, long id)
    {
        Q = q;
        _ep = ep;
        _rt = rt;
        _hosts = hosts;
        _mgr = mgr;
        _core = core;
        _log = rt.Log;
        _id = id;
        _info = new ConnectionInfo(id, q.Path, ep.LocalEndPoint, isTls: true);
        _head = new RequestHead(core.UnderscoresInHeaders == true, HttpVersion.Http30);
        H = new Http3ServerConnection(q, ep, this, new Http3ServerOptions
        {
            MaxFieldSectionSize = core.HeaderTotalMax,
            EnableConnectProtocol = true, // WebSockets over HTTP/3 (RFC 9220)
            RequestHeadTimeoutUs = core.ClientHeaderTimeoutMs * 1000L,
        });
        // A reload (or shutdown) retires this generation: GOAWAY at once, not at the endpoint's next idle tick.
        _retired = rt.RetiredToken.Register(static o => { var h = (Http3Connection)o!; h._ep.Run(h.Q, _ => h.Tick(QuicEndpoint.Now())); }, this);
    }

    public void OnEvent(in QuicEvent e, long now) => H.OnEvent(e, now);

    void IHttp3ServerHandler.OnConnected(Http3ServerConnection c) => _info.SetTls(Q.ServerName, "TLSv1.3", Q.ClientCertificate, Q.ClientVerify);

    void IHttp3ServerHandler.OnConnectionError(H3Error code, string why)
    {
        _log.Warn("security", new("event", why == "request header timeout" ? "header_deadline_exceeded" : "http3_connection_rejected"), new("conn", _id), new("remote", _info.RemoteAddress));
        _log.Info("http/3 connection error", new("conn", _id), new("code", code.ToString()), new("reason", why), new("remote", _info.RemoteAddress));
    }

    void IHttp3ServerHandler.OnStreamError(long streamId, H3Error code, string why) =>
        _log.Info("http/3 stream error", new("event", "http3_stream_rejected"), new("conn", _id), new("stream", streamId), new("code", code.ToString()), new("reason", why));

    string? IHttp3ServerHandler.CheckTrailer(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value) => RequestHead.CheckTrailer(name, value);

    IHttp3Request IHttp3ServerHandler.OnRequest(Http3ServerConnection c, long streamId, ReadOnlySpan<byte> block, bool endStream)
    {
        var stream = new H3Stream(streamId, this);
        var ctx = new HttpContextImpl(_rt, _info, stream, stream.Body, stream.Wire) { Mgr = _mgr, Upgrader = () => new H3TunnelStream(stream) };
        stream.Ctx = ctx;
        ctx.BeginRequest();
        _head.Begin(ctx.Req);
        int code;
        try
        {
            H.DecodeFields(block, _head.OnField);
            // The request has no body if the stream already ended: HTTP/3 has no END_STREAM flag on HEADERS, so only a
            // FIN right behind tells us; until then a body may follow (content-length, or DATA of unknown length).
            code = _head.Finish(endStream);
        }
        catch (QpackException e) when (e.Limit) { code = 431; }
        catch (QpackException e) { throw new H3Exception(H3Error.QpackDecompressionFailed, e.Message); }
        if (code == -1)
        {
            ctx.EndRequest();
            throw new H3Exception(H3Error.MessageError, _head.Why ?? "malformed request", connection: false);
        }
        if (code == 0 && ctx.Req.ContentLengthValue >= 0) stream.Body.Expected = ctx.Req.ContentLengthValue;
        if (endStream) stream.Body.Deliver(default, end: true);
        if (code == 0 && ctx.Req.ExpectContinue) stream.Body.SendContinue = () => stream.Wire.SendInterimAsync(100);
        _info.CountRequest();
        if (_info.Requests >= _core.KeepaliveRequestsMax) H.GoAway(); // keepalive_requests, as on the other protocols
        _mgr.Track(stream);
        // The handler's writes and its end are posted to this thread, so they come after we've returned the stream.
        _ = Task.Run(() => RunStreamAsync(stream, code));
        return stream;
    }

    // ------------------------------------------------------------------ the handler's side (thread pool)

    private async Task RunStreamAsync(H3Stream s, int code)
    {
        var ctx = s.Ctx;
        try
        {
            int reject = RequestLifecycle.Route(ctx, _hosts, TlsServer(), code > 0 ? code : 0);
            ctx.SetKeepAlive(true);
            s.Phase = "processing";
            bool clean = await RequestLifecycle.RunAsync(ctx, reject).ConfigureAwait(false);
            if (!clean && !s.IsAborted) s.Abort(ctx.Dropped ? "dropped" : "response incomplete", ctx.Dropped ? H3Error.RequestCancelled : H3Error.InternalError, reset: true);
            await RequestLifecycle.FinishAsync(ctx, _mgr).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException or OperationCanceledException or InvalidOperationException) { }
        catch (Exception e)
        {
            _log.Error("http/3 stream failed", new("conn", _id), new("stream", s.Id), new("error", e.GetType().Name), new("detail", e.Message), new("stack", e.StackTrace));
        }
        finally
        {
            await RequestLifecycle.FinishAsync(ctx, _mgr).ConfigureAwait(false);
            ctx.EndRequest();
            ctx.Resp.ReturnBuffer();
            _mgr.Untrack(s);
            s.Body.Release();
            s.Dispose();
            H.Finished(s.Id);
        }
    }

    /// <summary>
    /// The server whose context the handshake finished under (SNI): its client-certificate policy is what was checked,
    /// so Route refuses (421) a Host leading to a server with a different one, exactly as on TCP.
    /// </summary>
    private ServerRt TlsServer()
    {
        var s = Q.ServerName is { } sni ? _hosts.Resolve(sni) : _hosts.Default;
        // The context may differ from that server's (no SNI, or the default had none): find the one it belongs to.
        if (!ReferenceEquals(s.Scope.Get<SslConf>().QuicTls, Q.TlsContext))
            foreach (var x in _hosts.Servers)
                if (ReferenceEquals(x.Scope.Get<SslConf>().QuicTls, Q.TlsContext)) return x;
        return s;
    }

    /// <summary>Handler side: put bytes on the stream, waiting until QUIC has taken them (back-pressure).</summary>
    public ValueTask WriteAsync(H3Stream s, ReadOnlyMemory<byte> data, bool fin)
    {
        if (s.IsAborted) return ValueTask.FromException(new IOException("stream reset"));
        return new ValueTask(AwaitWrite(s, H.WriteAsync(s.Id, data, fin)));
    }

    private static async Task AwaitWrite(H3Stream s, Task done)
    {
        s.BeginWrite();
        try { await done.ConfigureAwait(false); }
        finally { s.EndWrite(0); }
    }

    /// <summary>Handler side: the body was read below its window: read more from the QUIC stream.</summary>
    public void ResumeReading(H3Stream s) => H.ResumeReading(s.Id);

    /// <summary>Handler side (or sweeper): reset the stream both ways.</summary>
    public void ResetLater(H3Stream s, H3Error code) => H.ResetLater(s.Id, code);

    /// <summary>Any thread: fail a write that's waiting (the stream is gone).</summary>
    public void FailWrites(H3Stream s) => H.FailWrites(s.Id);

    // ------------------------------------------------------------------ winding down

    /// <summary>GOAWAY: stop taking requests (reload, shutdown, keepalive_requests).</summary>
    public void GoAway() => H.GoAway();

    /// <summary>Endpoint thread, once per loop turn: the protocol's deadlines, then follow a reload (GOAWAY, then the drain deadline).</summary>
    public void Tick(long now)
    {
        H.Tick(now);
        if (!_rt.Retired) return;
        H.GoAway();
        if (Environment.TickCount64 > _rt.RetireDeadline) H.CloseNow("reload drain timeout", now);
    }

    /// <summary>The QUIC connection is gone: stop every handler.</summary>
    public void Closed()
    {
        _retired.Dispose();
        H.Closed();
    }
}
