using System.Buffers;
using System.Buffers.Text;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Security.Authentication;
using System.IO.Pipelines;
using System.Text;

namespace Httpgrl.Modules.Proxy;

internal static class ProxyHandler
{
    private const int MinConnBuffer = 64 << 10;
    private const int MaxChunkLine = 4096;
    private const int StaleRetries = 2;

    public static async ValueTask<HandlerResult> HandleAsync(HttpContext ctx, ProxyConf conf)
    {
        ProxyTarget t;
        string? dynUri = null;
        if (conf.DynUrl is { } dyn)
        {
            var v = dyn.Evaluate(ctx);
            int slash = v.IndexOf('/');
            var name = slash < 0 ? v : v[..slash];
            if (slash >= 0) dynUri = v[slash..];
            if (!conf.DynTargets!.TryGetValue(name, out t!))
            {
                ctx.Log.Warn("proxy_pass variable doesn't name an upstream block", new("value", name), new("uri", ctx.Request.Path));
                return HandlerResult.WithStatus(502);
            }
            ctx.Items[ChosenTargetKey] = t;
        }
        else t = conf.Target!;
        var req = ctx.Request;
        if (req.IsChunked && conf.Version == 10) return HandlerResult.WithStatus(411);
        bool upgrade = conf.UpgradeEnabled && conf.Version == 11 && WantsUpgrade(req);
        bool keepAlive = !upgrade && conf.Version == 11 && t.Group.KeepAlive > 0;
        var uri = dynUri is not null ? EscapeRequestUri(dynUri) : BuildUri(ctx, conf, t);
        if (uri is null)
        {
            ctx.Log.Error("proxy_pass URI from variables doesn't start with \"/\"", new LogField("uri", ctx.Request.Path));
            return HandlerResult.WithStatus(500);
        }
        var head = BuildRequestHead(ctx, conf, t, uri, upgrade, keepAlive);
        bool idempotent = IsIdempotent(req.Method);
        t.Dns?.EnsureStarted();
        t.Health?.EnsureStarted(); // before anything that depends on the peer count: an upstream with no addresses yet must still recover
        int maxTries = conf.NextUpstreamTries is int n and > 0 ? n : t.Group.Count;
        var tried = new List<UpstreamServer>(2);
        var abort = ctx.Aborted;
        int failStatus = 502, stale = 0;

        while (tried.Count < maxTries)
        {
            var server = t.Group.Pick(tried);
            if (server is null) break;
            var conn = t.Group.TakeIdle(server, t.Ssl);
            bool reused = conn is not null;
            if (conn is null && t.Group.Tunnel is { } pool)
            {
                // No agent connection parked: the agent refills its pool as soon as one is taken, so wait a little.
                conn = await pool.WaitAsync(conf.ConnectTimeoutMs, abort).ConfigureAwait(false);
                if (conn is null)
                {
                    if (abort.IsCancellationRequested) return HandlerResult.Drop;
                    tried.Add(server);
                    failStatus = 502;
                    ctx.Log.Warn("no tunnel connection available", new("upstream", server.Display), new("uri", req.RawTarget));
                    continue;
                }
                reused = true; // a parked connection, like a pooled one: if it turns out dead, retry quietly
            }
            if (conn is null)
            {
                try { conn = await UpstreamConn.ConnectAsync(server, t, conf.ConnectTimeoutMs, Math.Max(conf.HeaderBufferSize, MinConnBuffer), abort).ConfigureAwait(false); }
                catch (Exception e) when (e is SocketException or IOException or OperationCanceledException or AuthenticationException)
                {
                    if (abort.IsCancellationRequested) return HandlerResult.Drop;
                    bool timedOut = e is OperationCanceledException;
                    t.Group.Fail(server);
                    tried.Add(server);
                    failStatus = timedOut ? 504 : 502;
                    ctx.Log.Warn(timedOut ? "upstream connect timed out" : "upstream connect failed",
                        new("upstream", server.Display), new("uri", req.RawTarget), new("error", e.Message));
                    continue;
                }
            }

            conn.Requests++;
            ctx.Items[ProxyModule.UpstreamAddrKey] = server.Display;
            using var onAbort = abort.Register(static c => ((UpstreamConn)c!).Dispose(), conn);
            bool headSent = false, bodyStarted = false;
            UpstreamResponse resp;
            try
            {
                await conn.WriteAsync(head, conf.SendTimeoutMs).ConfigureAwait(false);
                headSent = true;
                if (req.HasBody)
                {
                    bodyStarted = true;
                    resp = await SendBodyAndReadAsync(ctx, conn, conf).ConfigureAwait(false);
                }
                else resp = await UpstreamResponse.ReadAsync(conn, conf.HeaderBufferSize, conf.ReadTimeoutMs, req.IsHead).ConfigureAwait(false);
            }
            catch (ClientBodyException e)
            {
                conn.Dispose();
                ExceptionDispatchInfo.Throw(e.InnerException!); // the core answers 400/413/timeouts for the client side
                throw;
            }
            catch (Exception e) when (e is UpstreamException or IOException or SocketException or OperationCanceledException or ObjectDisposedException)
            {
                conn.Dispose();
                if (abort.IsCancellationRequested) return HandlerResult.Drop;
                bool timedOut = e is OperationCanceledException;
                bool replayable = !bodyStarted && (!headSent || idempotent);
                // A pooled connection the peer closed (or reset) after our liveness check: retry quietly, it's not the peer's
                // fault. Anything the peer actually sent (a malformed or ambiguous answer) is its fault, and is reported.
                bool closedOnUs = e is IOException or SocketException or ObjectDisposedException || (e is UpstreamException { ClosedEarly: true });
                if (reused && closedOnUs && replayable && stale++ < StaleRetries) continue;
                t.Group.Fail(server);
                tried.Add(server);
                failStatus = timedOut ? 504 : 502;
                ctx.Log.Warn(timedOut ? "upstream timed out" : "upstream failed",
                    new("upstream", server.Display), new("uri", req.RawTarget), new("error", e.Message));
                if (!replayable) break;
                continue;
            }

            t.Group.Success(server);
            ctx.Items[ProxyModule.UpstreamStatusKey] = resp.Status.ToString(System.Globalization.CultureInfo.InvariantCulture);
            try { return await RelayAsync(ctx, conf, t, conn, resp, upgrade).ConfigureAwait(false); }
            catch (System.Text.RegularExpressions.RegexMatchTimeoutException)
            {
                conn.Dispose(); // a proxy_redirect regex timed out mid-relay: the core answers 500; the connection mustn't leak
                throw;
            }
        }

        if (tried.Count == 0) ctx.Log.Error("no upstream available", new LogField("upstream", t.Group.Name));
        return HandlerResult.WithStatus(failStatus);
    }

    // ------------------------------------------------------------------ request

    /// <summary>Client asked for a protocol switch we will tunnel. h2c is refused: it would let a client
    /// speak HTTP/2 straight to the backend, past every rule configured here (h2c smuggling).</summary>
    internal static bool WantsUpgrade(HttpRequest req)
    {
        if (req.Version != HttpVersion.Http11) return false;
        var up = req.Headers.Get("Upgrade");
        if (string.IsNullOrWhiteSpace(up)) return false;
        foreach (var r in up.AsSpan().Split(','))
            if (up.AsSpan()[r].Trim(" \t").StartsWith("h2c", StringComparison.OrdinalIgnoreCase)) return false;
        return HasConnectionToken(req.Headers, "upgrade");
    }

    private static bool HasConnectionToken(HeaderCollection h, string token)
    {
        for (int i = 0; i < h.Count; i++)
        {
            if (!h.NameAt(i).Equals("Connection", StringComparison.OrdinalIgnoreCase)) continue;
            var v = h.ValueAt(i);
            foreach (var r in v.AsSpan().Split(','))
                if (v.AsSpan()[r].Trim(" \t").Equals(token, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static bool IsIdempotent(string m) =>
        m is HttpMethods.Get or HttpMethods.Head or HttpMethods.Put or HttpMethods.Delete or HttpMethods.Options or HttpMethods.Trace;

    /// <summary>
    /// Path sent upstream. Default: our normalized path, re-encoded, so we and the backend can't disagree about
    /// what was requested (e.g. "..\" on a Windows backend, or double decoding). <c>proxy_pass_raw_uri on</c>
    /// forwards the client's bytes instead.
    /// </summary>
    private static readonly object ChosenTargetKey = new();

    /// <summary>The target this request is (or would be) proxied to, for $proxy_host / $proxy_port.</summary>
    internal static ProxyTarget? CurrentTarget(HttpContext ctx)
    {
        var c = ctx.Config<ProxyConf>();
        if (c.Target is { } t) return t;
        return ctx.Items.TryGetValue(ChosenTargetKey, out var o) ? o as ProxyTarget : null;
    }

    /// <summary>
    /// A request URI built from variables, made safe for the request line: control characters, spaces and non-ASCII
    /// are percent-encoded ($uri is decoded and may contain them); '%' is kept, so already-encoded input stays as is.
    /// Null if it doesn't start with '/'.
    /// </summary>
    internal static string? EscapeRequestUri(string uri)
    {
        if (!uri.StartsWith('/')) return null;
        int hash = uri.IndexOf('#');
        if (hash >= 0) uri = uri[..hash];
        bool clean = true;
        foreach (char c in uri) if (c is <= ' ' or >= (char)0x7f) { clean = false; break; }
        if (clean) return uri;
        var sb = new StringBuilder(uri.Length + 16);
        foreach (byte b in Encoding.UTF8.GetBytes(uri))
        {
            if (b is > (byte)' ' and < 0x7f) sb.Append((char)b);
            else sb.Append('%').Append("0123456789ABCDEF"[b >> 4]).Append("0123456789ABCDEF"[b & 15]);
        }
        return sb.ToString();
    }

    internal static string BuildUri(HttpContext ctx, ProxyConf conf, ProxyTarget t)
    {
        var req = ctx.Request;
        string uri;
        if (t.UriPart is null)
        {
            if (conf.RawUri == true && req.RawTarget.StartsWith('/')) return req.RawTarget;
            uri = EscapePath(req.Path);
        }
        else
        {
            var path = req.Path;
            var cmp = OperatingSystem.IsLinux() || OperatingSystem.IsFreeBSD() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
            uri = path.StartsWith(t.LocationPrefix!, cmp)
                ? t.UriPart + EscapePath(path[t.LocationPrefix!.Length..])
                : t.UriPart + EscapePath(path);
        }
        return req.Query.Length > 0 ? uri + "?" + req.Query : uri;
    }

    /// <summary>RFC 3986 pchar plus '/': everything else is percent-encoded (UTF-8).</summary>
    internal static string EscapePath(string path)
    {
        bool clean = true;
        foreach (char c in path) if (!IsPathChar(c)) { clean = false; break; }
        if (clean) return path;
        var sb = new StringBuilder(path.Length + 16);
        foreach (byte b in Encoding.UTF8.GetBytes(path))
        {
            if (b < 0x80 && IsPathChar((char)b)) sb.Append((char)b);
            else sb.Append('%').Append("0123456789ABCDEF"[b >> 4]).Append("0123456789ABCDEF"[b & 15]);
        }
        return sb.ToString();
    }

    private static bool IsPathChar(char c) =>
        char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~' or '!' or '$' or '&' or '\'' or '(' or ')' or '*' or '+' or ',' or ';' or '=' or ':' or '@' or '/';

    private static bool IsHopByHop(string name) =>
        name.Equals("Connection", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Proxy-Authenticate", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase)
        || name.Equals("TE", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Trailer", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Upgrade", StringComparison.OrdinalIgnoreCase);

    internal static byte[] BuildRequestHead(HttpContext ctx, ProxyConf conf, ProxyTarget t, string uri, bool upgrade, bool keepAlive)
    {
        var req = ctx.Request;
        var w = new HeadWriter();
        w.Latin1(req.Method).Byte(' ').Latin1(uri).Ascii(conf.Version == 11 ? " HTTP/1.1\r\n" : " HTTP/1.0\r\n");

        var sets = conf.SetHeaders;
        string host = t.HostHeader;
        if (sets is not null)
        {
            foreach (var (name, value) in sets)
            {
                if (!name.Equals("Host", StringComparison.OrdinalIgnoreCase)) continue;
                var v = value.Evaluate(ctx);
                if (v.Length > 0 && SafeValue(v)) host = v;
            }
        }
        w.Ascii("Host: ").Utf8(host).Ascii("\r\n");

        if (sets is not null)
        {
            foreach (var (name, value) in sets)
            {
                if (name.Equals("Host", StringComparison.OrdinalIgnoreCase)) continue;
                var v = value.Evaluate(ctx);
                if (v.Length == 0) continue; // nginx: empty value removes the header
                if (!SafeValue(v))
                {
                    ctx.Log.Warn("proxy_set_header value dropped: contains CR, LF or NUL", new LogField("header", name));
                    continue;
                }
                w.Ascii(name).Ascii(": ").Utf8(v).Ascii("\r\n");
            }
        }

        var h = req.Headers;
        for (int i = 0; i < h.Count; i++)
        {
            var name = h.NameAt(i);
            if (IsHopByHop(name) || name.Equals("Host", StringComparison.OrdinalIgnoreCase)
                || name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)
                || name.Equals("Expect", StringComparison.OrdinalIgnoreCase)
                || HasConnectionToken(h, name) || IsOverridden(sets, name))
                continue;
            w.Ascii(name).Ascii(": ").Latin1(h.ValueAt(i)).Ascii("\r\n");
        }

        if (req.IsChunked) w.Ascii("Transfer-Encoding: chunked\r\n");
        else if (req.ContentLength >= 0) w.Ascii("Content-Length: ").Long(req.ContentLength).Ascii("\r\n");

        if (upgrade) w.Ascii("Connection: upgrade\r\nUpgrade: ").Latin1(h.Get("Upgrade")!).Ascii("\r\n");
        else if (!keepAlive) w.Ascii("Connection: close\r\n");
        w.Ascii("\r\n");
        return w.ToArray();
    }

    private static bool IsOverridden(List<(string Name, ComplexValue Value)>? sets, string name)
    {
        if (sets is null) return false;
        foreach (var (n, _) in sets) if (n.Equals(name, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static bool SafeValue(string v) => v.IndexOfAny(['\r', '\n', '\0']) < 0;

    /// <summary>
    /// Upload the request body while already reading the response. An upstream may answer before it has read the whole
    /// body (401, 413, a redirect) and then stop reading; waiting for the upload to finish first would turn its answer
    /// into a send timeout or a broken pipe (502/504). On an early answer the upload stops (the rest of the client's
    /// body is abandoned, so that client connection closes after the response) and the upstream connection isn't
    /// reused. proxy_read_timeout runs from the end of the upload, as it would have without this.
    /// </summary>
    private static async ValueTask<UpstreamResponse> SendBodyAndReadAsync(HttpContext ctx, UpstreamConn conn, ProxyConf conf)
    {
        using var stopBody = new CancellationTokenSource();
        using var stopWrites = stopBody.Token.Register(static c => ((UpstreamConn)c!).CancelWrites(), conn);
        var send = SendBodyAsync(ctx, conn, conf, stopBody.Token).AsTask();
        var read = UpstreamResponse.ReadAsync(conn, conf.HeaderBufferSize, 0, ctx.Request.IsHead).AsTask();

        if (await Task.WhenAny(send, read).ConfigureAwait(false) == read)
        {
            stopBody.Cancel();
            if (!read.IsCompletedSuccessfully) conn.Dispose(); // the upstream broke: its failure is what gets reported
            await Settle(send).ConfigureAwait(false);
            var early = await read.ConfigureAwait(false); // rethrows a read failure
            early.KeepAlive = false; // part of the body may still be unsent (or half-written): never reuse this connection
            return early;
        }

        // The upload ended first.
        if (!send.IsCompletedSuccessfully)
        {
            var e = send.Exception!.InnerException!;
            // A client-side failure or our own send timeout: stop here. A closed or reset upstream may have answered
            // first, so its response is still read (the timeout below bounds that).
            if (e is ClientBodyException or OperationCanceledException)
            {
                conn.Dispose();
                await Settle(read).ConfigureAwait(false);
                await send.ConfigureAwait(false); // rethrows
            }
        }
        using var timeout = new CancellationTokenSource(conf.ReadTimeoutMs);
        var done = await Task.WhenAny(read, Task.Delay(Timeout.Infinite, timeout.Token)).ConfigureAwait(false);
        if (done != read)
        {
            conn.Dispose();
            await Settle(read).ConfigureAwait(false);
            throw new OperationCanceledException("upstream response timed out");
        }
        var resp = await read.ConfigureAwait(false);
        if (!send.IsCompletedSuccessfully) resp.KeepAlive = false;
        return resp;
    }

    private static async Task Settle(Task t)
    {
        try { await t.ConfigureAwait(false); }
        catch (Exception e) when (e is not OutOfMemoryException) { }
    }

    private static async ValueTask SendBodyAsync(HttpContext ctx, UpstreamConn conn, ProxyConf conf, CancellationToken stop)
    {
        const int Pre = 18, Post = 2; // room for "<hex>\r\n" before and "\r\n" after each chunk
        bool chunked = ctx.Request.IsChunked;
        var buf = ArrayPool<byte>.Shared.Rent(16 << 10);
        var hex = new byte[16];
        try
        {
            var body = ctx.Request.Body;
            while (true)
            {
                int n;
                try { n = await body.ReadAsync(chunked ? buf.AsMemory(Pre, buf.Length - Pre - Post) : buf, stop).ConfigureAwait(false); }
                catch (Exception e) when (e is not OutOfMemoryException && !stop.IsCancellationRequested) { throw new ClientBodyException(e); }
                if (n == 0) break;
                if (!chunked)
                {
                    await conn.WriteAsync(buf.AsMemory(0, n), conf.SendTimeoutMs).ConfigureAwait(false);
                    continue;
                }
                Utf8Formatter.TryFormat((uint)n, hex, out int hl, new StandardFormat('x'));
                int start = Pre - hl - 2;
                hex.AsSpan(0, hl).CopyTo(buf.AsSpan(start));
                buf[Pre - 2] = (byte)'\r';
                buf[Pre - 1] = (byte)'\n';
                buf[Pre + n] = (byte)'\r';
                buf[Pre + n + 1] = (byte)'\n';
                await conn.WriteAsync(buf.AsMemory(start, Pre - start + n + Post), conf.SendTimeoutMs).ConfigureAwait(false);
            }
            if (chunked) await conn.WriteAsync("0\r\n\r\n"u8.ToArray(), conf.SendTimeoutMs).ConfigureAwait(false);
        }
        finally { ArrayPool<byte>.Shared.Return(buf); }
    }

    // ------------------------------------------------------------------ response

    private static async ValueTask<HandlerResult> RelayAsync(HttpContext ctx, ProxyConf conf, ProxyTarget t, UpstreamConn conn, UpstreamResponse up, bool upgrade)
    {
        var r = ctx.Response;
        var hidden = conf.HideHeaders;

        if (up.Status == 101)
        {
            if (!upgrade)
            {
                conn.Dispose();
                ctx.Log.Warn("upstream sent 101 without an upgrade request", new LogField("upstream", conn.Server.Display));
                return HandlerResult.WithStatus(502);
            }
            r.Status = 101;
            CopyHeaders(ctx, conf, up, r.Headers, hidden);
            r.Headers.Set("Connection", "upgrade");
            r.Headers.Set("Upgrade", up.Upgrade ?? ctx.Request.Headers.Get("Upgrade")!);
            var client = await ctx.UpgradeAsync(conf.ReadTimeoutMs).ConfigureAwait(false);
            await TunnelAsync(client, conn, conf).ConfigureAwait(false);
            return HandlerResult.Done;
        }

        if (upgrade) up.KeepAlive = false; // upstream declined the switch; don't reuse a connection that offered one
        if (conf.InterceptErrors == true && up.Status >= 300 && ctx.HasErrorPage(up.Status))
        {
            conn.Dispose();
            return HandlerResult.WithStatus(up.Status);
        }

        r.Status = up.Status;
        // A body known to exceed the buffer can't free the upstream early (backpressure holds it until the client has
        // nearly everything), so buffering it would be pure overhead: stream it.
        bool buffered = conf.Buffering && up.Framing != BodyFraming.None
            && !(up.Framing == BodyFraming.Length && up.ContentLength > conf.BuffersTotal)
            && !string.Equals(up.Headers.Find(h => h.Name.Equals("X-Accel-Buffering", StringComparison.OrdinalIgnoreCase)).Value, "no", StringComparison.OrdinalIgnoreCase);
        CopyHeaders(ctx, conf, up, r.Headers, hidden);
        if (up.ContentLength >= 0 && up.Framing is BodyFraming.Length or BodyFraming.None) r.ContentLength = up.ContentLength;

        if (buffered) return await RelayBufferedAsync(ctx, conf, t, conn, up).ConfigureAwait(false);

        try
        {
            await CopyBodyAsync(conn, new DirectSink(r), up, conf.ReadTimeoutMs).ConfigureAwait(false);
        }
        catch (UpstreamException e)
        {
            conn.Dispose();
            if (ctx.Aborted.IsCancellationRequested) return HandlerResult.Drop;
            ctx.Log.Warn("upstream failed mid-response", new("upstream", conn.Server.Display), new("uri", ctx.Request.RawTarget), new("error", e.Message));
            // Before the head went out this is a clean 502; after, the core cuts the connection so the
            // truncated body can't pass for a complete one.
            return HandlerResult.WithStatus(502);
        }
        catch
        {
            conn.Dispose();
            throw;
        }

        if (up.KeepAlive && up.Framing != BodyFraming.UntilClose && conn.Buffered == 0) t.Group.ReturnIdle(conn);
        else conn.Dispose();
        return HandlerResult.Done;
    }

    private static ValueTask CopyBodyAsync(UpstreamConn conn, BodySink sink, UpstreamResponse up, int timeoutMs) => up.Framing switch
    {
        BodyFraming.Length => CopyLengthAsync(conn, sink, up.ContentLength, timeoutMs),
        BodyFraming.Chunked => CopyChunkedAsync(conn, sink, timeoutMs),
        BodyFraming.UntilClose => CopyUntilCloseAsync(conn, sink, timeoutMs),
        _ => ValueTask.CompletedTask,
    };

    /// <summary>
    /// proxy_buffering: a producer reads the upstream body into a bounded in-memory pipe and hands the connection back
    /// to the pool as soon as the body is complete, however slowly the client reads. The client side flushes whenever
    /// the pipe runs dry, so streamed responses still arrive promptly. Past the buffer size, backpressure applies
    /// (nothing spills to disk). Failures keep their meaning: an upstream failure reaches the client side as an
    /// UpstreamException (502, or a cut connection once the head is out); a client failure closes the upstream.
    /// </summary>
    private static async ValueTask<HandlerResult> RelayBufferedAsync(HttpContext ctx, ProxyConf conf, ProxyTarget t, UpstreamConn conn, UpstreamResponse up)
    {
        long limit = conf.BuffersTotal;
        // Fast path: the whole body already arrived with the head (most small responses). Copy it out, hand the
        // connection back at once, then write: no pipe, no second task.
        if (up.Framing == BodyFraming.Length && up.ContentLength <= conn.Buffered && up.ContentLength <= limit)
        {
            int len = (int)up.ContentLength;
            var copy = ArrayPool<byte>.Shared.Rent(Math.Max(1, len));
            try
            {
                conn.Buf.AsSpan(conn.Start, len).CopyTo(copy);
                conn.Start += len;
                if (up.KeepAlive && conn.Buffered == 0) t.Group.ReturnIdle(conn);
                else conn.Dispose();
                await ctx.Response.WriteAsync(copy.AsMemory(0, len)).ConfigureAwait(false);
            }
            finally { ArrayPool<byte>.Shared.Return(copy); }
            return HandlerResult.Done;
        }
        var pipe = new Pipe(new PipeOptions(pauseWriterThreshold: limit, resumeWriterThreshold: limit / 2, minimumSegmentSize: 16384, useSynchronizationContext: false));
        int state = 0; // 0 running, 1 producer finished (connection handed back), 2 consumer gave up
        var producer = ProduceAsync();
        var r = ctx.Response;
        var reader = pipe.Reader;
        try
        {
            while (true)
            {
                if (!reader.TryRead(out var res))
                {
                    await r.FlushAsync().ConfigureAwait(false); // about to wait for the upstream: give the client what we have
                    res = await reader.ReadAsync().ConfigureAwait(false);
                }
                foreach (var seg in res.Buffer) await r.WriteAsync(seg).ConfigureAwait(false);
                reader.AdvanceTo(res.Buffer.End);
                if (res.IsCompleted) break;
            }
            await reader.CompleteAsync().ConfigureAwait(false);
        }
        catch (UpstreamException e)
        {
            await reader.CompleteAsync().ConfigureAwait(false);
            if (ctx.Aborted.IsCancellationRequested) return HandlerResult.Drop;
            ctx.Log.Warn("upstream failed mid-response", new("upstream", conn.Server.Display), new("uri", ctx.Request.RawTarget), new("error", e.Message));
            return HandlerResult.WithStatus(502);
        }
        catch (Exception e)
        {
            await reader.CompleteAsync(e).ConfigureAwait(false);
            if (Interlocked.CompareExchange(ref state, 2, 0) == 0) conn.Dispose(); // unblocks a producer waiting on the upstream
            await producer.ConfigureAwait(false);
            throw;
        }
        await producer.ConfigureAwait(false);
        return HandlerResult.Done;

        async Task ProduceAsync()
        {
            var writer = pipe.Writer; // runs inline until its first real wait, then beside the consumer
            try
            {
                await CopyBodyAsync(conn, new PipeSink(writer), up, conf.ReadTimeoutMs).ConfigureAwait(false);
                await writer.CompleteAsync().ConfigureAwait(false);
            }
            catch (Exception e)
            {
                conn.Dispose();
                await writer.CompleteAsync(e is UpstreamException ? e : new UpstreamException("upstream read failed: " + e.Message)).ConfigureAwait(false);
                return;
            }
            if (Interlocked.CompareExchange(ref state, 1, 0) != 0) return; // the client side already gave up and closed it
            if (up.KeepAlive && up.Framing != BodyFraming.UntilClose && conn.Buffered == 0) t.Group.ReturnIdle(conn);
            else conn.Dispose();
        }
    }

    private static void CopyHeaders(HttpContext ctx, ProxyConf conf, UpstreamResponse up, HeaderCollection into, List<string>? hidden)
    {
        var rules = conf.RedirectRules;
        foreach (var (name, value) in up.Headers)
        {
            if (IsHopByHop(name) || up.IsConnectionListed(name)) continue;
            if (name.Equals("X-Accel-Buffering", StringComparison.OrdinalIgnoreCase)) continue; // addressed to us, as in nginx
            if (hidden is not null && hidden.Exists(x => x.Equals(name, StringComparison.OrdinalIgnoreCase))) continue;
            var v = value;
            if (rules.Length > 0)
            {
                if (name.Equals("Location", StringComparison.OrdinalIgnoreCase)) v = RewriteRedirect(ctx, rules, value);
                else if (name.Equals("Refresh", StringComparison.OrdinalIgnoreCase))
                {
                    // "5; url=http://...": only the URL part is a redirect.
                    int u = value.IndexOf("url=", StringComparison.OrdinalIgnoreCase);
                    if (u >= 0) v = value[..(u + 4)] + RewriteRedirect(ctx, rules, value[(u + 4)..]);
                }
            }
            try { into.Add(name, v); }
            catch (ArgumentException) { ctx.Log.Warn("proxy_redirect produced an invalid header value; dropped", new LogField("header", name)); }
        }
    }

    /// <summary>proxy_redirect: the first rule that matches wins. A prefix rule replaces the prefix; a regex rule the whole value.</summary>
    internal static string RewriteRedirect(HttpContext ctx, RedirectRule[] rules, string value)
    {
        foreach (var rule in rules)
        {
            if (rule.Prefix is { } p)
            {
                if (value.StartsWith(p, StringComparison.OrdinalIgnoreCase)) return rule.Replacement.Evaluate(ctx) + value[p.Length..];
                continue;
            }
            var m = rule.Regex!.Match(value);
            if (!m.Success) continue;
            ctx.SetCaptures(m);
            return rule.Replacement.Evaluate(ctx);
        }
        return value;
    }

    /// <summary>Read more from upstream, flushing what the client already has first (we're about to block).</summary>
    private static async ValueTask<int> FillAsync(UpstreamConn conn, BodySink r, int timeoutMs)
    {
        await r.BeforeUpstreamWaitAsync().ConfigureAwait(false);
        try { return await conn.FillAsync(timeoutMs).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw new UpstreamException("upstream read timed out"); }
        catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException) { throw new UpstreamException("upstream read failed: " + e.Message); }
    }

    private static async ValueTask CopyLengthAsync(UpstreamConn conn, BodySink r, long remaining, int timeoutMs)
    {
        while (remaining > 0)
        {
            if (conn.Buffered == 0 && await FillAsync(conn, r, timeoutMs).ConfigureAwait(false) == 0)
                throw new UpstreamException("upstream closed connection mid-body");
            int n = (int)Math.Min(conn.Buffered, remaining);
            await r.WriteAsync(conn.Buf.AsMemory(conn.Start, n)).ConfigureAwait(false);
            conn.Start += n;
            remaining -= n;
        }
    }

    private static async ValueTask CopyUntilCloseAsync(UpstreamConn conn, BodySink r, int timeoutMs)
    {
        while (true)
        {
            if (conn.Buffered > 0)
            {
                await r.WriteAsync(conn.Buf.AsMemory(conn.Start, conn.Buffered)).ConfigureAwait(false);
                conn.Start = conn.End = 0;
            }
            if (await FillAsync(conn, r, timeoutMs).ConfigureAwait(false) == 0) return;
        }
    }

    private static async ValueTask CopyChunkedAsync(UpstreamConn conn, BodySink r, int timeoutMs)
    {
        while (true)
        {
            int len = await LineAsync(conn, r, timeoutMs).ConfigureAwait(false);
            long size = ParseChunkSize(conn.Buf.AsSpan(conn.Start, len - 2));
            conn.Start += len;
            if (size < 0) throw new UpstreamException("invalid chunk size from upstream");
            if (size == 0)
            {
                int trailer = 0;
                while (true) // trailers are read and dropped
                {
                    int l = await LineAsync(conn, r, timeoutMs).ConfigureAwait(false);
                    bool valid = l == 2 || UpstreamResponse.ValidTrailer(conn.Buf.AsSpan(conn.Start, l - 2));
                    conn.Start += l;
                    if (l == 2) return;
                    if (!valid) throw new UpstreamException("invalid upstream trailer");
                    if ((trailer += l) > 8192) throw new UpstreamException("upstream trailer too large");
                }
            }
            await CopyLengthAsync(conn, r, size, timeoutMs).ConfigureAwait(false);
            while (conn.Buffered < 2)
                if (await FillAsync(conn, r, timeoutMs).ConfigureAwait(false) == 0) throw new UpstreamException("upstream closed connection mid-chunk");
            if (conn.Buf[conn.Start] != '\r' || conn.Buf[conn.Start + 1] != '\n') throw new UpstreamException("missing chunk terminator from upstream");
            conn.Start += 2;
        }
    }

    private static async ValueTask<int> LineAsync(UpstreamConn conn, BodySink r, int timeoutMs)
    {
        while (true)
        {
            int nl = conn.Buf.AsSpan(conn.Start, conn.Buffered).IndexOf((byte)'\n');
            if (nl >= 0)
            {
                if (nl == 0 || conn.Buf[conn.Start + nl - 1] != '\r') throw new UpstreamException("bare LF in chunked upstream body");
                return nl + 1;
            }
            if (conn.Buffered >= MaxChunkLine) throw new UpstreamException("upstream chunk line too long");
            if (await FillAsync(conn, r, timeoutMs).ConfigureAwait(false) == 0) throw new UpstreamException("upstream closed connection mid-body");
        }
    }

    internal static long ParseChunkSize(ReadOnlySpan<byte> line)
    {
        long size = 0;
        int i = 0, digits = 0;
        for (; i < line.Length; i++)
        {
            int c = line[i], v;
            if ((uint)(c - '0') <= 9) v = c - '0';
            else if ((uint)((c | 0x20) - 'a') <= 5) v = (c | 0x20) - 'a' + 10;
            else break;
            if (++digits > 15) return -1;
            size = (size << 4) | (uint)v;
        }
        if (digits == 0) return -1;
        while (i < line.Length && (line[i] == ' ' || line[i] == '\t')) i++;
        if (i < line.Length)
        {
            if (line[i] != ';') return -1;
            for (; i < line.Length; i++) if ((line[i] < 0x20 && line[i] != '\t') || line[i] == 0x7F) return -1; // ext: no CTLs (bare CR)
        }
        return size;
    }

    // ------------------------------------------------------------------ upgrade tunnel

    /// <summary>
    /// Byte-for-byte relay after a 101 (WebSocket or any other upgraded protocol). Ends when either side
    /// closes; idleness is enforced by the core across both directions (the tunnel's traffic all crosses
    /// the client socket), stalled upstream writes by proxy_send_timeout.
    /// </summary>
    private static async Task TunnelAsync(Stream client, UpstreamConn conn, ProxyConf conf)
    {
        using var stop = new CancellationTokenSource();
        try
        {
            if (conn.Buffered > 0)
            {
                await client.WriteAsync(conn.Buf.AsMemory(conn.Start, conn.Buffered)).ConfigureAwait(false);
                conn.Start = conn.End = 0;
            }
        }
        catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException)
        {
            conn.Dispose();
            return;
        }
        var up = ClientToUpstream(client, conn, conf.SendTimeoutMs, stop.Token);
        var down = UpstreamToClient(conn, client, stop.Token);
        await Task.WhenAny(up, down).ConfigureAwait(false);
        stop.Cancel();
        conn.Dispose();
        await Task.WhenAll(up, down).ConfigureAwait(false);
    }

    private static async Task ClientToUpstream(Stream client, UpstreamConn conn, int sendTimeoutMs, CancellationToken stop)
    {
        var buf = ArrayPool<byte>.Shared.Rent(16 << 10);
        try
        {
            int n;
            while ((n = await client.ReadAsync(buf, stop).ConfigureAwait(false)) > 0)
                await conn.WriteAsync(buf.AsMemory(0, n), sendTimeoutMs).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException or OperationCanceledException) { }
        finally { ArrayPool<byte>.Shared.Return(buf); }
    }

    private static async Task UpstreamToClient(UpstreamConn conn, Stream client, CancellationToken stop)
    {
        try
        {
            var buf = conn.Buf; // per-connection, never pooled: safe even if Dispose races this read
            int n;
            while ((n = await conn.ReadAsync(buf, 0).ConfigureAwait(false)) > 0)
                await client.WriteAsync(buf.AsMemory(0, n), stop).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException or OperationCanceledException) { }
    }
}

/// <summary>Reading the client's body failed; rethrown untouched so the core answers it.</summary>
internal sealed class ClientBodyException(Exception inner) : Exception(inner.Message, inner);

/// <summary>Append-only request-head builder (Latin-1 / ASCII / UTF-8 as appropriate per field).</summary>
internal sealed class HeadWriter
{
    private byte[] _b = new byte[1024];
    private int _n;

    private void Ensure(int extra)
    {
        if (_n + extra <= _b.Length) return;
        Array.Resize(ref _b, Math.Max(_b.Length * 2, _n + extra));
    }

    public HeadWriter Byte(char c) { Ensure(1); _b[_n++] = (byte)c; return this; }

    public HeadWriter Ascii(string s) => Latin1(s);

    /// <summary>Strings that came from the wire as bytes (Latin-1 decoded): written back byte-exact.</summary>
    public HeadWriter Latin1(string s)
    {
        Ensure(s.Length);
        foreach (char c in s) _b[_n++] = c <= 0xFF ? (byte)c : (byte)'?';
        return this;
    }

    /// <summary>Strings produced by config/variables: text, so UTF-8.</summary>
    public HeadWriter Utf8(string s)
    {
        Ensure(Encoding.UTF8.GetMaxByteCount(s.Length));
        _n += Encoding.UTF8.GetBytes(s, _b.AsSpan(_n));
        return this;
    }

    public HeadWriter Long(long v)
    {
        Ensure(20);
        Utf8Formatter.TryFormat(v, _b.AsSpan(_n), out int w);
        _n += w;
        return this;
    }

    public byte[] ToArray() => _b.AsSpan(0, _n).ToArray();
}

/// <summary>Where relayed body bytes go: straight to the client, or into the proxy_buffering pipe.</summary>
internal abstract class BodySink
{
    public abstract ValueTask WriteAsync(ReadOnlyMemory<byte> data);
    /// <summary>Called before a read that may block on the upstream.</summary>
    public abstract ValueTask BeforeUpstreamWaitAsync();
}

internal sealed class DirectSink(HttpResponse r) : BodySink
{
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> data) => r.WriteAsync(data);
    public override ValueTask BeforeUpstreamWaitAsync() => r.FlushAsync(); // the client gets what we have before we wait
}

internal sealed class PipeSink(PipeWriter w) : BodySink
{
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> data)
    {
        var res = await w.WriteAsync(data).ConfigureAwait(false); // waits while the buffer is full (backpressure)
        if (res.IsCompleted) throw new OperationCanceledException("client side gave up");
    }

    public override ValueTask BeforeUpstreamWaitAsync() => ValueTask.CompletedTask;
}
