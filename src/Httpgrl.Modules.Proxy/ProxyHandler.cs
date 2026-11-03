using System.Buffers;
using System.Buffers.Text;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Security.Authentication;
using System.Text;

namespace Httpgrl.Modules.Proxy;

internal static class ProxyHandler
{
    private const int MinConnBuffer = 64 << 10;
    private const int MaxChunkLine = 4096;
    private const int StaleRetries = 2;

    public static async ValueTask<HandlerResult> HandleAsync(HttpContext ctx, ProxyConf conf)
    {
        var t = conf.Target!;
        var req = ctx.Request;
        if (req.IsChunked && conf.Version == 10) return HandlerResult.WithStatus(411);
        bool upgrade = conf.UpgradeEnabled && conf.Version == 11 && WantsUpgrade(req);
        bool keepAlive = !upgrade && conf.Version == 11 && t.Group.KeepAlive > 0;
        var head = BuildRequestHead(ctx, conf, t, BuildUri(ctx, conf, t), upgrade, keepAlive);
        bool idempotent = IsIdempotent(req.Method);
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
                    await SendBodyAsync(ctx, conn, conf).ConfigureAwait(false);
                }
                resp = await UpstreamResponse.ReadAsync(conn, conf.HeaderBufferSize, conf.ReadTimeoutMs, req.IsHead).ConfigureAwait(false);
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
                // A pooled connection the peer closed after our liveness check: retry quietly, it's not the peer's fault.
                if (reused && !timedOut && replayable && stale++ < StaleRetries) continue;
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
            return await RelayAsync(ctx, conf, t, conn, resp, upgrade).ConfigureAwait(false);
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

    private static async ValueTask SendBodyAsync(HttpContext ctx, UpstreamConn conn, ProxyConf conf)
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
                try { n = await body.ReadAsync(chunked ? buf.AsMemory(Pre, buf.Length - Pre - Post) : buf).ConfigureAwait(false); }
                catch (Exception e) when (e is not OutOfMemoryException) { throw new ClientBodyException(e); }
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
        CopyHeaders(ctx, conf, up, r.Headers, hidden);
        if (up.ContentLength >= 0 && up.Framing is BodyFraming.Length or BodyFraming.None) r.ContentLength = up.ContentLength;

        try
        {
            switch (up.Framing)
            {
                case BodyFraming.Length: await CopyLengthAsync(conn, r, up.ContentLength, conf.ReadTimeoutMs).ConfigureAwait(false); break;
                case BodyFraming.Chunked: await CopyChunkedAsync(conn, r, conf.ReadTimeoutMs).ConfigureAwait(false); break;
                case BodyFraming.UntilClose: await CopyUntilCloseAsync(conn, r, conf.ReadTimeoutMs).ConfigureAwait(false); break;
            }
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

    private static void CopyHeaders(HttpContext ctx, ProxyConf conf, UpstreamResponse up, HeaderCollection into, List<string>? hidden)
    {
        var rules = conf.RedirectRules;
        foreach (var (name, value) in up.Headers)
        {
            if (IsHopByHop(name) || up.IsConnectionListed(name)) continue;
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
    private static async ValueTask<int> FillAsync(UpstreamConn conn, HttpResponse r, int timeoutMs)
    {
        await r.FlushAsync().ConfigureAwait(false);
        try { return await conn.FillAsync(timeoutMs).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw new UpstreamException("upstream read timed out"); }
        catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException) { throw new UpstreamException("upstream read failed: " + e.Message); }
    }

    private static async ValueTask CopyLengthAsync(UpstreamConn conn, HttpResponse r, long remaining, int timeoutMs)
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

    private static async ValueTask CopyUntilCloseAsync(UpstreamConn conn, HttpResponse r, int timeoutMs)
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

    private static async ValueTask CopyChunkedAsync(UpstreamConn conn, HttpResponse r, int timeoutMs)
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
                    conn.Start += l;
                    if (l == 2) return;
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

    private static async ValueTask<int> LineAsync(UpstreamConn conn, HttpResponse r, int timeoutMs)
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
        if (i < line.Length && line[i] != ';') return -1;
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
