using Httpgrl.Core.Http;
using Httpgrl.Core.Modules;

namespace Httpgrl.Core.Pipeline;

/// <summary>
/// Runs a request through the phases (find-location, rewrite, access, try_files, content), following
/// internal redirects and error_page, and renders core status responses.
/// </summary>
internal sealed class RequestPipeline(HttpHandler[] rewrite, HttpHandler[] access, HttpHandler[] content, HttpHandler[] log)
{
    private const int MaxRedirects = 10;

    public async ValueTask RunAsync(HttpContextImpl ctx)
    {
        try { await ProcessAsync(ctx).ConfigureAwait(false); }
        catch (HttpBodyException e)
        {
            ctx.SetKeepAlive(false);
            await RenderStatusAsync(ctx, e.Status).ConfigureAwait(false);
        }
        catch (Exception e) when (!IsTransportFault(ctx, e))
        {
            ctx.Log.Error("unhandled exception in request", new("conn", ctx.Info.Id), new("uri", ctx.Req.RawTargetValue),
                new("location", ctx.Loc?.Name), new("error", e.GetType().Name), new("detail", e.Message), new("stack", e.StackTrace));
            ctx.SetKeepAlive(false);
            await RenderStatusAsync(ctx, 500).ConfigureAwait(false);
        }
    }

    internal static bool IsTransportFault(HttpContextImpl ctx, Exception e) =>
        ctx.Conn.IsAborted || e is System.Net.Sockets.SocketException || e is ObjectDisposedException
        || (e is IOException && e.InnerException is System.Net.Sockets.SocketException);

    private async ValueTask ProcessAsync(HttpContextImpl ctx)
    {
        var req = ctx.Req;
        if (req.PathValue == "*")
        {
            ctx.SelectLocation(ctx.ServerRt.Root, null);
            ctx.Resp.Headers.Set("Allow", "GET, HEAD, OPTIONS");
            await RenderStatusAsync(ctx, 200).ConfigureAwait(false);
            return;
        }

        string? target = null;
        while (true)
        {
            if (target is null)
            {
                var loc = ctx.ServerRt.Find(req.PathValue, out var m);
                ctx.SelectLocation(loc, m);
            }
            else
            {
                if (++ctx.Redirects > MaxRedirects)
                {
                    ctx.Log.Error("internal redirection cycle", new("uri", req.RawTargetValue), new("target", target));
                    await RenderStatusAsync(ctx, 500).ConfigureAwait(false);
                    return;
                }
                ctx.Internal = true;
                if (!Redirect(ctx, target))
                {
                    await RenderStatusAsync(ctx, 500).ConfigureAwait(false);
                    return;
                }
                target = null;
            }

            HandlerResult r = ctx.Loc.Core.Internal && !ctx.Internal
                ? HandlerResult.WithStatus(404)
                : await RunPhasesAsync(ctx).ConfigureAwait(false);

            switch (r.Action)
            {
                case HandlerAction.InternalRedirect:
                    target = r.Uri;
                    continue;
                case HandlerAction.Done:
                    return;
                default:
                    int status = r.Action == HandlerAction.Status ? r.Status : 404;
                    if (TryErrorPage(ctx, status, out target, out int redirectStatus))
                    {
                        if (target is not null) continue;
                        await RenderStatusAsync(ctx, redirectStatus).ConfigureAwait(false);
                        return;
                    }
                    await RenderStatusAsync(ctx, status).ConfigureAwait(false);
                    return;
            }
        }
    }

    private static bool Redirect(HttpContextImpl ctx, string target)
    {
        var req = ctx.Req;
        if (target.StartsWith('@'))
        {
            if (!ctx.ServerRt.Named.TryGetValue(target, out var named))
            {
                ctx.Log.Error("named location not found", new LogField("location", target));
                return false;
            }
            ctx.SelectLocation(named, null);
            return true;
        }
        int q = target.IndexOf('?');
        var path = UriNormalizer.NormalizeDecoded(q < 0 ? target : target[..q]);
        if (path is null)
        {
            ctx.Log.Error("invalid internal redirect target", new LogField("target", target));
            return false;
        }
        req.PathValue = path;
        if (q >= 0) req.QueryValue = target[(q + 1)..];
        var loc = ctx.ServerRt.Find(path, out var m);
        ctx.SelectLocation(loc, m);
        return true;
    }

    private async ValueTask<HandlerResult> RunPhasesAsync(HttpContextImpl ctx)
    {
        foreach (var h in rewrite)
        {
            var r = await h(ctx).ConfigureAwait(false);
            if (r.Action != HandlerAction.Declined) return r;
        }
        foreach (var h in access)
        {
            var r = await h(ctx).ConfigureAwait(false);
            if (r.Action != HandlerAction.Declined) return r;
        }
        if (ctx.Loc.Core.TryFiles is { } tf)
        {
            var r = TryFiles(ctx, tf);
            if (r.Action != HandlerAction.Declined) return r;
        }
        if (ctx.Loc.Exclusive is { } exclusive) return await exclusive(ctx).ConfigureAwait(false);
        foreach (var h in content)
        {
            var r = await h(ctx).ConfigureAwait(false);
            if (r.Action != HandlerAction.Declined) return r;
        }
        return HandlerResult.WithStatus(404);
    }

    /// <summary>try_files: first existing candidate becomes the URI (processing stays in this location).</summary>
    private static HandlerResult TryFiles(HttpContextImpl ctx, TryFilesSpec tf)
    {
        foreach (var f in tf.Files)
        {
            var v = f.Evaluate(ctx);
            if (v.Length == 0) continue;
            var uri = UriNormalizer.NormalizeDecoded(v);
            if (uri is null) continue;
            if (ctx.Probe(uri) == (uri.EndsWith('/') ? ResourceKind.Directory : ResourceKind.File))
            {
                ctx.Req.PathValue = uri;
                return HandlerResult.Declined;
            }
        }
        if (tf.Fallback is null) return HandlerResult.WithStatus(tf.FallbackStatus);
        return HandlerResult.Redirect(tf.Fallback.Evaluate(ctx));
    }

    private static bool TryErrorPage(HttpContextImpl ctx, int status, out string? target, out int redirectStatus)
    {
        target = null;
        redirectStatus = 0;
        if (ctx.InErrorPage || ctx.Resp.HasStarted || status == HandlerResult.DropStatus) return false;
        var pages = ctx.Loc.Core.ErrorPages;
        if (pages is null || !pages.TryGetValue(status, out var page)) return false;
        if (page.IsDrop)
        {
            redirectStatus = HandlerResult.DropStatus;
            return true;
        }
        var uri = page.Uri!.Evaluate(ctx);
        if (uri.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || uri.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            ctx.Resp.Headers.Set("Location", uri);
            redirectStatus = page.Override is 301 or 302 or 303 or 307 or 308 ? page.Override : 302;
            return true;
        }
        ctx.InErrorPage = true;
        ctx.StatusOverride = page.Override == -1 ? status : page.Override;
        if (!ctx.Req.IsGetOrHead) ctx.Req.MethodValue = HttpMethods.Get;
        // Drop headers the failed attempt may have set (e.g. Allow, Location).
        ctx.Resp.Headers.Clear();
        target = uri;
        return true;
    }

    /// <summary>
    /// Answer a request that failed before routing (malformed head). Only the server-level drop shorthand
    /// applies here: a request we couldn't parse is never internally redirected.
    /// </summary>
    public static ValueTask RejectAsync(HttpContextImpl ctx, int status)
    {
        var pages = ctx.Loc.Core.ErrorPages;
        if (pages is not null && pages.TryGetValue(status, out var page) && page.IsDrop) status = HandlerResult.DropStatus;
        return RenderStatusAsync(ctx, status);
    }

    /// <summary>Core-rendered status response (cf. ngx_http_special_response_handler). 444 sends nothing and closes.</summary>
    public static async ValueTask RenderStatusAsync(HttpContextImpl ctx, int status)
    {
        var resp = ctx.Resp;
        if (status == HandlerResult.DropStatus)
        {
            ctx.Dropped = true;
            ctx.SetKeepAlive(false);
            resp.Status = status; // for the access log; no head is ever built
            return;
        }
        if (resp.HasStarted)
        {
            // Mid-body failure: the only honest signal left is to cut the connection.
            ctx.Broken = true;
            ctx.SetKeepAlive(false);
            return;
        }
        if (HttpStatus.ForcesClose(status)) ctx.SetKeepAlive(false);
        ctx.StatusOverride = 0;
        resp.Status = status;
        var h = resp.Headers;
        h.Remove("Content-Type");
        h.Remove("ETag");
        h.Remove("Last-Modified");
        h.Remove("Accept-Ranges");
        h.Remove("Content-Encoding");
        if (status < 300 || HttpStatus.HasNoBody(status))
        {
            resp.ContentLength = 0;
            return;
        }
        var body = HttpStatus.DefaultBody(status, ctx.Loc.Core.Tokens);
        h.Set("Content-Type", "text/html");
        resp.ContentLength = body.Length;
        await resp.WriteAsync(body).ConfigureAwait(false);
    }

    public async ValueTask RunLogAsync(HttpContextImpl ctx)
    {
        foreach (var h in log)
        {
            try { await h(ctx).ConfigureAwait(false); }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                ctx.Log.Error("log handler failed", new("error", e.GetType().Name), new("detail", e.Message));
            }
        }
    }
}

internal sealed class HttpRuntime
{
    public required ILogger Log { get; init; }
    public required Config.VariableRegistry Vars { get; init; }
    public required RequestPipeline Pipeline { get; init; }
    public required List<ListenBinding> Bindings { get; init; }
    public required string DefaultRoot { get; init; }
    public required MainConf Main { get; init; }
    public required EventsConf Events { get; init; }
}
