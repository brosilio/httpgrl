using Httpgrl.Core.Hosting;
using Httpgrl.Core.Http;

namespace Httpgrl.Core.Pipeline;

/// <summary>
/// What every protocol does with a parsed request, in this order: <see cref="Route"/> picks the server and applies the
/// TLS-identity rules, <see cref="RunAsync"/> runs the phases (or the rejection) and completes the response,
/// <see cref="FinishAsync"/> logs and releases. Between the last two a session does what its protocol needs (HTTP/1.1
/// drains the body for keep-alive). Framing, keep-alive and connection management stay in the sessions.
/// </summary>
internal static class RequestLifecycle
{
    /// <summary>
    /// Choose the server for the request's host (the default one if the request was already rejected) and select its
    /// server-level location. Returns the status to reject with: <paramref name="reject"/>, or 421 when the host leads
    /// to a server the TLS handshake (<paramref name="tlsServer"/>, null without TLS) wasn't made for.
    /// </summary>
    public static int Route(HttpContextImpl ctx, VirtualHosts hosts, ServerRt? tlsServer, int reject)
    {
        ctx.ServerRt = reject == 0 ? hosts.Resolve(ctx.Req.HostValue) : hosts.Default;
        if (reject == 0 && tlsServer is not null)
        {
            // A client may complete the handshake for one name (SNI) and then ask for another (Host). Never let that
            // carry it past a client-certificate policy it wasn't checked against (cf. nginx's 421).
            if (!ReferenceEquals(ctx.ServerRt.ClientAuth, tlsServer.ClientAuth)) reject = 421;
            // A server that refuses every handshake presents nothing over TLS, so it serves nothing over TLS either: a
            // Host naming it (e.g. the IP, after a handshake for a real name) is misdirected. error_page 421 =444 drops it.
            else if (ctx.ServerRt.RejectHandshake) reject = 421;
        }
        ctx.SelectLocation(ctx.ServerRt.Root, null);
        return reject;
    }

    /// <summary>
    /// Run the request (or answer the rejection) and complete the response. True if it completed cleanly: nothing broke,
    /// it wasn't dropped (444), and the declared framing was honoured. The response's buffers are released either way.
    /// </summary>
    public static async ValueTask<bool> RunAsync(HttpContextImpl ctx, int reject)
    {
        if (reject != 0) await RequestPipeline.RejectAsync(ctx, reject).ConfigureAwait(false);
        else await ctx.Rt.Pipeline.RunAsync(ctx).ConfigureAwait(false);
        // Dropped (444): nothing was written and nothing will be.
        bool clean = !ctx.Broken && !ctx.Dropped && await ctx.Resp.CompleteAsync().ConfigureAwait(false);
        ctx.Resp.ReturnBuffer();
        return clean;
    }

    /// <summary>The log phase, request-end callbacks (exactly once) and the response counters.</summary>
    public static async ValueTask FinishAsync(HttpContextImpl ctx, ConnectionManager mgr)
    {
        await ctx.Rt.Pipeline.RunLogAsync(ctx).ConfigureAwait(false);
        ctx.EndRequest();
        mgr.CountResponse(ctx.Resp.Status);
    }
}
