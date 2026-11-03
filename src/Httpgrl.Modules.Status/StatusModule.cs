using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Httpgrl.Modules.Status;

public sealed class StatusConf : ScopeConfig<StatusConf>
{
    internal Format Format;
    protected override void Inherit(StatusConf parent) { }
}

internal enum Format : byte { Nginx, Prometheus, Json }

/// <summary>
/// <c>stub_status [nginx|prometheus|json];</c> in a location: server-wide counters (ngx_http_stub_status_module).
/// The default format is byte-compatible with nginx's, so existing exporters and dashboards work; <c>prometheus</c>
/// is the text exposition format with more detail (responses by class, reloads, dropped log lines). Restrict it
/// with <c>allow</c>/<c>deny</c>: it reveals traffic levels.
/// </summary>
public sealed class StatusModule : IModule
{
    public string Name => "http_stub_status";

    public void Register(IModuleRegistry r) => r.AddDirective(new()
    {
        Name = "stub_status", Contexts = [ContextKind.Location], MaxArgs = 1, Handler = i =>
        {
            i.Conf<StatusConf>().Format = i.Args.Length == 0 ? Format.Nginx : i.Args[0] switch
            {
                "nginx" => Format.Nginx,
                "prometheus" => Format.Prometheus,
                "json" => Format.Json,
                var a => throw i.Error($"unknown format \"{a}\"; expected nginx, prometheus or json"),
            };
            var h = i.Conf<LocationHandlerConf>();
            if (h.Handler is not null) throw i.Error($"location already handled by \"{h.Owner}\"");
            h.Owner = "stub_status";
            h.Handler = Handle;
        },
    });

    public void Configure(IModuleSetup setup) { }

    private static async ValueTask<HandlerResult> Handle(HttpContext ctx)
    {
        if (!ctx.Request.IsGetOrHead)
        {
            ctx.Response.Headers.Set("Allow", "GET, HEAD");
            return HandlerResult.WithStatus(405);
        }
        var s = ctx.Stats();
        var format = ctx.Config<StatusConf>().Format;
        byte[] body = format switch
        {
            Format.Prometheus => Prometheus(s),
            Format.Json => Json(s),
            _ => Nginx(s),
        };
        var resp = ctx.Response;
        resp.Headers.Set("Content-Type", format switch
        {
            Format.Prometheus => "text/plain; version=0.0.4; charset=utf-8",
            Format.Json => "application/json",
            _ => "text/plain",
        });
        resp.Headers.Set("Cache-Control", "no-store");
        resp.ContentLength = body.Length;
        if (!ctx.Request.IsHead) await resp.WriteAsync(body).ConfigureAwait(false);
        return HandlerResult.Done;
    }

    private static byte[] Nginx(in ServerStats s) => Encoding.ASCII.GetBytes(string.Create(CultureInfo.InvariantCulture,
        $"Active connections: {s.Active} \nserver accepts handled requests\n {s.Accepted} {s.Handled} {s.Requests} \nReading: {s.Reading} Writing: {s.Writing} Waiting: {s.Waiting} \n"));

    private static byte[] Prometheus(in ServerStats s)
    {
        var b = new StringBuilder(1024);
        void Metric(string name, string type, string help, params (string? Labels, double Value)[] values)
        {
            b.Append("# HELP ").Append(name).Append(' ').Append(help).Append('\n');
            b.Append("# TYPE ").Append(name).Append(' ').Append(type).Append('\n');
            foreach (var (labels, value) in values)
            {
                b.Append(name);
                if (labels is not null) b.Append('{').Append(labels).Append('}');
                b.Append(' ').Append(value.ToString("R", CultureInfo.InvariantCulture)).Append('\n');
            }
        }
        Metric("httpgrl_connections_active", "gauge", "Open client connections.", (null, s.Active));
        Metric("httpgrl_connections", "gauge", "Open client connections by state.",
            ("state=\"reading\"", s.Reading), ("state=\"writing\"", s.Writing), ("state=\"waiting\"", s.Waiting));
        Metric("httpgrl_connections_accepted_total", "counter", "Accepted client connections.", (null, s.Accepted));
        Metric("httpgrl_connections_handled_total", "counter", "Accepted connections that were admitted (not refused by connection limits).", (null, s.Handled));
        Metric("httpgrl_requests_total", "counter", "Completed requests.", (null, s.Requests));
        Metric("httpgrl_responses_total", "counter", "Completed requests by response status class (444 counts as 4xx).",
            ("class=\"1xx\"", s.Responses1xx), ("class=\"2xx\"", s.Responses2xx), ("class=\"3xx\"", s.Responses3xx),
            ("class=\"4xx\"", s.Responses4xx), ("class=\"5xx\"", s.Responses5xx));
        Metric("httpgrl_reloads_total", "counter", "Successful configuration reloads.", (null, s.Reloads));
        Metric("httpgrl_log_lines_dropped_total", "counter", "Log lines dropped because stdout couldn't keep up.", (null, s.DroppedLogLines));
        Metric("httpgrl_uptime_seconds", "gauge", "Seconds since the server started.", (null, Math.Round(s.Uptime.TotalSeconds, 3)));
        Metric("httpgrl_build_info", "gauge", "Build information.", ($"version=\"{s.Version}\"", 1));
        return Encoding.UTF8.GetBytes(b.ToString());
    }

    private static byte[] Json(in ServerStats s)
    {
        var ms = new MemoryStream(512);
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WriteString("version", s.Version);
            w.WriteNumber("uptime_seconds", Math.Round(s.Uptime.TotalSeconds, 3));
            w.WriteStartObject("connections");
            w.WriteNumber("active", s.Active);
            w.WriteNumber("reading", s.Reading);
            w.WriteNumber("writing", s.Writing);
            w.WriteNumber("waiting", s.Waiting);
            w.WriteNumber("accepted", s.Accepted);
            w.WriteNumber("handled", s.Handled);
            w.WriteEndObject();
            w.WriteNumber("requests", s.Requests);
            w.WriteStartObject("responses");
            w.WriteNumber("1xx", s.Responses1xx);
            w.WriteNumber("2xx", s.Responses2xx);
            w.WriteNumber("3xx", s.Responses3xx);
            w.WriteNumber("4xx", s.Responses4xx);
            w.WriteNumber("5xx", s.Responses5xx);
            w.WriteEndObject();
            w.WriteNumber("reloads", s.Reloads);
            w.WriteNumber("log_lines_dropped", s.DroppedLogLines);
            w.WriteEndObject();
        }
        return ms.ToArray();
    }
}
