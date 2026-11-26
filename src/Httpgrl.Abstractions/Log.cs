namespace Httpgrl;

public enum LogLevel : byte { Debug, Info, Warn, Error }

public enum LogFieldKind : byte { String, Long, Double, Bool }

/// <summary>A structured log field. A struct with no boxing for numbers.</summary>
public readonly struct LogField
{
    public readonly string Key;
    public readonly LogFieldKind Kind;
    public readonly string? Str;
    public readonly long Long;
    public readonly double Double;

    public LogField(string key, string? value) { Key = key; Kind = LogFieldKind.String; Str = value; }
    public LogField(string key, long value) { Key = key; Kind = LogFieldKind.Long; Long = value; }
    public LogField(string key, double value) { Key = key; Kind = LogFieldKind.Double; Double = value; }
    public LogField(string key, bool value) { Key = key; Kind = LogFieldKind.Bool; Long = value ? 1 : 0; }
}

/// <summary>Structured logger. The core implementation writes one JSON object per line to stdout.</summary>
public interface ILogger
{
    bool IsEnabled(LogLevel level);
    void Write(LogLevel level, string message, ReadOnlySpan<LogField> fields);
}

/// <remarks>With a single field, write <c>new LogField(...)</c>: a lone target-typed <c>new(...)</c> binds to ReadOnlySpan's constructor.</remarks>
public static class LoggerExtensions
{
    public static void Debug(this ILogger l, string msg, params ReadOnlySpan<LogField> f) { if (l.IsEnabled(LogLevel.Debug)) l.Write(LogLevel.Debug, msg, f); }
    public static void Info(this ILogger l, string msg, params ReadOnlySpan<LogField> f) { if (l.IsEnabled(LogLevel.Info)) l.Write(LogLevel.Info, msg, f); }
    public static void Warn(this ILogger l, string msg, params ReadOnlySpan<LogField> f) { if (l.IsEnabled(LogLevel.Warn)) l.Write(LogLevel.Warn, msg, f); }
    public static void Error(this ILogger l, string msg, params ReadOnlySpan<LogField> f) { if (l.IsEnabled(LogLevel.Error)) l.Write(LogLevel.Error, msg, f); }
}

/// <summary>Safe default logging of request targets. Query and fragment values are never retained.</summary>
public static class LogPrivacy
{
    public static string PathOnly(string value)
    {
        int end = value.AsSpan().IndexOfAny('?', '#');
        return end < 0 ? value : value[..end];
    }
}

public static class SecurityLogging
{
    /// <summary>Emit a bounded, correlated security decision, independent of access_log. Event names must be constants.</summary>
    public static void SecurityEvent(this HttpContext ctx, string eventId)
    {
        ctx.Log.Warn("security", new("event", eventId), new("request_id", ctx.Request.Id),
            new("conn", ctx.Connection.Id), new("remote", ctx.Connection.RemoteAddress),
            new("method", ctx.Request.Method), new("path", ctx.Request.Path));
    }
}
