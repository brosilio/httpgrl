using Httpgrl.Quic;

namespace Httpgrl.Core.Logging;

/// <summary>The QUIC endpoint's reports, written through the server's logger.</summary>
internal sealed class QuicLogAdapter(ILogger log) : IQuicLog
{
    public void Write(QuicLogLevel level, string message, ReadOnlySpan<(string Key, string? Value)> fields)
    {
        var l = level == QuicLogLevel.Error ? LogLevel.Error : LogLevel.Warn;
        if (!log.IsEnabled(l)) return;
        // Rare paths (failures, refusals): an array per line is fine here.
        var f = new LogField[fields.Length];
        for (int i = 0; i < fields.Length; i++) f[i] = new LogField(fields[i].Key, fields[i].Value);
        log.Write(l, message, f);
    }
}
