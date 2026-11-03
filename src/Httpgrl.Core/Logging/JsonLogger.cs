using System.Buffers;
using System.Text.Json;
using System.Threading.Channels;

namespace Httpgrl.Core.Logging;

/// <summary>
/// One JSON object per line on stdout. Producers format on their own thread and enqueue; a dedicated thread does the
/// (possibly blocking) writes. The queue is bounded in bytes, not lines (request-controlled fields make line sizes vary
/// widely), so a stalled stdout costs at most <see cref="MaxQueuedBytes"/> of memory: past that, lines are dropped
/// instead of stalling request processing, and the drop count is reported once output recovers. If the output fails
/// for good, everything is dropped from then on.
/// </summary>
public sealed class JsonLogger : ILogger, IDisposable
{
    internal const long MaxQueuedBytes = 8 << 20;
    /// <summary>Whole-line cap. A record over it is written again with every string field cut to <see cref="ShortField"/>.</summary>
    internal const int MaxLine = 16 << 10;
    private const int MaxField = 4 << 10;
    private const int ShortField = 128;

    [ThreadStatic] private static ArrayBufferWriter<byte>? t_buf;
    [ThreadStatic] private static Utf8JsonWriter? t_writer;

    // Unbounded as a channel; bounded by _queuedBytes. (A bounded channel in DropWrite mode reports a dropped write
    // as a success, so drops couldn't be counted.)
    private readonly Channel<byte[]> _queue = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions
    {
        SingleReader = true,
        SingleWriter = false,
    });
    private long _queuedBytes;
    internal long QueuedBytes => Interlocked.Read(ref _queuedBytes);
    private volatile bool _dead;
    private readonly Stream _out;
    private readonly Thread _thread;
    private long _dropped;
    private long _droppedTotal;
    /// <summary>Lines dropped because the output couldn't keep up, since start.</summary>
    public long DroppedTotal => Interlocked.Read(ref _droppedTotal);
    private volatile LogLevel _min;

    public JsonLogger(Stream output, LogLevel min = LogLevel.Info)
    {
        _out = output;
        _min = min;
        _thread = new Thread(WriterLoop) { IsBackground = true, Name = "log-writer" };
        _thread.Start();
    }

    public static JsonLogger Stdout(LogLevel min = LogLevel.Info) => new(Console.OpenStandardOutput(), min);

    public LogLevel MinLevel { get => _min; set => _min = value; }

    public bool IsEnabled(LogLevel level) => level >= _min;

    public void Write(LogLevel level, string message, ReadOnlySpan<LogField> fields)
    {
        if (level < _min) return;
        if (_dead) { Drop(); return; }
        byte[] line;
        try
        {
            line = Format(level, message, fields, MaxField);
            if (line.Length > MaxLine) line = Format(level, message, fields, ShortField, truncated: true);
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException)
        {
            line = Format(LogLevel.Error, "log format error", [new("error", e.Message), new("orig_msg", message)], ShortField);
        }
        if (Interlocked.Add(ref _queuedBytes, line.Length) > MaxQueuedBytes || !_queue.Writer.TryWrite(line))
        {
            Interlocked.Add(ref _queuedBytes, -line.Length);
            Drop();
        }
    }

    private void Drop()
    {
        Interlocked.Increment(ref _dropped);
        Interlocked.Increment(ref _droppedTotal);
    }

    private static byte[] Format(LogLevel level, string message, ReadOnlySpan<LogField> fields, int maxField, bool truncated = false)
    {
        var buf = t_buf ??= new ArrayBufferWriter<byte>(512);
        buf.ResetWrittenCount();
        var w = t_writer ??= new Utf8JsonWriter(buf, new JsonWriterOptions { Indented = false, SkipValidation = false });
        w.Reset(buf);

        w.WriteStartObject();
        Span<char> ts = stackalloc char[32];
        DateTime.UtcNow.TryFormat(ts, out int n, "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", null);
        w.WriteString("ts"u8, ts[..n]);
        w.WriteString("level"u8, level switch
        {
            LogLevel.Debug => "debug"u8,
            LogLevel.Info => "info"u8,
            LogLevel.Warn => "warn"u8,
            _ => "error"u8,
        });
        w.WriteString("msg"u8, message.Length > maxField ? message[..maxField] : message);
        foreach (ref readonly var f in fields)
        {
            switch (f.Kind)
            {
                case LogFieldKind.String:
                    if (f.Str is null) w.WriteNull(f.Key);
                    else w.WriteString(f.Key, f.Str.Length > maxField ? f.Str[..maxField] : f.Str);
                    break;
                case LogFieldKind.Long: w.WriteNumber(f.Key, f.Long); break;
                case LogFieldKind.Double: w.WriteNumber(f.Key, double.IsFinite(f.Double) ? f.Double : 0); break;
                case LogFieldKind.Bool: w.WriteBoolean(f.Key, f.Long != 0); break;
            }
        }
        if (truncated) w.WriteBoolean("truncated"u8, true);
        w.WriteEndObject();
        w.Flush();
        // The JSON writer escapes all control characters, so the line can never contain a raw newline.
        var span = buf.WrittenSpan;
        var line = new byte[span.Length + 1];
        span.CopyTo(line);
        line[^1] = (byte)'\n';
        return line;
    }

    private void WriterLoop()
    {
        var reader = _queue.Reader;
        try
        {
            while (reader.WaitToReadAsync().AsTask().GetAwaiter().GetResult())
            {
                while (reader.TryRead(out var line))
                {
                    Interlocked.Add(ref _queuedBytes, -line.Length);
                    _out.Write(line);
                }
                long dropped = Interlocked.Exchange(ref _dropped, 0);
                if (dropped > 0) _out.Write(Format(LogLevel.Warn, "log lines dropped", [new("count", dropped)], ShortField));
                _out.Flush();
            }
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException or NotSupportedException)
        {
            // stdout is gone for good: nothing left to report to. Stop queueing, and free what's queued.
            _dead = true;
            while (reader.TryRead(out _)) { }
            Interlocked.Exchange(ref _queuedBytes, 0);
        }
    }

    public void Dispose()
    {
        _queue.Writer.TryComplete();
        _thread.Join(TimeSpan.FromSeconds(2));
    }
}
