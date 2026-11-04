using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Net.Sockets;
using Httpgrl.Core.Hosting;
using Httpgrl.Core.Http;
using Httpgrl.Core.Http2;
using Httpgrl.Core.Logging;
using Httpgrl.Core.Pipeline;

namespace Httpgrl.Tests;

internal static partial class Fuzz
{
    /// <summary>
    /// A live HTTP/2 session (real configuration and handlers, in-memory transport) fed arbitrary frame sequences. The
    /// server must end within seconds of the input running out, log no errors, and only ever send well-formed HTTP/2:
    /// SETTINGS first, frames within the client's size limit, independently decodable header blocks (no interleaving),
    /// no PUSH_PROMISE, nothing on a stream after RST_STREAM and only RST_STREAM after END_STREAM, and no more DATA than
    /// the client's windows could have allowed. Input: the frames after the client preface.
    /// </summary>
    private static Target H2SessionTarget()
    {
        static byte[] Fr(FrameType type, byte flags, int sid, params byte[] p)
        {
            var f = new byte[9 + p.Length];
            FrameWriter.Header(f, p.Length, type, flags, sid);
            p.CopyTo(f, 9);
            return f;
        }
        static byte[] Hd(params (string, string)[] fields)
        {
            var buf = new byte[64];
            int len = 0;
            foreach (var (n, v) in fields) HpackEncoder.Encode(ref buf, ref len, n, v);
            return buf[..len];
        }
        var get = Hd((":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "fuzz.test"));
        var post = Hd((":method", "POST"), (":scheme", "https"), (":path", "/up"), (":authority", "fuzz.test"), ("content-length", "4"));
        var big = Hd((":method", "GET"), (":scheme", "https"), (":path", "/big"), (":authority", "fuzz.test"));
        var ws = Hd((":method", "CONNECT"), (":protocol", "websocket"), (":scheme", "https"), (":path", "/"), (":authority", "fuzz.test"));
        var settings = FrameWriter.Settings((SettingId.InitialWindowSize, 100), (SettingId.MaxFrameSize, 16384));
        byte[][] seeds =
        [
            [.. settings, .. Fr(FrameType.Headers, 5, 1, get), .. Fr(FrameType.Headers, 4, 3, post), .. Fr(FrameType.Data, 1, 3, 1, 2, 3, 4)],
            [.. settings, .. Fr(FrameType.Headers, 5, 1, big), .. FrameWriter.WindowUpdate(1, 1000), .. FrameWriter.WindowUpdate(0, 5000), .. FrameWriter.RstStream(1, H2Error.Cancel)],
            [.. FrameWriter.Settings(), .. Fr(FrameType.Headers, 1, 1, get[..3]), .. Fr(FrameType.Continuation, 4, 1, get[3..]), .. FrameWriter.Ping(new byte[8], false), .. FrameWriter.GoAway(1, H2Error.NoError)],
            [.. FrameWriter.Settings(), .. Fr(FrameType.Headers, 4, 1, ws), .. Fr(FrameType.Data, 0, 1, 0x81, 0x00), .. Fr(FrameType.Data, 9, 1, 1, (byte)'x', 0)],
        ];
        return new Target("h2-session", seeds,
            B("\x00\x00\x00", "\x01", "\x04", "\x05", "\x08", "\x09", "\x00\x00\x00\x01", "\x00\x00\x00\x03", "\x7f\xff\xff\xff", "\x82", "\x84", "\x86", "\xbe", "\x40", "\x20", "\xff"),
            data =>
            {
                lock (SessionGate) return RunSession(data);
            }, MaxLen: 4096);
    }

    private static readonly object SessionGate = new();
    private static readonly Lazy<(HttpRuntime Rt, ConnectionManager Mgr, ServerRt Server, VirtualHosts Hosts, ErrorCounter Log)> SessionFixture = new(() =>
    {
        var dir = Path.Combine(Path.GetTempPath(), "httpgrl-fuzz-h2-" + Environment.ProcessId);
        Directory.CreateDirectory(dir);
        File.WriteAllBytes(Path.Combine(dir, "big"), new byte[200_000]);
        var log = new JsonLogger(Stream.Null, LogLevel.Error);
        var conf = $$"""
            http { server { listen 127.0.0.1:0; server_name fuzz.test; root {{dir}}; client_body_timeout 1s; send_timeout 1s;
              location = / { return 200 "ok"; }
              location /up { return 200 "posted"; }
            } }
            """;
        var built = ServerBuilder.BuildText(conf, dir, [new Httpgrl.Modules.Rewrite.RewriteModule(), .. Httpgrl.Modules.StaticFiles.StaticFiles.Modules()], log, new Dictionary<string, object>());
        var counter = new ErrorCounter();
        var rt = new HttpRuntime
        {
            Log = counter, Vars = built.Vars, Pipeline = built.Pipeline, Bindings = built.Bindings, DefaultRoot = built.DefaultRoot,
            Main = built.Main, Events = built.Events, Modules = built.Modules, Persistent = built.Persistent,
        };
        var mgr = new ConnectionManager(1024, 1024, counter);
        var hosts = rt.Bindings[0].Hosts;
        return (rt, mgr, hosts.Default, hosts, counter);
    });

    private sealed class ErrorCounter : Httpgrl.ILogger
    {
        public int Errors;
        public string? Last;
        public bool IsEnabled(LogLevel level) => level >= LogLevel.Error;
        public void Write(LogLevel level, string message, ReadOnlySpan<LogField> fields)
        {
            if (level < LogLevel.Error) return;
            Interlocked.Increment(ref Errors);
            Last = message;
        }
    }

    private static bool RunSession(byte[] data)
    {
        var (rt, mgr, server, hosts, counter) = SessionFixture.Value;
        int errors0 = Volatile.Read(ref counter.Errors);
        var toServer = new Pipe(new PipeOptions(pauseWriterThreshold: 0));
        var fromServer = new Pipe(new PipeOptions(pauseWriterThreshold: 0));
        var transport = new FuzzDuplex(toServer.Reader.AsStream(), fromServer.Writer.AsStream());
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        var conn = new Connection(1, socket, default) { Generation = rt };
        var info = new ConnectionInfo(1, null, null, true);
        var session = new Http2Session(conn, transport, rt, mgr, hosts, server, info, server.Root.Core);
        var run = session.RunAsync();
        var w = toServer.Writer.AsStream();
        w.Write(FrameReader.Preface);
        w.Write(data);
        w.Flush();
        toServer.Writer.Complete();
        if (!run.Wait(TimeSpan.FromSeconds(10))) throw new Finding("the session didn't end after its input did");
        fromServer.Writer.Complete();
        var output = ReadAll(fromServer.Reader.AsStream());
        if (Volatile.Read(ref counter.Errors) != errors0) throw new Finding("error logged: " + counter.Last);
        CheckServerOutput(data, output);
        return true;
    }

    private static byte[] ReadAll(Stream s)
    {
        var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }

    /// <summary>Everything the server sent must be valid HTTP/2 within what the client's own frames allowed.</summary>
    private static void CheckServerOutput(byte[] input, byte[] output)
    {
        // What the client allowed: its largest frame size and stream window, and the window updates it sent.
        long maxFrame = 16384, initialWindow = 65535, connCredit = 65535;
        var credit = new Dictionary<int, long>();
        var cin = input.AsSpan();
        while (cin.Length > 0)
        {
            int n;
            Frame f;
            ReadOnlySpan<byte> p;
            try { n = FrameReader.TryRead(cin, 1 << 24, out f, out p); }
            catch (H2Exception) { break; }
            if (n == 0) break;
            if (f.Type == FrameType.Settings && !f.Has(FrameFlags.Ack))
                for (int i = 0; i + 6 <= p.Length; i += 6)
                {
                    ushort id = BinaryPrimitives.ReadUInt16BigEndian(p[i..]);
                    uint v = BinaryPrimitives.ReadUInt32BigEndian(p[(i + 2)..]);
                    if (id == SettingId.MaxFrameSize) maxFrame = Math.Max(maxFrame, v);
                    if (id == SettingId.InitialWindowSize) initialWindow = Math.Max(initialWindow, v);
                }
            if (f.Type == FrameType.WindowUpdate)
            {
                long inc = BinaryPrimitives.ReadUInt32BigEndian(p) & 0x7FFFFFFF;
                if (f.StreamId == 0) connCredit += inc;
                else credit[f.StreamId] = credit.GetValueOrDefault(f.StreamId) + inc;
            }
            cin = cin[n..];
        }

        var o = output.AsSpan();
        bool first = true;
        int blockStream = 0;
        var decodeBlock = new List<byte>();
        var ended = new HashSet<int>();
        var reset = new HashSet<int>();
        var sent = new Dictionary<int, long>();
        long totalData = 0;
        while (o.Length > 0)
        {
            if (o.Length < 9) throw new Finding("server output ends mid-frame");
            int len = (o[0] << 16) | (o[1] << 8) | o[2];
            var type = (FrameType)o[3];
            byte flags = o[4];
            int sid = (int)(BinaryPrimitives.ReadUInt32BigEndian(o[5..]) & 0x7FFFFFFF);
            if (o.Length < 9 + len) throw new Finding("server output ends mid-frame");
            var p = o.Slice(9, len);
            if (len > maxFrame) throw new Finding($"server sent a {len}-byte frame, over the client's {maxFrame}");
            if (first && type != FrameType.Settings) throw new Finding("server didn't start with SETTINGS");
            first = false;
            if (blockStream != 0 && type != FrameType.Continuation) throw new Finding("server interleaved a frame into a header block");
            if (type == FrameType.PushPromise) throw new Finding("server pushed");
            if (sid != 0 && reset.Contains(sid)) throw new Finding($"server sent {type} on stream {sid} after resetting it");
            if (sid != 0 && ended.Contains(sid) && type != FrameType.RstStream) throw new Finding($"server sent {type} on stream {sid} after END_STREAM");
            switch (type)
            {
                case FrameType.Headers:
                case FrameType.Continuation:
                    if (type == FrameType.Continuation && blockStream != sid) throw new Finding("CONTINUATION without its HEADERS");
                    if (type == FrameType.Headers) decodeBlock.Clear();
                    decodeBlock.AddRange(p.ToArray());
                    blockStream = (flags & FrameFlags.EndHeaders) != 0 ? 0 : sid;
                    if (blockStream == 0)
                    {
                        // The encoder is stateless: every block decodes on its own.
                        try { new HpackDecoder(4096, 1 << 20).Decode([.. decodeBlock], (_, _) => { }); }
                        catch (HpackException e) { throw new Finding("server sent an undecodable header block: " + e.Message); }
                    }
                    if (type == FrameType.Headers && (flags & FrameFlags.EndStream) != 0) ended.Add(sid);
                    break;
                case FrameType.Data:
                    sent[sid] = sent.GetValueOrDefault(sid) + len;
                    totalData += len;
                    if (sent[sid] > initialWindow + credit.GetValueOrDefault(sid)) throw new Finding($"server overran stream {sid}'s window");
                    if (totalData > connCredit) throw new Finding("server overran the connection window");
                    if ((flags & FrameFlags.EndStream) != 0) ended.Add(sid);
                    break;
                case FrameType.RstStream:
                    reset.Add(sid);
                    break;
            }
            o = o[(9 + len)..];
        }
    }

    private sealed class FuzzDuplex(Stream read, Stream write) : Stream
    {
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => read.ReadAsync(buffer, ct);
        public override Task<int> ReadAsync(byte[] b, int o, int c, CancellationToken ct) => read.ReadAsync(b, o, c, ct);
        public override int Read(byte[] b, int o, int c) => read.Read(b, o, c);
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        {
            await write.WriteAsync(buffer, ct).ConfigureAwait(false);
            await write.FlushAsync(ct).ConfigureAwait(false);
        }
        public override Task WriteAsync(byte[] b, int o, int c, CancellationToken ct) => WriteAsync(b.AsMemory(o, c), ct).AsTask();
        public override void Write(byte[] b, int o, int c) { write.Write(b, o, c); write.Flush(); }
        public override Task FlushAsync(CancellationToken ct) => write.FlushAsync(ct);
        public override void Flush() => write.Flush();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
