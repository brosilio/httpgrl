using System.Net;
using System.Text;
using Httpgrl.Core.Http3;
using Httpgrl.Core.Quic;

namespace Httpgrl.Tests;

/// <summary>
/// A minimal HTTP/3 client over our QUIC client, for tests: a control stream with SETTINGS, requests as HEADERS
/// (+ DATA) + FIN, responses parsed frame by frame. Also raw primitives (arbitrary bytes on new streams) for the
/// attack tests.
/// </summary>
internal sealed class H3Client : IDisposable
{
    public readonly QuicEndpointTests.UdpClient Udp;
    public QuicConnection C => Udp.C;
    private readonly QuicTlsContext _tls;
    private readonly string _authority;

    public sealed class Response
    {
        public string? Status;
        public readonly List<(string Name, string Value)> Headers = new();
        public readonly MemoryStream Body = new();
        public ulong? Reset;
        public bool Done;
        public string? Header(string n) => Headers.Find(h => h.Name == n).Value;
        public string Text => Encoding.UTF8.GetString(Body.ToArray());
    }

    private readonly Dictionary<long, (H3FrameReader Reader, Response R)> _open = new();
    private readonly byte[] _buf = new byte[65536];
    private long _control = -1;

    public H3Client(IPEndPoint server, string? caFile = null, string sni = "h3.test", string alpn = "h3")
    {
        _tls = QuicTlsContext.Client(caFile);
        _authority = sni;
        Udp = new QuicEndpointTests.UdpClient(server, _tls, alpn, new QuicOptions { MaxStreamsUni = 10 }, sni);
    }

    /// <summary>Complete the handshake and open our control stream (SETTINGS). False if the handshake failed.</summary>
    public bool Connect(bool settings = true)
    {
        if (!Udp.Run(() => C.HandshakeComplete || C.IsClosed, 10_000) || !C.HandshakeComplete) return false;
        if (settings)
        {
            _control = C.OpenStream(bidi: false);
            C.StreamWrite(_control, [(byte)H3StreamType.Control, .. H3FrameWriter.Settings((H3Settings.MaxFieldSectionSize, 16384))], fin: false);
        }
        return true;
    }

    public static byte[] Headers(params (string, string)[] fields)
    {
        var block = new byte[64];
        int len = 0;
        QpackEncoder.Begin(ref block, ref len);
        foreach (var (n, v) in fields) QpackEncoder.Encode(ref block, ref len, n, v);
        return Frame(H3FrameType.Headers, block.AsSpan(0, len));
    }

    public static byte[] Frame(ulong type, ReadOnlySpan<byte> payload)
    {
        var f = new byte[16 + payload.Length];
        int h = H3FrameWriter.Header(f, type, payload.Length);
        payload.CopyTo(f.AsSpan(h));
        return f[..(h + payload.Length)];
    }

    /// <summary>Start a request; returns its stream. Extra fields go after the pseudo-fields.</summary>
    public long Send(string method, string path, byte[]? body = null, bool fin = true, params (string, string)[] extra)
    {
        var fields = new List<(string, string)> { (":method", method), (":scheme", "https"), (":authority", _authority), (":path", path) };
        fields.AddRange(extra);
        var bytes = new List<byte>(Headers([.. fields]));
        if (body is not null) bytes.AddRange(Frame(H3FrameType.Data, body));
        return SendRaw([.. bytes], fin);
    }

    /// <summary>Arbitrary bytes on a new bidirectional stream.</summary>
    public long SendRaw(byte[] bytes, bool fin = true)
    {
        long id = C.OpenStream(bidi: true);
        if (id < 0) throw new Exception("no stream credit");
        int at = 0;
        Udp.Run(() =>
        {
            int n = C.StreamWrite(id, bytes.AsSpan(at), fin);
            if (n > 0) at += n;
            return at >= bytes.Length;
        }, 10_000);
        _open[id] = (new H3FrameReader(1 << 20), new Response());
        return id;
    }

    /// <summary>Arbitrary bytes on a new unidirectional stream.</summary>
    public long SendUni(byte[] bytes, bool fin = false)
    {
        long id = C.OpenStream(bidi: false);
        C.StreamWrite(id, bytes, fin);
        return id;
    }

    public Response Wait(long id, int timeoutMs = 10_000)
    {
        var r = _open[id].R;
        Udp.Run(() => { Pump(); return r.Done || C.IsClosed; }, timeoutMs);
        return r;
    }

    public Response Get(string path, params (string, string)[] extra) => Wait(Send("GET", path, null, true, extra));

    /// <summary>Read what's arrived on every open request stream.</summary>
    public void Pump()
    {
        while (C.TryGetEvent(out _)) { }
        foreach (var (id, (reader, r)) in _open)
        {
            if (r.Done) continue;
            while (true)
            {
                int n = C.StreamRead(id, _buf, out bool fin, out ulong? reset);
                if (reset is not null) { r.Reset = reset; r.Done = true; break; }
                if (n > 0)
                    reader.Feed(_buf.AsSpan(0, n), (t, p) =>
                    {
                        if (t != H3FrameType.Headers) return;
                        var fields = new List<(string, string)>();
                        new QpackDecoder(1 << 20).Decode(p, (a, b) => fields.Add((Encoding.Latin1.GetString(a), Encoding.Latin1.GetString(b))));
                        var status = fields.Find(f => f.Item1 == ":status").Item2;
                        if (status is not null && status.StartsWith('1')) return; // interim
                        if (r.Status is null) { r.Status = status; r.Headers.AddRange(fields); }
                    }, d => r.Body.Write(d));
                if (fin) { r.Done = true; break; }
                if (n == 0) break;
            }
        }
    }

    public void Dispose()
    {
        Udp.Dispose();
        _tls.Dispose();
    }
}
