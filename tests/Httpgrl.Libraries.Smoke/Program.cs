// The protocol libraries through their public API only: a QUIC server endpoint serving HTTP/3 with
// Http3ServerConnection, and the QUIC client endpoint making one HTTP/3 request over loopback UDP, verifying the
// server's certificate. Exits 0 on
// success, 1 on failure, and 0 with a note when this system's OpenSSL has no QUIC API (as httpgrl itself does).
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Httpgrl.Http3;
using Httpgrl.HttpFields;
using Httpgrl.Quic;

if (QuicTlsContext.Unavailable is { } why)
{
    Console.WriteLine("smoke: skipped, QUIC TLS unavailable: " + why);
    return 0;
}

string dir = Directory.CreateTempSubdirectory("httpgrl-smoke-").FullName;
try
{
    using (var key = ECDsa.Create(ECCurve.NamedCurves.nistP256))
    {
        var req = new CertificateRequest("CN=smoke.test", key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("smoke.test");
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        File.WriteAllText(Path.Combine(dir, "s.crt"), cert.ExportCertificatePem());
        File.WriteAllText(Path.Combine(dir, "s.key"), key.ExportPkcs8PrivateKeyPem());
    }
    using var serverTls = QuicTlsContext.Server(Path.Combine(dir, "s.crt"), Path.Combine(dir, "s.key"), ["h3"]);
    using var clientTls = QuicTlsContext.Client(Path.Combine(dir, "s.crt"));

    using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
    var app = new HelloApp();
    using var ep = new QuicEndpoint(socket, serverTls, _ => serverTls, app, NullQuicLog.Instance);
    app.Endpoint = ep;
    ep.Start();

    var (status, body) = Client.Get(socket.LocalEndPoint!, clientTls, "/hello");
    if (status != "200" || body != "hello from /hello")
    {
        Console.WriteLine($"smoke: FAILED, got status {status} body '{body}'");
        return 1;
    }
    Console.WriteLine("smoke: ok, HTTP/3 over the public API");
    return 0;
}
finally
{
    try { Directory.Delete(dir, true); } catch (IOException) { }
}

/// <summary>Serves every GET with "hello from {path}".</summary>
sealed class HelloApp : IQuicApplication, IHttp3ServerHandler
{
    public QuicEndpoint Endpoint = null!;
    private readonly Dictionary<QuicConnection, Http3ServerConnection> _conns = new(ReferenceEqualityComparer.Instance);

    public void Started(QuicConnection c) => _conns[c] = new Http3ServerConnection(c, Endpoint, this);
    public void OnEvent(QuicConnection c, in QuicEvent e, long now) { if (_conns.TryGetValue(c, out var h)) h.OnEvent(e, now); }
    public void Closed(QuicConnection c) { if (_conns.Remove(c, out var h)) h.Closed(); }
    public void Tick(long now) { foreach (var h in _conns.Values) h.Tick(now); }

    public string? CheckTrailer(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value) => null;

    public IHttp3Request OnRequest(Http3ServerConnection c, long streamId, ReadOnlySpan<byte> fieldSection, bool endStream)
    {
        string path = "";
        c.DecodeFields(fieldSection, (n, v) => { if (n.SequenceEqual(":path"u8)) path = Encoding.ASCII.GetString(v); });
        byte[] head = new byte[256];
        int len = 0;
        QpackEncoder.Begin(ref head, ref len);
        QpackEncoder.Encode(ref head, ref len, ":status", "200");
        var body = Encoding.ASCII.GetBytes("hello from " + path);
        var response = new byte[len + body.Length + 32];
        int w = H3FrameWriter.Header(response, H3FrameType.Headers, len);
        head.AsSpan(0, len).CopyTo(response.AsSpan(w));
        w += len;
        w += H3FrameWriter.Header(response.AsSpan(w), H3FrameType.Data, body.Length);
        body.CopyTo(response.AsSpan(w));
        w += body.Length;
        c.WriteAsync(streamId, response.AsMemory(0, w), fin: true).ContinueWith(_ => c.Finished(streamId), TaskScheduler.Default);
        return new Sink();
    }

    private sealed class Sink : IHttp3Request
    {
        public bool HasRoom => true;
        public bool Deliver(ReadOnlySpan<byte> data, bool end) => true;
        public void Abort(string reason, H3Error code) { }
    }
}

/// <summary>One GET over HTTP/3, through the public client endpoint.</summary>
sealed class Client(string path) : IQuicApplication
{
    public string Status = "", Body = "";
    public readonly ManualResetEventSlim Done = new();
    private long _request = -1;
    private readonly byte[] _buf = new byte[65536];
    private readonly H3FrameReader _reader = new(1 << 16);
    private readonly QpackDecoder _qpack = new(1 << 16);

    public static (string Status, string Body) Get(EndPoint server, QuicTlsContext tls, string path)
    {
        var app = new Client(path);
        using var ep = new QuicClientEndpoint(app);
        ep.Start();
        var c = ep.Connect(server, "smoke.test", ["h3"], tls);
        app.Done.Wait(10_000);
        ep.Run(c, q => q.Close(0x100, "", QuicClock.Now()));
        return (app.Status, app.Body);
    }

    public void Closed(QuicConnection c) => Done.Set();

    public void OnEvent(QuicConnection c, in QuicEvent e, long now)
    {
        if (e.Kind == QuicEventKind.Connected)
        {
            long control = c.OpenStream(bidi: false);
            c.StreamWrite(control, [(byte)H3StreamType.Control, .. H3FrameWriter.Settings((H3Settings.MaxFieldSectionSize, 1 << 16))], fin: false);
            byte[] head = new byte[256];
            int len = 0;
            QpackEncoder.Begin(ref head, ref len);
            QpackEncoder.Encode(ref head, ref len, ":method", "GET");
            QpackEncoder.Encode(ref head, ref len, ":scheme", "https");
            QpackEncoder.Encode(ref head, ref len, ":authority", "smoke.test");
            QpackEncoder.Encode(ref head, ref len, ":path", path);
            var frame = new byte[len + 16];
            int h = H3FrameWriter.Header(frame, H3FrameType.Headers, len);
            head.AsSpan(0, len).CopyTo(frame.AsSpan(h));
            _request = c.OpenStream(bidi: true);
            c.StreamWrite(_request, frame.AsSpan(0, h + len), fin: true);
        }
        else if (e.Kind == QuicEventKind.StreamReadable && e.StreamId == _request)
        {
            int n;
            while ((n = c.StreamRead(_request, _buf, out bool fin, out _)) > 0 || fin)
            {
                _reader.Feed(_buf.AsSpan(0, n),
                    (type, payload) => { if (type == H3FrameType.Headers) _qpack.Decode(payload, (k, v) => { if (k.SequenceEqual(":status"u8)) Status = Encoding.ASCII.GetString(v); }); },
                    data => Body += Encoding.ASCII.GetString(data));
                if (fin) { Done.Set(); break; }
            }
        }
    }
}
