using System.Text;

namespace Httpgrl.Modules.Proxy;

internal enum BodyFraming : byte { None, Length, Chunked, UntilClose }

/// <summary>
/// An upstream response head, parsed as strictly as client requests are: a backend must not be able to
/// split our response or desync the client connection (CRLF only, no obs-fold, single Content-Length,
/// Transfer-Encoding exactly "chunked" and never alongside Content-Length).
/// </summary>
internal sealed class UpstreamResponse
{
    public int Status;
    public bool Http11;
    public readonly List<(string Name, string Value)> Headers = new();
    public BodyFraming Framing;
    public long ContentLength = -1;
    public bool KeepAlive;
    public string? Upgrade;
    private readonly List<string> _connectionTokens = new();

    public bool IsConnectionListed(string name)
    {
        foreach (var t in _connectionTokens)
            if (t.Equals(name, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    /// <summary>Read the next final (or 101) response head; interim 1xx responses are skipped.</summary>
    public static async ValueTask<UpstreamResponse> ReadAsync(UpstreamConn conn, int maxHead, int timeoutMs, bool requestWasHead)
    {
        while (true)
        {
            int headLen;
            while ((headLen = conn.Buf.AsSpan(conn.Start, conn.Buffered).IndexOf("\r\n\r\n"u8)) < 0)
            {
                if (conn.Buffered >= maxHead) throw new UpstreamException("upstream sent too big header");
                // The buffer is never smaller than maxHead, so compacting always frees room.
                if (conn.End == conn.Buf.Length)
                {
                    Buffer.BlockCopy(conn.Buf, conn.Start, conn.Buf, 0, conn.Buffered);
                    conn.End -= conn.Start;
                    conn.Start = 0;
                }
                int n = await conn.ReadAsync(conn.Buf.AsMemory(conn.End), timeoutMs).ConfigureAwait(false);
                if (n == 0) throw new UpstreamException(conn.Buffered == 0 ? "upstream closed connection before responding" : "upstream closed connection mid-header");
                conn.End += n;
            }
            if (headLen + 4 > maxHead) throw new UpstreamException("upstream sent too big header"); // may arrive in one read
            var r = new UpstreamResponse();
            r.Parse(conn.Buf.AsSpan(conn.Start, headLen + 4), requestWasHead);
            conn.Start += headLen + 4;
            if (r.Status is >= 100 and < 200 && r.Status != 101) continue; // 100 Continue, 102, 103: not forwarded
            return r;
        }
    }

    /// <summary>Parse one head, from the status line through the empty line (inclusive). Throws <see cref="UpstreamException"/> only.</summary>
    internal void Parse(ReadOnlySpan<byte> head, bool requestWasHead)
    {
        int eol = head.IndexOf("\r\n"u8);
        var line = head[..eol];
        if (line.StartsWith("HTTP/1.1 "u8)) Http11 = true;
        else if (!line.StartsWith("HTTP/1.0 "u8)) throw new UpstreamException("invalid upstream status line");
        if (line.Length < 12 || !IsDigit(line[9]) || !IsDigit(line[10]) || !IsDigit(line[11]) || (line.Length > 12 && line[12] != ' '))
            throw new UpstreamException("invalid upstream status line");
        Status = (line[9] - '0') * 100 + (line[10] - '0') * 10 + (line[11] - '0');
        if (Status < 100) throw new UpstreamException("invalid upstream status code");
        foreach (byte b in line[12..]) if ((b < 0x20 && b != '\t') || b == 0x7F) throw new UpstreamException("invalid upstream status line");

        int pos = eol + 2;
        int clCount = 0, teCount = 0;
        string? te = null;
        bool close = !Http11;
        while (true)
        {
            int nl = head[pos..].IndexOf("\r\n"u8);
            var h = head.Slice(pos, nl);
            pos += nl + 2;
            if (h.IsEmpty) break;
            if (h.IndexOf((byte)'\r') >= 0 || h.IndexOf((byte)'\n') >= 0) throw new UpstreamException("bare CR/LF in upstream header");
            int colon = h.IndexOf((byte)':');
            if (colon <= 0) throw new UpstreamException("invalid upstream header");
            foreach (byte b in h[..colon]) if (!HttpChars.IsToken(b)) throw new UpstreamException("invalid upstream header name");
            var v = h[(colon + 1)..];
            int s = 0, e = v.Length;
            while (s < e && (v[s] == ' ' || v[s] == '\t')) s++;
            while (e > s && (v[e - 1] == ' ' || v[e - 1] == '\t')) e--;
            v = v[s..e];
            foreach (byte b in v) if ((b < 0x20 && b != '\t') || b == 0x7F) throw new UpstreamException("invalid upstream header value");
            var name = Encoding.ASCII.GetString(h[..colon]);
            var value = Encoding.Latin1.GetString(v);

            if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
            {
                clCount++;
                if (!long.TryParse(value, System.Globalization.NumberStyles.None, null, out var cl)) throw new UpstreamException("invalid upstream Content-Length");
                if (ContentLength >= 0 && ContentLength != cl) throw new UpstreamException("conflicting upstream Content-Length");
                ContentLength = cl;
                continue;
            }
            if (name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)) { teCount++; te = value; continue; }
            if (name.Equals("Connection", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var r in value.AsSpan().Split(','))
                {
                    var tok = value.AsSpan()[r].Trim(" \t");
                    if (tok.IsEmpty) continue;
                    if (tok.Equals("close", StringComparison.OrdinalIgnoreCase)) close = true;
                    else if (tok.Equals("keep-alive", StringComparison.OrdinalIgnoreCase)) { if (!Http11) close = false; }
                    else _connectionTokens.Add(tok.ToString());
                }
                continue;
            }
            if (name.Equals("Upgrade", StringComparison.OrdinalIgnoreCase)) Upgrade = value;
            Headers.Add((name, value));
        }

        if (teCount > 0 && clCount > 0) throw new UpstreamException("upstream sent both Content-Length and Transfer-Encoding");
        if (teCount > 1 || (te is not null && !te.Equals("chunked", StringComparison.OrdinalIgnoreCase))) throw new UpstreamException("unsupported upstream Transfer-Encoding");

        if (requestWasHead || Status is (>= 100 and < 200) or 204 or 304) Framing = BodyFraming.None;
        else if (te is not null) Framing = BodyFraming.Chunked;
        else if (ContentLength >= 0) Framing = BodyFraming.Length;
        else { Framing = BodyFraming.UntilClose; close = true; }
        KeepAlive = !close;
    }

    private static bool IsDigit(byte b) => (uint)(b - '0') <= 9;
}
