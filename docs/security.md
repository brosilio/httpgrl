# Security model

httpgrl's defaults are stricter than nginx's wherever nginx's are unsafe, and every defence below has a test that
attacks it (see [Development](development.md#testing)). Deviations from nginx are marked.


## Timeouts and slow clients

A sweeper thread checks every connection's deadlines; each connection only stamps times into its record, so enforcement stays cheap however many connections there are.
- Header timeout: the whole request head must arrive within `client_header_timeout` of its first byte. Trickling one byte at a time does not extend it.
- Idle connections: an idle new or keep-alive connection is closed at its deadline.
- Slow uploads and slow readers: body reads and response writes each have a per-operation timeout plus a minimum transfer rate. That covers slow-body uploads and slow-read downloads.

## Connection limits

- Connections are capped globally and per client (IPv4 address or IPv6 /64).
- When the table is full, the longest-idle keep-alive connection is evicted.
- Unread request bodies are drained only up to 64 KiB; anything larger closes the connection. Closes are lingering, so a client's unread data can't trigger a reset that destroys our response.

## HTTP/2 (`http2 on`)

- **Request strictness carries over.** Lower-case field names; pseudo-fields first, once each, and only the request ones; no connection-specific fields (`TE` only as `trailers`); no control characters other than HTAB (HTTP/1.1's rule; RFC 9113 only forbids CR, LF and NUL), and no surrounding whitespace, in values. `:scheme` must be `https`. `:path` goes through the same normalizer, `:authority` and `Host` must agree, and there's one valid `content-length`, which the DATA frames must match. A malformed request resets its stream (`PROTOCOL_ERROR`); the connection carries on.
- **HPACK stays bounded and in step.** Integers, strings, the dynamic table (capped at the size we advertise) and the decoded header list are all bounded. A list over the limit gets a 431 for that request only: the block is still decoded to the end, so compression state never desynchronizes. Every header block is decoded, even one about to be refused, for the same reason. The response encoder never uses the dynamic table: no state across responses, nothing to probe.
- **Rapid reset (CVE-2023-44487).** `http2_max_concurrent_streams` counts handlers, not open streams, so a reset stream holds its slot until its handler has stopped. Streams the client resets, and ones that are refused or malformed, also draw on a budget: GOAWAY `ENHANCE_YOUR_CALM` when it runs out. Bursts of real, completed requests don't touch it.
- **CONTINUATION floods** (2024): a header block is capped in compressed size and in fragments, and must arrive within `client_header_timeout`.
- **Control-frame floods:** SETTINGS, PING, RST_STREAM, unknown frames, and empty DATA and header fragments share one budget per connection, and the DATA frames we send refill it. WINDOW_UPDATE and PRIORITY aren't charged: busy clients send thousands, and they cost us nothing to process.
- **Each stream has its own deadlines,** enforced by the same sweeper: `client_body_timeout` and minimum rates on uploads, and `send_timeout` while a client keeps its window closed. A stalled stream is reset without its connection. The slow-read minimum rate is measured on the connection, over its writes: one stream's bytes wait behind its siblings', so a stream's own rate says nothing about the client.
- **WebSockets** (extended CONNECT) are translated into the HTTP/1.1 upgrade request modules already handle, with a fresh `Sec-WebSocket-Key` for the backend. The tunnel is that one stream: idle timeout across both directions, as on HTTP/1.1, and a slot under `http2_max_concurrent_streams` for as long as it's open. Only `websocket` is tunnelled; a plain CONNECT is a 405.
- **Ending connections:** errors end with a GOAWAY that the client gets to read, thanks to a lingering close. Reload, shutdown and `keepalive_requests` drain in two steps (RFC 9113 6.8): a GOAWAY that refuses nothing yet, plus a PING. When the PING comes back, the final GOAWAY names the last request the client sent before it saw the first one, and later streams are ignored, which the client retries elsewhere. Running streams finish (within `reload_drain_timeout`), then a FIN and a bounded read to the client's close. A session drains itself, so reload doesn't close an HTTP/2 connection as an "idle" keep-alive while a request is on the wire.

## HTTP/3 (`http3 on`, `listen ... quic`)


- `client_header_timeout` is an absolute deadline from request stream opening, including implicitly opened streams. Partial headers and other QUIC traffic cannot extend it; expiry closes the connection with `H3_EXCESSIVE_LOAD`.
- **Client certificates:** judged by the same code as on TCP, as soon as the handshake completes and before any request is read. A request whose authority leads to a server with a different client-certificate policy than the one the handshake chose (SNI) gets 421, as on TCP. Switching server on SNI carries that server's verify mode into the handshake (OpenSSL's context switch alone wouldn't).
- **The same request rules as HTTP/2** (it's the same validator): lower-case names, pseudo-fields first and once, no connection-specific fields, one matching `content-length`, the same path normalizer. A malformed request resets its stream (`H3_MESSAGE_ERROR`); framing violations close the connection with the code RFC 9114 names. A request with no body is recognized by its stream ending right behind the HEADERS frame (HTTP/3 has no END_STREAM flag).
- **QPACK without a dynamic table.** We advertise a capacity of 0, so field sections are static references and literals only. A dynamic reference is `QPACK_DECOMPRESSION_FAILED`, and an insert on the encoder stream is `QPACK_ENCODER_STREAM_ERROR`. No compression state means nothing to desynchronize, nothing to block on, and nothing to probe. Sizes are bounded as in HPACK, and a section over the limit gets 431 for that request only.
- **Address validation.** The server sends no more than three times what it received until the client's address is validated. That applies to the handshake and again after every migration. An Initial that doesn't authenticate creates no state at all (no TLS object). Retry (always, or automatically under load) uses stateless sealed tokens. Unknown connection IDs get rate-limited stateless resets, always smaller than what triggered them.
- **Migration.** A connection follows a client to a new address only for its newest packet with real (non-probing) frames, after the handshake. A replayed datagram is a duplicate and moves nothing. The new path is validated (PATH_CHALLENGE) under the amplification limit, falls back to the old one if it doesn't answer, and gets a fresh connection ID. Per-client limits follow the validated address: migrating into a client's full connection allowance closes the migrating connection with `NO_VIABLE_PATH`.
- **Back-pressure both ways.** Uploads are read from QUIC only as the handler consumes them (QUIC credit follows), and responses wait until QUIC has taken their bytes. Each stream has its own `client_body_timeout`, minimum rate and `send_timeout`, enforced by the sweeper; a stalled stream is reset without its connection. QUIC's idle timeout comes from `keepalive_timeout`.
- **Ending connections.** Reload, shutdown and `keepalive_requests` send GOAWAY at once. Requests in flight finish (within `reload_drain_timeout`); later streams are refused with `H3_REQUEST_REJECTED`, which clients retry safely; then the connection closes. A connection stays on the configuration it started under.

## Strict parsing

- Line endings must be CRLF. Bare LF or CR, obs-fold, and whitespace before `:` are rejected.
- Exactly one `Content-Length`. `Transfer-Encoding` must be exactly `chunked` and never alongside `Content-Length`.
- No `Transfer-Encoding` on HTTP/1.0. Exactly one `Host`, validated and lower-cased. An HTTP/1.1 request in absolute
  form (`GET http://a.test/ HTTP/1.1`) still needs a valid `Host` field (RFC 9112 3.2), though the target's authority
  is what selects the server. `$request_uri` is the origin-form path and query even then, as in nginx, so
  `return 302 $request_uri;` can't be pointed at another host.
- Redirect targets built from variables (`return`, `rewrite ... redirect|permanent`, `error_page ... http(s)://...`)
  are percent-encoded for the header, including `\`, which browsers read as `/`. If the result starts with `//`
  but the configured text doesn't, the leading slashes collapse to one: with the common
  `rewrite ^/(.*)/$ /$1 permanent;`, `GET //evil.example/` redirects to `/evil.example`, not to another host.
  *(Deviation: nginx sends `//evil.example`.)* Write `//host/...` literally if you mean a protocol-relative URL.
- Header names containing `_` are ignored unless `underscores_in_headers on` (nginx's default too). CGI-style
  backends (FastCGI, WSGI, Rack) fold `_` and `-` into one variable name, so `X_Client_Verify` would otherwise reach
  them as the `X-Client-Verify` a proxy sets or strips.
- Chunk sizes, chunk lines and trailers are bounded. Chunk extensions and trailer fields (which are dropped) must still be well-formed: no control characters, so no bare CR for another parser to read as a line end.
- In short, anything a proxy in front of or behind the server could read differently is a 400. The reverse proxy depends on this.

## Paths

- URIs are percent-decoded, dot-segments are resolved, and an escape above `/` is a 400. Control characters (`%00`–`%1F`, `%7F`) and invalid UTF-8 are rejected. **Deviation:** nginx accepts `%0A` in paths. A decoded newline in `$uri` could reach response or upstream headers, and slip past anchored regexes (`$` also matches before a trailing newline, in PCRE as in .NET). So `if ($uri ~ "^/admin$")` can't be fooled by `/admin%0A`.
- Every mapped filesystem path is checked to stay inside its `root`/`alias` directory. This closes nginx's classic `location /img { alias /x/; }` + `/img../` hole. A value with variables is checked against its constant leading directory. One that *begins* with a variable (`root $doc;`) has none, so its evaluated value must be an absolute path without `.`/`..` segments, and is itself the boundary: whatever a variable holds, the request can't climb out of it. (Which directory a variable names is still the configuration's business: don't build one from request input.)
- Regexes run on .NET's linear-time engine whenever the pattern allows it (no backreferences or lookarounds). The rest backtrack with a 50 ms match timeout. A location or request-expression timeout fails the request with a 500 and one `warn` line; a Host timeout drops the request and an SNI timeout refuses the handshake. Neither "matched" nor "didn't match" can be assumed without failing open somewhere (`if ($x ~ ...) { return 403; }` versus `!~`), and nginx also answers a failed regex execution with a 500.
- Modules never see filesystem paths. They ask the core for resources by request path, so the mapping, containment and safe-open policy has exactly one implementation (`Core/Files/LocalFiles.cs`). CI enforces this with `scripts/check-boundaries.sh`.
- Location matching is case-insensitive on case-insensitive filesystems.
- On Windows, ADS names (`:`), trailing dots and spaces, and device names (`CON`, `NUL`, ...) are refused.

## File serving

- Unix opens use `O_NONBLOCK|O_CLOEXEC`, so a FIFO in the web root can't hang a thread. Non-seekable files get a 403.
- Directory listings are HTML-escaped and their hrefs percent-encoded, with a `./` prefix so a file named `javascript:` can't become a link scheme.
- Symlinks are followed by default (as nginx), including out of the root. `disable_symlinks on` refuses them race-free.

## Response headers

`HeaderCollection` rejects CR, LF, NUL and non-Latin-1 characters, so response splitting is impossible. Framing headers are always written by the core.

## Logging

Log lines are produced by `Utf8JsonWriter`, so a log line is always a single JSON object. A blocked stdout drops lines (and counts them) instead of stalling requests. The queue is bounded in bytes (8 MiB), not lines, and a line is at most 16 KiB (a record over that is written again with every string field cut short and `"truncated":true`), so request-controlled fields can't make a stalled stdout cost gigabytes. If stdout fails for good, lines are dropped from then on.

## Reverse proxy

- Upstream responses are parsed as strictly as requests: CRLF only, no obs-fold, exactly one `Content-Length` (repeats are refused even when they agree), a status of 100–599, `Transfer-Encoding: chunked` only and never alongside `Content-Length`, a bounded head, and well-formed chunk extensions and trailers. A broken or hostile backend gets a 502; it can't split our response or desync the client.
- If an upstream fails after the head went out, the client connection is cut, so a truncated body never looks complete.
- The response is read while the request body is still uploading. An upstream that answers early (401, 413, a redirect) and stops reading gets its answer relayed instead of a send timeout turning it into a 504; the rest of the client's body is abandoned (that client connection closes after the response) and the upstream connection isn't reused.
- Hop-by-hop headers and headers named in `Connection` are stripped in both directions. `Proxy-Authorization` never reaches the upstream.
- `proxy_set_header` values containing CR, LF or NUL are dropped, never sent.
- `Upgrade: h2c` is never tunnelled (h2c smuggling would bypass every rule configured here). An unsolicited `101` from an upstream is a 502.
- Upstream TLS is verified by default.
- Pooled keep-alive connections are reused only under the exact TLS settings they were verified with.

## Post-quantum key exchange

TLS is the platform's (OpenSSL on Linux), and httpgrl doesn't override its choice of
key exchange. With **OpenSSL 3.5 or later** (Debian 13, Ubuntu 25.04, Fedora 42 and newer), TLS 1.3 connections
negotiate the hybrid **`X25519MLKEM768`** (X25519 plus ML-KEM-768, FIPS 203), the same group browsers use. That
protects today's traffic against being recorded and decrypted later by a quantum computer. It applies to client
connections and to our own outgoing ones (upstreams, tunnel agents) whenever the other end supports it too. On older
OpenSSL (Debian 12 has 3.0) the same binary falls back to classical X25519, so scanners such as SSL Labs report no
post-quantum support. Upgrading the OS turns it on; httpgrl needs no change. Not covered:
- **Post-quantum certificates (ML-DSA).** Public CAs don't issue them and browsers don't accept them yet.
- **Choosing groups.** .NET has no API for this, so `ssl_ecdh_curve` is accepted and ignored. Use the system
  OpenSSL configuration (`Groups = ...`) to restrict them.
- **Logging the negotiated group.** .NET doesn't report it, so there's no `$ssl_curve`.

## Client certificates (mTLS)

- Chains are built only against `ssl_client_certificate`. There are no system roots, no AIA downloads (a client-supplied URL never makes the server connect out) and no revocation fetches. The leaf must allow TLS client authentication (EKU), be within its validity period and respect `ssl_verify_depth`.
- SNI picks the TLS policy, and `Host` picks the server. If they land on servers with different client-certificate policies, the request gets a **421**. So a client can't do the handshake for an open name and then ask for a protected one (or the reverse, carrying a verified identity to a server that didn't ask for it).
- With `ssl_crl`, each CRL's signature is verified against the issuing certificate of the chain being checked. A CRL that names a CA from the bundle but isn't signed by it fails the config load. A CRL that is missing or out of date for any CA in the chain fails the check closed, never open.
- Session resumption is off where client certificates are requested. A resumed session would skip, or only partly redo, the check.
- **OCSP stapling is ours, not the platform's.** .NET's own stapler refetches on every handshake when it has no valid response, so a responder outage would turn client handshakes into a flood of requests to the CA. So httpgrl turns it off and drives stapling itself: its own fetch schedule and backoff, its own verification and logging. The platform only puts our verified response on the wire. That uses .NET internals through `UnsafeAccessor` (`StaplingAccess.cs`). It's AOT-safe, and because a native AOT binary embeds its runtime, those internals can't change under a built binary; a self-check makes `ssl_stapling on` a config error if they ever don't bind.
- The connection's TLS identity can only be set by the core (`ConnectionInfo.SetTls` is internal).

## Rate limits

Zones are bounded by bytes, not entries, so a key built from client input can't exhaust memory. `$remote_net` keys IPv6 clients by /64. A `limit_conn` slot is released however the request ends, including resets mid-tunnel.

## Sockets

- On Unix only `SO_REUSEADDR` is set (restarts over TIME_WAIT). .NET's `ReuseAddress` would also set `SO_REUSEPORT`, letting any same-user process silently share the port and take some of its connections. That's opt-in per socket via `listen ... reuseport`.
- The server doesn't identify itself by default (`server_tokens off`).
