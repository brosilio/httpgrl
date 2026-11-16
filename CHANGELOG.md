# Changelog

All notable changes to httpgrl. Versions follow [Semantic Versioning](https://semver.org/). While at 0.y.z, a
minor bump may break configuration, the plugin API or the Core APIs; the entry says how.

## [0.5.0] - Unreleased

### Changed (may need action)
- JSON log schema 2 removes query/fragment values from URI fields and replaces access-log Referer values with
  presence flags. Consumers must use the new `event`, `outcome`, route and upstream fields. Privacy changes are
  intentional; historical full-query logs require separate retention/access review.
- CI also runs the optional operational detector's standard-library Python 3 tests.

### Added
- Protocol libraries, public API for other software: `Httpgrl.Quic` (QUIC transport, recovery, TLS, server
  endpoint), `Httpgrl.Http3` (HTTP/3 framing, QPACK, `Http3ServerConnection`) and `Httpgrl.HttpFields` (HPACK,
  Huffman). The server is rebuilt on them and uses only their public API. No change on the wire or in configuration.
  See `docs/plan-protocol-libraries.md`.
- Process/instance/version metadata, explicit truncation flags, correlated security decision events, and exactly-once
  access logging for interrupted HTTP/1, HTTP/2 and HTTP/3 handler lifecycles.
- Final server-side response outcome, normalized path, selected server/location and upstream details in access records.
- A bounded offline/streaming log detector; central TLS collection, retention, metrics/probe alert and host audit examples;
  application audit-event contract and incident runbook in `docs/security-monitoring.md`.

### Fixed
- HTTP/3 absolute header deadlines, routing regex timeouts failing open, and QUIC migration per-client limit bypasses.

## [0.4.3] - 2026-11-05

### Added
- HTTP/3 for servers with `ssl_verify_client`. OpenSSL collects the client's certificate during the QUIC handshake,
  and the same verification as on TCP judges it: the CA bundle only, depth, key usage, `ssl_crl` failing closed, and
  `$ssl_client_verify`. A refusal closes with TLS's alert (`certificate_required`, `bad_certificate`). A Host leading
  to a server with a different client-certificate policy gets 421, as on TCP. These servers issue no session tickets.
  They now get HTTP/3 and Alt-Svc (before, they were kept off HTTP/3).
- ChaCha20-Poly1305 for QUIC, alongside AES-GCM. The client picks, so devices without AES hardware get it. Header
  protection uses OpenSSL's raw ChaCha20.
- A test pins TLS session resumption over QUIC (it already worked); 0-RTT stays refused.

### Fixed
- Switching server on SNI during a QUIC handshake now applies that server's client-certificate settings. OpenSSL's
  context switch alone keeps the first context's.

## [0.4.2] - 2026-11-05

### Fixed
- HTTP/2: a drain (reload, shutdown, `keepalive_requests`) could drop its final GOAWAY when the last request finished
  at the same moment. The connection closed without it: nothing was lost, since clients stop opening streams at the
  first GOAWAY, but the close wasn't clean. The final GOAWAY is now queued before anything can start the close.

## [0.4.1] - 2026-11-05

### Fixed
- HTTP/3 refused every connection when the quic listener's default server had no certificate (`ssl_reject_handshake
  on`, the usual way to hide domains from scans by IP). Handshakes now start from any HTTP/3 server's context, and SNI
  picks the server. No SNI, or the default's name, still gets no handshake.

## [0.4.0] - 2026-11-05

HTTP/2 and HTTP/3, both opt-in and both written in-house (see docs/plan-http2-http3.md).

### Changed (may need action)
- Plugin and Core API: `HttpVersion` gains `Http20` and `Http30`, and `HttpVersions.Name` names them ("HTTP/2.0",
  "HTTP/3.0"). Nothing else in the API changed, but code that assumed every request is HTTP/1.x should handle the new
  values. For example, `Connection`/`Upgrade` headers don't exist on HTTP/2 and HTTP/3, so WebSockets there arrive as
  translated upgrade requests (see below).

### Added
- **HTTP/2** with `http2 on;` (off by default, permanently), offered through ALPN on TLS listeners. HPACK, framing and
  flow control are our own. There's no `h2c`. Requests get HTTP/1.1's strict parsing rules, and defences cover rapid
  reset (CVE-2023-44487), CONTINUATION floods, HPACK bombs and control-frame floods. Every stream has its own
  deadlines. Reloads drain in two steps (GOAWAY, PING, final GOAWAY), so no request is lost. Also
  `http2_max_concurrent_streams`. nginx's old `listen ... http2` parameter logs that it doesn't enable HTTP/2.
- **HTTP/3** with `http3 on;` and `listen 443 quic;` (off by default, permanently). On Linux with OpenSSL 3.5 or newer;
  elsewhere quic listeners are skipped with a warning.
  - The QUIC transport is our own, with no msquic and no System.Net.Quic: loss recovery, CUBIC with pacing,
    migration and NAT rebinding, key updates, Retry, stateless resets, GSO.
  - TLS comes from OpenSSL's QUIC TLS API. QPACK uses no dynamic table.
  - TCP responses carry `Alt-Svc` automatically; an explicit `add_header Alt-Svc` wins.
  - Also `http3_max_concurrent_streams`, `quic_retry` and `quic_gso`.
  - Servers that require client certificates aren't served over HTTP/3 yet: they answer 421 and get no Alt-Svc.
- **WebSockets over HTTP/2 and HTTP/3** (extended CONNECT, RFC 8441 and 9220). Modules see an ordinary HTTP/1.1 upgrade
  request, so `proxy_pass` tunnels them to HTTP/1.1 backends unchanged.

### Fixed
- TLS session resumption works again with the strict cipher default. The default list is installed as OpenSSL's
  process-wide default, so .NET keeps its server contexts and their session caches.

## [0.3.0] - 2026-11-04

### Changed (may need action)
- TLS cipher suites now default to AEAD only. TLS 1.3 keeps its suites; TLS 1.2 offers ECDHE with AES-GCM or
  ChaCha20-Poly1305. The CBC suites SSL Labs rates as weak, static-RSA key exchange and SHA-1 MACs are gone. Very old
  TLS 1.2 clients that only speak CBC (roughly pre-2014 browsers) can no longer connect: list the suites you need in
  `ssl_ciphers` to bring them back.

### Added
- `ssl_ciphers` is implemented (it was accepted and ignored). A list of suite names, OpenSSL or IANA form, gives
  exactly those suites for TLS 1.2, in order; TLS 1.3 keeps its own unless the list names some. Unknown names are a
  config error, and broken suites (NULL, anonymous, export, RC4, DES/3DES, MD5) are refused. OpenSSL cipher
  expressions (`HIGH:!aNULL:!MD5`) log a warning and the default applies. On Windows the OS chooses, and an explicit
  list is a config error.

## [0.2.0] - 2026-11-04

Security fixes from a test and fuzzing sweep. Minor bump because one default changed behaviour (see "Changed").

### Changed (may need action)
- Request header names containing `_` are now ignored (nginx's default). CGI-style backends fold `_` and `-`
  together, so `X_Client_Verify` could stand in for a header the proxy sets or strips. If a backend relies on
  underscored headers, set `underscores_in_headers on;`.
- A declared `Content-Length` over `client_max_body_size` is now a 413 before any handler runs (as nginx does),
  including for locations that never read the body.

### Security
- Path traversal: a `root`/`alias` that begins with a variable (`root $doc;`) had no containment check, so a
  request-influenced value with `../` reached the filesystem. The value must now be an absolute path without dot
  segments, and is itself the boundary.
- Open redirect: `$request_uri` was the raw target, so an absolute-form request (`GET http://evil.example/x`) chose
  the host of `return 302 $request_uri;`. It's now the origin-form path and query, as in nginx.
- Proxy: an over-limit request body no longer gets its head sent upstream before the request fails.
- Proxy: a malformed answer on a pooled upstream connection is reported, instead of being retried quietly as if the
  connection had gone stale.
- A regex that has to backtrack and times out now fails the request with a 500 and one warn line, instead of an
  error line with a stack trace on every request (log flooding). `server_name` regexes use the linear-time engine
  when the pattern allows.
- RFC 9112 3.2: an HTTP/1.1 absolute-form request needs a valid `Host` field. Host names like `a..` and bracketed
  non-addresses (`[]`) are rejected.

### Added
- `underscores_in_headers on|off`.
- Fuzz targets for path mapping through `root`/`alias`, `Range`, `Host`/SNI names and rewrite results, plus
  end-to-end request-smuggling tests through the proxy.
- CI on push (GitHub Actions running `scripts/ci.sh`).
- Documentation of post-quantum key exchange (`X25519MLKEM768` with OpenSSL 3.5+).

## [0.1.0] - 2026-11-04

First release. httpgrl is a cross-platform HTTP/1.1 server and reverse proxy in C#, with nginx-compatible-ish
configuration, native AOT, strict security defaults, compiled-in modules and single-line JSON logs.

### Server
- nginx-style configuration: `include`, `server`/`location` matching (exact, prefix, `^~`, regex, named),
  `root`/`alias` with containment checks, `try_files`, `index`, `error_page`, `return`, `rewrite`, `if`, `set`, `map`.
- Strict request parsing (one `Content-Length`, `chunked` only, never both, one validated `Host`, CRLF only), with
  whole-head timeouts, per-operation timeouts and minimum rates enforced by a single sweeper.
- Global and per-client connection caps that evict idle keep-alives first; `limit_req` and `limit_conn`.
- TLS with SNI, `ssl_verify_client` against a configured CA only, fail-closed `ssl_crl`, OCSP stapling with
  backoff, and `ssl_reject_handshake`.
- `SIGHUP` reload that builds a complete new configuration and swaps it in only if everything succeeded.
  Plaintext keep-alives migrate to the new configuration; `reload_drain_timeout` bounds the old one.
- PROXY protocol v1/v2 listeners, `disable_symlinks`, `autoindex` (HTML/JSON, streamed), `gzip`/`brotli` (with
  `_static`), `add_header`, `allow`/`deny`, `stub_status`, `$request_id`, and a hardened systemd unit.

### Reverse proxy
- `proxy_pass` to TCP, TLS (verified by default) or unix-socket upstreams, with keep-alive pools, passive and active
  health checks, runtime DNS re-resolution, `proxy_buffering`, `proxy_redirect`, and WebSocket/Upgrade
  tunnelling (never `h2c`).
- Upstream responses are parsed as strictly as requests. Variables in `proxy_pass` may only select an `upstream`
  block (no SSRF).
- Reverse tunnels: an agent behind NAT (`listen tunnel:NAME`) dials a remote httpgrl (`upstream { tunnel; }` +
  `tunnel_accept`) over mutual TLS and serves the requests it sends back.

### Engineering
- Native AOT with warnings as errors, no third-party runtime dependencies, no runtime plugin loading.
- Modules see only `Httpgrl.Abstractions`, a boundary enforced by `scripts/check-boundaries.sh`.
- A dependency-free test suite that runs on the JIT and as native AOT, mutation fuzz targets for every parser of
  untrusted bytes, a soak test and a load generator.

[0.3.0]: https://github.com/brosilio/httpgrl/releases/tag/v0.3.0
[0.2.0]: https://github.com/brosilio/httpgrl/releases/tag/v0.2.0
[0.1.0]: https://github.com/brosilio/httpgrl/releases/tag/v0.1.0
