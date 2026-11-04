# Changelog

All notable changes to httpgrl. Versions follow [Semantic Versioning](https://semver.org/). While at 0.y.z, a
minor bump may break configuration, the plugin API or the Core APIs; the entry says how.

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
