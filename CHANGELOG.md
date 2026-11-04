# Changelog

All notable changes to httpgrl. Versions follow [Semantic Versioning](https://semver.org/). While at 0.y.z, a
minor bump may break configuration, the plugin API or the Core APIs; the entry says how.

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

[0.1.0]: https://github.com/brosilio/httpgrl/releases/tag/v0.1.0
