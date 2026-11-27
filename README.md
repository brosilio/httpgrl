# httpgrl

A small, fast HTTP server in C# (.NET 10, native AOT) that reads nginx-style configuration. It speaks HTTP/1.1,
plus HTTP/2 and HTTP/3 when you turn them on, with its own QUIC implementation. Every feature is a module built on
one plugin API, compiled in.

There are no third-party runtime dependencies. TLS uses the platform stack (OpenSSL on Linux). The output is a single
~8 MB executable that needs no .NET runtime and logs one JSON object per line to stdout.

## Features

- **Static files:** index files, directory listings, `try_files`, byte ranges and conditional requests,
  precompressed siblings, race-free `disable_symlinks`.
- **Reverse proxy:** upstream groups with weights, passive and active health checks, keep-alive pools, runtime DNS
  re-resolution, buffering, `proxy_redirect`, and WebSockets with no extra configuration.
- **Reverse tunnels:** serve a site from a machine with no open ports. It dials out to a public httpgrl.
- **TLS:** SNI, AEAD-only ciphers by default, client certificates with CRLs, and OCSP stapling with its own backoff.
  Post-quantum key exchange comes with OpenSSL 3.5.
- **HTTP/2 and HTTP/3** (opt-in): HPACK, QUIC, QPACK, migration, CUBIC with pacing, GSO, and WebSockets over both.
- **Rewrite, map and headers:** `return`, `rewrite`, `set`, a restricted `if`, `map`, and an `add_header` that
  merges across levels.
- **Limits and access:** `limit_req`, `limit_conn`, `allow`/`deny`, and per-client connection caps.
- **Compression:** gzip and brotli, including streamed responses.
- **Operations:** all-or-nothing reload on `SIGHUP`, `stub_status` (nginx, Prometheus or JSON), a hardened systemd
  unit and a distroless Docker image.

Defaults are stricter than nginx's wherever nginx's are unsafe, and the [security model](docs/security.md) lists
every deviation.

## Quick start

```sh
./scripts/ci.sh                                   # build, test on JIT, test as native AOT, publish
dotnet publish src/Httpgrl -c Release -r linux-x64 -o artifacts/linux-x64
artifacts/linux-x64/httpgrl -c conf/httpgrl.conf  # -t: test the config and exit

docker build -t httpgrl . && docker run --rm -p 8080:8080 --read-only --cap-drop ALL httpgrl
```

Prebuilt Linux x86-64 binaries are attached to each [release](https://github.com/brosilio/httpgrl/releases).

## Documentation

| Document | What's in it |
|---|---|
| [Configuration reference](docs/configuration.md) | Every directive (core, TLS, HTTP/2 and HTTP/3, rewrite, limits, access, compression) and every variable. |
| [Reverse proxy and tunnels](docs/proxy.md) | `proxy_pass`, `upstream`, health checks, buffering, and reverse tunnels. |
| [Running httpgrl](docs/operations.md) | Signals, reload semantics, systemd and Docker. |
| [Security model](docs/security.md) | What the server defends against, how, and where it deviates from nginx. |
| [Security monitoring](docs/security-monitoring.md) | The JSON log schema, event catalog, detector and alerting examples, and the incident runbook. |
| [Development](docs/development.md) | Project layout, design decisions, testing (fuzzing, soak, benchmark) and writing a module. |
| [Changelog](CHANGELOG.md) | Release history ([semver](https://semver.org/)). |

## Roadmap

Open work is tracked in [issues](https://github.com/brosilio/httpgrl/issues):
- QUIC datagrams for games ([#1](https://github.com/brosilio/httpgrl/issues/1)) and WebTransport over HTTP/3 ([#2](https://github.com/brosilio/httpgrl/issues/2)).
- HTTP/2 and HTTP/3 hardening: an interop matrix and bad-network runs ([#3](https://github.com/brosilio/httpgrl/issues/3)).
- Per-protocol metrics ([#4](https://github.com/brosilio/httpgrl/issues/4)), and QUIC ECN and v2 ([#5](https://github.com/brosilio/httpgrl/issues/5)).
- Signed images.
- Windows and macOS. They're deferred until there's hardware to test on: Linux is the only platform exercised today.
  The Windows- and macOS-specific code paths (path guards, socket options, SChannel and Secure Transport TLS) are
  untested.

Also not yet supported: `disable_symlinks if_not_owner`, `map ... hostnames`, OCSP checking of client certificates,
an open-file cache, and `sendfile(2)` for plaintext responses.

## License

[BSD Zero Clause](LICENSE).
