# Running httpgrl

## Running

```sh
dotnet publish src/Httpgrl -c Release -r linux-x64 -o artifacts/linux-x64
artifacts/linux-x64/httpgrl -c conf/httpgrl.conf     # -t: test the config and exit
```

Output is a single ~8 MB executable. Logs go to stdout as one JSON object per line.
`SIGTERM`/`SIGINT`/`SIGQUIT` shut down gracefully, bounded by `worker_shutdown_timeout`.

## Reload

Reload with `SIGHUP` (`kill -HUP <pid>`, `docker kill -s HUP <container>`). It re-reads the config and
everything it references: includes, certificates, CA bundles and CRLs. Upstream hostnames are resolved again.
- **All or nothing.** If anything fails (a syntax error, an unreadable certificate, a port that can't be bound),
  the error is logged and the running configuration stays exactly as it was.
- **Listeners** are kept when the same address is still configured (no dropped connections and no window where
  it isn't listening), opened when new, and closed when removed. `backlog`/`reuseport` and `worker_connections`
  changes need a restart; you get a warning.
- **New connections** use the new configuration. **In-flight requests** finish on the old one.
  **Plaintext keep-alive connections** aren't closed: their next request runs under the new configuration
  (unless the address changed what it speaks, plaintext to `ssl` or `proxy_protocol` on/off: then the connection
  is closed, since it never had the handshake or header the new configuration requires).
  (Closing idle keep-alives races clients that are just sending a request, and a client can't safely retry a
  POST. nginx has this race on reload; we don't.) **TLS connections** are closed once idle, with a normal FIN:
  their handshake was made under the old certificates and client-certificate policy, so they reconnect and
  handshake again. Anything still running on the
  old configuration after `reload_drain_timeout` (default 60s, taken from the *new* configuration) is closed with a
  FIN: WebSockets and other upgraded tunnels, long polls, slow downloads. So a reload never leaves the old
  configuration (its certificates, upstreams, CRLs) in force indefinitely. WebSocket clients see the connection
  drop and reconnect, landing on the new configuration.
- The old configuration's resources (upstream keep-alive pools) are released when its last connection ends.

## systemd

`dist/httpgrl.service` is a hardened unit; installation steps are in its header. It runs as a dedicated user
with only `CAP_NET_BIND_SERVICE` (so it can bind 80/443), a read-only filesystem view, no access to /home, and
a system-call filter. It also uses `MemoryDenyWriteExecute=yes`, which a JIT-compiling .NET app can't use; a
native AOT binary never needs writable+executable memory. `systemctl reload httpgrl` validates the config with
`-t`, then sends `SIGHUP`. Logs land in the journal as JSON lines (`journalctl -u httpgrl -o cat | jq .`).

## Docker

```sh
docker build -t httpgrl .                              # native AOT binary on a distroless, non-root base (~32 MB)
docker run --rm -p 8080:8080 --read-only --cap-drop ALL httpgrl
docker run --rm -p 8080:8080 -v "$PWD/site:/srv/www:ro" -v "$PWD/my.conf:/etc/httpgrl/httpgrl.conf:ro" httpgrl
docker build --target test .                           # run the test suite inside the build
docker compose up --build                              # see compose.yaml
```

- **Base image:** `mcr.microsoft.com/dotnet/runtime-deps:10.0-noble-chiseled`. That's libc, OpenSSL and CA certificates; no shell, no package manager. The binary needs no .NET runtime.
- **User and port:** runs as the non-root `app` user (uid 1654), so it listens on 8080. Map it with `-p 80:8080`.
- **Hardening:** the server writes nothing to disk, so `--read-only` and `--cap-drop ALL` just work.
- **Files:** config is `/etc/httpgrl/httpgrl.conf` (from `conf/docker/httpgrl.conf`), mime types are `/etc/httpgrl/mime.types`, content is `/srv/www`. The bundled config is validated with `-t` during the build.
- **Shutdown:** `docker stop` sends SIGTERM, which is a graceful shutdown bounded by `worker_shutdown_timeout`.
- **Reload:** `docker kill -s HUP <container>` after changing a mounted config or certificate.
- **Architecture:** the image targets the architecture it's built on (`linux-x64` or `linux-arm64`, via `TARGETARCH`). Native AOT doesn't cross-compile across architectures without a cross toolchain, so multi-arch builds run each platform under emulation.
- **No `HEALTHCHECK`:** the image has no shell or curl to run one with. Use your orchestrator's HTTP probe against a path you serve.

## Security monitoring

See [security monitoring](security-monitoring.md) for the implementation plan, JSON schema 2, event catalog,
request/upstream correlation, privacy defaults, detector rules and collection/alerting deployment examples. Access
logs distinguish complete, incomplete and dropped responses. Query strings and Referer values are omitted.
The server remains dependency-free; optional operational detection and CI detector tests use Python 3 standard library.
