# httpgrl

A small, fast, cross-platform HTTP/1.1 server in C# (.NET 10, native AOT) that reads nginx-style config.
It serves static files, index files and directory listings. Every feature is a module built on one plugin API.

No third-party runtime dependencies. TLS uses the platform stack (`SslStream`: OpenSSL / SChannel / Secure Transport).

```sh
./scripts/ci.sh                                   # build, test on JIT, test as native AOT, publish
dotnet publish src/Httpgrl -c Release -r linux-x64 -o artifacts/linux-x64
artifacts/linux-x64/httpgrl -c conf/httpgrl.conf  # -t: test config and exit
```

Output is a single ~8 MB executable. Logs go to stdout as one JSON object per line.
`SIGTERM`/`SIGINT`/`SIGQUIT` shut down gracefully, bounded by `worker_shutdown_timeout`.

**Reload** with `SIGHUP` (`kill -HUP <pid>`, `docker kill -s HUP <container>`). It re-reads the config and
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

## Layout

| Project | Role |
|---|---|
| `src/Httpgrl.Abstractions` | **The plugin API.** It is the only thing modules reference. |
| `src/Httpgrl.Core` | Config parser, HTTP/1.1 engine, connection management, TLS, logging. Also the core modules (`http_core`, `http_ssl`, `http_log`), which are written against the same API. |
| `src/Httpgrl.Modules.StaticFiles` | `http_index`, `http_autoindex`, `http_static`. |
| `src/Httpgrl.Modules.Rewrite` | `http_rewrite` (`return`, `set`, `if`, `break`) and `http_map`. |
| `src/Httpgrl.Modules.Headers` | `http_headers`: `add_header`. |
| `src/Httpgrl.Modules.Limits` | `http_limit_req`, `http_limit_conn`. |
| `src/Httpgrl.Modules.Access` | `http_access`: `allow`, `deny`. |
| `src/Httpgrl.Modules.Status` | `http_stub_status`: status and metrics endpoint. |
| `src/Httpgrl.Modules.Compression` | `http_compression`: gzip and brotli. |
| `src/Httpgrl.Modules.Proxy` | `http_proxy`: `proxy_pass`, `upstream {}`, WebSocket/Upgrade tunnelling. |
| `src/Httpgrl` | Host executable. The compiled-in module list is in `Program.cs`. |
| `tests/Httpgrl.Tests` | A dependency-free test runner. It runs on the JIT, and `ci.sh` also publishes and runs it as native AOT. |

Inside Core:
- `Config/`: lexer, parser, scopes, and the `$variable` compiler.
- `Http/`: request parser, URI normaliser, body decoder, response writer, session loop.
- `Pipeline/`: location/vhost routing and phase execution.
- `Hosting/`: sockets, the connection table and the deadline sweeper.

## Configuration

The syntax is nginx's. Unknown directives are errors, reported with `file:line`. A handful of nginx
tuning directives (`worker_processes`, `sendfile`, `tcp_nopush`, `user`, `pid`, ...) are accepted with a warning and have no effect.

| Directive | Context | Default | Notes |
|---|---|---|---|
| `include glob;` | any | | Relative paths resolve against the main config's directory. Wildcards are allowed in the file name. |
| `error_log stdout [level];` | main | `info` | `debug info warn error`. Only stdout is supported. |
| `worker_shutdown_timeout t;` | main | `10s` | Graceful-stop limit. |
| `reload_drain_timeout t;` | main | `60s` | *(httpgrl-specific)* After a reload, connections still on the old configuration (tunnels, long polls, slow transfers) are closed this long after it. `0` closes them at the next sweep (within 250 ms). nginx reuses `worker_shutdown_timeout` for this and defaults to no limit. |
| `worker_connections n;` | events | `16384` | Global connection cap. When full, the longest-idle keep-alive connection is evicted. |
| `connections_per_client n;` | events | `256` | Cap per IPv4 address or per IPv6 /64. `0` disables it. *(httpgrl-specific)* |
| `server`, `listen`, `server_name` | | `*:80` | `listen [addr:]port \| [v6]:port \| unix:/path [ssl] [proxy_protocol] [default_server] [reuseport] [backlog=n]`, or `listen tunnel:name` (see [Reverse tunnels](#reverse-tunnels)). With `proxy_protocol`, every connection must start with a PROXY protocol v1 or v2 header (from a load balancer or TCP relay), read within `ssl_handshake_timeout`. A missing, malformed or slow header closes the connection, and the parser never reads past the header. The relayed addresses are in `$proxy_protocol_addr`, `$proxy_protocol_port`, `$proxy_protocol_server_addr` and `$proxy_protocol_server_port`; `$remote_addr` stays the socket peer, as in nginx. Only enable it on sockets that only your relay can reach: anyone who can connect can claim any address. Server names can be exact, `*.x`, `x.*`, `.x`, or `~regex`. |
| `listen ... reuseport` | server | off | Sets `SO_REUSEPORT` so other processes of the same user can share the port, for multi-process setups or zero-downtime restarts. Every listener on that address must agree. Without it, a second instance fails to start. Unix only. |
| `location [=\|^~\|~\|~*] uri {}`, `location @name {}` | server, location | | nginx matching order. Nesting is supported. |
| `root path;` / `alias path;` | | `<confdir>/html` | Both accept `$variables`. |
| `index file ...;` | | `index.html` | |
| `autoindex on\|off;` `autoindex_format html\|json;` `autoindex_exact_size;` `autoindex_localtime;` | | `off` | Dotfiles are hidden. At most 50k entries are listed. Listings are streamed (chunked, no `Content-Length`), so a big directory doesn't cost its whole rendering in memory. |
| `try_files file ... uri\|=code\|@name;` | server, location | | |
| `error_page code ... [=[code]] uri;` | | | The nginx forms, including `= @named`. |
| `error_page code ... =444;` | | | *(httpgrl shorthand)* For these codes, close the connection and send nothing. At server level it also applies to malformed requests. The nginx idiom `error_page 404 = @drop;` + `location @drop { return 444; }` works too, but only for requests that parsed. |
| `internal;` | location | | |
| `types {}` / `default_type` | | built-in list / `text/plain` | `conf/mime.types` is provided. |
| `client_header_timeout` | http, server | `10s` | Applies to the **whole** request head, not to each read. |
| `client_body_timeout` / `send_timeout` | | `30s` | Per read / per write. |
| `client_body_min_rate` / `send_min_rate` | | `256` B/s | Measured over time spent blocked on the client. *(httpgrl-specific)* |
| `keepalive_timeout` / `keepalive_requests` | | `60s` / `1000` | |
| `client_max_body_size` | | `1m` | |
| `large_client_header_buffers n size;` | http, server | `4 8k` | Max line = size; max head = n×size; at most 100 headers. |
| `ssl_handshake_timeout` | http, server | `10s` | |
| `ssl_certificate` / `ssl_certificate_key` | http, server | | PEM. The chain is read from the cert file. Selected by SNI. Relative paths (here and in every `ssl_*` file directive) resolve against the main configuration file's directory, as in nginx, whichever included file they're written in. |
| `ssl_protocols` | http, server | `TLSv1.2 TLSv1.3` | Older protocols are a config error. |
| `ssl_ciphers list;` | http, server | **AEAD only** | **Deviation:** the default is stricter than nginx's `HIGH:!aNULL:!MD5`. TLS 1.3 uses its three suites (all AEAD). TLS 1.2 gets ECDHE with AES-GCM or ChaCha20-Poly1305 only: no CBC (SSL Labs rates it weak), no static-RSA key exchange, no SHA-1 MACs. A list of suite names, in OpenSSL (`ECDHE-RSA-AES128-GCM-SHA256`) or IANA (`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`) form, gives exactly those suites for TLS 1.2, in that order. As in nginx, TLS 1.3 keeps its suites unless the list names TLS 1.3 suites itself. Unknown names are a config error, and broken suites (NULL, anonymous, export, RC4, DES/3DES, MD5) are refused even when listed. OpenSSL cipher *expressions* (`HIGH:!aNULL`, `kEECDH+AESGCM`) need OpenSSL's rule engine, which .NET doesn't expose: they log a warning and the default applies, so stock configs still load. Windows' TLS stack can't take a suite list, so there the OS decides and an explicit list is a config error. `ssl_prefer_server_ciphers` is accepted and ignored: the server's order is used. **Session resumption:** .NET only keeps a server's OpenSSL context, where resumable sessions live, when no suite list is passed to it. So the default list is installed as OpenSSL's process-wide default instead, from memory at startup, and verified with in-memory handshakes. Servers on the default list resume TLS 1.2 and 1.3 sessions. An explicit list is passed per server, which costs resumption for that server (exact suites, every connection a full handshake). The default also applies to outgoing TLS (proxy upstreams, tunnels). If it can't be installed (no OpenSSL 3), the default list is passed per server too, with a warning. Either way, every handshake's negotiated suite is checked against the server's list, and a connection outside it is closed. |
| `ssl_reject_handshake on\|off;` | http, server | `off` | Refuse every TLS handshake that routes to this server, before any certificate is sent. Typically on the `default_server`: then clients without SNI (anyone connecting by IP) and with names no other server claims get nothing, so a scan of the address learns no domains. Such a server needs no certificate. Requests that still reach it, after a handshake for a real name followed by `Host: <ip>`, get **421**; add `error_page 421 =444;` to drop them silently. |
| `ssl_verify_client off\|on\|optional\|optional_no_ca;` | http, server | `off` | Client certificates (mTLS). `on`: required. `optional`: a certificate is not required, but one that's presented must verify. `optional_no_ca`: also accepts an unknown issuer (the verdict is in `$ssl_client_verify`); expired or wrong-purpose certificates still fail. A failed check fails the TLS handshake (nginx answers 400 instead). TLS session resumption is disabled on these servers, so every connection gets the full check. |
| `ssl_client_certificate file;` | http, server | | PEM CA bundle that client certificates must chain to. It's the *only* trust anchor: system roots are never used. Its CA names are sent to clients (not on Windows). Required for `on`/`optional`. |
| `ssl_verify_depth n;` | http, server | `1` | Maximum chain length above the client certificate: `1` means issued directly by a CA in the bundle. Raise it for intermediates (the client must send them). |
| `ssl_crl file;` | http, server | | PEM (any number of `X509 CRL` blocks) or DER. Like nginx (OpenSSL `CRL_CHECK_ALL`), *every* certificate in the chain below the trust anchor needs a current CRL from its issuer: so with an intermediate CA, include the root's CRL and the intermediate's. A missing, expired or not-yet-valid CRL fails the check. CRLs are read at load: reload (`SIGHUP`) to pick up new ones. Full CRLs only; delta and indirect CRLs and unknown critical extensions are a config error. Signatures: ECDSA or RSA PKCS#1 with SHA-256/384/512. |
| `ssl_stapling on\|off;` | http, server | `off` | Staple an OCSP response for our certificate, so clients needn't ask the CA (faster, more private handshakes). httpgrl fetches it itself: on the first handshake (never at load), refreshed hourly, and after a failure retried only every 5 minutes, whatever the traffic (nginx's schedule). A valid response keeps being stapled through a responder outage, and stops being stapled the moment it expires. Every response is verified before use: a successful basic response, about this certificate, signed by its issuer or by a responder certificate the issuer delegated OCSP signing to, consistent with its responder ID, within its validity. "revoked" is stapled as is (clients then reject the certificate) and logged; "unknown" isn't stapled. Failures, revocation and recovery are logged. The response survives reloads. The certificate file must include the issuer, and the certificate must name a responder (Let's Encrypt certificates no longer do), or `ssl_stapling_responder` must be set; otherwise a warning says nothing will be stapled. With `off`, nothing is fetched. |
| `ssl_stapling_verify on;` | http, server | | Always the case. `off` is a config error. |
| `ssl_stapling_file file;` | http, server | | Staple this DER response instead of fetching (nothing is fetched). Verified at load: invalid, or not about this certificate, is a config error; expired is a warning and nothing is stapled. Reload to pick up a new file. |
| `ssl_stapling_responder url;` | http, server | | Fetch from this URL instead of the certificate's. It changes where, not who: the response must still be signed by the issuer (or its delegate). |
| `ssl_ocsp`, `ssl_trusted_certificate` | | | Not supported, and a config error rather than silently ignored. |
| `disable_symlinks off\|on [from=$document_root\|/path];` | http, server, location | `off` | `on`: refuse (403) any path with a symlink in a component after `from` (default: after `/`, so a root reached through a symlink needs `from=$document_root`). Symlinks may lead out of the root, which a lexical containment check can't see. The check is race-free: one `openat(O_NOFOLLOW)` per component, each relative to the directory just opened, so a symlink can't be swapped in between check and open. `try_files`/`index` treat such paths as missing; directory listings hide symlinks, and enumerate the verified directory descriptor itself (through `/proc/self/fd`; without procfs, listings under `disable_symlinks` are refused with a 403 rather than done racily). `if_not_owner` isn't supported (a config error). Not on Windows. |
| `underscores_in_headers on\|off;` | http, server | `off` | Request header names with `_` are ignored when off (taken from the default server, since it applies before `Host` picks one). See the security model for why. |
| `http2 on\|off;` | http, server | **`off`** | *(opt-in, permanently)* Offer HTTP/2 through ALPN on TLS listeners; clients that don't speak it get HTTP/1.1. Decided by the server the TLS handshake selected (SNI). Never `h2c`: no cleartext HTTP/2, by upgrade or prior knowledge. nginx's old `listen ... http2` parameter doesn't enable it (it logs a warning saying so). Header limits come from `large_client_header_buffers`, as in nginx 1.19.7+. WebSockets work over HTTP/2 too (extended CONNECT, RFC 8441). Modules see them as ordinary HTTP/1.1 upgrade requests (`GET` with `Upgrade: websocket`), so `proxy_pass` tunnels them to HTTP/1.1 backends unchanged. Other `:protocol` values, `h2c` included, get a 501. |
| `http2_max_concurrent_streams n;` | http, server | `128` | Concurrent requests per HTTP/2 connection. Counts running handlers, not open streams, so a client that resets streams can't exceed it. Past it, a stream is refused (`REFUSED_STREAM`). |
| `server_tokens on\|off;` | | **`off`** | `off`: no `Server` header and no product name on error pages. `on`: `Server: httpgrl/<version>` plus the error-page footer. Note: nginx's `off` still sends a header; here `off` sends none. |
| `access_log stdout\|off;` | | `stdout` | nginx's `access_log /path [format];` is accepted with a warning: records go to stdout as JSON anyway, and `log_format` is ignored. `error_log /path [level];` likewise (the level applies). That lets a stock nginx config load unchanged. |

### Rewrite, map and headers

The rewrite directives of a block (`return`, `set`, `if`, `break`) form a script that runs in config order. The
server block's script runs first for every request, then the selected location's. A block's script is not
inherited by nested locations (nginx semantics).

| Directive | Context | Default | Notes |
|---|---|---|---|
| `return code [text];` `return 301\|302\|303\|307\|308 url;` `return url;` `return 444;` | server, location, if | | nginx semantics. Without text, the core renders the body and `error_page` applies. `$variables` in redirect URLs are re-encoded, so a decoded `$uri` can't inject headers. `444` closes the connection silently. |
| `set $var value;` | server, location, if | | Declares `$var` (usable anywhere in the config, even before the `set`). Values are per request and survive internal redirects. Built-in variables can't be overwritten. |
| `if (condition) { ... }` | server, location, if | | Conditions: `($var)` (false if empty or `"0"`), `$var = value`, `$var != value`, `$var ~ regex`, `~*` (case-insensitive), `!~`, `!~*`. A positive regex match sets `$1`..`$9`. **Deviation:** the block may contain only `return`, `set`, `break` and nested `if`. nginx's "if is evil" comes from `if` being a half-location where other directives misbehave; here that can't happen. For a conditional header or upstream, compute a value with `map`. File tests (`-f`, `-d`, ...) aren't supported (modules never see paths): use `try_files`. Quote regexes that contain `{`, `}` or `;`. |
| `break;` | server, location, if | | Stops the rest of the current block's script. |
| `rewrite regex replacement [last\|break\|redirect\|permanent];` | server, location, if | | nginx semantics. Matches `$uri`; `$1`..`$9` in the replacement. No flag: the URI changes and the script carries on; afterwards the location is chosen again for the new URI. `last`: stop here and continue in the new URI's location (whose rewrites run; at most 10 such cycles, then 500). `break`: stop and stay in this location with the new URI. `redirect`/`permanent`, or a replacement starting with `http://`/`https://`: answer 302/301. A replacement with its own `?args` gets the original arguments appended, unless it ends with `?`. A rewrite can reach `internal` locations; a URI that climbs above `/` is a 500. `rewrite_log` is accepted (no-op). |
| `map $source $result { ... }` | http | | `default value;`, exact `key value;` (case-sensitive, checked first), then `~regex value;` / `~*regex value;` in order. A regex match sets `$1`..`$9` for the value. Values may contain variables, including other maps. `\~` starts a literal key with `~`. The result is computed when used, not cached. Reference cycles between maps fail that request with a 500 and are logged; they can't recurse without bound. `hostnames` and `include` are not supported. |
| `add_header name value [always];` | http, server, location | | Sent on 200, 201, 204, 206, 301, 302, 303, 304, 307 and 308, or on every status with `always`. An empty value (e.g. from a `map`) sends nothing. **Deviations, both deliberate:** (1) levels **merge**. A location that adds one header keeps the server's and http's (nginx drops all inherited `add_header`s as soon as a level has its own, a classic way to lose HSTS). An inner entry replaces outer entries of the same name, and `add_header X "";` removes an inherited one. (2) The header **replaces** any header of that name already in the response (from a handler or an upstream) instead of duplicating it. Framing headers (`Content-Length`, `Connection`, ...) are a config error. Values with CR, LF or NUL are dropped and logged. |

```nginx
map $scheme $hsts { https "max-age=63072000; includeSubDomains"; }
add_header Strict-Transport-Security $hsts always;   # only over TLS
add_header X-Content-Type-Options nosniff always;

location /admin {
    if ($ssl_client_verify != SUCCESS) { return 403; }  # with ssl_verify_client optional
    proxy_pass http://admin;
}
```

### Rate and connection limits

```nginx
http {
    limit_req_zone  $remote_net zone=perclient:10m rate=20r/s;
    limit_req_zone  $remote_net zone=login:1m rate=10r/m;
    limit_conn_zone $remote_net zone=conns:10m;

    limit_req  zone=perclient burst=40 nodelay;    # everywhere...
    limit_conn conns 20;

    server {
        location /login { limit_req zone=login burst=5; }   # ...and stricter here (both apply)
        location /health { limit_req off; limit_conn off; }
    }
}
```

| Directive | Context | Default | Notes |
|---|---|---|---|
| `limit_req_zone key zone=name:size rate=Nr/s\|Nr/m;` | http | | nginx's leaky bucket per key. The key may combine variables; an empty key isn't limited (use a `map` to exempt clients). `size` is a memory budget (at least 32k; roughly 128 bytes + the key per client), so long keys can't grow a zone past it. When full, the least recently seen keys are forgotten. A key too long to fit at all is rejected. |
| `limit_req zone=name [burst=n] [nodelay\|delay=n];` | http, server, location | | Within `burst`, excess requests are delayed to the rate (`nodelay`: served at once; `delay=n`: the first n excess served at once). Beyond it: rejected. Several per level; a request must pass all of them, and one that's rejected isn't charged to the others. Counted once per request, whatever internal redirects follow. **Deviation:** levels **merge**. A location's own `limit_req` adds to inherited ones instead of replacing them all (nginx), so a stricter `/login` limit can't silently lift the server-wide one. The same zone at an inner level replaces the outer entry; `limit_req off;` drops inherited limits. |
| `limit_conn_zone key zone=name:size;` / `limit_conn zone n;` | http / http, server, location | | At most n requests in flight per key. A request holds its slot until it ends (a WebSocket for its whole life) and releases it however it ends, including a reset. A full zone refuses new keys. Merges across levels like `limit_req`; `limit_conn off;` too. |
| `limit_req_status` / `limit_conn_status code;` | http, server, location | **`429`** | nginx defaults to 503, which tells clients and monitoring the server is broken. `444` drops the connection without a response. `error_page` applies to other codes. |
| `limit_req_dry_run` / `limit_conn_dry_run on\|off;` | http, server, location | `off` | Account and log, but never delay or reject. |
| `limit_req_log_level` / `limit_conn_log_level info\|notice\|warn\|error;` | http, server, location | `warn` | Rejections are logged at this level; delays one level lower. |

Limits run at the start of the access phase, after the rewrite phase, so `return` isn't limited (as in nginx).
Zone state survives a reload as long as the zone keeps its name, size and key. Requests still running on the old
configuration keep counting against `limit_conn`.

### Access control and status

| Directive | Context | Default | Notes |
|---|---|---|---|
| `allow address\|CIDR\|unix:\|all;` / `deny ...;` | http, server, location | | Checked in order; the first match decides; no match allows. Denied: 403 (`error_page 403 =444` drops instead). As in nginx, a level with its own rules replaces the inherited list. **Deviation:** a network with host bits set (`192.168.1.1/24`) is a config error rather than silently masked. Runs after `limit_req`/`limit_conn` (nginx's order). |
| `stub_status [nginx\|prometheus\|json];` | location | `nginx` | Server-wide counters. `nginx` is byte-compatible with nginx's output, so existing exporters work. `prometheus` is the text exposition format, with responses by status class, reloads, dropped log lines and memory (resident, managed heap, GC-committed, full GCs) added. Counters cover the process lifetime (they survive reloads); "requests" counts completed requests. Restrict it with `allow`/`deny`. |

```nginx
location = /metrics { stub_status prometheus; allow 10.0.0.0/8; deny all; }
```

### Compression

```nginx
gzip on;
brotli on;                 # preferred when the client accepts both
gzip_types text/plain text/css application/json application/javascript image/svg+xml;
```

| Directive | Context | Default | Notes |
|---|---|---|---|
| `gzip on\|off;` / `brotli on\|off;` | http, server, location | `off` | Compresses 200, 403 and 404 responses (as nginx) of a matching type that aren't already encoded and don't say `Cache-Control: no-transform`. Works for files, handler output and proxied responses, including streamed ones (each flush goes through the compressor, so SSE and long polls still deliver promptly). Compressed responses are chunked, get a weak ETag, and drop `Accept-Ranges`; range requests are served uncompressed. |
| `gzip_types type ...;` / `brotli_types` | http, server, location | common text types | One list for both (`*` matches everything). `text/html` is always included. **Deviation:** the default covers HTML, plain text, CSS, JS, JSON, XML, SVG, wasm and friends (nginx: only text/html). |
| `gzip_comp_level 1..9;` / `brotli_comp_level 0..11;` | http, server, location | `1` / `4` | |
| `gzip_min_length size;` | http, server, location | `256` | Applies when the length is known up front (nginx: 20). |
| `gzip_vary on\|off;` | http, server, location | **`on`** | Adds `Vary: Accept-Encoding` to every compressible response, compressed or not, and merges with an existing `Vary`. nginx defaults to off, which lets shared caches serve gzip to clients that didn't ask for it. |
| `gzip_static on\|off\|always;` / `brotli_static on\|off;` | http, server, location | `off` | Serve a precompressed sibling (`x.br`, then `x.gz`) when the client accepts it (`always`: the `.gz` regardless). It's opened through the core like any file (containment, `disable_symlinks`), keeps the original's `Content-Type`, and is served with a known length; conditional requests and ranges apply to it. Adds `Vary: Accept-Encoding`. Falls back to the original, which on-the-fly compression may still handle. |
| `gzip_proxied`, `gzip_disable`, `gzip_buffers`, `gzip_http_version` | | | Accepted and ignored with a warning, so nginx configs load. Responses compress regardless of `Via`. |

**BREACH:** compressing a response that reflects attacker-controlled input next to a secret (a CSRF token, say)
over TLS lets an attacker who can observe response sizes recover the secret. That's why compression is off by
default. Don't enable it for such responses, or mask the secrets per response.

Dropping traffic aimed at the server's address rather than a name, over HTTP and HTTPS:

```nginx
server { listen 80 default_server;  return 444; }                                       # Host: <ip>, or unknown names
server { listen 443 ssl default_server; ssl_reject_handshake on; error_page 421 =444; }  # no SNI / unknown SNI / Host: <ip>
```

**Choosing a key:** `$remote_net` is the client's IPv4 address, or its IPv6 **/64**. A single IPv6 client typically
controls a whole /64 and can rotate through 2^64 addresses, so `$binary_remote_addr` (also available) lets it
dodge any per-address limit. `$remote_net` is the same grouping the core's per-client connection cap uses.
Behind a proxy or CDN, key on a header that it sets and clients can't.

Variables: `$uri $request_uri $args $is_args $host $server_name $scheme $https $remote_addr $remote_port`
`$server_addr $server_port $request_method $server_protocol $document_root $request_filename $status`
`$body_bytes_sent $request_time $connection $connection_requests $msec $time_iso8601 $binary_remote_addr $remote_net`
`$limit_req_status $limit_conn_status $request_id`

`$request_id` is 32 random hex characters, made on first use and stable for the request, and is in every access-log
line. Pass it upstream with `proxy_set_header X-Request-ID $request_id;`. To keep an id a trusted proxy in
front already set: `map $http_x_request_id $rid { "" $request_id; default $http_x_request_id; }`. Don't do
that for untrusted clients: they choose the value., `$1`..`$9` from regex
locations, and the prefix families `$http_*`, `$sent_http_*`, `$arg_*` and `$cookie_*`.

TLS variables: `$ssl_protocol $ssl_server_name $ssl_client_verify` (`SUCCESS`, `FAILED:reason`, `NONE`) and, when a
client certificate was presented, `$ssl_client_s_dn $ssl_client_i_dn $ssl_client_serial $ssl_client_escaped_cert` and
`$ssl_client_fingerprint`. The fingerprint is the lowercase hex **SHA-256** of the certificate (nginx uses SHA-1).
The access log records `client_verify`. Modules read the same data from `ctx.Connection.ClientCertificate`,
`ClientVerify` and `ClientVerified`.

To hand the identity to a backend, set it with `proxy_set_header` (for example
`proxy_set_header X-Client-Verify $ssl_client_verify;`). A request header with the same name as one set by
`proxy_set_header` is always dropped, even when the value is empty, so a client can't forge it.

### Reverse proxy

```nginx
upstream app {
    server 10.0.0.2:8080 weight=2 max_fails=3 fail_timeout=10s;
    server 10.0.0.3:8080;
    server 10.0.0.9:8080 backup;
    keepalive 64;                 # idle connections kept per peer
}
server {
    location /api/ { proxy_pass http://app/v1/; }           # /api/x -> /v1/x
    location /ws/  { proxy_pass http://app; }               # WebSockets: nothing else needed
    location /     { proxy_pass https://origin.example; proxy_set_header Host $host; }
}
```

| Directive | Context | Default | Notes |
|---|---|---|---|
| `proxy_pass http\|https://host[:port][/uri];` / `http://upstream_name[/uri];` / `http://unix:/path.sock:[/uri];` | location | | With a URI part, the matched location prefix is replaced by it; without one, the path is passed through. Every address a hostname resolves to becomes a peer, and hostnames are re-resolved while running (see `upstream_resolve_interval`). `localhost` and `*.localhost` are always `127.0.0.1` and `::1` and are never looked up (RFC 6761); a resolver could add more, such as Debian's `127.0.1.1` hostname alias. |
| `proxy_pass http://$var[...];` | location | | With variables, the URL is evaluated per request and split at the first `/`, as in nginx. **Deviation:** the host part must be the name of an `upstream` block, otherwise the request gets a 502 and a log line. It is never resolved as an arbitrary host, because a variable fed by the request (`$arg_*`, `$http_*`) would turn the server into an open proxy to anything it can reach (SSRF). That covers the usual use, picking an upstream with `map`. A URI part replaces the request URI. Control characters, spaces and non-ASCII in it are percent-encoded, so a decoded `$uri` can't break the request line. There's no `proxy_redirect default` mapping for these locations. |
| `upstream name { server addr [weight=n] [max_fails=n] [fail_timeout=t] [backup] [down] [resolve]; keepalive n; keepalive_timeout t; keepalive_requests n; }` | http | `keepalive 32`, `60s`, `1000` | Smooth weighted round-robin. Passive health checks: a peer is skipped after `max_fails` failures within `fail_timeout`. Implicit upstreams (a plain host in `proxy_pass`) get the same defaults. A hostname that doesn't resolve at load is a config error, unless the server has `resolve`: then it starts without addresses (502 until they appear). |
| `health_check [uri=/path] [interval=5s] [timeout=2s] [fails=1] [passes=1] [status=200-399] [host=name];` | upstream | | Active checks (in nginx, an nginx Plus feature): every interval, a `GET` of `uri` to each peer, using the scheme and TLS settings the locations that proxy to this upstream use, with `Host` from `proxy_pass` unless `host=` is set. One verdict per peer serves every location, so locations that reach the group with different schemes, TLS settings (name, verification, trust, protocols) or, without `host=`, a different `Host` are a config error. A peer that fails `fails` checks in a row (connect error, timeout, or a status outside `status`) leaves rotation; `passes` good checks bring it back. If every peer is actively down, requests get an immediate 502 rather than being tried anyway (passive failures still fall back to trying everyone). Checks start with the first proxied request and probe whatever addresses DNS currently gives. |
| `upstream_resolve_interval t\|off;` | http | `30s` | **Deviation:** every upstream hostname (in `upstream` blocks and `proxy_pass`) is re-resolved this often through the system resolver (`/etc/hosts`, nsswitch, DNS). nginx resolves once unless you use a `resolver` and `resolve`. A failed or empty answer keeps the last good addresses. Peers whose address stays keep their failure counts and pooled connections; removed ones finish in-flight requests and close their idle connections. `off` resolves once at load. The system resolver doesn't report TTLs, hence an interval. |
| `proxy_set_header name value;` | http, server, location | | An empty value removes the header. Setting any header at a level replaces the inherited list (nginx). `Host` defaults to the upstream's authority (`$proxy_host`). `Connection`/`Upgrade` are accepted but ignored, because the module manages them. |
| `proxy_hide_header name;` | | | Drop a response header coming from the upstream. |
| `proxy_cache`, `proxy_cache_bypass`, `proxy_no_cache`, `proxy_cache_*` | | | Accepted and ignored with a warning: there's no proxy cache. |
| `proxy_buffering on\|off;` / `proxy_buffers n size;` | http, server, location | `on`, `8 8k` | With buffering, the upstream body is read into memory (up to n×size) while the client is being written to, so the upstream connection goes back to the pool as soon as the body is in, however slowly the client reads. Bodies that arrived with the head take a fast path; bodies known to be larger than the buffer are streamed (buffering couldn't free the upstream early, so it would only cost). The client is flushed whenever the buffer runs dry, so streamed responses (SSE, long polls) still arrive promptly. An upstream's `X-Accel-Buffering: no` turns it off for that response, and the header isn't forwarded. **Deviation:** nothing spills to disk; past the buffer, backpressure applies. A truncated buffered body becomes a clean 502 if nothing had reached the client yet; otherwise the connection is cut, as when streaming. `proxy_max_temp_file_size`, `proxy_temp_path`, `proxy_busy_buffers_size` and `proxy_temp_file_write_size` are accepted and ignored with a warning. |
| `proxy_redirect default\|off;` / `proxy_redirect redirect replacement;` | http, server, location | `default` | Rewrites `Location` and the URL in `Refresh` from the upstream. `default` maps the `proxy_pass` URL to the location: with `location /one/ { proxy_pass http://app:8080/two/; }`, `http://app:8080/two/x` becomes `/one/x`. That needs a prefix or exact location, so regex and named locations get no default mapping. Prefix rules match case-insensitively and replace the prefix; `~regex` / `~*regex` rules replace the whole value and can use `$1`..`$9`; replacements may contain variables. The first matching rule wins. A level with rules replaces the inherited list; `off` turns rewriting off. |
| `proxy_http_version 1.0\|1.1;` | | **`1.1`** | nginx defaults to 1.0. 1.1 is required for keep-alive and Upgrade. |
| `proxy_connect_timeout` / `proxy_send_timeout` / `proxy_read_timeout` | | `10s` / `60s` / `60s` | Connect timeout includes the TLS handshake. Send/read are per operation; the wait for the response head starts when the request body has been sent. For upgraded tunnels, `proxy_read_timeout` is the idle timeout counted across *both* directions. |
| `proxy_buffer_size size;` | | `8k` | Maximum size of the upstream response head. Bigger is a 502. |
| `proxy_next_upstream_tries n;` | | all peers | Connect errors and timeouts move on to the next peer. Once a request was sent, only idempotent requests without a body are retried. |
| `proxy_intercept_errors on\|off;` | | `off` | Upstream statuses ≥ 300 that have an `error_page` here are replaced by it, including the `=444` drop. |
| `proxy_upgrade on\|off;` | | **`on`** | *(httpgrl)* Tunnel `Upgrade` requests (WebSocket etc.) without the nginx `map`/`proxy_set_header` boilerplate. `h2c` is never tunnelled. |
| `proxy_pass_raw_uri on\|off;` | | **`off`** | *(httpgrl)* Off: the upstream gets our normalized, re-encoded path, so we and the backend agree on what was requested. On: the client's bytes, as nginx does without a URI part. |
| `proxy_ssl_verify on\|off;` | | **`on`** | nginx defaults to off. Verification uses the system trust store, or `proxy_ssl_trusted_certificate`. |
| `proxy_ssl_server_name on\|off;` / `proxy_ssl_name name;` | | **`on`** / host | SNI and the name to verify. |
| `proxy_ssl_trusted_certificate file;` / `proxy_ssl_protocols` | | | PEM CA bundle (read at load). `TLSv1.2 TLSv1.3`. |

Variables: `$proxy_host $proxy_port $proxy_add_x_forwarded_for $upstream_addr $upstream_status`. Responses stream
through without buffering (nginx's `proxy_buffering off`), and are flushed whenever the upstream pauses, so SSE and long-polling work.

A pooled connection that the upstream closed or reset before answering is retried quietly (up to twice, idempotent
requests only), since keep-alive races aren't the upstream's fault. Anything the upstream actually sent, such as a
malformed or ambiguous answer, is reported and counted as a failure even on a pooled connection.

### Reverse tunnels

*(httpgrl; nginx has no equivalent.)* Serve sites from a machine with no open ports, such as a box on a home network
behind NAT. The **agent** (the machine with the content) dials out to a **remote** httpgrl with a public address and
parks a few connections there. The remote sends requests down those connections and the agent answers them. Both ends
are ordinary httpgrl configurations.

```nginx
# remote (public)
http {
    upstream home { tunnel; }                       # peers are whichever agents have dialed in
    server {
        listen 443 ssl;  server_name tunnel.example.com;
        ssl_certificate ...;  ssl_certificate_key ...;
        ssl_verify_client optional;  ssl_client_certificate /etc/httpgrl/agents-ca.pem;
        location = /.well-known/httpgrl-tunnel { tunnel_accept home; }
    }
    server {
        listen 443 ssl;  server_name home.example.com;
        location / { proxy_pass http://home; proxy_set_header Host $host; }
    }
}

# agent (behind NAT)
http {
    tunnel home {
        connect tunnel.example.com:443;
        certificate /etc/httpgrl/home.crt;  certificate_key /etc/httpgrl/home.key;   # CN or a DNS SAN = "home"
    }
    server {
        listen tunnel:home;  server_name home.example.com;
        location / { proxy_pass http://127.0.0.1:8080; }            # or root, or anything else
    }
}
```

How it works:
- The agent opens TLS connections to the remote, presenting its certificate, and sends
  `GET /.well-known/httpgrl-tunnel` with `Upgrade: httpgrl-tunnel`.
- The remote answers `101` and parks the connection in the `tunnel` upstream's pool. From then on the direction is
  reversed: the remote writes requests and the agent serves them like any accepted connection (its own `server`
  blocks, locations, limits and logs apply).
- On the remote, it's a normal upstream: strict parsing of the agent's answers, keep-alive reuse, request bodies,
  WebSockets and `X-Forwarded-For` all work as with any other `proxy_pass`.
- The agent keeps `pool` idle connections parked and dials a replacement as soon as one starts serving. A request
  that finds the pool empty waits up to `proxy_connect_timeout` for one. If no agent has been connected for longer
  than that, requests fail at once (502) instead of each waiting.
- Each parked connection has a read pending, so one the agent closes (or one that dies) leaves the pool at once.
  The remote closes idle parked connections after `idle=` and the agent redials. Doing it from the remote's side
  means a request can never be written into a connection the agent is just closing.

| Directive | Context | Default | Notes |
|---|---|---|---|
| `upstream name { tunnel [max=n]; }` | upstream | `max=64` | Peers are agents that dialed in through `tunnel_accept`. At most `n` connections are parked or serving at once; past that, agents get a 503 and back off. Can't be combined with `server` or `health_check`. Use `proxy_pass http://name` (the tunnel is already TLS, so `https://` is a config error). `keepalive_timeout`/`keepalive_requests` apply. |
| `tunnel_accept upstream [client=name] [idle=t];` | location | `client=` the upstream's name, `idle=120s` | Accepts agents into the named tunnel upstream. **The agent's client certificate must verify against `ssl_client_certificate`, and its CN or a DNS SAN must be `client=`** (by default, the tunnel's name). So a certificate issued for one tunnel can't park in, or squat, another; otherwise it's a 403. The handshake must be a bodiless HTTP/1.1 `GET` upgrading to `httpgrl-tunnel` (400 otherwise). Use `ssl_verify_client on` on a dedicated server, or `optional` when the same server also serves ordinary clients. Keep `idle` above `proxy_read_timeout`, since a request that's waiting for the agent's answer counts as idle. |
| `tunnel name { connect host[:port]; certificate f; certificate_key f; ... }` | http | | The agent side. `connect` is the remote (port 443 by default; hostnames are resolved on each dial). `certificate`/`certificate_key` (required) are what the remote checks. `trusted_certificate f` verifies the remote against this PEM bundle instead of the system roots. `server_name n` is the name the remote's certificate must match, also used for SNI and `Host` (default: the `connect` host; required when that's an IP). `uri /path` defaults to `/.well-known/httpgrl-tunnel`. `pool n` idle connections (default 4), `max n` in total (default 64). `connect_timeout t` (default 10s) covers TCP, TLS and the upgrade handshake. `idle_timeout t` (default 5m) is a backstop: normally the remote closes idle connections first. Relative paths resolve against the config directory. |
| `listen tunnel:name [default_server];` | server | | Puts the server behind the tunnel. Nothing is bound. Requests arrive as plain HTTP/1.1 inside the tunnel's TLS, so `$scheme` is `http` and `$remote_addr` is the remote. The original client is in `X-Forwarded-For` if the remote sets it. Connections stay open between requests whatever `keepalive_timeout` says (the remote decides when it's done with one); `keepalive_requests` still applies. |

Details:
- **Failures.** The agent backs off exponentially, with jitter, from 1s up to 30s while the remote is unreachable or
  refusing. It logs the first failure and then each doubling, and logs `tunnel connected` once it recovers. TCP
  keep-alives on the agent's sockets notice a remote that silently went away.
- **Reload, remote side.** Parked connections of the old configuration are closed right away (connections in use
  finish their request first). The agents redial into the new configuration, and requests arriving meanwhile wait
  for them, so nothing fails.
- **Reload, agent side.** If the tunnel's remote, URI, name, certificate and trust are unchanged, its connections
  are kept: they move to the new configuration at their next request, as plaintext keep-alives do. If any of those
  changed, the connections are closed and redialed with the new settings, so rotating the agent's certificate
  takes effect.

## Security model

**Fuzzing.** Every parser of untrusted or semi-trusted bytes has a mutation-fuzz target in
`tests/Httpgrl.Tests/Fuzz.cs`: the request head, the URI normalizer, chunked bodies, upstream response heads, the
config parser (with every module's directives), CRLs, OCSP responses, PROXY protocol headers, `Accept-Encoding`,
the tunnel handshake response, `Range`, `Host`/SNI names, rewrite results, and the mapping of request paths through
`root`/`alias` (checked for containment independently of the mapper). Each target states which rejections are legitimate and
which invariants an accepted input must hold (e.g. never both `Content-Length` and `chunked`, no dot segments
in a path). The test suite runs a fixed-seed pass of each, so CI is also a regression fuzz. For long runs:

```sh
dotnet run -c Release --project tests/Httpgrl.Tests -- --fuzz all 600        # 10 minutes, all targets, random seed
dotnet run -c Release --project tests/Httpgrl.Tests -- --fuzz request 60 42  # one target, fixed seed
```

**Soak test** (Linux). Runs the real binary as a child process under mixed load: static, proxied and POSTed
requests, WebSockets, rate-limited paths, slow-loris, garbage, oversized heads, mid-download resets and abandoned
bodies. It reloads every few seconds, then checks for leaked file descriptors, memory growth, error-level log
lines, failed requests, and a clean exit on SIGTERM. It samples the server's own memory metrics, to tell managed
heap growth (garbage awaiting a full GC, which is normal) from native growth (which would be a leak):

```sh
dotnet run -c Release --project tests/Httpgrl.Tests -- --soak artifacts/linux-x64/httpgrl 300   # add --no-reload to isolate reloads
```

**Benchmark.** There's no wrk dependency: `--bench url [seconds] [connections]` runs a keep-alive load generator. On one
box, proxying to a second httpgrl with buffering on: about 54k req/s for 1 KiB responses and about 2 GiB/s for 1 MiB,
level with buffering off.

A finding prints the seed, iteration and input, which reproduce it exactly. It's dependency-free and not
coverage-guided, so it's a complement to, not a replacement for, a coverage-guided fuzzer.

**Timeouts and slow clients.** A sweeper thread checks every connection's deadlines; each connection only stamps times into its record, so enforcement stays cheap however many connections there are.
- Header timeout: the whole request head must arrive within `client_header_timeout` of its first byte. Trickling one byte at a time does not extend it.
- Idle connections: an idle new or keep-alive connection is closed at its deadline.
- Slow uploads and slow readers: body reads and response writes each have a per-operation timeout plus a minimum transfer rate. That covers slow-body uploads and slow-read downloads.

**Connection limits.**
- Connections are capped globally and per client (IPv4 address or IPv6 /64).
- When the table is full, the longest-idle keep-alive connection is evicted.
- Unread request bodies are drained only up to 64 KiB; anything larger closes the connection. Closes are lingering, so a client's unread data can't trigger a reset that destroys our response.

**HTTP/2** (`http2 on`):
- **Request strictness carries over.** Lower-case field names; pseudo-fields first, once each, and only the request ones; no connection-specific fields (`TE` only as `trailers`); no CR, LF or NUL, and no surrounding whitespace, in values. `:scheme` must be `https`. `:path` goes through the same normalizer, `:authority` and `Host` must agree, and there's one valid `content-length`, which the DATA frames must match. A malformed request resets its stream (`PROTOCOL_ERROR`); the connection carries on.
- **HPACK stays bounded and in step.** Integers, strings, the dynamic table (capped at the size we advertise) and the decoded header list are all bounded. A list over the limit gets a 431 for that request only: the block is still decoded to the end, so compression state never desynchronizes. Every header block is decoded, even one about to be refused, for the same reason. The response encoder never uses the dynamic table: no state across responses, nothing to probe.
- **Rapid reset (CVE-2023-44487).** `http2_max_concurrent_streams` counts handlers, not open streams, so a reset stream holds its slot until its handler has stopped. Streams the client resets, and ones that are refused or malformed, also draw on a budget: GOAWAY `ENHANCE_YOUR_CALM` when it runs out. Bursts of real, completed requests don't touch it.
- **CONTINUATION floods** (2024): a header block is capped in compressed size and in fragments, and must arrive within `client_header_timeout`.
- **Control-frame floods:** SETTINGS, PING, PRIORITY, RST_STREAM, WINDOW_UPDATE, unknown frames, and empty DATA and header fragments share one budget per connection.
- **Each stream has its own deadlines,** enforced by the same sweeper: `client_body_timeout` and minimum rates on uploads, and `send_timeout` while a client keeps its window closed. A stalled stream is reset without its connection.
- **WebSockets** (extended CONNECT) are translated into the HTTP/1.1 upgrade request modules already handle, with a fresh `Sec-WebSocket-Key` for the backend. The tunnel is that one stream: idle timeout across both directions, as on HTTP/1.1, and a slot under `http2_max_concurrent_streams` for as long as it's open. Only `websocket` is tunnelled; a plain CONNECT is a 405.
- **Ending connections:** errors end with a GOAWAY that the client gets to read, thanks to a lingering close. Reload, shutdown and `keepalive_requests` send GOAWAY and let running streams finish (within `reload_drain_timeout`).

**Strict parsing.**
- Line endings must be CRLF. Bare LF or CR, obs-fold, and whitespace before `:` are rejected.
- Exactly one `Content-Length`. `Transfer-Encoding` must be exactly `chunked` and never alongside `Content-Length`.
- No `Transfer-Encoding` on HTTP/1.0. Exactly one `Host`, validated and lower-cased. An HTTP/1.1 request in absolute
  form (`GET http://a.test/ HTTP/1.1`) still needs a valid `Host` field (RFC 9112 3.2), though the target's authority
  is what selects the server. `$request_uri` is the origin-form path and query even then, as in nginx, so
  `return 302 $request_uri;` can't be pointed at another host.
- Header names containing `_` are ignored unless `underscores_in_headers on` (nginx's default too). CGI-style
  backends (FastCGI, WSGI, Rack) fold `_` and `-` into one variable name, so `X_Client_Verify` would otherwise reach
  them as the `X-Client-Verify` a proxy sets or strips.
- Chunk sizes, chunk lines and trailers are bounded. Chunk extensions and trailer fields (which are dropped) must still be well-formed: no control characters, so no bare CR for another parser to read as a line end.
- In short, anything a proxy in front of or behind the server could read differently is a 400. The future proxy module depends on this.

**Paths.**
- URIs are percent-decoded, dot-segments are resolved, and an escape above `/` is a 400. Control characters (`%00`–`%1F`, `%7F`) and invalid UTF-8 are rejected. **Deviation:** nginx accepts `%0A` in paths. A decoded newline in `$uri` could reach response or upstream headers, and slip past anchored regexes (`$` also matches before a trailing newline, in PCRE as in .NET). So `if ($uri ~ "^/admin$")` can't be fooled by `/admin%0A`.
- Every mapped filesystem path is checked to stay inside its `root`/`alias` directory. This closes nginx's classic `location /img { alias /x/; }` + `/img../` hole. A value with variables is checked against its constant leading directory. One that *begins* with a variable (`root $doc;`) has none, so its evaluated value must be an absolute path without `.`/`..` segments, and is itself the boundary: whatever a variable holds, the request can't climb out of it. (Which directory a variable names is still the configuration's business: don't build one from request input.)
- Regexes run on .NET's linear-time engine whenever the pattern allows it (no backreferences or lookarounds). The rest backtrack with a 50 ms match timeout. A timeout fails the request with a 500 and one `warn` line. Neither "matched" nor "didn't match" can be assumed without failing open somewhere (`if ($x ~ ...) { return 403; }` versus `!~`), and nginx also answers a failed regex execution with a 500.
- Modules never see filesystem paths. They ask the core for resources by request path, so the mapping, containment and safe-open policy has exactly one implementation (`Core/Files/LocalFiles.cs`). CI enforces this with `scripts/check-boundaries.sh`.
- Location matching is case-insensitive on case-insensitive filesystems.
- On Windows, ADS names (`:`), trailing dots and spaces, and device names (`CON`, `NUL`, ...) are refused.

**File serving.**
- Unix opens use `O_NONBLOCK|O_CLOEXEC`, so a FIFO in the web root can't hang a thread. Non-seekable files get a 403.
- Directory listings are HTML-escaped and their hrefs percent-encoded, with a `./` prefix so a file named `javascript:` can't become a link scheme.
- Symlinks are followed by default (as nginx), including out of the root. `disable_symlinks on` refuses them race-free.

**Response headers.** `HeaderCollection` rejects CR, LF, NUL and non-Latin-1 characters, so response splitting is impossible. Framing headers are always written by the core.

**Logging.** Log lines are produced by `Utf8JsonWriter`, so a log line is always a single JSON object. A blocked stdout drops lines (and counts them) instead of stalling requests. The queue is bounded in bytes (8 MiB), not lines, and a line is at most 16 KiB (a record over that is written again with every string field cut short and `"truncated":true`), so request-controlled fields can't make a stalled stdout cost gigabytes. If stdout fails for good, lines are dropped from then on.

**Reverse proxy.**
- Upstream responses are parsed as strictly as requests: CRLF only, no obs-fold, exactly one `Content-Length` (repeats are refused even when they agree), a status of 100–599, `Transfer-Encoding: chunked` only and never alongside `Content-Length`, a bounded head, and well-formed chunk extensions and trailers. A broken or hostile backend gets a 502; it can't split our response or desync the client.
- If an upstream fails after the head went out, the client connection is cut, so a truncated body never looks complete.
- The response is read while the request body is still uploading. An upstream that answers early (401, 413, a redirect) and stops reading gets its answer relayed instead of a send timeout turning it into a 504; the rest of the client's body is abandoned (that client connection closes after the response) and the upstream connection isn't reused.
- Hop-by-hop headers and headers named in `Connection` are stripped in both directions. `Proxy-Authorization` never reaches the upstream.
- `proxy_set_header` values containing CR, LF or NUL are dropped, never sent.
- `Upgrade: h2c` is never tunnelled (h2c smuggling would bypass every rule configured here). An unsolicited `101` from an upstream is a 502.
- Upstream TLS is verified by default.
- Pooled keep-alive connections are reused only under the exact TLS settings they were verified with.

**Post-quantum key exchange.** TLS is the platform's (OpenSSL on Linux), and httpgrl doesn't override its choice of
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

**Client certificates (mTLS).**
- Chains are built only against `ssl_client_certificate`. There are no system roots, no AIA downloads (a client-supplied URL never makes the server connect out) and no revocation fetches. The leaf must allow TLS client authentication (EKU), be within its validity period and respect `ssl_verify_depth`.
- SNI picks the TLS policy, and `Host` picks the server. If they land on servers with different client-certificate policies, the request gets a **421**. So a client can't do the handshake for an open name and then ask for a protected one (or the reverse, carrying a verified identity to a server that didn't ask for it).
- With `ssl_crl`, each CRL's signature is verified against the issuing certificate of the chain being checked. A CRL that names a CA from the bundle but isn't signed by it fails the config load. A CRL that is missing or out of date for any CA in the chain fails the check closed, never open.
- Session resumption is off where client certificates are requested. A resumed session would skip, or only partly redo, the check.
- **OCSP stapling is ours, not the platform's.** .NET's own stapler refetches on every handshake when it has no valid response, so a responder outage would turn client handshakes into a flood of requests to the CA. So httpgrl turns it off and drives stapling itself: its own fetch schedule and backoff, its own verification and logging. The platform only puts our verified response on the wire. That uses .NET internals through `UnsafeAccessor` (`StaplingAccess.cs`). It's AOT-safe, and because a native AOT binary embeds its runtime, those internals can't change under a built binary; a self-check makes `ssl_stapling on` a config error if they ever don't bind.
- The connection's TLS identity can only be set by the core (`ConnectionInfo.SetTls` is internal).

**Rate limits.** Zones are bounded by bytes, not entries, so a key built from client input can't exhaust memory. `$remote_net` keys IPv6 clients by /64. A `limit_conn` slot is released however the request ends, including resets mid-tunnel.

**Sockets.**
- Regexes use the linear-time `NonBacktracking` engine where possible. Otherwise they run with a 50 ms match timeout.
- On Unix only `SO_REUSEADDR` is set (restarts over TIME_WAIT). .NET's `ReuseAddress` would also set `SO_REUSEPORT`, letting any same-user process silently share the port and take some of its connections. That's opt-in per socket via `listen ... reuseport`.
- The server doesn't identify itself by default (`server_tokens off`).

## Writing a module

A module declares directives (and variables), stores settings in typed per-scope config slots that inherit
top-down, then installs phase handlers. That is the same lifecycle as an nginx module.

```csharp
public sealed class MethodsConf : ScopeConfig<MethodsConf>
{
    public string[]? Allowed;
    protected override void Inherit(MethodsConf parent) => Allowed ??= parent.Allowed;   // unset => parent's
}

public sealed class AllowMethodsModule : IModule
{
    public string Name => "http_allow_methods";

    public void Register(IModuleRegistry r) => r.AddDirective(new()
    {
        Name = "allow_methods", Contexts = ContextKind.HttpAny, MinArgs = 1, MaxArgs = -1,
        Handler = i => i.Conf<MethodsConf>().Allowed = i.Args,
    });

    public void Configure(IModuleSetup setup) => setup.AddHandler(Phase.Access, ctx =>
    {
        var allowed = ctx.Config<MethodsConf>().Allowed;
        if (allowed is null || Array.IndexOf(allowed, ctx.Request.Method) >= 0)
            return new(HandlerResult.Declined);                       // let the chain continue
        ctx.Response.Headers.Set("Allow", string.Join(", ", allowed));
        return new(HandlerResult.WithStatus(405));                  // core renders it (or the error_page)
    }, order: 0);
}
```

Then add it to the list in `src/Httpgrl/Program.cs`. There is no reflection and no dynamic loading, so AOT stays sound.

**Key API facts**
- **Phases:** `Rewrite → Access → (try_files) → Content → Log`.
- **Handler results:** a handler returns `Declined` (next handler), `Done`, `WithStatus(code)` (the core renders the body or the `error_page`), or `Redirect("/uri" | "@named")` (internal redirect).
- **Exclusive content handler:** a directive can claim a whole location by setting `LocationHandlerConf.Handler`. That is how `proxy_pass` will work.
- **`HttpContext` gives you:**
  - `Request.Body`: decoded, limited and timed out; sends `100 Continue` on first read.
  - `Response.WriteAsync` and `Response.SendFileAsync`, with automatic Content-Length or chunked framing.
  - Resources by request path, never by filesystem path:
    - `Probe(uri)` returns missing, file or directory.
    - `OpenFile(uri, out FileResource)` returns an open file with its length, modification time and content type, or the reason it failed: not found, forbidden, is a directory, not a regular file.
    - `ListDirectory(uri, ...)` returns the entries.
    - The core does the root/alias mapping, containment check and safe open.
  - `ContentTypeFor(name)`, `Variable`, `Capture`.
  - `Aborted`: a token signalled when the client goes away.
  - `Response.FlushAsync()` to push buffered bytes now (streaming).
  - `UpgradeAsync(idleTimeout)`: send a `101` and get the raw duplex stream back. Bytes the client already pipelined are included. The timeout is idleness across both directions.
  - `HasErrorPage(code)`, and `inv.ReadFile(...)` for config-time files (modules have no filesystem access of their own).
- **Lifetime:** a module instance belongs to one loaded configuration. Every reload builds fresh instances from the list in `Program.cs`, so per-configuration state can live in fields. If a module implements `IDisposable`, it is disposed once the configuration it belongs to has been replaced *and* its last connection has ended (the proxy closes its upstream pools this way).
- **Counters:** `ctx.Stats()` returns a `ServerStats` snapshot (connections by state, requests, responses by class, reloads, dropped log lines, uptime). `stub_status` is built on it.
- **Changing the URI:** `ctx.SetUri(path, query, reselectLocation)` rewrites the request URI in place (normalized by the core), optionally choosing the location again. `rewrite` is built on it.
- **Long-lived handlers:** `ctx.ConfigurationRetired` is cancelled when a reload replaces the configuration the request runs under, or when the server starts shutting down. A handler that holds a connection indefinitely (tunnel parking does) should let go on it, rather than wait to be cut by `reload_drain_timeout` or the shutdown timeout. `ctx.Aborted` is the connection itself going away.
- **Request end:** `ctx.OnRequestEnd(callback, state)` runs exactly once when the request is over, whether it completed or the connection broke mid-request. Use it to release per-request reservations (`limit_conn` does).
- **State across reloads:** `setup.Persistent(key, () => new T())` hands back the object the previous configuration stored under `key`, or makes a new one. Rate-limit zones use it so a `SIGHUP` doesn't reset everyone's counters. A failed reload never touches it, and keys the new configuration doesn't ask for are dropped.
- **Content negotiation:** `AcceptEncoding.Choose(header, gzip, brotli)`, `Accepts` and `AddVary` implement RFC 9110 `Accept-Encoding` handling once, for every module that needs it.
- **Body encoding:** from a header filter, `ctx.Response.EncodeBody(sink => new GZipStream(sink, ...))` sends the body through an encoder. The core switches to chunked framing, flushes the encoder on `FlushAsync`, writes its trailer at completion, and frees it if the response is cut short.
- **Header filters:** `setup.AddHeaderFilter(ctx => ...)` runs once per response just before its head is written, for handler, proxied and core-rendered responses alike (`add_header` is one).
- **Variables:** register fixed ones in `Register` (`r.AddVariable`). Declare config-defined ones while parsing with `inv.AddVariable` (`set` and `map` do this). Uses resolve after parsing, so order in the file doesn't matter. `ctx.SetCaptures(match)` makes a regex match the source of `$1`..`$9`.
- **Config time:** `DirectiveInvocation` has `Flag/Size/Millis/Int` parsers and `Compile` (for `$variables`). Throw `inv.Error("...")` for errors that report `file:line`.
- **Example:** the upgrade, exclusive-handler and body APIs are exercised by `TestModule` in `tests/Httpgrl.Tests/IntegrationTests.cs`.

## Roadmap

In priority order. Nothing here is implemented yet unless it's ticked.

1. [x] **Reload without restart** (`SIGHUP`): re-read config and certificates; keep the old configuration if the new one fails; old connections finish on the old configuration.
2. [x] **Revocation for client certificates** (`ssl_crl`): signed, unexpired CRLs for every CA in the chain.
3. [x] **`add_header`, `map`, `set`, `if`**: security headers, and per-location rules such as requiring `$ssl_client_verify`.
4. [x] **Rate limiting**: `limit_req` and `limit_conn` zones.
5. [x] **Hardening**: fuzzing the parsers (request, URI, chunked, upstream, config, CRL, Accept-Encoding) and a soak test (`--soak`).
6. [x] **Operations**: status/metrics endpoint (`stub_status`), `$request_id`, `allow`/`deny`, gzip/brotli, a hardened systemd unit.
7. [x] **Proxy**: `proxy_redirect`, runtime DNS re-resolution, active health checks, variables in `proxy_pass` (upstream names only), `proxy_buffering`.
8. [ ] **HTTP/2**: framing, HPACK and flow control written in-house, TLS from `SslStream` (ALPN `h2`). Never `h2c`.
   See [docs/plan-http2-http3.md](docs/plan-http2-http3.md).
9. [ ] **HTTP/3**: QUIC transport and QPACK written in-house, with no `libmsquic` or `System.Net.Quic`. The TLS 1.3
   handshake comes from OpenSSL 3.5's QUIC TLS API and packet protection from .NET/OpenSSL primitives, so no crypto
   of our own. Owning the transport also gives QUIC datagrams (WebTransport later). Same plan.
10. [ ] **Release process**: ~~a first `v0.x` tag~~ (v0.1.0; semver, see `CHANGELOG.md`), ~~CI on push~~ (`.github/workflows/ci.yml` runs `scripts/ci.sh`), signed images.
11. [ ] **Windows and macOS**: make sure they work, with CI on both. Deferred until there's hardware to test on: Linux is the
    only platform actually exercised today, and Windows/macOS-specific code paths (path guards, socket options, SChannel /
    Secure Transport TLS) are untested.

Also not yet: `disable_symlinks if_not_owner`, `map ... hostnames`, OCSP checking of client certificates, open-file cache, `sendfile(2)` for plaintext responses
(responses currently use buffered `pread` + `send`; over TLS that's unavoidable anyway).
