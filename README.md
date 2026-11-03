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
  **Plaintext keep-alive connections** aren't closed: their next request runs under the new configuration.
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
| `server`, `listen`, `server_name` | | `*:80` | `listen [addr:]port \| [v6]:port \| unix:/path [ssl] [default_server] [reuseport] [backlog=n]`. Server names can be exact, `*.x`, `x.*`, `.x`, or `~regex`. |
| `listen ... reuseport` | server | off | Sets `SO_REUSEPORT` so other processes of the same user can share the port, for multi-process setups or zero-downtime restarts. Every listener on that address must agree. Without it, a second instance fails to start. Unix only. |
| `location [=\|^~\|~\|~*] uri {}`, `location @name {}` | server, location | | nginx matching order. Nesting is supported. |
| `root path;` / `alias path;` | | `<confdir>/html` | Both accept `$variables`. |
| `index file ...;` | | `index.html` | |
| `autoindex on\|off;` `autoindex_format html\|json;` `autoindex_exact_size;` `autoindex_localtime;` | | `off` | Dotfiles are hidden. At most 50k entries are listed. |
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
| `ssl_certificate` / `ssl_certificate_key` | http, server | | PEM. The chain is read from the cert file. Selected by SNI. |
| `ssl_protocols` | http, server | `TLSv1.2 TLSv1.3` | Older protocols are a config error. |
| `ssl_verify_client off\|on\|optional\|optional_no_ca;` | http, server | `off` | Client certificates (mTLS). `on`: required. `optional`: a certificate is not required, but one that's presented must verify. `optional_no_ca`: also accepts an unknown issuer (the verdict is in `$ssl_client_verify`); expired or wrong-purpose certificates still fail. A failed check fails the TLS handshake (nginx answers 400 instead). TLS session resumption is disabled on these servers, so every connection gets the full check. |
| `ssl_client_certificate file;` | http, server | | PEM CA bundle that client certificates must chain to. It's the *only* trust anchor: system roots are never used. Its CA names are sent to clients (not on Windows). Required for `on`/`optional`. |
| `ssl_verify_depth n;` | http, server | `1` | Maximum chain length above the client certificate: `1` means issued directly by a CA in the bundle. Raise it for intermediates (the client must send them). |
| `ssl_crl file;` | http, server | | PEM (any number of `X509 CRL` blocks) or DER. Like nginx (OpenSSL `CRL_CHECK_ALL`), *every* certificate in the chain below the trust anchor needs a current CRL from its issuer: so with an intermediate CA, include the root's CRL and the intermediate's. A missing, expired or not-yet-valid CRL fails the check. CRLs are read at load: reload (`SIGHUP`) to pick up new ones. Full CRLs only; delta and indirect CRLs and unknown critical extensions are a config error. Signatures: ECDSA or RSA PKCS#1 with SHA-256/384/512. |
| `ssl_ocsp`, `ssl_trusted_certificate` | | | Not supported, and a config error rather than silently ignored. |
| `server_tokens on\|off;` | | **`off`** | `off`: no `Server` header and no product name on error pages. `on`: `Server: httpgrl/<version>` plus the error-page footer. Note: nginx's `off` still sends a header; here `off` sends none. |
| `access_log stdout\|off;` | | `stdout` | |

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
| `gzip_proxied`, `gzip_disable`, `gzip_buffers`, `gzip_http_version`, `gzip_static` | | | Accepted and ignored with a warning, so nginx configs load. Responses compress regardless of `Via`; precompressed files aren't served yet. |

**BREACH:** compressing a response that reflects attacker-controlled input next to a secret (a CSRF token, say)
over TLS lets an attacker who can observe response sizes recover the secret. That's why compression is off by
default. Don't enable it for such responses, or mask the secrets per response.

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
| `proxy_pass http\|https://host[:port][/uri];` / `http://upstream_name[/uri];` / `http://unix:/path.sock:[/uri];` | location | | With a URI part, the matched location prefix is replaced by it; without one, the path is passed through. Every address a hostname resolves to becomes a peer, and hostnames are re-resolved while running (see `upstream_resolve_interval`). |
| `proxy_pass http://$var[...];` | location | | With variables, the URL is evaluated per request and split at the first `/`, as in nginx. **Deviation:** the host part must be the name of an `upstream` block, otherwise the request gets a 502 and a log line. It is never resolved as an arbitrary host, because a variable fed by the request (`$arg_*`, `$http_*`) would turn the server into an open proxy to anything it can reach (SSRF). That covers the usual use, picking an upstream with `map`. A URI part replaces the request URI. Control characters, spaces and non-ASCII in it are percent-encoded, so a decoded `$uri` can't break the request line. There's no `proxy_redirect default` mapping for these locations. |
| `upstream name { server addr [weight=n] [max_fails=n] [fail_timeout=t] [backup] [down] [resolve]; keepalive n; keepalive_timeout t; keepalive_requests n; }` | http | `keepalive 32`, `60s`, `1000` | Smooth weighted round-robin. Passive health checks: a peer is skipped after `max_fails` failures within `fail_timeout`. Implicit upstreams (a plain host in `proxy_pass`) get the same defaults. A hostname that doesn't resolve at load is a config error, unless the server has `resolve`: then it starts without addresses (502 until they appear). |
| `health_check [uri=/path] [interval=5s] [timeout=2s] [fails=1] [passes=1] [status=200-399] [host=name];` | upstream | | Active checks (in nginx, an nginx Plus feature): every interval, a `GET` of `uri` to each peer, using the scheme and TLS settings of the location that proxies to this upstream, with `Host` from `proxy_pass` unless `host=` is set. A peer that fails `fails` checks in a row (connect error, timeout, or a status outside `status`) leaves rotation; `passes` good checks bring it back. If every peer is actively down, requests get an immediate 502 rather than being tried anyway (passive failures still fall back to trying everyone). Checks start with the first proxied request and probe whatever addresses DNS currently gives. |
| `upstream_resolve_interval t\|off;` | http | `30s` | **Deviation:** every upstream hostname (in `upstream` blocks and `proxy_pass`) is re-resolved this often through the system resolver (`/etc/hosts`, nsswitch, DNS). nginx resolves once unless you use a `resolver` and `resolve`. A failed or empty answer keeps the last good addresses. Peers whose address stays keep their failure counts and pooled connections; removed ones finish in-flight requests and close their idle connections. `off` resolves once at load. The system resolver doesn't report TTLs, hence an interval. |
| `proxy_set_header name value;` | http, server, location | | An empty value removes the header. Setting any header at a level replaces the inherited list (nginx). `Host` defaults to the upstream's authority (`$proxy_host`). `Connection`/`Upgrade` are accepted but ignored, because the module manages them. |
| `proxy_hide_header name;` | | | Drop a response header coming from the upstream. |
| `proxy_redirect default\|off;` / `proxy_redirect redirect replacement;` | http, server, location | `default` | Rewrites `Location` and the URL in `Refresh` from the upstream. `default` maps the `proxy_pass` URL to the location: with `location /one/ { proxy_pass http://app:8080/two/; }`, `http://app:8080/two/x` becomes `/one/x`. That needs a prefix or exact location, so regex and named locations get no default mapping. Prefix rules match case-insensitively and replace the prefix; `~regex` / `~*regex` rules replace the whole value and can use `$1`..`$9`; replacements may contain variables. The first matching rule wins. A level with rules replaces the inherited list; `off` turns rewriting off. |
| `proxy_http_version 1.0\|1.1;` | | **`1.1`** | nginx defaults to 1.0. 1.1 is required for keep-alive and Upgrade. |
| `proxy_connect_timeout` / `proxy_send_timeout` / `proxy_read_timeout` | | `10s` / `60s` / `60s` | Connect timeout includes the TLS handshake. Send/read are per operation. For upgraded tunnels, `proxy_read_timeout` is the idle timeout counted across *both* directions. |
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

## Security model

**Fuzzing.** Every parser of untrusted or semi-trusted bytes has a mutation-fuzz target in
`tests/Httpgrl.Tests/Fuzz.cs`: the request head, the URI normalizer, chunked bodies, upstream response heads, the
config parser (with every module's directives) and CRLs. Each target states which rejections are legitimate and
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

A finding prints the seed, iteration and input, which reproduce it exactly. It's dependency-free and not
coverage-guided, so it's a complement to, not a replacement for, a coverage-guided fuzzer.

**Timeouts and slow clients.** One sweeper thread enforces every deadline. There are no per-operation timers.
- Header timeout: the whole request head must arrive within `client_header_timeout` of its first byte. Trickling one byte at a time does not extend it.
- Idle connections: an idle new or keep-alive connection is closed at its deadline.
- Slow uploads and slow readers: body reads and response writes each have a per-operation timeout plus a minimum transfer rate. That covers slow-body uploads and slow-read downloads.

**Connection limits.**
- Connections are capped globally and per client (IPv4 address or IPv6 /64).
- When the table is full, the longest-idle keep-alive connection is evicted.
- Unread request bodies are drained only up to 64 KiB; anything larger closes the connection. Closes are lingering, so a client's unread data can't trigger a reset that destroys our response.

**Strict parsing.**
- Line endings must be CRLF. Bare LF or CR, obs-fold, and whitespace before `:` are rejected.
- Exactly one `Content-Length`. `Transfer-Encoding` must be exactly `chunked` and never alongside `Content-Length`.
- No `Transfer-Encoding` on HTTP/1.0. Exactly one `Host`, validated and lower-cased.
- Chunk sizes, chunk lines and trailers are bounded.
- In short, anything a proxy in front of or behind the server could read differently is a 400. The future proxy module depends on this.

**Paths.**
- URIs are percent-decoded, dot-segments are resolved, and an escape above `/` is a 400. NUL and invalid UTF-8 are rejected.
- Every mapped filesystem path is checked to stay inside its `root`/`alias` directory. This closes nginx's classic `location /img { alias /x/; }` + `/img../` hole.
- Modules never see filesystem paths. They ask the core for resources by request path, so the mapping, containment and safe-open policy has exactly one implementation (`Core/Files/LocalFiles.cs`). CI enforces this with `scripts/check-boundaries.sh`.
- Location matching is case-insensitive on case-insensitive filesystems.
- On Windows, ADS names (`:`), trailing dots and spaces, and device names (`CON`, `NUL`, ...) are refused.

**File serving.**
- Unix opens use `O_NONBLOCK|O_CLOEXEC`, so a FIFO in the web root can't hang a thread. Non-seekable files get a 403.
- Directory listings are HTML-escaped and their hrefs percent-encoded, with a `./` prefix so a file named `javascript:` can't become a link scheme.
- Symlinks are followed (nginx default).

**Response headers.** `HeaderCollection` rejects CR, LF, NUL and non-Latin-1 characters, so response splitting is impossible. Framing headers are always written by the core.

**Logging.** Log lines are produced by `Utf8JsonWriter`, so a log line is always a single JSON object. A blocked stdout drops lines (and counts them) instead of stalling requests.

**Reverse proxy.**
- Upstream responses are parsed as strictly as requests: CRLF only, no obs-fold, a single `Content-Length`, `Transfer-Encoding: chunked` only and never alongside `Content-Length`, a bounded head. A broken or hostile backend gets a 502; it can't split our response or desync the client.
- If an upstream fails after the head went out, the client connection is cut, so a truncated body never looks complete.
- Hop-by-hop headers and headers named in `Connection` are stripped in both directions. `Proxy-Authorization` never reaches the upstream.
- `proxy_set_header` values containing CR, LF or NUL are dropped, never sent.
- `Upgrade: h2c` is never tunnelled (h2c smuggling would bypass every rule configured here). An unsolicited `101` from an upstream is a 502.
- Upstream TLS is verified by default.
- Pooled keep-alive connections are reused only under the exact TLS settings they were verified with.

**Client certificates (mTLS).**
- Chains are built only against `ssl_client_certificate`. There are no system roots, no AIA downloads (a client-supplied URL never makes the server connect out) and no revocation fetches. The leaf must allow TLS client authentication (EKU), be within its validity period and respect `ssl_verify_depth`.
- SNI picks the TLS policy, and `Host` picks the server. If they land on servers with different client-certificate policies, the request gets a **421**. So a client can't do the handshake for an open name and then ask for a protected one (or the reverse, carrying a verified identity to a server that didn't ask for it).
- With `ssl_crl`, each CRL's signature is verified against the issuing certificate of the chain being checked. A CRL that names a CA from the bundle but isn't signed by it fails the config load. A CRL that is missing or out of date for any CA in the chain fails the check closed, never open.
- Session resumption is off where client certificates are requested. A resumed session would skip, or only partly redo, the check.
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
- **Request end:** `ctx.OnRequestEnd(callback, state)` runs exactly once when the request is over, whether it completed or the connection broke mid-request. Use it to release per-request reservations (`limit_conn` does).
- **State across reloads:** `setup.Persistent(key, () => new T())` hands back the object the previous configuration stored under `key`, or makes a new one. Rate-limit zones use it so a `SIGHUP` doesn't reset everyone's counters. A failed reload never touches it, and keys the new configuration doesn't ask for are dropped.
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
5. [ ] **Hardening**: ~~fuzzing the parsers~~ (done: request, URI, chunked, upstream, config, CRL); ~~soak test~~ (done: `--soak`); CI on Windows and macOS.
6. [x] **Operations**: status/metrics endpoint (`stub_status`), `$request_id`, `allow`/`deny`, gzip/brotli, a hardened systemd unit.
7. [ ] **Proxy**: ~~`proxy_redirect`~~, ~~runtime DNS re-resolution~~, ~~active health checks~~, ~~variables in `proxy_pass`~~ (done); `proxy_buffering on`.
8. [ ] **HTTP/2.**
9. [ ] **Release process**: CI on push, a first `v0.x` tag, signed images.

Also not yet: `gzip_static` (precompressed files), `rewrite`, `map ... hostnames`, OCSP, open-file cache, `disable_symlinks`, `sendfile(2)` for plaintext responses
(responses currently use buffered `pread` + `send`; over TLS that's unavoidable anyway).
