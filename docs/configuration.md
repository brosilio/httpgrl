# Configuration reference

The syntax is nginx's. Unknown directives are errors, reported with `file:line`. A handful of nginx
tuning directives (`worker_processes`, `sendfile`, `tcp_nopush`, `user`, `pid`, ...) are accepted with a warning and have no effect.

The [reverse proxy and tunnel](proxy.md) directives have their own page, and the
[security model](security.md) explains the defaults that are stricter than nginx's.

## Core, TLS and protocols

| Directive | Context | Default | Notes |
|---|---|---|---|
| `include glob;` | any | | Relative paths resolve against the main config's directory. Wildcards are allowed in the file name. |
| `error_log stdout [level];` | main | `info` | `debug info warn error`. Only stdout is supported. |
| `worker_shutdown_timeout t;` | main | `10s` | Graceful-stop limit. |
| `reload_drain_timeout t;` | main | `60s` | *(httpgrl-specific)* After a reload, connections still on the old configuration (tunnels, long polls, slow transfers) are closed this long after it. `0` closes them at the next sweep (within 250 ms). nginx reuses `worker_shutdown_timeout` for this and defaults to no limit. |
| `worker_connections n;` | events | `16384` | Global connection cap. When full, the longest-idle keep-alive connection is evicted. |
| `connections_per_client n;` | events | `256` | Cap per IPv4 address or per IPv6 /64. `0` disables it. On a `proxy_protocol` listener it counts the client the PROXY header names (the relay itself for `LOCAL`/`UNKNOWN`), from the moment the header is read, so clients behind one load balancer don't share one cap; until then only `worker_connections` and the header deadline apply. *(httpgrl-specific)* |
| `server`, `listen`, `server_name` | | `*:80` | `listen [addr:]port \| [v6]:port \| unix:/path [ssl] [proxy_protocol] [default_server] [reuseport] [backlog=n]`, or `listen tunnel:name` (see [Reverse tunnels](proxy.md#reverse-tunnels)). With `proxy_protocol`, every connection must start with a PROXY protocol v1 or v2 header (from a load balancer or TCP relay), read within `ssl_handshake_timeout`. A missing, malformed or slow header closes the connection, and the parser never reads past the header. The relayed addresses are in `$proxy_protocol_addr`, `$proxy_protocol_port`, `$proxy_protocol_server_addr` and `$proxy_protocol_server_port`; `$remote_addr` stays the socket peer, as in nginx. Only enable it on sockets that only your relay can reach: anyone who can connect can claim any address. Server names can be exact, `*.x`, `x.*`, `.x`, or `~regex`. |
| `listen ... quic` | server | | A UDP socket serving HTTP/3 (QUIC), e.g. `listen 443 quic;` next to `listen 443 ssl;`. It needs `http3 on` (without it, a config error) and the server's `ssl_certificate`. It can't be combined with `ssl` or `proxy_protocol`. Linux with OpenSSL 3.5 or newer: elsewhere quic listeners are skipped with one warning, and everything else starts as usual, so one config works on old and new systems. Kept across reloads like TCP listeners. |
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
| `http3 on\|off;` | http, server | **`off`** | *(opt-in, permanently)* Serve HTTP/3 on the server's `listen ... quic` sockets, and advertise it on its TCP responses with `Alt-Svc: h3=":port"; ma=86400`. **Deviation:** nginx needs that header added by hand; here an explicit `add_header Alt-Svc` still wins. The transport is our own QUIC (no msquic), with TLS from OpenSSL 3.5's QUIC API: the AES-GCM and ChaCha20-Poly1305 suites (the client picks, so devices without AES hardware get ChaCha20), post-quantum key exchange where OpenSSL offers it, ALPN `h3` required. Client certificates (`ssl_verify_client`) work over HTTP/3 with the same verdicts as over TCP: OpenSSL collects the certificate during the QUIC handshake, and the same verification code judges it (the configured CA bundle only, chain depth, purpose, `ssl_crl` failing closed, `$ssl_client_verify`). A refusal closes the connection with TLS's alert (`certificate_required`, `bad_certificate`). These servers issue no session tickets, so every connection gets the full check. Other servers' TLS sessions resume over QUIC (tickets, valid until the next reload); 0-RTT is never accepted. WebSockets work over HTTP/3 too (RFC 9220), as over HTTP/2. |
| `http3_max_concurrent_streams n;` | http, server | `128` | Concurrent requests per HTTP/3 connection (QUIC's bidirectional stream limit). |
| `quic_retry on\|off;` | http, server | `off` | Validate every client's address with a Retry (one more round trip) before keeping any state for it. Off, Retry is still used automatically once many handshakes are pending. Retry tokens are AEAD-sealed and bound to the client's address, the time and its connection IDs. |
| `quic_gso on\|off;` | http, server | `on` | Send runs of QUIC datagrams with one system call (UDP GSO). If the kernel or route refuses, it turns off by itself with a warning. |
| `server_tokens on\|off;` | | **`off`** | `off`: no `Server` header and no product name on error pages. `on`: `Server: httpgrl/<version>` plus the error-page footer. Note: nginx's `off` still sends a header; here `off` sends none. |
| `access_log stdout\|off;` | | `stdout` | nginx's `access_log /path [format];` is accepted with a warning: records go to stdout as JSON anyway, and `log_format` is ignored. Access records include final outcome, route and upstream details; query values and Referer values are omitted (schema 2). `error_log /path [level];` likewise (the level applies). That lets a stock nginx config load unchanged. |

For HTTP/3 on a client's first visit (before it has seen `Alt-Svc`), publish an HTTPS DNS record that offers it,
for example `example.com. 3600 IN HTTPS 1 . alpn="h3,h2"`.

## Rewrite, map and headers

The rewrite directives of a block (`return`, `set`, `if`, `break`) form a script that runs in config order. The
server block's script runs first for every request, then the selected location's. A block's script is not
inherited by nested locations (nginx semantics).

| Directive | Context | Default | Notes |
|---|---|---|---|
| `return code [text];` `return 301\|302\|303\|307\|308 url;` `return url;` `return 444;` | server, location, if | | nginx semantics. Without text, the core renders the body and `error_page` applies. `$variables` in redirect URLs are re-encoded (controls, spaces, non-ASCII and `\`), so a decoded `$uri` can't inject headers, and a redirect URL whose own text doesn't start with `//` never comes out protocol-relative (see [Strict parsing](security.md#strict-parsing)). `444` closes the connection silently. |
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

## Rate and connection limits

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

**Choosing a key:** `$remote_net` is the client's IPv4 address, or its IPv6 **/64**. A single IPv6 client typically
controls a whole /64 and can rotate through 2^64 addresses, so `$binary_remote_addr` (also available) lets it
dodge any per-address limit. `$remote_net` is the same grouping the core's per-client connection cap uses.
Behind a proxy or CDN, key on a header that it sets and clients can't.

## Access control and status

| Directive | Context | Default | Notes |
|---|---|---|---|
| `allow address\|CIDR\|unix:\|all;` / `deny ...;` | http, server, location | | Checked in order; the first match decides; no match allows. Denied: 403 (`error_page 403 =444` drops instead). As in nginx, a level with its own rules replaces the inherited list. **Deviation:** a network with host bits set (`192.168.1.1/24`) is a config error rather than silently masked. Runs after `limit_req`/`limit_conn` (nginx's order). |
| `stub_status [nginx\|prometheus\|json];` | location | `nginx` | Server-wide counters. `nginx` is byte-compatible with nginx's output, so existing exporters work. `prometheus` is the text exposition format, with responses by status class, reloads, dropped log lines and memory (resident, managed heap, GC-committed, full GCs) added. Counters cover the process lifetime (they survive reloads); "requests" counts completed requests. Restrict it with `allow`/`deny`. |

```nginx
location = /metrics { stub_status prometheus; allow 10.0.0.0/8; deny all; }
```

Dropping traffic aimed at the server's address rather than a name, over HTTP and HTTPS:

```nginx
server { listen 80 default_server;  return 444; }                                       # Host: <ip>, or unknown names
server { listen 443 ssl default_server; ssl_reject_handshake on; error_page 421 =444; }  # no SNI / unknown SNI / Host: <ip>
```

## Compression

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

## Variables

`$uri $request_uri $args $is_args $host $server_name $scheme $https $remote_addr $remote_port`
`$server_addr $server_port $request_method $server_protocol $document_root $request_filename $status`
`$body_bytes_sent $request_time $connection $connection_requests $msec $time_iso8601 $binary_remote_addr $remote_net`
`$limit_req_status $limit_conn_status $request_id`, `$1`..`$9` from regex locations, and the prefix families
`$http_*`, `$sent_http_*`, `$arg_*` and `$cookie_*`. The proxy's variables are listed [on its page](proxy.md#reverse-proxy).

`$request_id` is 32 random hex characters, made on first use and stable for the request, and is in every access-log
line. Pass it upstream with `proxy_set_header X-Request-ID $request_id;`. To keep an id a trusted proxy in
front already set: `map $http_x_request_id $rid { "" $request_id; default $http_x_request_id; }`. Don't do
that for untrusted clients: they choose the value.

TLS variables: `$ssl_protocol $ssl_server_name $ssl_client_verify` (`SUCCESS`, `FAILED:reason`, `NONE`) and, when a
client certificate was presented, `$ssl_client_s_dn $ssl_client_i_dn $ssl_client_serial $ssl_client_escaped_cert` and
`$ssl_client_fingerprint`. The fingerprint is the lowercase hex **SHA-256** of the certificate (nginx uses SHA-1).
The access log records `client_verify`. Modules read the same data from `ctx.Connection.ClientCertificate`,
`ClientVerify` and `ClientVerified`.

To hand the identity to a backend, set it with `proxy_set_header` (for example
`proxy_set_header X-Client-Verify $ssl_client_verify;`). A request header with the same name as one set by
`proxy_set_header` is always dropped, even when the value is empty, so a client can't forge it.
