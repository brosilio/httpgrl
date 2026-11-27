# Reverse proxy and tunnels

## Reverse proxy

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

Variables: `$proxy_host $proxy_port $proxy_add_x_forwarded_for $upstream_addr $upstream_status`.

A pooled connection that the upstream closed or reset before answering is retried quietly (up to twice, idempotent
requests only), since keep-alive races aren't the upstream's fault. Anything the upstream actually sent, such as a
malformed or ambiguous answer, is reported and counted as a failure even on a pooled connection.

## Reverse tunnels

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
