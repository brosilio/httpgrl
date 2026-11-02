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

## Layout

| Project | Role |
|---|---|
| `src/Httpgrl.Abstractions` | **The plugin API.** It is the only thing modules reference. |
| `src/Httpgrl.Core` | Config parser, HTTP/1.1 engine, connection management, TLS, logging. Also the core modules (`http_core`, `http_ssl`, `http_log`), which are written against the same API. |
| `src/Httpgrl.Modules.StaticFiles` | `http_index`, `http_autoindex`, `http_static`. |
| `src/Httpgrl.Modules.Rewrite` | `http_return`. Later: `rewrite`, `set`, `if`. |
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
| `return code [text];` `return 301\|302\|303\|307\|308 url;` `return url;` `return 444;` | server, location | | nginx semantics. A server-level `return` wins over the location's. Without text, the core renders the body and `error_page` applies. `$variables` in redirect URLs are re-encoded, so a decoded `$uri` can't inject headers. `444` closes the connection silently. |
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
| `server_tokens on\|off;` | | **`off`** | `off`: no `Server` header and no product name on error pages. `on`: `Server: httpgrl/<version>` plus the error-page footer. Note: nginx's `off` still sends a header; here `off` sends none. |
| `access_log stdout\|off;` | | `stdout` | |

Variables: `$uri $request_uri $args $is_args $host $server_name $scheme $https $remote_addr $remote_port`
`$server_addr $server_port $request_method $server_protocol $document_root $request_filename $status`
`$body_bytes_sent $request_time $connection $connection_requests $msec $time_iso8601`, `$1`..`$9` from regex
locations, and the prefix families `$http_*`, `$sent_http_*`, `$arg_*` and `$cookie_*`.

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
| `proxy_pass http\|https://host[:port][/uri];` / `http://upstream_name[/uri];` / `http://unix:/path.sock:[/uri];` | location | | With a URI part, the matched location prefix is replaced by it; without one, the path is passed through. Hostnames are resolved once at load, and every address becomes a peer. Variables in the URL are not supported. |
| `upstream name { server addr [weight=n] [max_fails=n] [fail_timeout=t] [backup] [down]; keepalive n; keepalive_timeout t; keepalive_requests n; }` | http | `keepalive 32`, `60s`, `1000` | Smooth weighted round-robin. Passive health checks: a peer is skipped after `max_fails` failures within `fail_timeout`. Implicit upstreams (a plain host in `proxy_pass`) get the same defaults. |
| `proxy_set_header name value;` | http, server, location | | An empty value removes the header. Setting any header at a level replaces the inherited list (nginx). `Host` defaults to the upstream's authority (`$proxy_host`). `Connection`/`Upgrade` are accepted but ignored, because the module manages them. |
| `proxy_hide_header name;` | | | Drop a response header coming from the upstream. |
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

**Sockets.**
- Regexes use the linear-time `NonBacktracking` engine where possible. Otherwise they run with a 50 ms match timeout.
- On Unix only `SO_REUSEADDR` is set (restarts over TIME_WAIT). .NET's `ReuseAddress` would also set `SO_REUSEPORT`, letting any same-user process silently share the port and take some of its connections. That's opt-in per socket via `listen ... reuseport`.
- The server doesn't identify itself by default (`server_tokens off`).

## Writing a module

A module declares directives (and variables), stores settings in typed per-scope config slots that inherit
top-down, then installs phase handlers. That is the same lifecycle as an nginx module.

```csharp
public sealed class HeadersConf : ScopeConfig<HeadersConf>
{
    public List<(string Name, ComplexValue Value)>? Add;
    protected override void Inherit(HeadersConf parent) => Add ??= parent.Add;   // unset => parent's
}

public sealed class AddHeaderModule : IModule
{
    public string Name => "http_add_header";

    public void Register(IModuleRegistry r) => r.AddDirective(new()
    {
        Name = "add_header", Contexts = ContextKind.HttpAny, MinArgs = 2, MaxArgs = 2, Repeatable = true,
        Handler = i => (i.Conf<HeadersConf>().Add ??= new()).Add((i.Args[0], i.Compile(i.Args[1]))),
    });

    public void Configure(IModuleSetup setup) => setup.AddHandler(Phase.Rewrite, ctx =>
    {
        foreach (var (n, v) in ctx.Config<HeadersConf>().Add ?? [])
            ctx.Response.Headers.Add(n, v.Evaluate(ctx));
        return HandlerResult.Declined;               // let the chain continue
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
- **Config time:** `DirectiveInvocation` has `Flag/Size/Millis/Int` parsers and `Compile` (for `$variables`). Throw `inv.Error("...")` for errors that report `file:line`.
- **Example:** the upgrade, exclusive-handler and body APIs are exercised by `TestModule` in `tests/Httpgrl.Tests/IntegrationTests.cs`.

## Not yet / next

- Also missing: `rewrite`/`set`/`if`/`map`, `add_header`, `proxy_redirect`, `proxy_buffering on`, variables in `proxy_pass`, runtime DNS re-resolution, active health checks, gzip, `limit_req`, open-file cache, `disable_symlinks`, config reload on `SIGHUP`, HTTP/2.
- Responses use buffered `pread` + `send`. Over TLS that's unavoidable; for plaintext, a `sendfile(2)` path is a possible later optimisation.
