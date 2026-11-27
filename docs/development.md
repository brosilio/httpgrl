# Development

The ground rules for contributors (and agents) are in [AGENTS.md](../AGENTS.md): no runtime plugin loading,
native AOT always works, no third-party dependencies, modules see only the plugin API, stricter-than-nginx
defaults, and how branches and releases work.

## Building and testing

```sh
./scripts/ci.sh                                   # build, test on JIT, test as native AOT, publish, -t check
dotnet build -c Release && dotnet run -c Release --no-build --project tests/Httpgrl.Tests   # the tests on the JIT
```

Native AOT needs `clang` and the `zlib` development headers. CI (`.github/workflows/ci.yml`) runs `scripts/ci.sh` on
every push to `develop` and `main`.

## Layout

| Project | Role |
|---|---|
| `src/Httpgrl.Abstractions` | **The plugin API.** It is the only thing modules reference. |
| `src/Httpgrl.Core` | Config parser, HTTP/1.1 and HTTP/2 engines, the HTTP/3 server adapter, connection management, TLS, logging. Also the core modules (`http_core`, `http_ssl`, `http_log`), which are written against the same API. |
| `src/Httpgrl.HttpFields` | **Protocol library.** HPACK and its Huffman code, shared by HTTP/2 and QPACK. No dependencies. |
| `src/Httpgrl.Quic` | **Protocol library.** QUIC: the connection state machine on a caller-supplied clock, recovery and congestion control, the server and client UDP endpoints, and TLS behind `QuicTlsContext` (built in: OpenSSL 3.5's QUIC API, loaded per platform; clients verify the server by default). No dependencies. |
| `src/Httpgrl.Http3` | **Protocol library.** HTTP/3 framing, QPACK, and `Http3ServerConnection` (control and QPACK streams, request streams, GOAWAY, the request-head deadline). Depends only on the two above. |
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
| `tests/Httpgrl.Libraries.Smoke` | Uses the protocol libraries through their public API only (a QUIC server serving HTTP/3, and a client request), on the JIT and as native AOT. |

The protocol libraries are public API for other software (see [Design decisions](#design-decisions)). The server uses them the way any other consumer
would: through their public API, with no `InternalsVisibleTo` to Core. `scripts/check-boundaries.sh` enforces which
library may reference which.

Inside Core:
- `Config/`: lexer, parser, scopes, and the `$variable` compiler.
- `Http/`: request parser, URI normaliser, body decoder, response writer, session loop.
- `Pipeline/`: location/vhost routing and phase execution.
- `Hosting/`: sockets, the connection table and the deadline sweeper.
- `Http2/`: HTTP/2 framing, sessions and streams.
- `Http3/`: the HTTP/3 server adapter: maps `Http3ServerConnection` requests onto the pipeline and follows reloads.

## Design decisions

These came out of the HTTP/2–HTTP/3 and protocol-library plans, and still hold. Open work from those plans is
tracked in GitHub issues ([#1](https://github.com/brosilio/httpgrl/issues/1)–[#8](https://github.com/brosilio/httpgrl/issues/8)).

**HTTP/2 and HTTP/3**
- **Written in-house.** No `libmsquic` and no `System.Net.Quic`: they need a native package that may not be on a
  given system, and .NET doesn't expose QUIC datagrams, which WebTransport needs. HTTP/2 framing, HPACK, the QUIC
  transport, HTTP/3 framing and QPACK are ours.
- **No cryptography of our own.** The TLS 1.3 handshake is always the system OpenSSL's: `SslStream` over TCP, and
  OpenSSL 3.5's QUIC TLS API (`SSL_set_quic_tls_cbs`) for QUIC. Packet protection uses .NET's `AesGcm`, AES-ECB and
  `HKDF`, which call OpenSSL; ChaCha20's header-protection mask comes from OpenSSL's EVP.
- **HTTP/3 is Linux-only and needs OpenSSL 3.5 or newer.** Elsewhere a `quic` listener logs once why HTTP/3 is
  unavailable and the server starts anyway (`-t` reports it too), so one config works on old and new systems.
- **Off by default, permanently.** `http2 on;` and `http3 on;` are required. HTTP/1.1 stays the only protocol a
  config gets without asking.
- **`Alt-Svc` is automatic with `http3 on`** (an explicit `add_header Alt-Svc` wins).
- **WebSockets over HTTP/2 and HTTP/3** (extended CONNECT) reach modules as HTTP/1.1 upgrade requests, so modules
  don't care which protocol carried them.
- **Timers:** the HTTP/1 sweeper keeps its deadlines (and enforces per-stream ones); QUIC's millisecond timers run
  on each endpoint's own thread. Either way: cheap per connection, impossible for a client to dodge.
- **0-RTT is never accepted** on the server (it's replayable). `proxy_pass` upstreams and tunnels stay HTTP/1.1.

**Protocol libraries** (`Httpgrl.HttpFields`, `Httpgrl.Quic`, `Httpgrl.Http3`)
- **Public API for other software,** first of all an AOT-first game engine that uses QUIC for multiplayer (native
  QUIC on desktop and consoles, WebTransport in browsers).
- **The server dogfoods them:** Core reaches QUIC and HTTP/3 only through their public API, with no
  `InternalsVisibleTo` to Core (the libraries grant it to the test suite only). `tests/Httpgrl.Libraries.Smoke` uses
  only the public API, on the JIT and as native AOT, and grows with each feature.
- **I/O-free at the core:** a `QuicConnection` takes datagrams in and gives datagrams out, on a clock the caller
  supplies. The socket loops (`QuicServerEndpoint`, `QuicClientEndpoint`) are separate, optional types.
- **Dependency direction is enforced** by `scripts/check-boundaries.sh`: `Httpgrl.HttpFields` and `Httpgrl.Quic`
  reference nothing of ours, `Httpgrl.Http3` only those two, and none of them reference Core or Abstractions.
- **Safe defaults;** anything game-specific (drop-oldest queues, a congestion-bypass budget) is opt-in per connection.
- **Distributed by project reference,** not NuGet. Their API is semver public API (see AGENTS.md).
- HTTP/1, HTTP/2, hosting and the pipeline stay in Core until a consumer outside httpgrl needs them.

## Testing

The suite in `tests/Httpgrl.Tests` is dependency-free (`Harness.cs`) and runs real sockets and real TLS. A filter
runs part of it: a substring of the test names, or `=` plus one exact name.

### Fuzzing

Every parser of untrusted or semi-trusted bytes has a mutation-fuzz target in
`tests/Httpgrl.Tests/Fuzz.cs`: the request head, the URI normalizer, chunked bodies, upstream response heads, the
config parser (with every module's directives), CRLs, OCSP responses (whole signed responses, and re-signed
response contents so the acceptance rules are reached), HTTP/2 and HTTP/3 request heads, PROXY protocol headers, `Accept-Encoding`,
the tunnel handshake response, `Range`, `Host`/SNI names, rewrite results, and the mapping of request paths through
`root`/`alias` (checked for containment independently of the mapper). Each target states which rejections are legitimate and
which invariants an accepted input must hold (e.g. never both `Content-Length` and `chunked`, no dot segments
in a path). The test suite runs a fixed-seed pass of each, so CI is also a regression fuzz. Inputs derive from
(seed, iteration, target) alone, identically in every process, so a printed seed and iteration reproduce a finding.
A long run gives the slow, stateful targets (sessions, connections, config) a larger share of its time. For long runs:

```sh
dotnet run -c Release --project tests/Httpgrl.Tests -- --fuzz all 600        # 10 minutes, all targets, random seed
dotnet run -c Release --project tests/Httpgrl.Tests -- --fuzz request 60 42  # one target, fixed seed
dotnet run -c Release --project tests/Httpgrl.Tests -- "proxy:"              # tests whose name contains "proxy:"
dotnet run -c Release --project tests/Httpgrl.Tests -- "=fuzz: uri parser (20000 mutated inputs, fixed seed)"  # one test by exact name
```

A finding prints the seed, iteration and input, which reproduce it exactly. It's dependency-free and not
coverage-guided, so it's a complement to, not a replacement for, a coverage-guided fuzzer.

### Soak test (Linux)

Runs the real binary as a child process under mixed load: static, proxied and POSTed
requests, WebSockets, rate-limited paths, slow-loris, garbage, oversized heads, mid-download resets and abandoned
bodies, with HTTP/2 and HTTP/3 mixed in (requests, uploads through the proxy, WebSockets). It reloads every few seconds, then checks for leaked file descriptors, memory growth, error-level log
lines, failed requests, and a clean exit on SIGTERM. It samples the server's own memory metrics, to tell managed
heap growth (garbage awaiting a full GC, which is normal) from native growth (which would be a leak):

```sh
dotnet run -c Release --project tests/Httpgrl.Tests -- --soak artifacts/linux-x64/httpgrl 300   # add --no-reload to isolate reloads
```

### Benchmark

There's no wrk dependency: `--bench url [seconds] [connections]` runs a keep-alive load generator. On one
box, proxying to a second httpgrl with buffering on: about 54k req/s for 1 KiB responses and about 2 GiB/s for 1 MiB,
level with buffering off. `--bench-h2 url [seconds] [streams]` does the same over one HTTP/2 connection (TLS), with
.NET's client: about 23k req/s for 1 KiB files, 400 MiB/s for 40 KB and 480 MiB/s for 1 MiB on 64 streams. The client
is the limit there, so it measures regressions, not the server's ceiling.

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
- **Exclusive content handler:** a directive can claim a whole location by setting `LocationHandlerConf.Handler`. That is how `proxy_pass` works.
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
- **Audit events:** `ctx.ResponseOutcome` exposes the final server-side result and `ctx.RouteLabel` names the selected configuration location. `ctx.SecurityEvent("constant_event_id")` emits a bounded, correlated decision through `ILogger`; use constant IDs and never put secrets in custom fields. See the [event contract](security-monitoring.md).
- **Example:** the upgrade, exclusive-handler and body APIs are exercised by `TestModule` in `tests/Httpgrl.Tests/IntegrationTests.cs`.
