# httpgrl — ground rules for agents and contributors

These are deliberate design decisions made by the project owner, not accidents to clean up. Don't
"improve" them away. If a task seems to need breaking one, stop and ask the owner first.

## Non-negotiables

1. **No runtime plugin loading. Ever.**
   - Modules are compiled in and listed in `src/Httpgrl/Program.cs`, like nginx's static modules.
   - Don't add `load_module`, `AssemblyLoadContext`, reflection-based discovery, scripting hosts or "drop a DLL in a folder" mechanisms.
   - Why: it breaks native AOT, and it makes the binary's behaviour depend on files beside it, which is an attack surface.

2. **Native AOT must always work.**
   - Every project builds with `IsAotCompatible` and `TreatWarningsAsErrors`, so a trim or AOT warning is a build failure.
   - Never suppress those warnings. No reflection, `dynamic`, `Activator` on unknown types, runtime codegen, or reflection-based `System.Text.Json` serialization (use `Utf8JsonWriter`/`Utf8JsonReader`).
   - `scripts/ci.sh` publishes the test suite itself as native AOT and runs it. "It builds" is not "it works under AOT".

3. **No third-party runtime dependencies.**
   - Only the .NET base libraries. TLS uses the platform stack (`SslStream`).
   - A third-party package is acceptable only for TLS or security, and only with the owner's agreement.
   - Tests are dependency-free too (`tests/Httpgrl.Tests/Harness.cs`): no xunit or nunit. Keep builds light and quick.

4. **Modules see only the plugin API.**
   - Feature modules reference `Httpgrl.Abstractions`, never `Httpgrl.Core`.
   - New features (proxy, rewrite, headers, limits, ...) are modules built through `IModule`, directives, `ScopeConfig<T>` and phase handlers.
   - If a module needs something the API doesn't offer, extend `Httpgrl.Abstractions` deliberately and minimally. Don't reach into Core.
   - **Modules never see filesystem paths.** They name resources by the validated request path and ask the core through `ctx.Probe`, `ctx.OpenFile` and `ctx.ListDirectory`, then send with `Response.SendFileAsync(FileResource, ...)`. Don't add a `MapToPath`-style escape hatch to the API.
   - Why: filesystem policy (containment, safe opens, a future `disable_symlinks` or open-file cache) has exactly one implementation.
   - This is a design boundary, not a sandbox: .NET can't stop compiled-in code from calling `System.IO`. So `scripts/check-boundaries.sh`, which `ci.sh` runs, fails the build if a module project uses filesystem APIs, P/Invoke, process spawning, reflection or assembly loading, or references anything but `Httpgrl.Abstractions`.
   - The `$request_filename`/`$document_root` variables exist for *config* (e.g. a future FastCGI module's params), not as a way for module code to get at paths.
   - The core's own features (`http_core`, `http_ssl`, `http_log`) use the same API.

5. **Best implementation over backwards compatibility.**
   - Nothing is released and there are no compatibility promises: rename, restructure and delete freely when it's better.
   - The config is nginx-*compatible-ish*. Follow nginx syntax and semantics unless they are unsafe or worse. Where we deviate, document it in `docs/` (the directive's entry in `docs/configuration.md` or `docs/proxy.md`, and `docs/security.md` for security behaviour).

6. **Security defaults are stricter than nginx. Don't loosen them to match nginx.** In particular:
   - **Request parsing:** strict. CRLF only, no obs-fold, a single `Content-Length`, `Transfer-Encoding: chunked` only and never alongside `Content-Length`, exactly one validated `Host`. Anything ambiguous is a 400. A future proxy module depends on this for smuggling safety.
   - **Timeouts and slow clients:** `client_header_timeout` covers the *whole* request head, not each read (the slow-loris defence). Body reads and response writes have per-operation timeouts *and* minimum rates. Whatever enforces deadlines must stay cheap per connection at scale and impossible for a client to dodge (no deadline a trickle of bytes can keep pushing out). Today the connection sweeper enforces the HTTP/1 deadlines; protocols that need finer timing (QUIC loss detection, pacing) use whatever mechanism serves them best.
   - **Connection limits:** connections are capped globally and per client (IPv4 address or IPv6 /64). Idle keep-alives are evicted first.
   - **Paths:** decoded request paths never contain control characters (400). The core maps every request path through `root`/`alias` and checks it stays inside. All request-driven filesystem access lives in `src/Httpgrl.Core/Files/LocalFiles.cs`. Unix file opens use `O_NONBLOCK|O_CLOEXEC`.
   - **Sockets:** only `SO_REUSEADDR` by default. Never use .NET's `ReuseAddress` on Unix, because it silently adds `SO_REUSEPORT`. Port sharing is explicit, per socket: `listen ... reuseport`.
   - **Client certificates:** verified only against the configured CA bundle (no system roots, no AIA downloads, no resumption). A request whose `Host` resolves to a server with a different client-certificate policy than the SNI-selected one gets a 421. Only the core sets a connection's TLS identity. `ssl_crl` fails closed: a missing, expired or unverifiable CRL for any CA in the chain rejects the certificate. Unsupported revocation features (OCSP, delta/indirect CRLs) are config errors, never silently ignored.
   - **Server identity:** `server_tokens` is **off by default**, meaning no `Server` header and no product name on error pages. `on` is opt-in.
   - **Response headers:** `HeaderCollection` rejects CR, LF and NUL. Framing headers belong to the core.
   - **Proxying:**
     - Upstream responses get the same strict parsing as requests.
     - Upstream TLS is verified by default.
     - The upstream receives the normalized path unless `proxy_pass_raw_uri on`.
     - `h2c` is never tunnelled.
     - Pooled upstream connections are reused only under the TLS identity they were verified with.
     - Mid-body upstream failure cuts the client connection, never "completes" it.
     - Variables in `proxy_pass` may only select an `upstream` block by name, never an arbitrary host (SSRF).
     - Keep these defaults even where nginx's differ.

7. **Logging is single-line JSON on stdout.** Write through `ILogger` / `Utf8JsonWriter`. Never write directly with `Console.Write`, and never build JSON by string concatenation. The logger must never block request processing; it drops lines (and counts them) instead.

8. **Write hot paths like C.** Spans, pooled buffers, byte-level parsing, no LINQ or per-request allocations where avoidable, no hidden thread-pool hops. Config-time code may be ordinary C#.

9. **Test instances are worthless.**
   - Tests and manual runs use throwaway temp dirs, ephemeral ports and disposable processes. Kill them freely.
   - Never design for, or protect, a "dev instance's" state.
   - Never kill processes by pattern (`pkill -f`): it can hit your own shell or unrelated software. Use the exact PID.

## Deliberate nginx deviations worth protecting

- `if` blocks accept only rewrite directives (`return`, `set`, `break`, `if`). Don't let other modules register into
  the `if` context: that recreates nginx's "if is evil". Conditional behaviour goes through `map` variables.
- `add_header` merges across levels, and replaces same-named response headers. Both prevent silently losing security headers.

## Depending on .NET internals (one place only)

`src/Httpgrl.Core/Modules/StaplingAccess.cs` reaches into `SslStreamCertificateContext` with `UnsafeAccessor` so
OCSP stapling is driven by us (the platform's fetcher has no backoff). It's the only such dependency, and it's
deliberate:
- It's AOT-safe (no reflection), and a native AOT binary embeds its runtime, so it can't break under a built
  binary; it can only break when the SDK/runtime is upgraded.
- On any runtime upgrade, read `SslStreamCertificateContext.Linux.cs` and `Interop.OpenSsl.cs` (dotnet/runtime, at
  the matching tag) against the comment in `StaplingAccess.Create`, and make sure the `ssl_stapling` tests pass
  under AOT. `StaplingAccess.SelfTest` turns a missing member into a config error, never a silent no-op.
- Don't add more of these without the owner's agreement.

## OpenSSL's process default (one deliberate piece of global state)

`src/Httpgrl.Core/Modules/OpenSslDefaults.cs` loads the AEAD-only cipher default into OpenSSL's process-wide
`system_default` (public OpenSSL API, from memory), so .NET can keep caching server contexts and TLS sessions resume.
It's fixed, installed once, and identical for every configuration, so loading a configuration still changes nothing
the running one depends on. Don't make it follow `ssl_ciphers` or vary between reloads; per-server lists use a
`CipherSuitesPolicy`. The "tls: sessions resume" and "ssl_ciphers" tests pin both properties.

## Reload

`SIGHUP` builds a complete new configuration (fresh module instances) and swaps it in only if *everything*
succeeded, including binding new listeners. Keep it that way: building a configuration must have no side
effects on the running one (no logger level changes, no global state), and module state belongs to the
module instance, except state deliberately carried over with `IModuleSetup.Persistent` (rate-limit zones).
That is the only sanctioned way to keep state across a reload: a build may *adopt* the previous object, never
mutate the running configuration. Resources that must be closed go in `IDisposable.Dispose` on the module, which runs when
the old configuration's last connection ends. Idle plaintext keep-alives migrate to the new configuration at their next request rather than being closed
(closing them races clients' requests); TLS connections close, since their handshake belongs to the old
configuration. No connection outlives its configuration by more than
`reload_drain_timeout` (enforced by the sweeper), so a reload that rotates certificates or revokes access
actually takes effect.

## Branches and releases

- **Always work on `develop`.** Commit there (or on short-lived topic branches cut from it and merged back).
- **`main` is "mostly stable".** It only moves by merging `develop` once `./scripts/ci.sh` passes. Never commit directly to `main`, and never rewrite its history.
- **Releases are cut from tagged commits on `main`** (e.g. `v0.2.0`). Tag only on `main`, only on a commit that passed CI. Bump `<Version>` in `Directory.Build.props` to match the tag, and add the release to `CHANGELOG.md`.
- **Versions follow [Semantic Versioning 2.0.0](https://semver.org/)** everywhere: tags (`vMAJOR.MINOR.PATCH`), `<Version>`, the changelog and the binary's reported version. The public API is the configuration language, the plugin API (`Httpgrl.Abstractions`), the protocol libraries (`Httpgrl.Quic`, `Httpgrl.Http3`, `Httpgrl.HttpFields`) and the Core APIs other software builds on (`ServerBuilder`, `HttpServer`, `JsonLogger`).
  - While at `0.y.z` (initial development), a breaking change bumps MINOR and anything else bumps PATCH.
  - From `1.0.0`: breaking changes bump MAJOR, new features MINOR, fixes PATCH.
  - "Best implementation over backwards compatibility" still holds, but a break is a version bump that's called out in the changelog, never a silent change.
- Don't push, merge into `main`, or tag unless the owner asks.

## Workflow

- Verify with `./scripts/ci.sh`. It runs the build, the tests on the JIT, the same tests as native AOT, the AOT server publish, and a `-t` config check. It must pass before work is called done.
- Every security behaviour has a test in `tests/Httpgrl.Tests`. Adding a defence means adding the test that attacks it.
- Every parser of untrusted bytes has a target in `tests/Httpgrl.Tests/Fuzz.cs` with its invariants. A new parser
  (or a new way to accept input in an existing one) gets a target or a stronger invariant in the same change.
- Keep the docs current: the directive tables (`docs/configuration.md`, `docs/proxy.md`), the security model (`docs/security.md`), the module guide and design decisions (`docs/development.md`), and the feature list in `README.md`.
- New module project: `scripts/new-module-project.sh Name` (csproj with the Abstractions-only reference, plus its
  registration in the solution, host, tests and Dockerfile). Then list the module in `Program.cs` and `Harness.cs`.
