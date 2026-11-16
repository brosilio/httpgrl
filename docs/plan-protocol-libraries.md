# Protocol libraries: roadmap

Status (2026-11-16): agreed with the owner. M0 is done (on `develop`, uncommitted until reviewed); M1 is next.

## Why

The owner's AOT-first game engine (`dotnetgameengine`, see its `docs/DESIGN.md`) uses httpgrl's QUIC stack for
multiplayer: native QUIC on desktop and consoles, WebTransport over HTTP/3 in browsers, one server stack for both.
Today everything is `internal` to `Httpgrl.Core`. This roadmap moves the protocol stack into public libraries and
rebuilds the server on them, so every feature the engine gets is also exercised by httpgrl itself.

## Decisions

1. **Protocol libraries first.** We extract `Httpgrl.Quic` and `Httpgrl.Http3` (with QPACK), plus a small shared
   header-field codec. HTTP/1, HTTP/2, hosting and the pipeline stay in `Httpgrl.Core` until something outside
   httpgrl needs them; they're too intertwined to split without a consumer to tell us where the seams belong.
2. **The server dogfoods the libraries.** `Httpgrl.Core` reaches QUIC and HTTP/3 only through their public API,
   with no `InternalsVisibleTo` from the libraries to Core. Whatever the server needs, another consumer can have too.
3. **Libraries are I/O-free at the core.** A `QuicConnection` takes datagrams in and gives datagrams out, on a clock
   the caller supplies. Socket loops (server endpoint, client endpoint) are separate, optional types built on that.
4. **Distributed by project reference.** The engine references the csproj files (submodule or sibling checkout).
   No NuGet packaging for now. The libraries' public API is semver public API (AGENTS.md "Branches and releases"):
   while we're at `0.y`, a breaking change bumps MINOR.
5. **AGENTS.md still applies in full:** native AOT with warnings as errors, no third-party dependencies, hot paths
   written like C, strict parsing, and stricter-than-nginx defaults. Library defaults are the safe ones; anything
   game-specific (drop-oldest queues, a congestion-bypass budget) is opt-in per connection.
6. **Dependency direction is enforced.** `Httpgrl.Quic` references nothing of ours. `Httpgrl.Http3` references only
   `Httpgrl.Quic` and the field codec. Neither references `Httpgrl.Core` or `Httpgrl.Abstractions`.
   `scripts/check-boundaries.sh` fails the build otherwise.
7. **Supersedes decision 9 of `plan-http2-http3.md`** ("server side only"): QUIC gets a real client. Upstreams
   (`proxy_pass`) stay HTTP/1.1; the client exists for library consumers.

## Definition of done (every milestone)

- `./scripts/ci.sh` passes: build, tests on the JIT, the same tests as native AOT, AOT server publish, `-t` check.
- Every new parser of untrusted bytes has a target in `tests/Httpgrl.Tests/Fuzz.cs`, and every new defence has a
  test that attacks it.
- `tests/Httpgrl.Libraries.Smoke` (added in M0) is a native AOT console program that uses **only the public API** of
  the libraries, and it grows with each milestone. It's what the engine will do, so it proves the API is enough.
- README.md (security model, directive table) and CHANGELOG.md are updated, and the work is committed on `develop`.
  Releases are cut separately, when the owner asks.

## M0: restructure (no behaviour change)

Goal: same server, same wire behaviour, built on public libraries.

- **New projects**, made with the same csproj conventions (AOT-compatible, warnings as errors):
  - `src/Httpgrl.Quic`: everything in `Core/Quic/`. `IpKey` (the per-client /64 key that `Endpoint.cs` borrows from
    `Hosting`) either moves into the library or is replaced by an endpoint hook that limits connections per client.
    The global and per-client caps stay enforced in the server endpoint.
  - `src/Httpgrl.Http3`: frames, QPACK, control and request-stream state machines. The HTTP/3 code that touches the
    pipeline (`Application.cs`, and the pipeline parts of `Connection.cs`/`Stream.cs`) stays in Core as an adapter
    that maps library request streams onto `Pipeline`.
  - Shared field codec (working name `Httpgrl.HttpFields`): HPACK/QPACK prefix integers, Huffman, and field
    name/value validation. QPACK uses it from `Http2/Hpack` today. Core's HPACK moves onto it too.
  - Extended CONNECT validation (`Http2/RequestHead.cs`) is shared by HTTP/2 and HTTP/3, so the protocol-neutral
    checks move to the field codec, and the "which `:protocol` do we accept" policy stays with the caller.
- **Public API, kept small.** Options types, `QuicConnection` (feed datagrams, poll for output, next timer, events),
  streams, `QuicServerEndpoint`, and an HTTP/3 connection that surfaces request streams. Everything else stays
  `internal`. Logging goes through a minimal library-level hook (no dependency on Abstractions' `ILogger`); Core
  adapts it to `ILogger`.
- **Tests:** the existing suite passes unchanged on JIT and AOT (proof of no behaviour change). The smoke program
  does an in-memory client↔server handshake and one HTTP/3 request over the public API. `check-boundaries.sh`
  learns the dependency rules in decision 6.
- **Docs:** README's architecture/module guide shows the new layout. `new-module-project.sh` is unaffected.

### M0 as built

- `src/Httpgrl.HttpFields` (HPACK, Huffman, `FieldHandler`), `src/Httpgrl.Quic` (all of the old `Core/Quic/`),
  `src/Httpgrl.Http3` (frames, QPACK, and the new `Http3ServerConnection`). Namespaces `Httpgrl.HttpFields`,
  `Httpgrl.Quic`, `Httpgrl.Http3`.
- `Http3ServerConnection` holds all of RFC 9114's server side that used to be in Core's `Http3Connection`: control
  and QPACK streams, SETTINGS, request-stream framing and trailers, GOAWAY, write back-pressure, and the absolute
  request-head deadline. It asks its application (`IHttp3ServerHandler`) what a request means and hands each request's
  body to an `IHttp3Request`. Core's `Http3Connection` is now that application: routing, the pipeline, reload, logs.
- The endpoint logs through `IQuicLog` (Core adapts it to `ILogger`). Client-certificate policy is an
  `IQuicClientCertificatePolicy` (Core's `ClientAuth` implements it). `QuicTlsContext.Unavailable` is public.
- The per-client key is `ClientKey` in Httpgrl.Quic, a twin of Core's `IpKey`; a test checks the two group every
  address the same way.
- Deferred from the M0 bullets above: the extended CONNECT checks stay in Core's `RequestHead` for now (they move with
  WebTransport in M3), and `Http3ServerConnection` posts work through `QuicEndpoint` directly (an interface comes with
  M1's client endpoint).
- Public surface: the types Core and the smoke program need, nothing more. `QuicConnection` members that expose
  internal machinery (`Recovery`, `Cipher`, `PeerParameters`) stay internal; tests see them through
  `InternalsVisibleTo("Httpgrl.Tests")`, which the libraries grant to the test suite only.

## M1: QUIC client and pluggable TLS

- **TLS behind an interface.** Today `QuicTls` already talks to its connection through `IQuicTlsHost`. M1 makes the
  other direction public too: an `IQuicTlsSession` (feed CRYPTO bytes at a level, advance, report ALPN, the peer
  certificate result and errors) and an `IQuicTlsProvider` that makes sessions for client or server. The OpenSSL 3.5
  implementation becomes one provider. Consoles plug in their own.
- **Per-platform OpenSSL loading.** Library names come from a resolver (`NativeLibrary.SetDllImportResolver`, which
  is AOT-safe), with defaults per OS (`libssl.so.3`, `libssl.3.dylib`, `libssl-3-x64.dll`) and an override for
  callers. "Not found" stays a clear error, never a crash on first use.
- **Client side:**
  - `QuicClientEndpoint`, a UDP socket loop: one socket, one or more connections, the same timer mechanism as the
    server.
  - Verification on by default: the server certificate is checked against system roots or a caller-supplied CA
    bundle, plus the hostname and ALPN. Turning verification off is an explicit, loudly named option.
  - New client-only parsing gets fuzz targets: Version Negotiation, Retry (integrity tag verified, at most one
    accepted, ignored after the first Handshake packet), and the server's transport parameters
    (`original_destination_connection_id` and `retry_source_connection_id` checked).
- **Clock:** confirm that every path of `QuicConnection` takes `now` from the caller (no `Stopwatch` inside), and
  add a test that drives a whole connection, including PTO and the idle timeout, on a fake clock.
- **Tests:** client↔server over real loopback UDP. A wrong hostname, an untrusted CA and a wrong ALPN each fail the
  handshake. A test TLS provider that wraps the OpenSSL one proves the interface is enough. The smoke program
  connects with the public client endpoint.

## M2: datagrams for games

All of this is per-connection options, and defaults stay as they are today (the safe ones for the server).

- **Queue policy:** `DropNewest` (today's behaviour), `DropOldest`, plus an optional maximum age. Expired datagrams
  are discarded at send time and counted.
- **Pooled buffers:** no `byte[]` per datagram. Received datagrams are delivered as a span to a callback, or as a
  pooled lease the caller returns. Sends copy into pooled slots. A test asserts zero allocations per datagram in
  steady state (`GC.GetAllocatedBytesForCurrentThread`).
- **Ack and loss events:** `SendDatagram` returns an id. Recovery already tracks frames per packet, so it raises
  `DatagramAcked(id)` / `DatagramLost(id)` instead of treating datagrams like PING frames internally.
- **Urgent budget (opt-in):** a small allowance that lets datagrams go out when the congestion window or pacing
  would hold them, so tick packets don't go stale after a loss burst. It's bounded (a few packets per RTT, and
  configurable) and never bypasses the anti-amplification limit or the peer's `max_datagram_frame_size`. Bypassed
  bytes still count as in flight. A test checks it can't be used to flood.
- **`MaxDatagramFrameSize`:** settable through public options (it's 0 today and nothing sets it). The server's
  HTTP/3 turns it on only when HTTP datagrams are enabled (M3).
- **Tests:** an in-memory lossy link (seeded drop/reorder/delay) checks each queue policy, max age on a fake clock,
  that ack and loss events match what the link did, and the budget's bounds. The smoke program sends tick
  datagrams through a lossy link.

## M3: WebTransport over HTTP/3

- **Codepoints:** at the start of M3, check what Chrome, Firefox and Safari actually ship (settings such as
  `SETTINGS_ENABLE_WEBTRANSPORT` vs `SETTINGS_WT_MAX_SESSIONS`, stream signal values, capsule types) against the
  current draft-ietf-webtrans-http3. Support what browsers negotiate, and write down the version matrix in this file.
- **HTTP/3 library:**
  - `SETTINGS_H3_DATAGRAM` (0x33), `SETTINGS_ENABLE_CONNECT_PROTOCOL` and the WebTransport settings, sent only
    when enabled.
  - RFC 9297 HTTP datagrams (quarter stream ID) and the capsule protocol. The capsule parser gets a fuzz target
    with strict limits.
  - Extended CONNECT with `:protocol=webtransport`. The library hands the session to the application, which
    accepts or refuses it.
  - WT bidirectional and unidirectional stream types bound to a session; session close and drain; and
    `CLOSE_WEBTRANSPORT_SESSION` with an error code. Closing a session resets its streams, and closing the CONNECT
    stream closes the session.
  - Limits: maximum sessions per connection, and per-session stream and datagram limits. Streams that name an
    unknown session are buffered only briefly and up to a bound, then reset.
- **Server (dogfooding):** as `plan-http2-http3.md` Phase 5 planned, a WebTransport session API in
  `Httpgrl.Abstractions` (accept and open streams, datagrams, drain, close; modules never see QUIC types). Plus one
  module that uses it: an echo/test module first, and later a proxy to a backend. Off by default, opt-in per
  `location`. `:protocol` values other than `websocket` and `webtransport` stay 501.
- **Tests:** a library-level session with the public client from M1 (streams both ways, datagrams, close codes,
  the limits). The server module tested end to end. A manual browser check (Chrome and Firefox against a local
  instance with a test page) recorded in this file. The smoke program opens a WT session.

## After M3 (not scheduled)

- Splitting HTTP/1 and HTTP/2 out of Core, once a consumer needs it.
- Connection migration and path validation on the client (needed for mobile, not desktop or console).
- 0-RTT for the client (game reconnects), with replay safety decided per use.
