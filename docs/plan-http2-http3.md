# HTTP/2 and HTTP/3: implementation plan

Status: plan, 2026-11-04. Nothing here is implemented yet.

## Decisions

1. **HTTP/2 and HTTP/3 are general-purpose httpgrl features**, with no application-specific paths.
2. **No `libmsquic` and no `System.Net.Quic`.** They need a native package that may not be on a given system, and
   .NET doesn't expose QUIC datagrams, which WebTransport needs. We write the HTTP/2 framing, HPACK, the QUIC
   transport, HTTP/3 framing and QPACK ourselves.
3. **We don't write cryptography.** The TLS 1.3 handshake is always the system OpenSSL's, and so are the
   cryptographic primitives:
   - **HTTP/1.1 and HTTP/2 over TCP:** `SslStream`, as today. ALPN offers `h2` and `http/1.1`.
   - **HTTP/3 over QUIC:** OpenSSL 3.5's third-party QUIC TLS API (`SSL_set_quic_tls_cbs`,
     `SSL_set_quic_tls_transport_params`). OpenSSL runs the handshake and hands us CRYPTO bytes and traffic secrets.
     This is the same `libssl.so.3` .NET loads, and it's already present on Debian 13 (checked here and on the
     production box). Certificates, signature algorithms and `X25519MLKEM768` come with it.
   - **QUIC packet protection:** .NET's `AesGcm`, AES-ECB (header protection) and `HKDF`, which call OpenSSL.
     Initially QUIC offers only the AES-GCM suites. The ChaCha20 header-protection mask needs raw ChaCha20, which
     .NET doesn't expose, and AES-GCM is the mandatory suite anyway. ChaCha20 can come later through OpenSSL's EVP.
4. **HTTP/3 is Linux-only and needs OpenSSL 3.5 or newer.** Elsewhere, a `quic` listener logs once why HTTP/3 is
   unavailable, and the server starts anyway (`-t` reports it too), so one config file works on old and new systems.
   HTTP/1.1 and HTTP/2 are unaffected.
5. **Off by default, permanently.** `http2 on;` and `http3 on;` are required to enable them. There's no plan to flip
   the default; HTTP/1.1 stays the only protocol a config gets without asking.
6. **`Alt-Svc` is automatic when `http3 on`.** A server with HTTP/3 enabled and a `quic` listener advertises it on
   its TCP responses, with the right port. An explicit `add_header Alt-Svc` wins. (A deviation: nginx needs the
   header added by hand.)
7. **WebSockets over HTTP/2 and HTTP/3 (extended CONNECT, RFC 8441/9220) come before WebTransport,** which then
   reuses the same machinery.
8. **Timers: whatever works best.** The HTTP/1 sweeper stays for its deadlines. QUIC's millisecond timers (loss
   detection, PTO, pacing, ACK delay) get the best mechanism we can find, most likely one timing wheel shared by all
   QUIC connections on a dedicated thread. The requirement from AGENTS.md is the intent: cheap per connection at
   scale, and impossible for a client to dodge.
9. **Server side only.** `proxy_pass` upstreams and reverse tunnels stay HTTP/1.1.

## Who writes what

| Piece | Written by us | Provided |
| --- | --- | --- |
| HTTP/2 frames, stream state machine, flow control, writer | yes | |
| HPACK (static/dynamic tables, Huffman) | yes | |
| QUIC packets, frames, ACKs, loss recovery, congestion control, flow control, streams, connection IDs, Retry, migration, datagrams | yes | |
| TLS 1.3 handshake (TCP and QUIC) | | OpenSSL (`SslStream`, QUIC TLS API) |
| AEAD, header protection, HKDF | | .NET / OpenSSL primitives |
| HTTP/3 frames, control streams, QPACK | yes | |
| UDP I/O | glue | `Socket` (UDP), later GSO/GRO via socket options |

## Phase 0: request-scoped core (prerequisite for both)

Today each connection owns one reusable `HttpContextImpl`, and requests run one at a time. Multiplexing needs:

- **Contexts per request** for `HttpContextImpl`, the request body, the response and the per-request deadlines,
  pooled for reuse. The connection record keeps identity, TLS info, generation, limits and idle state.
- **A protocol-neutral response sink.** HTTP/1 writes a status line, chunks and lengths; HTTP/2 and HTTP/3 write
  HEADERS and DATA frames. `HttpResponse` stays the module-facing API; `Transfer-Encoding` becomes HTTP/1-only.
- **One request-lifecycle runner** that every protocol feeds normalized request heads into: vhost and location
  selection, the SNI/`Host`/client-certificate checks (421), the phases, logging and `OnRequestEnd` exactly once.
- **Stream records the sweeper can see.** Per-stream read and write deadlines and minimum rates, alongside
  per-connection ones. It's still one sweeper thread.
- **Exit criteria:** no behaviour change; the full suite passes on the JIT and under AOT, the soak test is clean, and
  benchmarks show no regression.

## Phase 1: HTTP/2 (RFC 9113, HPACK RFC 7541)

**Scope:**
- **Negotiation:** ALPN `h2` over TLS only. Never `h2c`, neither as upgrade nor prior knowledge (AGENTS.md).
- **Connection setup:** the client preface, then SETTINGS negotiation and ACKs.
- **Frames:** DATA, HEADERS, CONTINUATION, SETTINGS, WINDOW_UPDATE, RST_STREAM, PING and GOAWAY. PRIORITY is parsed
  and ignored (RFC 9113 deprecated the priority tree). PUSH_PROMISE is never sent (`SETTINGS_ENABLE_PUSH=0`).
- **Streams:** the full stream state machine, with stream errors (RST_STREAM) kept distinct from connection errors
  (GOAWAY).
- **HPACK:** a decoder with Huffman decoding and dynamic-table size updates. The encoder starts with static table
  plus literals (no dynamic state).
- **Flow control:** per stream and per connection, with a single serialized frame writer and bounded queues.
- **Request validation:** the same strictness as HTTP/1.1, translated:
  - pseudo-headers come first, exactly once, with no unknown ones;
  - `:authority` and `Host` must agree;
  - no connection-specific fields (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade`);
  - field names are lower-case and contain no CR, LF or NUL;
  - `content-length` must match the DATA frames received.
- **Reload and shutdown:** GOAWAY with the last stream ID; in-flight streams finish within `reload_drain_timeout`.
- **Directives:** nginx's `http2 on|off` (server level), plus limits: `http2_max_concurrent_streams`,
  `http2_max_field_size`, `http2_max_header_size`, `http2_recv_buffer_size`.
- **Then:** WebSockets over HTTP/2 through extended CONNECT (RFC 8441, `SETTINGS_ENABLE_CONNECT_PROTOCOL`). The
  existing `UpgradeAsync` handlers (proxy tunnels) get a duplex stream either way, so modules don't care which
  protocol carried the request. Done before Phase 2 starts.

**Attacks to test, each with a test that fails without the defence:**
- **Rapid reset (CVE-2023-44487):** streams opened and immediately reset still count, with a reset-rate limit.
- **CONTINUATION flood (2024):** header blocks are bounded by total size and fragment count across CONTINUATION
  frames, with no unbounded buffering.
- **HPACK bomb:** decoded size is limited (`max_header_size`), and the dynamic table is capped no matter what
  SETTINGS says.
- **Floods of SETTINGS, PING, empty DATA or WINDOW_UPDATE frames:** per-connection budgets; a peer over budget gets
  GOAWAY `ENHANCE_YOUR_CALM`.
- **Window games:** zero-window slow reads hit the existing minimum-rate defence, and windows that overflow are a
  FLOW_CONTROL_ERROR.
- **Stream-ID abuse:** IDs going backwards, even (server-initiated) IDs, and exhausting `max_concurrent_streams`.

**New fuzz targets:** the frame parser, the HPACK decoder (with Huffman), and a session-level target that feeds frame
sequences to a session with a fake clock. The invariants: bounded memory, no state-machine violations, and no request
reaching the pipeline that HTTP/1 would have refused.

## Phase 2: QUIC transport (RFC 8999, 9000, 9001, 9002, 9221)

**Scope:**
- **Packets:** parsing long and short headers, version negotiation (QUIC v1 only), and coalesced packets.
- **Keys:** Initial secrets (the v1 salt), Handshake and 1-RTT keys from OpenSSL's yielded secrets, and key update.
- **Frames:** PADDING, PING, ACK, RESET_STREAM, STOP_SENDING, CRYPTO, NEW_TOKEN, STREAM, the MAX_* and *_BLOCKED
  frames, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, PATH_CHALLENGE/RESPONSE, CONNECTION_CLOSE, HANDSHAKE_DONE, and
  DATAGRAM (RFC 9221, negotiated from the start, since owning it is the point).
- **Abuse defences:**
  - the 3× anti-amplification limit before address validation;
  - Retry with stateless, AEAD-sealed tokens under load (`quic_retry on|off`);
  - stateless reset.
- **Connection IDs:** the server picks routable connection IDs, keeps a connection-ID → connection table, and issues
  and retires IDs.
- **Loss recovery and congestion control (RFC 9002):** ACK handling, PTO, and persistent congestion. NewReno comes
  first, then CUBIC, with pacing.
- **Flow control and streams:** stream and connection limits, and per-stream state machines.
- **Paths:** path validation, NAT rebinding, and migration. Per-client limits follow the validated address.
- **Not now:** idle timeouts and the handshake timeout are in scope; 0-RTT is **not** (it's replayable, as on TCP
  where we don't offer it).
- **UDP:** start with plain socket I/O, then GSO/GRO (`UDP_SEGMENT`/`UDP_GRO` socket options) as a measured
  optimization.

**TLS through OpenSSL:**
- per-server contexts with SNI selection through OpenSSL's client-hello callback;
- certificates loaded from the same `ssl_certificate` files;
- `CipherString` and `Ciphersuites` restricted to AES-GCM.
- Servers with `ssl_verify_client` don't advertise HTTP/3 at first; client certificates over QUIC come later, with
  the same CA-only policy.
- The callbacks are `[UnmanagedCallersOnly]` function pointers (AOT-safe). All interop lives in one Core file with
  its own tests, like `LocalFiles.cs`.

**Testing:**
- **A deterministic in-process network** with a virtual clock and configurable loss, reordering, duplication, delay
  and rate. It drives client and server state machines directly, so recovery and congestion behaviour are
  repeatable, and it runs under AOT in CI.
- **Fuzz targets:** packet header parsing, frame parsing, variable-length integers, transport parameters, and a
  connection-level target driven by the virtual network.
- **Interop with independent implementations:** curl's HTTP/3 (ngtcp2/quiche), Chrome, Firefox and the QUIC interop
  runner's test cases. These run as optional, scripted checks; they aren't build or runtime dependencies.

## Phase 3: HTTP/3 (RFC 9114, QPACK RFC 9204)

**Scope:**
- **Streams:** control streams and SETTINGS; request streams; and peer-initiated stream classification and limits.
- **QPACK:** advertise a dynamic-table capacity of 0 at first. The decoder handles static and literal fields with
  Huffman (shared with HPACK); the encoder uses static plus literals.
- **Shared validation:** the same field and pseudo-field rules as HTTP/2.
- **GOAWAY** on reload and shutdown.
- **Listening:** `listen 443 quic [reuseport];` (nginx syntax) next to the TCP listener on the same port, opened and
  closed transactionally with it on reload.
- **Advertising:** with `http3 on`, `Alt-Svc: h3=":<quic port>"; ma=86400` on the server's TCP responses
  (automatic; an explicit `add_header Alt-Svc` wins). Document HTTPS DNS records for first-visit HTTP/3.
- **Directives:** `http3 on|off`, `http3_max_concurrent_streams`, `quic_retry`, `quic_gso`, plus the shared header
  limits.
- **Then:** WebSockets over HTTP/3 through extended CONNECT (RFC 9220), reusing HTTP/2's handling.

## Phase 4: hardening and release

- Soak and load tests with HTTP/2 and HTTP/3 mixed into `--soak`, plus bad-network runs through the virtual network.
- Interop matrix: browsers, curl, h2load, and the QUIC interop runner.
- Both stay opt-in (`http2 on;`, `http3 on;`) for good; hardening is about trusting them on the open internet, not
  about flipping a default.

## Phase 5: datagrams, extended CONNECT, WebTransport

- HTTP datagrams and capsules (RFC 9297) over our own QUIC DATAGRAM support.
- A WebTransport session API in `Httpgrl.Abstractions`, built on the extended CONNECT support from Phases 1 and 3:
  accepting and opening streams, datagrams, drain, and close with error codes. Modules never see QUIC types.
- WebTransport over HTTP/3 to whichever draft browsers implement at that point, behind a capability flag.

## Cross-cutting

- **Timers:** see decision 8. Whatever QUIC uses, the coarse deadlines (idle, handshake, minimum rates, reload
  drain) stay enforced the same way for every protocol.
- **Reload:** UDP sockets belong to `HttpServer` like TCP listeners and are kept across reloads. QUIC connections
  stay on the generation they were authenticated under, get GOAWAY at reload, and are closed after
  `reload_drain_timeout`. The connection-ID table survives reloads.
- **Limits:** connections (global, per client), concurrent streams per connection and per client, header-table
  memory, queued outbound bytes, flow-control windows, datagram rates.
- **Metrics:** `stub_status` gains per-protocol connection and stream counts.
- **Logging:** the access log gets `proto` `HTTP/2.0` or `HTTP/3.0` and a stream ID.

## Rough size

These are sequence and relative size, not dates:
- Phase 0: medium.
- HTTP/2: large.
- The QUIC transport is the biggest single piece; loss recovery and congestion control alone are substantial.
- HTTP/3 and QPACK: medium on top of QUIC.
- Hardening: ongoing.

Each phase is merged only with its fuzz targets, attack tests and AOT runs, as every feature so far has been.

## Risks

- **Managed UDP performance.** It'll trail msquic; GSO/GRO and batching narrow the gap. It's measured, not assumed.
- **Congestion-control correctness.** This is subtle; it's mitigated by the deterministic network simulator and
  interop testing.
- **OpenSSL 3.5's QUIC TLS API is new.** Pin behaviour with tests; on systems without it, HTTP/3 is reported
  unavailable, never half-working.
- **Attack surface.** HTTP/2 and QUIC are where recent server CVEs cluster. That's why each phase lands with fuzz
  targets and attack tests, and why both ship off by default at first.
