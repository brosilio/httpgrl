# Security monitoring and incident evidence

## Plan and delivery status

1. **Request evidence:** record final server-side completion, selected route/server, normalized path, upstream,
   request ID and process identity. Run the log phase once even when transport I/O throws. Implemented.
2. **Security decisions:** stable event IDs for routing failures, rejected requests, access denials, resource opens,
   deadlines, limits, protocol refusals and upstream body failures. Implemented; event coverage is listed below.
3. **Privacy and integrity:** omit Referer values and query/fragment values from URI fields, bound/truncate records,
   mark truncation, retain nonblocking logging and dropped-line metrics. Implemented.
4. **Detection:** configurable sensitive-resource, size, denial/success, incomplete-response, audit-policy and
   evidence-loss rules with bounded state and hostile-input tests. Implemented in `dist/monitoring/detect.py`.
5. **Operations:** provide central TLS forwarding, retention, metrics and end-to-end probe alerts, host audit
   examples, application correlation contract and incident runbook. Templates prepared. Production installation,
   collector credentials, recipient configuration and real application instrumentation remain deployment work.
6. **Verification:** repository CI includes detector tests, request regressions, a redaction fuzz target, and the
   usual JIT/native AOT runs. External rsyslog/Prometheus/Loki configs must also be validated with the deployed versions.

This is detection support, not proof that every exploit will be detected. A complete 200 means the server completed
its response; it does not prove the client received it, that access was authorized, or that a state change occurred.
Use application audit events and host evidence to establish impact. A failed request can also have side effects.

## Log schema 2 (0.5.0)

Every JsonLogger record carries `schema`, `instance` (machine name), `process_id` (random per process), `version`,
`ts`, `level`, and `msg`. Collector labels should add deployment/environment identity and the deployed binary's
SHA-256/revision from the release manifest. A version alone is not a unique build identity. Do not treat source IP,
Host, User-Agent, Referer, or a client-supplied request ID as trusted identity. Multiple instances can share a machine
name: use process ID and collector deployment labels too.

`event=http_access` includes:

| Field | Meaning |
|---|---|
| `request_id`, `conn` | Server-generated request ID, and connection ID scoped to its process |
| `remote`, `method`, `host`, `proto`, `tls`, `client_verify` | Request/connection context |
| `uri` | Original request target with literal query/fragment removed; encoding preserved |
| `path` | Current normalized path after rewrites/internal redirects |
| `query_present`, `referer_present` | Presence only; no values |
| `server`, `location` | Selected configuration server name and final location label; not filesystem paths |
| `status`, `bytes`, `rt` | Final status, response body bytes sent, duration in seconds |
| `outcome` | `complete`, `incomplete`, or `dropped`; distinguish an incomplete 200 from a complete response |
| `upstream`, `upstream_status` | Last selected upstream and response status, or null; not a full retry history |

`access_log off` still disables access records. `error_log stdout warn` also suppresses them: use **info** for
monitoring. Request-scoped security decisions are separate warn records and survive `access_log off`; some transport
records use info. No protocol logs request bodies, cookies or authorization headers through the access logger.

Privacy is deliberately conservative: the old access `referer` value is replaced by `referer_present`, and query
values are removed from `uri`. JsonLogger applies the same URI stripping to diagnostic `uri`, `target`, and
`request_uri` fields, and redacts fields named `query`, `referer`, `authorization`, or `cookie`. Encoded delimiters
remain part of the path. Secrets embedded in **paths**, User-Agent, custom fields, configuration values or exception
messages cannot be identified automatically; avoid placing secrets there and review custom module logs. Existing
historical records may contain query secrets and need restricted access/retention. No option restores full query logging.

Strings are bounded, total record size is bounded, and `truncated=true` marks shortened evidence. JSON encoding prevents
newlines from turning one event into multiple records. Logs can be dropped under pressure: that is intentional to keep
request handling nonblocking. Preserve and alert on the loss counter; do not infer "no attack" from an empty log.

### Stable event vocabulary

| Event | Evidence |
|---|---|
| `routing_regex_timeout` | Location/expression/Host matching was indeterminate; TCP SNI includes stage/connection |
| `request_rejected`, `tls_policy_mismatch` | Request rejected before handlers; correlate with access status |
| `access_denied` | Access-module rule denied a request |
| `filesystem_mapping_denied`, `filesystem_access_denied` | Core mapping refused, or an open returned forbidden; not proof of traversal |
| `header_deadline_exceeded` | HTTP/1/2 connection header deadline or HTTP/3 unfinished request head expired |
| `connection_aborted`, `stream_aborted` | Deadline/rate/lifecycle reason; not every abort is an attack |
| `migration_limit_exceeded` | Validated QUIC destination was already at its per-client cap |
| `http2_connection_rejected`, `http2_stream_rejected`, `http3_connection_rejected`, `http3_stream_rejected` | Protocol rejection |
| `client_certificate_rejected` | TCP client-certificate rejection |
| `rate_limit_exceeded`, `connection_limit_exceeded` | Request module limit rejection |
| `rate_limit_would_reject`, `connection_limit_would_reject` | Dry-run decisions; no rejection |
| `upstream_response_failed` | Upstream body failed during relay |
| `log_lines_dropped` | Logger reports queued-output loss when output recovers |

Request-scoped decisions carry `request_id`, `conn`, `remote`, `method`, and `path`. Pre-request events cannot carry
a request ID. QUIC migration records carry the peer endpoint but currently no HTTP request/connection ID; correlate
by process/time/peer with care. Probe/list operations, QUIC handshake certificate failures and every low-level parser
failure are not all covered by dedicated events. Transport events and counters supplement access records.

## Local analysis and alerts

The detector uses Python 3's standard library **outside the server**. It adds no dependency to the httpgrl binary.
Python 3 is now a CI prerequisite for detector tests. Copy `policy.example.json`, replace the example hostname and
resource paths with your inventory, and keep the policy file controlled by operators:

```sh
journalctl -u httpgrl.service --since '1 hour ago' -o cat --no-pager > requests.jsonl
python3 -B dist/monitoring/detect.py --policy dist/monitoring/policy.example.json < requests.jsonl
python3 -B dist/monitoring/test_detect.py
```

For example, `never_success` is appropriate for `/.env` or `/.git` if they must never be served. Do not classify every
200 from `/admin` as compromise: legitimate users need it. Configure response-size thresholds for known exports based
on expected behavior. Prefix rules use path boundaries (`/admin` matches `/admin/x`, not `/administrator`); host-scoped
rules avoid conflating virtual hosts. An SPA's deliberate catch-all 200 may trigger sensitive-path rules: tune by actual
route semantics rather than suppressing every sensitive-path alert.

The detector emits JSON `security_alert` records on stdout. It does not send notifications, block IPs or change server
state. Forward those alerts to your collector/notification routing. Rules cover unexpected sensitive successes,
large sensitive responses, repeated denials followed by success from the same peer/host/path, successful status with
incomplete outcome, selected security events, truncation, log loss, and explicit application authorization violations.
Denials/success correlation is a lead, not proof that the same person made both requests (NAT/proxies exist).

Input should be chronological UTC JSON lines from a trusted collector. Malformed/oversized records produce bounded
loss alerts; lines are limited to 64 KiB. Correlation and alert suppression are bounded by `max_keys` and
`window_seconds`; the detector alerts when denial-correlation capacity is reached. State is in memory; restarts lose
it and may repeat alerts. Replay a window of raw logs after restart. Capacity/clock skew/late delivery can weaken
correlation. Preserve raw central logs for reanalysis. Policy errors are operator errors and should prevent deployment.

`httpgrl-monitor.service` provides a local journal consumer with five-minute replay on restart. Install the script
at `/usr/local/lib/httpgrl-monitor/detect.py`, policy at `/etc/httpgrl-monitor/policy.json` (operator writable only),
and the unit under `/etc/systemd/system`. Its dynamic user belongs to `systemd-journal` and can read the journal;
use a collector-side detector instead if that access is inappropriate. Monitor this service's availability too.

## Central collection, retention and missing evidence

Examples in `dist/monitoring/` are **not installed automatically**:

1. Merge the loopback-only metrics/probe server from `httpgrl.conf.example`; check `httpgrl -t` before reloading.
   Add `proxy_set_header X-Request-ID $request_id` to proxy locations, accounting for inheritance of other headers.
2. Apply the service logging drop-in and a host-appropriate persistent journal budget. The example retains at most
   14 days / 1 GiB locally; disk limits can evict evidence sooner. Disable per-service journal rate suppression only
   with a disk budget. Watch journald suppression, disk pressure and collector failures independently.
3. Merge `rsyslog.conf.example` with the existing collector. Do not load `imjournal` twice. Replace destination/CA,
   configure a writable work directory, install its TLS driver, and validate with `rsyslogd -N1` before reload.
   TLS peer-name verification is required. Queueing is bounded and disk-assisted, not a guarantee against loss during
   crashes or saturation. Monitor imjournal input rate limits, journal cursor gaps, queue capacity and action failures.
   Use a dedicated remote collector outside the web host; restrict deletion, encrypt storage, and choose a retention
   period (e.g. 30 days searchable plus 90 days restricted archive) suitable for your volume and privacy needs.
4. Scrape `/metrics` from an allowed source using job `httpgrl`. Load `prometheus.rules.yml`; validate using
   `promtool check rules`. Configure an Alertmanager route and real receiver. `up==0` catches failed configured targets;
   the absence rule catches an entirely missing job. Maintain expected-instance inventory to catch a removed single target.
5. Enable the probe service/timer after verifying its loopback port. It emits a normal access record every minute.
   At the **remote collector**, alert if no complete `/monitoring-probe` record arrives for five minutes. This catches
   disabled access logs, dead forwarding, filters and journal loss that scrape health alone cannot detect.
   `loki.rules.yml` supplies examples for Loki: adapt labels and create an absence rule for each expected instance.
   Preserve collector host identity rather than allowing JSON `instance` to overwrite trusted labels.
6. Forward detector records (`httpgrl-monitor.service`) as well as raw server records; the rsyslog example selects both.
   Configure notification grouping and ownership. No destination or recipients are assumed in this repository.

Deployment acceptance: send a normal request and a denied request; find both at the remote collector by request ID.
Temporarily stop forwarding (leave the server running) and verify the missing-probe alert fires, then restore forwarding
and verify recovery. Exercise a synthetic sensitive-path policy against a disposable instance and verify the actual
notification reaches the chosen recipient. Check disk-queue recovery, collector parsing errors and monitor restart replay.
Never inject a real secret to test redaction. Record deployed binary SHA-256, config revision and collector policy revision.

These configurations follow the [rsyslog forwarding documentation](https://docs.rsyslog.com/doc/configuration/modules/omfwd.html),
[Prometheus alerting rules](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/),
[Loki metric queries](https://grafana.com/docs/loki/latest/query/metric_queries/) and
[systemd journal settings](https://www.freedesktop.org/software/systemd/man/258/journald.conf.d.html).
Validate against installed versions before use; these services are optional external infrastructure.

## Application audit events

Only the application knows the authenticated actor, authorization decision and committed result. At each sensitive
operation, log a bounded event such as:

```json
{"ts":"2026-11-08T12:00:00Z","event":"application_audit","request_id":"SERVER_GENERATED_ID","actor_id":"internal-account-id","action":"export","resource_id":"report-id","authorized":true,"outcome":"success"}
```

Log failed authorization and successful/failed committed actions separately where useful. Never include passwords,
session tokens, full records or secret resource content. Treat actor/resource IDs as protected data. An application's
`authorized:false,outcome:success` is a critical invariant violation; the detector recognizes it. Other sensitive actions
need application-specific rules (e.g. an unexpected role grant). Replace client X-Request-ID at the trusted front door;
accept it at the application only from the authenticated/restricted proxy hop. Forward both app audit and access logs
centrally and join by request ID plus deployment identity. The local journal detector only consumes httpgrl logs; route
application logs through a separate detector input or a centralized merged feed to use application rules.

This contract is ready for applications; no application repository or audit sink is included here, so application
instrumentation and confirmation of actual audit events are explicit rollout requirements.

## Host evidence and incident response

Use `audit.rules.example` with the real service UID on Linux hosts with auditd. Record `execve`/`execveat` and `connect`
for that UID; inspect the associated `SYSCALL`, `EXECVE`, `SOCKADDR` and process records, and forward audit logs separately.
Server starts during deployments are expected. After startup, child execution by a static AOT web server should be rare.
Outbound connections need an allowlist of configured upstreams, DNS, tunnels, health checks and certificate-status services;
not every connection is malicious. Keep this inventory with the configuration revision. UDP sendto-based traffic is not
fully covered by connect rules; use host/network flow telemetry if that matters. Shared UIDs weaken attribution: give
httpgrl a dedicated UID. Validate rules with the host's audit tools and monitor audit backlog/lost records. The guidance
is consistent with [NSA/ASD web-shell detection recommendations](https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF).

On an alert:

1. Preserve raw access, security, upstream/application and host logs around the timestamp, plus deployment/config IDs.
2. Correlate by request ID, process ID, connection, upstream and route. Check `outcome`, bytes and any log-loss signal.
3. Determine impact from application commit/audit events, file changes and host/network events—not HTTP status alone.
4. If compromise is plausible, preserve host evidence and isolate according to your incident procedure; do not automatically
   ban every IP that triggered a parser error or destroy evidence by restarting blindly.
5. Add a replay/regression for the observed behavior and tune the alert with a documented reason.

The [OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) covers event selection,
correlation and protection of sensitive log data.
