# bower tap and bower top

`bower tap` shows what Bower decided, and what it would send, as events pass the
collector. `bower top` shows per-stage throughput, queue, delivery, syslog and tap
counters. Both exist in the C# and Rust CLIs and collectors with the same endpoints,
limits, output and exit codes.

Neither one sees raw input. The earliest tap point is after the privacy engine.

## bower tap

```bash
export BOWER_INGEST_TOKEN=...            # the shared operator token, never printed
bower tap --collector http://127.0.0.1:4319 \
  [--stage redacted|decided|queued] [--source APP] [--event-type TYPE] \
  [--limit N] [--duration SECONDS] [--sample N] > frames.jsonl
```

Frames are JSON lines on stdout. The start and end summaries go to stderr. There is no
`--out` option and the collector writes nothing to disk. Exit code 1 means the collector
refused the session (the message says why) or could not be reached.

### Tap points

| `--stage` | Shows |
|---|---|
| `redacted` (default) | Every final outcome: accepted, rejected, quarantined (schema, validation, redaction or transform failures) and identity conflicts |
| `decided` | Outcomes decided by policy (stage `policy`) |
| `queued` | Events written to the durable queue in this request |

There is no `parsed` or raw point. `--stage parsed` fails with "There is no
pre-redaction tap point".

`--source` matches `application.name` exactly and `--event-type` matches `eventType`
exactly. Both accept 1 to 128 characters from letters, digits and `. _ : / @ -`.
`--sample N` keeps 1 in N matching outcomes, chosen deterministically.

### Frames

The stream is server-sent events (`text/event-stream`). Its schema version is
`bower.tap/v1`, and the frame schema is
[`schemas/tap/tap-frame.schema.json`](../../schemas/tap/tap-frame.schema.json).

- `start`: session id, effective tap point and filters, and caps after clamping.
- `frame`: one outcome (below).
- `end`: reason (`limit`, `duration` or `shutdown`) plus frames sent, dropped and rate
  limited.
- `: keep-alive` comment: written after 15 s without a frame.

```json
{"schemaVersion":"bower.tap/v1","sequence":1,"observedAt":"2026-10-27T01:52:22.07+00:00",
 "stage":"policy","action":"redact-and-accept","queued":true,"duplicate":false,"suppressed":false,
 "eventType":"authentication_failure","application":"TestApplication","environment":"test",
 "policyId":"BWR-POL-AUTH-FAILURE","reasons":[],"event":{"schemaVersion":"1.0.0","...":"..."}}
```

- `stage` and `action` match the `/v1/status` `pipeline.rows`, so a sample can be
  joined to its counter.
- `event` is present only for accepted events (`accept`, `redact-and-accept`, including
  duplicates and suppressed events). It holds the exact redacted payload handed to the
  queue.
- Every other outcome has `eventOmitted: "not-accepted"` and metadata only: event type,
  application, environment, policy id and the bounded reason codes the producer already
  receives.
- An accepted payload over `BOWER_TAP_MAX_EVENT_BYTES` gives
  `eventOmitted: "size-cap"`.
- A record that never reached the privacy engine (a transform or redaction failure) has
  no event type or application, only its stage, action and stable code.
- Event type, application and environment are cut to 128 characters.

Generated privacy alert events are not tapped. They are counted by the `pipeline`
counters of the source event.

### Access

`GET /v1/tap` sits behind the same bearer authentication as `/v1/status`. It is
stricter than status:

- With ingest tokens configured, only the shared `BOWER_INGEST_TOKEN` (producer
  `default`) and producers listed in `BOWER_TAP_PRODUCERS` may tap. Per-producer tokens
  from `BOWER_INGEST_TOKENS_FILE` are producer credentials. They get 403
  `tap-not-authorized`, so one producer can never read another's events.
- With ingest authentication off, tap works only on a loopback listener. A collector
  started with `BOWER_ALLOW_UNAUTHENTICATED_INGEST=true` on another address refuses tap
  with 403.
- `BOWER_TAP_ENABLED=false` answers 404 `tap-disabled`.

Every session is audited in the collector log. Event ids `1200` (opened), `1201`
(closed) and `1202` (refused) record the producer id (never the token), the session id,
tap point, filters, limit, duration, sample, end reason, elapsed time and frame counts.
The log never holds frame content.

### Limits

| Variable | Default | Range | Effect |
|---|---|---|---|
| `BOWER_TAP_ENABLED` | `true` | `true`/`false` | Serve `/v1/tap` |
| `BOWER_TAP_MAX_SESSIONS` | `2` | 1-16 | Concurrent sessions; more get 429 `tap-session-limit` with `Retry-After: 5` |
| `BOWER_TAP_MAX_EVENTS_PER_SECOND` | `20` | 1-1000 | Per session; frames over the allowance are dropped and counted as rate limited |
| `BOWER_TAP_MAX_DURATION_SECONDS` | `300` | 1-3600 | Longest session. `--duration` defaults to 60 and is clamped to this |
| `BOWER_TAP_MAX_EVENTS` | `1000` | 1-10000 | Most frames per session. `--limit` defaults to 100 and is clamped to this |
| `BOWER_TAP_MAX_EVENT_BYTES` | `16384` | 1024-1048576 | Larger accepted events are shown as metadata only |
| `BOWER_TAP_PRODUCERS` | empty | producer ids | Tokens-file producers allowed to tap |

Invalid values stop start-up with the variable name in the message. Invalid request
parameters get 400 `tap-stage-invalid`, `tap-filter-invalid` or
`tap-parameter-invalid`. Tap settings are operational only, so they do not change the
configuration hash.

### Effect on ingest

Publishing to the tap never blocks or slows ingest, the queue or delivery:

- With no session open, publishing is one read of an empty list.
- With sessions open, each outcome is offered to each session's buffer of 64 frames.
  The offer never waits. A full buffer (slow client) drops the frame and counts it in
  `framesDropped`.
- The rate allowance is checked before the buffer, so a fast producer cannot fill a
  session faster than its cap.
- Frame JSON is built by the stream task, not on the ingest path.
- Delivery (`QueueDeliveryWorker` / `worker.rs`) is never involved.

Tests publish thousands of outcomes to a reader that never reads. They complete quickly
with exactly 64 frames buffered and every other frame counted as dropped or rate
limited.
`dotnet run --project tests/Bower.Benchmarks -c Release` also measures accepted-event
ingest with no tap, an idle tap and two stalled sessions.

## bower top

```bash
bower top --collector http://127.0.0.1:4319 [--interval 2] [--once] [--iterations N]
```

`top` polls `/v1/status` (send `BOWER_INGEST_TOKEN` when set) and prints rates from the
difference between two samples. `--once` takes two samples one interval apart, prints
one view and exits.

```
bower top  http://127.0.0.1:4319  status healthy  interval 2.0 s

Intake  attempts 57 (8.0/s)  capacity refusals 2  privacy alert refusals 0

STAGE          EVENTS      /S  ACCEPTED  REJECTED QUARANTINED   OTHER SUPPRESSED    QUEUED DUPLICATES
transform           1     0.5         0         0           1       0          0         0          0
validation          3     0.5         0         0           3       0          0         0          0
policy             51     6.5        44         7           0       0          1        40          3
total              55     7.5        44         7           4       0          1        40          3
...
SYSLOG             PROTOCOL    FRAMES      /S    QUEUED  REJECTED  DROPPED MALFORMED OVERSIZED  DENIED RECV ERRORS  CONNS
edge-firewall      udp            130    15.0        27         5        4         2         1       1           1      0

Queue     queued 3  retrying 1  uploading 2  dead letters 0  undelivered bytes 6144  oldest undelivered 11 s
Delivery  output azure-logs-ingestion  limit 4 (1-16)  in flight 1  latency 85 ms  throttles 1  server errors 0  timeouts 0
Tap       enabled  sessions 1/2  opened 3  refused 1  frames sent 120  dropped 4  rate limited 9
```

Sections:

- Stage table: each row sums the `pipeline.rows` of one stage. The `total` row is
  `pipeline.eventsIn`, so `top` reconciles exactly with the selection metrics described
  in [suppression, archive and source silence](suppression-archive-and-source-silence.md).
- Policy table: lists `pipeline.rows` one to one.
- Sources: from the new `activity` status field (busiest 50 sources by accepted event
  count).
- Syslog: when `BOWER_SYSLOG_CONFIG` is set, listener frames per second plus queued,
  rejected, dropped (UDP buffer), malformed, oversized, senders denied, receive errors
  and open connections.
- Queue and delivery: from the `queue` and `delivery` blocks.

Rates use integer tenths, so the C# and Rust CLIs print byte-identical text. The
shared fixtures are in `rust/crates/bower-cli/tests/fixtures/top`.

## Status fields added

`/v1/status` gains two additive, metadata-only fields in both runtimes:

- `activity`: `[{application, environment, lastSeenAt, eventCount}]`, at most 50.
- `tap`: `{enabled, activeSessions, maximumSessions, sessionsOpened, sessionsRefused,
  framesSent, framesDropped, framesRateLimited}`.

## Console pipeline view (planned)

The console pipeline view (issue #101) is designed to use these contracts:

- Counts come from the `/v1/status` fields above, relayed by the management API.
- Samples use the `bower.tap/v1` frame and the same caps, gated to `Bower.Operator` and
  above. Viewers see counts only.

That relay is not built yet. Today tap is reachable only from the collector's own
listener.
