# Suppression, selection metrics, source silence and the archive

Four collector capabilities for running Bower at volume and proving coverage. All are
off unless configured, keep the queue at schema version 5 (new tables are additive)
and behave the same in the C# and Rust collectors.

## Suppression

A policy can cap a noisy event type per key without losing the count:

```yaml
decision:
  action: accept
  minimumValueScore: 50
  neverSample: false
suppression:
  keyFields: [source.ipAddress]   # 1–5 string paths or labels.<key>
  windowSeconds: 60               # 1–86400, windows aligned to the Unix epoch
  allowPerWindow: 20              # 1–100000
```

- The first `allowPerWindow` events per key in each window are queued as usual.
  Later ones are counted in the queue database inside the same transaction as the
  duplicate check, and the collector answers `"suppressed": true` (HTTP 202).
  Duplicates never consume allowance. Counts survive restarts. When the queue
  database is at its physical storage limit a suppressible event is refused with
  the same capacity backpressure as any other event and is not counted.
- Within 5 seconds of a window ending, one `telemetry_aggregation_summary` event
  (action `telemetry.suppressed`) is queued with the suppressed and admitted counts,
  the key fields and their redacted values, the window bounds and the first and last
  suppressed times. Its id derives from the window, so it is never duplicated.
- The summary goes through policy like any event. A bundle that suppresses must also
  accept `telemetry_aggregation_summary`, or it does not load; if the summary is
  later refused (for example its policy was changed to require a field it lacks),
  windows stay open and the collector logs the failure instead of dropping counts.
  The same applies when the queue is at capacity: closing is retried every 5 seconds
  with a warning (`EventId 1302`) until there is room. Alert on that warning.
  Example policies: [`examples/policies/suppression`](../../examples/policies/suppression).
- `neverSample` policies, non-accepting policies and the summary type itself cannot
  suppress. Choose key fields that keep distinct actors in distinct windows: a key
  of `eventType` alone lets one noisy client hide another.
- `bower policy test` and `bower policy diff` report the policy decision only;
  suppression is stateful and applies when an event is queued. The Azure Functions
  collector has no durable queue and never suppresses.

## Population diff

Run every sample through two policy directories before rollout:

```bash
bower policy diff --baseline policies/current --candidate policies/proposed \
  samples/*.json --fail-on-change
```

Output lists each event whose decision or deciding policy changes, with both bundle
hashes. Metadata only; exit 3 on any change when `--fail-on-change` is set. Attach the
output to the policy change, as `AGENTS.md` requires for policy content changes.

## Selection metrics

`GET /v1/status` (token protected) includes `pipeline`: events and bytes received,
queued, duplicated and suppressed since start, per stage (`redaction`, `schema`,
`validation`, `policy`), policy id and decision. No payload content. Queued bytes
include Bower's decision context.

## Intake metrics

`GET /v1/status` also includes `intake`, so a full queue is distinguishable from an
idle collector. Same shape in the C# and Rust collectors:

```json
"intake": {"observedSince": "2026-10-26T01:00:00+00:00",
  "attemptedRequests": 42, "attemptedBytes": 51234,
  "capacityRefusals": 5, "capacityRefusedBytes": 6100,
  "privacyAlertRefusals": 1, "privacyAlertRefusedBytes": 1300,
  "lastRefusalAt": "2026-10-26T01:20:31.5+00:00", "lastRefusalReason": "queue-capacity"}
```

- Boundary: one attempt per candidate submitted to processing on `/v1/events` or a
  signed pack parser endpoint, after authentication, producer authorisation and (for
  packs) parsing. Rate-limited, unauthorised, oversized or unparseable requests are not
  attempts. Bytes are the UTF-8 candidate JSON, as for `pipeline.bytesIn`.
- Both refusal kinds return HTTP 503 (`Collector queue is at capacity; retry later.`).
  They differ in what was committed:
  - `capacityRefusals` (reason `queue-capacity`): the queue refused the event itself,
    whichever admission branch refused it. Nothing was committed for the attempt: no
    queue row, no `pipeline` count, no source activity, no evidence.
  - `privacyAlertRefusals` (reason `privacy-alert-capacity`): the event was decided
    first and its outcome is already in `pipeline` (and, if accepted, its row is queued
    and its source marked seen). Only the privacy alert for a high-risk detection was
    refused. This applies to accepted, quarantined (invalid) and rejected events.
- A retry is a new attempt. After a `queue-capacity` refusal it counts in `pipeline`
  once admitted. After a `privacy-alert-capacity` refusal of an accepted event, the
  retry is reported as a duplicate (HTTP 200) and emits the alert; alert ids are stable,
  so retries never create a second alert.
- `lastRefusalReason` is one of the two bounded codes above, matching `lastRefusalAt`
  (the latest refusal); both are `null` before any refusal.
- Counters are process lifetime: they start at zero at `observedSince` (collector start)
  and reset only on restart. There is no reset endpoint. Updates are lock free and
  safe under concurrent intake: the time and reason are written before a refusal is
  counted, so a snapshot never shows a refusal without them. Metadata only: no
  payloads, event ids, credentials or request text.

## Source silence

Set `BOWER_SOURCE_EXPECTATIONS` to a JSON file
([schema](../../schemas/configuration/source-expectations.schema.json),
[example](../../examples/source-expectations.json)):

```json
{"apiVersion": "bower.security/v1", "kind": "SourceExpectations",
 "sources": [{"application": "FinanceApi", "environment": "production", "maximumSilenceMinutes": 15}]}
```

- A source is seen when an event from it is queued, deduplicated or suppressed.
  Rejected and quarantined events do not count: they never reach the SIEM.
- `/health` becomes `degraded` while any expected source is overdue. `/v1/status`
  lists each source as `active` (seen within its allowance), `pending` (not seen yet,
  still inside its first allowance), `silent` or `never-seen` (overdue). Heartbeats
  report `active` sources as `healthy` and every other state by name, so the console
  counts pending and quiet sources as not healthy. A pending source is never reported
  as healthy: there is no evidence from it yet.
- A source never seen gets its allowance from when the collector first began
  expecting it. That monitoring start is stored per source in the queue database
  (`source_monitoring`), so restarting the collector, however often, cannot extend
  the deadline. A source added to the expectations file gets its own allowance from
  the next start; existing sources keep theirs. A source removed from the file is
  forgotten at the next start, and listing it again later starts a fresh allowance.
  Starting without `BOWER_SOURCE_EXPECTATIONS` forgets every monitoring start. Each
  start that forgets sources logs a warning (`EventId 1321`) with the count and the
  `application/environment` ids, so a reset is auditable.
- A monitoring start recorded while the host clock ran ahead (for example before time
  synchronisation) is replaced by the earlier time at the next start. A start only
  ever moves earlier, which can shorten a deadline but never extend it.
- Last-seen times are saved every minute; after a crash up to a minute of activity
  is lost, which can only make a source look quieter, never healthier.
- Offline: `bower sources check --expectations sources.json --database queue.db`
  exits 3 when any source is overdue. It reads, never writes, the collector's
  monitoring starts, so a source the collector reports as `pending` is `pending` here
  too. A source the collector has never monitored gets no grace and, never seen, is
  reported as `never-seen` at once.

## Archive and replay

Set `BOWER_ARCHIVE_PATH` to keep every stored event beyond queue retention, for
example for a records-authority period such as AFDA Express v2.

- Every minute the collector writes `segment-<first sequence>.jsonl.gz` files of up to
  10,000 events, each with a manifest holding the file digest, sequence range and the
  queue ledger chain hash at both ends. A segment is committed once its manifest is
  published. Files are written under unique temporary names, flushed and moved into
  place without replacing an existing file, and the directory is synced after each
  move; a segment left without a manifest by a crash is an uncommitted orphan and is
  rewritten.
- A writer extends only its own queue's chain: if the queue ledger hash at the archive
  head differs from the manifest (another collector's archive, a queue restored from an
  older backup) or the queue has not reached that sequence, the run fails with
  `lineage-mismatch` and writes nothing.
- Every writer (the collector job and `bower archive create`, in either runtime) holds
  an exclusive OS lock on `archive.lock` in the archive directory for its whole run,
  taken before it reads the archive head. A second writer fails at once with an I/O
  error and writes nothing. Orphan segments and abandoned `segment-*.tmp` files (up to
  1,000 per run) are removed only by the lock owner. The lock is `flock` on Unix, so
  keep the archive on a local or lock-capable file system. Where the lock is not
  enforced (an unsupported file system, or `DOTNET_SYSTEM_IO_DISABLEFILELOCKING` set)
  the writer refuses to run rather than write unlocked.
- The archive continues the queue ledger chain, so it verifies without the queue:

  ```bash
  bower archive verify --archive /mnt/bower-archive --anchor 48213:<ledger head hash>
  ```

  Use a ledger head witnessed by the management console as the anchor. Without one,
  verification proves the archive is internally consistent from its first segment;
  only an anchor proves nothing was cut from the start or rewritten wholesale.
- While an archive is configured, retention purges acknowledged events only up to
  verified archive coverage of this queue. Before each run it checks that every
  segment exists and matches its manifest digest and ledger chain, that the archive
  starts at or below the oldest event still stored, and that the archived chain hash
  equals the queue ledger hash at the highest boundary both record (so an archive
  written by another queue, even with overlapping sequence numbers, is refused).
  Otherwise retention purges nothing and logs event 1202 with a reason code
  (`segment-missing`, `segment-digest-mismatch`, `archive-starts-above-retained`,
  `lineage-mismatch`, `manifest-invalid` and so on) and sequence numbers only.
  Undelivered, retrying and dead-lettered events are never purged. Segments already
  verified are not re-read while their manifest, size and write time are unchanged; any
  change triggers full verification. Before each purge batch, the segments holding the
  events about to be removed are re-hashed regardless, so silent corruption or a
  timestamp-preserving restore stops the purge. An archive started on an existing queue begins at
  the oldest event still stored.
- Bower never deletes or rewrites committed archive segments. Put the directory on
  write-once storage and manage retention there.
- `bower archive replay --archive DIR --collector-url URL [--from ISO] [--to ISO]
  [--event-type TYPE]... [--dry-run]` verifies the archive, then posts each selected
  event through a collector's full intake, labelled `bowerReplay: archive`, with
  `BOWER_INGEST_TOKEN`. Replay into a collector with its own queue; the original
  queue reports replayed events as duplicates. Events older than five years fail
  `timeGenerated` validation.
- `bower archive create --archive DIR --database queue.db` archives a queue by hand.
  While a collector is writing the same archive it fails on the writer lock instead
  of racing it; rerun it later.
