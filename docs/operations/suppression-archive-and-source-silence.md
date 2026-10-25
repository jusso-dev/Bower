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
  Duplicates never consume allowance. Counts survive restarts.
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
- `/health` becomes `degraded` while any expected source is quiet. `/v1/status` lists
  each source as `active`, `silent` or `never-seen`. Heartbeats report each as an
  `application` source, so silent ones appear in the console's fleet exceptions.
- A source never seen gets its allowance from collector start-up before it is
  reported. Last-seen times are saved every minute; after a crash up to a minute of
  activity is lost, which can only make a source look quieter, never healthier.
- Offline: `bower sources check --expectations sources.json --database queue.db`
  exits 3 when any source is quiet (no start-up grace).

## Archive and replay

Set `BOWER_ARCHIVE_PATH` to keep every stored event beyond queue retention, for
example for a records-authority period such as AFDA Express v2.

- Every minute the collector writes `segment-<first sequence>.jsonl.gz` files of up to
  10,000 events, each with a manifest holding the file digest, sequence range and the
  queue ledger chain hash at both ends. Files are flushed and renamed into place; a
  segment left without a manifest by a crash is rewritten.
- The archive continues the queue ledger chain, so it verifies without the queue:

  ```bash
  bower archive verify --archive /mnt/bower-archive --anchor 48213:<ledger head hash>
  ```

  Use a ledger head witnessed by the management console as the anchor. Without one,
  verification proves the archive is internally consistent from its first segment;
  only an anchor proves nothing was cut from the start or rewritten wholesale.
- While an archive is configured, retention purges only archived events. An archive
  started on an existing queue begins at the oldest event still stored.
- Bower never deletes or rewrites archive segments. Put the directory on write-once
  storage and manage retention there.
- `bower archive replay --archive DIR --collector-url URL [--from ISO] [--to ISO]
  [--event-type TYPE]... [--dry-run]` verifies the archive, then posts each selected
  event through a collector's full intake, labelled `bowerReplay: archive`, with
  `BOWER_INGEST_TOKEN`. Replay into a collector with its own queue; the original
  queue reports replayed events as duplicates. Events older than five years fail
  `timeGenerated` validation.
- `bower archive create --archive DIR --database queue.db` archives a stopped
  collector's queue by hand. Never run it against an archive a collector is writing.
