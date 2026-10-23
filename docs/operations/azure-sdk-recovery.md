# Azure delivery and SDK recovery (AZ-01, AZ-03, AZ-04, DUR-01)

This change is validated with simulated HTTP responses and local queues only.
Ingestion acceptance is not Sentinel query verification. No live Azure permission,
upload, production replay or historical loss claim is made.

## Request ownership and failure classification

Both data planes construct their own JSON-array requests, at most 1,048,576
uncompressed UTF-8 bytes including brackets and commas. Default concurrency remains
four; each result belongs to the IDs in its own request. C# uses the supported
`LogsIngestionClient.UploadAsync(RequestContent, ...)` protocol overload, not the
SDK enumerable batching/callback overload. Rust has its own reordered-response
regression; it does not inherit the defective callback attribution algorithm.
Acknowledgements contain only `azure-logs-ingestion:accepted:owned-batches` and the
accepted IDs; arbitrary service request IDs and response bodies are not retained.

Malformed, mismatched and locally invalid payloads still fail individually.
An HTTP error alone does not prove record poison: 401/403, DCR/stream errors,
throttling, transport/token failures and 5xx become retryable `destination-*`
failures. Ambiguous 400 batches can be bisected, with at most 16 additional
requests per delivery call (SDK transport retries are separately bounded).
Valid siblings can progress; unresolved singletons stay pending. A future
server retry deadline suppresses immediate isolation. There is intentionally no
heuristic parsing of potentially sensitive service error bodies to condemn a
record. Persistent unresolved 400s need operator investigation.

## Durable destination circuit and persistence integration

The queue currently feeds one configured destination. A future retrying row with
`last_failure_code GLOB 'destination-*'` pauses **all new leases** from that queue,
including newly queued backlog. Its existing `next_attempt_at` survives process
restart. The worker uses the later of a 30-second destination cooldown and the
terminal response's Retry-After deadline (seconds, HTTP date, or Azure millisecond
headers). Healthy records do not exhaust poison budgets during an outage: the
same failure-settlement transaction refunds the lease's attempt increment.
The circuit opens again when the greatest outstanding deadline expires. Request
concurrency and queue capacity remain bounded; a full queue must apply intake
backpressure rather than delete pending records.

No new persisted columns or migration are needed. The integration is six SQL
lines in each queue implementation: a lease-selection `NOT EXISTS` guard and an
attempt refund restricted to retryable destination settlements. Persistence/lease
fencing changes must preserve those operations inside their existing transactions
and guards. `destination-` is a reserved internal code prefix, case-sensitive in
both runtimes; adapters must not use it for individual permanent failures.

Upgrade all workers using a queue together. Do not concurrently run an older
worker: older workers ignore this circuit and can still consume attempt budgets.
The on-disk schema stays readable, but rollback restores the older unsafe delivery
semantics; stop delivery and preserve the queue instead of rolling back an active
outage. These changes alone do not add a mixed-version runtime rejection fence;
that remains part of persistence migration coordination. Multi-destination routing
would require destination-keyed circuit storage before sharing a queue.

## SDK accounting and migration

`EmitResult.AcceptedForDelivery` means accepted into process memory, not durable
storage and not confirmed collector acceptance. The nonblocking channel now returns
`bounded-buffer-full` instead of silently discarding while reporting acceptance.
Applications needing critical audit durability must use a transactional outbox;
process crash recovery is not supplied by this in-memory SDK.

Resolve `IBowerTelemetryDiagnostics` from the service provider (registered by
`AddBower`) and read `DeliveryStatus`, a payload-free, consistent snapshot:

- `Accepted = Delivered + Failed + Pending`.
- `Rejected` counts calls never accepted (overflow, stopped or faulted sender).
- `Delivered` means collector HTTP acceptance, not Azure or Sentinel delivery.
- `Retries`, `LastFailureCode` and `SenderState` expose sender health without bodies.

The existing `IBowerTelemetry` interface is unchanged; diagnostics are an optional
additive interface, so custom implementations do not acquire a required member.
The built-in client defaults to three send attempts, a 250 ms retry delay and the
existing request timeout. Retry applies only to network/timeouts, 408, 429 and 5xx;
422 and other permanent collector rejections are explicitly failed. Options bound
attempts to 1–10, retry delay to 0–30 seconds, request timeout and shutdown flush to
at most one minute. Retries reuse the same event ID. An HTTP response lost after
collector acceptance can cause replay; collector idempotency remains necessary.

Fail-open continues accepting later events while exposing failures. Strict mode
closes the writer on terminal failure; later producers receive `sender-faulted`.
Shutdown closes intake, drains within the configured flush timeout, then cancels
and joins the sender before disposing transport resources. Every remaining
accepted item becomes explicitly failed with `shutdown-timeout`; no accepted
items remain pending when disposal returns. Poll/export status before application
exit; counters are in-memory and are not an audit ledger.

## Conditional historical reconciliation and controlled replay

The prior false acknowledgement was reproduced with simulated HTTP. Historical
production loss is **not established**. If an affected deployment existed:

1. Identify exact release, default/explicit concurrency, deployment and retention
   windows. Stop unsafe delivery/purge as appropriate under operator authority.
   Preserve consistent queue/WAL backups, source identities and retained evidence.
2. Compare available source event IDs with destination query results for the
   intended workspace/table and time window. Review mismatched acknowledgements;
   neither an old acknowledgement nor one successful canary proves completeness.
   Purged records may not be reconstructable. Do not infer missing IDs from counts.
3. Repair identity, exact-DCR permissions, endpoint and stream configuration.
   Pending destination failures resume automatically after the persisted deadline;
   no replay is needed for those rows. Verify a separately authorised canary by ID
   and expected sanitized fields at the destination.
4. Inventory old dead letters with metadata-only commands and select exact reviewed
   IDs under explicit operational authority. Stop queue users for the offline
   maintenance window and preserve the consistent backup before replay. Use the
   audited wrapper with a trusted, already compiled C# CLI apphost or Rust `bower`
   executable; do not substitute `dotnet run`, a shell command or an unreviewed
   executable. Pre-provision private local audit storage outside the checkout:

   ```sh
   bower queue dead-letters --database /path/to/bower.db --max 100
   mkdir -m 700 /path/to/replay-audit
   python3 tools/audited-replay/replay.py \
     --cli /opt/bower/bower \
     --database /path/to/bower.db \
     --audit-directory /path/to/replay-audit/CHG-123-batch-1 \
     --operator operator-17 --change-reference CHG-123 \
     --event REVIEWED_EVENT_ID
   ```

   Historical auth failures may have `azure-http-401`, `azure-http-403`, or
   `max-attempts-exceeded:` codes. The wrapper accepts exact IDs only; broad prefix
   replay can include unrelated poison events. Existing replay handles dead letters
   only; it cannot recover purged records or automatically replay incorrectly delivered rows.
   Source replay requires stable IDs, retained content and separate reconciliation.
5. Retain the wrapper's audit directory with the external approved change record:
   failure classification, before/after metadata counts, release and trusted binary
   installation details, queue identity, exact command and destination query evidence.
   Operator/change references are assertions, not authentication or an approval
   service. The bare CLI still prints a count without this external operator audit;
   invoke the wrapper for controlled replay. Neither a count nor CLI success proves
   destination delivery. Reconcile the selected IDs against queue metadata and
   destination queries before closing the change.

### Offline audit guarantees and recovery

`tools/audited-replay/replay.py` uses only Python 3's standard library on POSIX.
No cloud calls or direct queue SQL are made. It passes a shell-free argument array
containing only `queue replay`, the resolved database path, repeated exact `--event`
values and `--max` equal to the number of IDs. It accepts 1–100 distinct IDs, each
1–128 ASCII characters; operator and change-reference identifiers are required and
limited to 1–80 characters. Identifiers must start with an ASCII letter or digit;
remaining characters may also include `.`, `_`, `:`, `@` and `-`. Unsupported IDs
are refused, never rewritten. Supply non-secret identifiers only: no payloads,
credentials, URLs or free-form investigation notes. Timeout defaults to 60 seconds
and may be set with `--timeout-seconds` to 1–300 seconds.

The audit parent must already exist, be owned by the current user and have no
group/other permission bits. Each invocation requires a **new** audit directory
(0700). Files are 0600. `intent.json` records the operator, change reference, exact
IDs, bound, timeout, UTC timestamp and operation UUID. The command template,
SHA-256 hashes of resolved CLI/database paths, CLI executable hash and database
device/inode identify the local operation without retaining filesystem paths.
Keep the path mapping and release details in the access-controlled change record;
the apphost hash alone does not identify the C# managed assemblies. Installations
and queue paths must remain stable and access-controlled for the maintenance window.

The wrapper fsyncs the new directory's parent, writes/fsyncs intent, atomically
publishes it without overwrite and fsyncs the audit directory **before launching
the CLI**. An audit failure at any of these steps prevents invocation. After the
CLI ends, `outcome.json` is published with the same durability steps. Records
contain only fixed outcome classifications and the exit code, never CLI stdout,
stderr, exception details or raw events. The wrapper discards both CLI output
streams, including the CLI's count. `cli-exit-zero` means only that the command
exited zero: fewer or none of the selected IDs may have been dead-lettered.
Queue effects remain unverified; `delivery_verified` is always false.

Wrapper exit codes: **0** means zero CLI exit plus saved outcome; **1** means a
saved nonzero/timeout/interrupted/launch-failed outcome; **2** means refused input,
local validation or audit failure. Any nonzero CLI outcome is conservatively
ambiguous about queue effects. Timeout kills/waits for the direct CLI process;
abrupt wrapper termination can leave its child running.

After a crash, missing/invalid outcome, leftover `.pending` file, or any reported
outcome audit failure, preserve the entire directory and treat queue effects as
**ambiguous**, even if a complete-looking outcome file exists. A failure to fsync
may leave visible but not durable data. Never delete evidence to retry. The tool
refuses every existing audit directory and has no automatic retry/resume path.
Ensure any surviving CLI has stopped, then reconcile selected IDs against queue
state and destination evidence. Only separately reviewed remaining IDs may enter
a new, explicitly approved batch with a fresh audit directory/change reference.
The wrapper cannot prevent a privileged operator from bypassing it or choosing a
different directory; it is not an exactly-once queue transaction or a tamper-proof
audit service. Store evidence on reliable local storage supporting fsync and hard
links, retain it under operator policy, and protect it from modification/deletion.

Validation: `python3 -B -m unittest discover -s tools/audited-replay -v` covers
success, command/launch failure, every pre-launch sync boundary, post-command audit
failure, input bounds/injection, timeout and abrupt wrapper death using isolated
synthetic CLI fixtures. No production replay or live destination check is involved.

No recovery or replay operation was performed as part of this implementation.
