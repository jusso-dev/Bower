# Independent Windows destination identity proof

Use this after [WEC setup and native qualification](WEC-SETUP.md). A passed
generator phase proves native Security events, forwarded events and exact
durable-queue identities agree. It does **not** prove Sentinel delivery. The
independent `query-wec.py` helper performs that remaining comparison without
retrieving event payloads or using the ingestion application's identity.

## 1. Preserve the original exported evidence

For each completed phase, download these four files from the owned run's
`results/qualification/<RunId>/windows/<phase>/` prefix into a local evidence
directory:

```text
<phase>.json
<phase>-native.ids
<phase>-forwarded.ids
<phase>-queue.ids
```

Use the ownership-checked export/download procedure for the current run. Keep
original bytes: Windows writes CRLF-terminated ASCII ID files and may write a
UTF-8 BOM on the JSON report. Do not open/save them in an editor or normalize
line endings. File-byte SHA-256 hashes in the phase report bind all three ID
files. The verifier accepts LF or CRLF, but a changed file fails its original
byte-hash check. Its separate **canonical set hash** uses sorted IDs, LF
separators and no final newline; that hash is intentionally different from a
Windows file-byte hash.

The helper requires all three exact identity sets to match, no repeated IDs,
the expected native count, valid source/forwarded counters, a completed generator
at the requested 10/sec or 100/sec rate and `nativeVerified=true`. It independently
checks the underlying numbers and file hashes; changing the boolean alone cannot
make a failed phase pass. There is no counts-only fallback when queue IDs are
missing. Preserve failed inputs and diagnose them before destination validation.

The current native generator uses one `LOGON_NEW_CREDENTIALS` session per phase
and one stable synthetic invalid credential pair, supplied explicitly to every
SMB attempt. Dedicated worker threads impersonate only that owned session;
the last worker cleans up its IPC connection after the other attempts finish.
The verifier requires successful initialization and zero session setup,
impersonation, revert and handle-close failures. `startedAt`/`endedAt` must match
the generator's actual attempt interval, excluding session preparation. It also
checks the observed native event rate from the first/last native timestamps;
successful scheduling alone cannot satisfy the traffic envelope.

Windows can timestamp an audit event just after its authentication attempt
returns. The phase therefore records `eventWindowEndedAt` exactly five seconds
after `endedAt` and `eventWindowPaddingSeconds=5`. Native and destination event
selection use this fixed, exclusive upper bound. The verifier checks that native
extrema lie inside it and queries the same window, while measuring generator rate
over the unpadded attempt interval. Missing, changed or unbounded padding fails;
do not retrofit new timing fields into an old report. Preserve earlier attempts
as baseline evidence and execute a new phase with the corrected generator.

These are Bower's generated `winevt-` root event identities. `WindowsEventRecord`
hashes the original XML channel, computer, source record number and UTC timestamp
truncated to microseconds, separated by U+001F, then uses the first 32 lowercase
SHA-256 hex characters. The signed Windows parser maps this generated `id`
directly to the envelope EventId. Native and forwarded exports calculate that
same identity; the receiving WEC bookmark and any user-provided parser correlation
field are not substitute event IDs. Queue and Sentinel comparisons use the actual
root EventId, not a secondary parser field.

## 2. Use the isolated verifier identity

The private Azure state directory must already contain:

- `azure-state.json`, with the workspace ID/resource scope and the separate
  `identities.verifier` application metadata.
- `verifier-identity.pem`, readable only by its owner, at the exact path recorded
  in that state.

The helper reuses `query-firewall.py`'s reviewed transport. It validates subscription
`945092a0-2500-4b25-85a4-99f1c3135906`, tenant
`f4f33fb1-b681-40d1-a854-6f888d45b891`, workspace scope and verifier identity.
It signs the verifier in through an owner-only `azure-cli-verifier` cache under
the supplied state directory, checks the authenticated principal, and performs a
TLS-verified Logs query. It does not use or modify the normal `~/.azure` cache.
Redirects, pagination, partial/error responses, oversized bodies and unexpected
schemas fail closed. The transport caps responses at 64 MiB and the verifier
caps aggregate identities at 200,000.

Use paths only in commands. Never paste PEM contents, access tokens or state
contents into SSM text, terminal output, screenshots or Git. Remove the isolated
credential cache and private identity material during final campaign cleanup.

## 3. Query after delivery has had time to complete

After the phase finishes, wait for normal delivery—or fault removal and queue
drain for the one-hour outage—then run:

```bash
python3 lab/aws/monitoring/query-wec.py \
  --phase <evidence>/<phase>.json \
  --native <evidence>/<phase>-native.ids \
  --forwarded <evidence>/<phase>-forwarded.ids \
  --queue <evidence>/<phase>-queue.ids \
  --azure-state-dir <private-azure-state-directory> \
  --output <evidence>/<phase>-sentinel-verification-01.json
```

The output directory must exist. Reports are created exclusively with private
permissions; existing files are never overwritten. If ingestion is still delayed,
keep the failed report, wait, and run again with a new numbered output filename.
No automatic retries silently replace an earlier result.

The query selects `BowerSecurity_CL`, the exact `<RunId>-windows` collector ID,
`windows-security` application, `production` application environment and
`authentication_failure` event type within the phase's bounded native-event window.
`production` is the signed Windows pack's application environment; the collector's
own lab setting is separate. The destination query does **not** restrict results
to an expected-ID `in` list, because that would hide extra destination events.
Periodic collector health records are outside this authentication population.

For each EventId it requests only copy count and first/last generated/ingested
timestamps. The query uses an explicit ingestion cutoff recorded in the report,
so the result states what Sentinel contained at that time. Its bounded extra
row detects excessive results. Unexpected IDs, duplicate aggregate rows,
out-of-window timestamps or malformed identities cannot be silently discarded.

## 4. Interpret and retain the result

Exit statuses are:

| Exit | Meaning |
|---:|---|
| 0 | Exact native/WEC/queue/Sentinel identities agree, with no extra or duplicate destination rows. |
| 1 | A complete destination query ran but identities are missing, extra or duplicated; a failed report is retained. |
| 2 | Invalid/missing evidence, credential/transport error, incomplete query response or another validation failure; no passing evidence is emitted. |

`strictPass` and `destinationQueryVerified` require zero missing IDs, zero extra
IDs and zero duplicate rows. A complete response containing no events is a valid
query result and a failed delivery check. `identityComplete=true` with duplicates
is also a failure. Source mismatch prevents the live query entirely.

The report retains source-file and phase-file hashes, canonical expected/actual/
missing/extra/duplicate identity-set hashes, counts, generation/ingestion extrema,
workspace/verifier IDs, the exact metadata-only query and its hash, query cutoff
and completion time, and both verifier script hashes. `destinationIdentityRows`
contains the bounded aggregate identity/timestamp rows for independent audit.
Console output omits that potentially large row array; no event bodies, actor
names, native XML, certificates or bearer tokens are returned or stored in the
report.

Preserve each report alongside the original phase/ID files and the run's setup
artifact/provenance hashes. Capture screenshots of the summary and independent
destination result with UTC timestamps. This proves only the named phase's
identity reconciliation at its cutoff. The full one-hour outage duration,
buffered queue state, restoration, health recovery, restart/upgrade behavior and
final AWS/Azure absence checks require their own evidence; this helper never
marks the whole campaign production-qualified.

## Local checks

```bash
python3 -m unittest discover -s lab/aws/tests -p test_wec_reconciliation.py -v
```

Tests exercise exact sets, Windows line endings and file hashes, source/rate
failures, missing/extra/duplicate destination records, query scope, malformed and
partial responses, bounds, and report creation. All live queries are mocked.
Passing these tests is not evidence that Sentinel received the live campaign.

The verifier also requires zero SMB session cleanup failures. Cleanup result
codes may contain only success (`0`) or no existing connection (`2250`). The
current per-phase profile must report `executionKind=native-windows`, exactly
one cleanup result, no active
attempts or workers at return, and the explicit stable-credential mode. Older
per-worker evidence allows at most 64 cleanup results. Initialization failure
reasons must be empty and SMB credential-conflict code `1219` is rejected.
These guards prevent successful event generation from masking failed isolation
cleanup; they do not inspect or retain credentials.


## Diagnose native generation before another load run

Use a fresh phase name and the existing owned Windows host. The `diagnostic`
action forces exactly **one** SMB attempt and one worker, regardless of rate or
duration environment values. It never sets `nativeVerified` or delivery proof.
It queries actual Security/ForwardedEvents and queue identities for that one
attempt; `diagnosticNativeMatched=true` means one distinct valid network logon
reached the local queue, not that a 10/100-event-per-second workload qualified.

```bash
python3 lab/aws/monitoring/run.py Windows lab/aws/monitoring/wec-qualification.ps1 \
  --state <owned-state.json> --timeout 300 \
  --env BOWER_WEC_ACTION=diagnostic --env BOWER_WEC_PHASE=diag-phase-explicit-01 \
  --env BOWER_WEC_PROFILE=phase-explicit
```

The default `phase-explicit` profile creates one new network logon session and
uses the same synthetic nonexistent account and random invalid password for all
calls in that phase. Credentials remain in process memory and never enter SSM
arguments, reports or files. This tests whether changing passwords or implicit
credentials caused earlier SMB collisions/stalls; it does not assume that
repeated SMB failures each produced a Security event. Exact native counts,
network logon type/IP fields, source rates and identity reconciliation still
decide qualification.

For a separate one-event comparison only, select
`BOWER_WEC_PROFILE=worker-null` with a different diagnostic phase name. That uses
the earlier per-worker isolated token with implicit credentials. It is rejected
for `BOWER_WEC_ACTION=phase`; it cannot silently become the load profile.
Neither profile disconnects connections from the caller's logon session. The
existing loopback-session and nonexistent-account guards remain enabled.

Immediately after the generator returns, before timestamp parsing or drain
checks, the harness creates and flushes `<phase>-generator.json` (maximum
32 KiB, never overwritten) and emits the same JSON with
`recordType="generator-checkpoint"`. Preserve this separately from the eventual
`<phase>.json` result. Failure output also includes the generator summary. It
contains attempt/result-code accounting, initialization reasons, cleanup
counters, active attempts and remaining workers; it contains no exception text,
password, token or raw event. A timestamp-parse, worker-drain or later channel
failure cannot erase the already written generator checkpoint. If execution is
killed before the generator returns, no completed checkpoint is claimed; retain
the SSM failure metadata.

`drained=false`, `activeAtReturn>0` or `workersRemainingAtReturn>0` means work
was still pending at the bounded drain deadline. A partial checkpoint is not a
successful diagnostic. Preserve it and diagnose before another phase. Do not
clear unrelated SMB sessions or weaken account/session guards to force a rerun.

After one-event native proof succeeds, use fresh phase names for 10/s then 100/s:

```bash
python3 lab/aws/monitoring/run.py Windows lab/aws/monitoring/wec-qualification.ps1 \
  --state <owned-state.json> --timeout 600 \
  --env BOWER_WEC_ACTION=phase --env BOWER_WEC_PHASE=stable-steady-01 \
  --env BOWER_WEC_PROFILE=phase-explicit --env BOWER_WEC_RATE=10 --env BOWER_WEC_SECONDS=10

python3 lab/aws/monitoring/run.py Windows lab/aws/monitoring/wec-qualification.ps1 \
  --state <owned-state.json> --timeout 600 \
  --env BOWER_WEC_ACTION=phase --env BOWER_WEC_PHASE=stable-burst-01 \
  --env BOWER_WEC_PROFILE=process-explicit --env BOWER_WEC_RATE=100 --env BOWER_WEC_SECONDS=10
```

Require every actual native identity, matching forwarded and queue identities,
and the unchanged 99% attempt/native-rate thresholds. Run the independent
Sentinel verifier afterward. A successful WNet return-code count or a fast
cached error alone never qualifies either workload. Retain the earlier failed
per-call-password and implicit-token runs as failed evidence.

### Exporting an incomplete generator checkpoint

`export-wec-evidence.ps1` accepts the immutable `<phase>-generator.json` checkpoint
(up to 32 KiB) when generation failed before the phase report or ID files exist.
It uploads only the fixed available metadata files and emits the version 1
`wec-evidence-export` summary with `partialEvidence=true`, the exact missing file
list and qualification flags false. See [WEC-SETUP.md](WEC-SETUP.md) for the full
summary schema. This is preservation of failed evidence: neither a checkpoint
nor an export summary is an acceptable `--phase` input to `query-wec.py`. The
verifier continues to require successful native proof and all three exact source
ID files before issuing any independent destination claim.


## Separate connection warm-up from the measured workload

Every current `phase-explicit` load phase first submits exactly 100 preparatory
SMB attempts at 10/s in the same owned logon session. Preparation has a total
30-second verification budget. It then waits for the fixed five-second audit
window, reconciles the actual warm-up Security/ForwardedEvents/queue identity
sets and source counters, and captures the measured source baseline **after**
those events have drained. No measured calls are scheduled if warm-up or its
reconciliation fails. Diagnostic one-event mode does not run warm-up.

The preparatory attempts and resulting events are retained separately as:

```text
<phase>-warmup.json
<phase>-warmup-native.ids
<phase>-warmup-forwarded.ids
<phase>-warmup-queue.ids
```

These are metadata and exact synthetic IDs only. Preserve the separate files and
their hashes alongside the ordinary phase files; they must not be merged into
the measured identity sets. The generator checkpoint also embeds warm-up attempt
accounting, actual native/forwarded/queue counts, identity-file hashes and the
completion timestamp. If initialization or a blocked native call prevents warm-up
completion, retain the failed generator checkpoint; no successful warm-up is
claimed. An uninterruptible native call may outlive the verification budget; that
is a failed phase, never permission to extend its qualification window.

Warm-up exists because the observed failed 600-attempt run produced only 567
native events: all 33 missing events occurred in its first seven seconds, with
exactly ten native events per second thereafter and no Windows audit-loss/full
records. SMB call completion is not proof of an independent server audit event.
The warm-up report records that distinction honestly; it makes no throughput or
delivery qualification claim. It requires identical actual native, forwarded
and queued warm-up sets before continuing.

The measured clock starts only after warm-up reconciliation. A measured 600-attempt
10/s phase still requires exactly 600 distinct native events, the same 600 WEC and
queue identities, unchanged error counters, at least 99% of the requested native
rate, and independent Sentinel reconciliation. The 100/s threshold is unchanged.
The verifier checks that the warm-up window and its completion precede the
measured start, and rejects failed, overlapping, incomplete or simulated warm-up
metadata. Retain the earlier failed steady phase and its native histogram as
failed evidence; never relabel its 567 events as a passing 600-event run.


### Isolated workers for concurrent native generation

`BOWER_WEC_PROFILE=worker-explicit` gives each of the at most four workers its own
NEW_CREDENTIALS logon session. Each worker explicitly supplies the phase's stable
synthetic invalid credentials and submits serial connection attempts within its
own session. Round-robin assignment warms every owned session before measurement;
the existing 100 calls at 10/sec and 30-second warm-up/drain bound remain unchanged.
The measured count/rate and exact native → forwarded → queue identity gates also
remain unchanged. Every owned session is cancelled under its own impersonation,
then reverted and closed. Cleanup waits for every worker to finish its connection
attempts and is serialized, preventing cancellation from overlapping live attempts
or another cancellation. Evidence must account for one successful/absent-connection
cleanup result per worker. The shared-session `phase-explicit` profile remains
available for comparison and previously captured evidence.

Use a fresh phase name for the isolated-worker probe (100/sec for one second),
then a fresh 6,000-event burst only after the probe passes native count/rate
reconciliation. If the one-second probe preserves every identity but narrowly
misses the rate due to fixed endpoint latency, retain that failure and use a
fresh ten-second/1,000-event capacity probe at the same 100/sec and 99% rate
gates before the full burst. Never relabel the failed short probe as a pass. API return code 1326 alone never proves a native Security event;
shared-session concurrent calls can return that code without a corresponding
4625. Preserve these failed runs as generator failures, without claiming Bower
loss or weakening source evidence requirements.

For `worker-explicit`, the measured interval ends at the final authentication
attempt (or the requested interval end, whichever is later); serialized cleanup
is excluded from throughput timing. Cleanup still must finish within its bounded
wait and all cleanup results must pass before the phase can qualify. Native
Security timestamps independently prove the source event rate.

The isolated-worker profile caps concurrency at four owned sessions. Earlier
64-session native probes encountered RPC busy/failed return codes and incomplete
attempts, including with all cleanup held behind a completion barrier. Reducing
session count changes load-generator implementation only; the exact native event
counts and 100/sec burst requirement are unchanged. Failed probe checkpoints
remain failed evidence.


### Separate RPC client processes

`BOWER_WEC_PROFILE=process-explicit` retains the four-worker scheduler, native
SMB authentication, exact identity checks and rate gates, but gives each worker
a separate PowerShell process and NEW_CREDENTIALS session. This investigates RPC
binding failures observed with multiple impersonated threads, including after a
host reboot. It is a generator implementation alternative, not evidence of a
qualified rate until the native and destination checks pass.

Each child compiles the same reviewed native wrapper, receives only synthetic
invalid credentials over redirected stdin, and accepts a fixed protocol:
connect, cancel, revert and close. Responses are numeric error codes only.
Credentials never appear in command arguments or the generated child script.
Pipe responses are limited to 16 characters and a total 30-second deadline.
Stderr is discarded through a fixed 1-KiB buffer, with a 4-KiB total cap; overflow
terminates that owned child without logging its output. Start/registration and
disposal are synchronized so late creators cannot escape the owned child set.
The parent owns each child Process object, waits for successful handle cleanup
and process exit, and terminates only those owned children on bounded failure.
A forced termination cannot qualify the phase. The generated phase-worker script
contains code only, is bounded to 128 KiB, and remains on the temporary lab host
until host teardown. Its adjacent `.sha256` sidecar records the exact script hash.
The evidence isolation enum is `per-process-logon-new-credentials`; all four
owned cleanups, native event counts/rates and destination identities remain
mandatory. Local child-protocol tests inject a fake native class and are marked
simulated; Windows CI additionally exercises the parent process transport with
that same fake class, without making an SMB request. The pipe carries only Base64
setup, fixed commands and numeric replies. The child explicitly detects a
byte-order mark because Windows PowerShell 5.1 can emit one while constructing
the inherited-encoding pipe writer. Fixtures cover UTF-8 and UTF-16 parent
encodings, including the real parent transport with a fake native backend.

## Run the one-hour Windows destination outage

Use this sequence only after the steady and 6,000-event burst have passed native
and Sentinel identity reconciliation on the same pinned collector candidate.
The fault blocks outbound TCP 443 only for
`C:\Program Files\Bower\Bower.Collector.exe`; SSM and the native SMB generator
remain reachable. The test is an isolated lab qualification, not a production
firewall change.

### Freeze the plan and establish the baseline

Record the run ID, exact instance ID and tags, candidate executable/SQLite hashes,
boot identity, helper hashes, expected **36,000 events at 10/sec for 3,600 seconds**,
99% minimum observed rate, warm-up exclusion, and destination-query requirement.
Verify the actual enabled instance-expiry schedule leaves enough time for the
whole test, recovery, evidence download and teardown; a cached local state file
can contain an earlier expiry. Use a fresh phase/sampler scope. Hash the complete
plan before dispatch and pass that hash to the sampler.

Use a 4,500-second (75-minute) resource series to cover baseline, the hour of
buffering and recovery. Its expected full series is 301 samples at 15-second
intervals. Start it before the firewall fault:

```bash
state=/private/tmp/bower-validation/state.json
phase=wec-outage-01
plan_sha256=REPLACE_WITH_THE_FROZEN_PLAN_SHA256

python3 lab/aws/monitoring/run.py Windows lab/aws/monitoring/sample-resources-windows.ps1 \
  --state "$state" --timeout 90 \
  --env BOWER_SAMPLE_ACTION=start --env "BOWER_SAMPLE_SCOPE=$phase" \
  --env "BOWER_PLAN_SHA256=$plan_sha256" --env BOWER_SAMPLE_SECONDS=4500

python3 lab/aws/monitoring/run.py Windows lab/aws/monitoring/observe-wec-outage.ps1 \
  --state "$state" --timeout 60 --env "BOWER_WEC_PHASE=$phase" \
  > before-outage.json
```

Require a healthy source, no pending/dead-lettered events, no existing outage
rule, and the intended boot/candidate before continuing. The observer is read
only and projects counters and fixed failure metadata; it never reads queue
payloads, emits credentials or changes a firewall rule. Its restore-readiness
flag is an operational decision aid, not delivery or production qualification.

### Apply the guarded fault, then generate the workload

```bash
python3 lab/aws/monitoring/run.py Windows lab/aws/monitoring/wec-destination-outage.ps1 \
  --state "$state" --timeout 120 --env BOWER_WEC_OUTAGE_ACTION=on \
  > outage-on.json

python3 lab/aws/monitoring/run.py Windows lab/aws/monitoring/wec-qualification.ps1 \
  --state "$state" --timeout 4800 --no-wait \
  --env BOWER_WEC_ACTION=phase --env "BOWER_WEC_PHASE=$phase" \
  --env BOWER_WEC_PROFILE=process-explicit \
  --env BOWER_WEC_RATE=10 --env BOWER_WEC_SECONDS=3600 \
  > generator-dispatch.json
```

The first command registers a SYSTEM restoration task before applying the
app-scoped rule. That independent guard is scheduled about 70 minutes later and
must remain enabled. Record its actual next-run time. The `on` response must
confirm the rule is enabled; it does not claim the destination actually failed.
Retain the exact SSM command ID from `generator-dispatch.json`.

The generator performs its separate 100-event warm-up and identity drain before
starting the measured hour. Those warm-up events can also be buffered during the
fault, so total pending count can exceed 36,000. Do not include them in the
measured identity set. The warm-up report's completion is a useful lower bound
for the measured start; final generator timestamps remain authoritative.

Within the first few minutes, run the observer again with the same phase and
save a new output filename. Require `destinationFailureObserved=true`, a growing
pending queue, unchanged source error counters and no unexpected successful
delivery during the measured window. `generatorAvailable=false` is normal while
the generator is still running. If generation fails, dead letters appear or the
fault does not produce a real delivery failure, restore connectivity safely and
retain the run as failed. Do not leave a failed test blocked just to reach an
hour on the clock.

### Restore after generation and durable admission

Near the expected end of the measured hour, poll the observer and retain each
observation. A full SSM command can still be `InProgress` after generation ends:
reading and hashing 36,000 Security and ForwardedEvents records can take several
minutes. The generator writes its checkpoint and initial phase report before
those expensive reads.

`readyForManualRestore=true` requires the complete 36,000-attempt checkpoint,
correct generation duration/rate, native owned-session cleanup, exactly 36,000
new source admissions, at least 36,000 pending events, no dead letters or new
source errors, a real destination failure, no measured delivery success, the
same boot and at least 3,600 monotonic seconds of blocking. Before restoration,
capture a scoped, metadata-only Sentinel observation while the rule is still
enabled. Use the verified warm-up completion UTC timestamp as the lower bound,
which excludes the preparatory events:

```bash
python3 lab/aws/monitoring/query-wec-outage.py \
  --plan <frozen-outage-plan.json> --since <verified-warmup-completion-UTC> \
  --azure-state-dir <private-azure-state-directory> \
  --output <evidence>/outage-before-restore-01.json
```

The plan must have `kind=native-windows-wec-destination-outage`,
`status=frozen-before-dispatch`, the owned `runId`/`phase`, and a `measured` object
with `rate=10`, `seconds=3600` and `expectedNativeCount=36000`. The helper uses the
same isolated verifier identity and fixed subscription/tenant checks as the full
reconciler. It queries only the selected Windows authentication population,
records its event-time window and ingestion cutoff, and rejects partial,
continued, malformed or changing-plan evidence. Exit 0 means no rows were
visible at the cutoff; exit 1 retains a nonempty observation; exit 2 means the
observation could not be validated. Reports are exclusive, private files.
`destinationQueryVerified` and `deliveryQualified` remain false even for an empty
observation. Retain the query, cutoff, completeness checks and count; this
observation supplements the final identity proof.

Restore promptly when the readiness checks pass, without waiting for full native
reconciliation to finish:

```bash
python3 lab/aws/monitoring/run.py Windows lab/aws/monitoring/wec-destination-outage.ps1 \
  --state "$state" --timeout 120 --env BOWER_WEC_OUTAGE_ACTION=off \
  > outage-off.json
```

Require `removed=true` and `minimumDurationPassed=true`, with unchanged boot and
clock frequency. If the independent guard already restored connectivity, the
command reads that original restoration outcome and removes the owned scheduled
task; it does not replace the actual restoration timestamp with a later manual
one. An early or changed-boot restoration remains failed qualification even
though connectivity is restored.

### Prove recovery, export and clean up

Poll the observer until pending count is zero, delivery succeeds again and no
source errors or dead letters appear. After restoration,
`readyForManualRestore=false` is expected because there is no longer an active
fault. Retain that recovery timeline separately from the before-restore readiness
record.

Wait for the generator command to finish and require complete native/WEC/queue
identity reconciliation. Export the phase and query Sentinel using the earlier
sections of this guide. Require exactly 36,000 distinct identities and rows,
zero missing/extra/duplicate rows, and inspect destination ingestion timestamps
against the captured fault/restoration interval. The pre-restore zero-count
observation alone cannot replace this final query, because destination indexing
can be delayed.

After the full 4,500-second sampling window, export the resource series with the
same scope and plan hash:

```bash
python3 lab/aws/monitoring/run.py Windows lab/aws/monitoring/sample-resources-windows.ps1 \
  --state "$state" --timeout 120 \
  --env BOWER_SAMPLE_ACTION=export --env "BOWER_SAMPLE_SCOPE=$phase" \
  --env "BOWER_PLAN_SHA256=$plan_sha256"
```

Require `samplingComplete=true`, 301 samples and no failed samples. Download all
three resource files and verify their recorded byte sizes and SHA-256 hashes.
Keep the full queue-growth/recovery series, source counters, CPU, resident memory
and actual queue-volume free disk. Preserve the fault-on/off metadata, generator
checkpoint, warm-up and phase identities, exact destination rows, failed attempts
and sanitized screenshots. Only then tear down the run's AWS/Azure resources and
private staging, and independently verify cleanup.

Local observer and restoration tests make no firewall or cloud calls:

```bash
pwsh -NoProfile -File lab/aws/tests/test_wec_outage.ps1
pwsh -NoProfile -File lab/aws/tests/test_wec_outage_observer.ps1
python3 -m unittest discover -s lab/aws/tests -p test_wec_outage_query.py
```
