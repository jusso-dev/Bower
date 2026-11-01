# Short Windows accepted-queue crash proof

Use this **after** the hourly Windows qualification has finished, its exact
36,000-event destination reconciliation has passed, and its complete 4,500-second
resource series has been exported and downloaded. Resolve any other campaign
failure before adding this fault. It uses the same pinned collector and existing
host; it does not alter the completed hourly evidence or require another hour.

This checks 600 accepted native events through a forced collector process death,
SCM recovery and destination delivery. Generation finishes before the crash.
It does not qualify concurrent source catch-up, a power loss, a fresh-host restore,
an installer upgrade or duplicate-alert handling.

## Freeze and review the separate plan

Choose a new phase for every attempt. Record the exact run/instance, candidate
commit and executable/SQLite hashes, helper hashes, predecessor source and
Sentinel report hashes, predecessor sampler plan/export hashes, and these gates:

- 600 measured events at 10/sec for 60 seconds; the helper's 100-event warm-up is
  excluded. Keep its native 99% rate and exact identity gates.
- A new `BowerRecovery-<run>-<phase>` rule blocks only the collector executable's
  outbound TCP 443. A separate SYSTEM task removes it after ten minutes.
- All 600 phase IDs and **all `winevt-` queue IDs** must survive the crash.
  Collector-health IDs are outside this identity set. The read-only SQLite query
  fails above 200,000 IDs; it never silently truncates a prefix or reads payloads.
- The receiving-log bookmark, boot, candidate, service identity, registry
  environment hash and source configuration hash must remain unchanged. The
  restarted process must have a different PID and later start time, become
  healthy within 60 seconds, and have no source errors or dead letters.
- Delivery remains blocked until the after-restart snapshot. The durable
  delivered count must not change. Final Sentinel reconciliation requires exactly
  600 distinct IDs/rows and no missing, extra or duplicate rows.

Hash the frozen plan. The helper records its hash but cannot independently verify
an off-host Sentinel report; the operator must verify the predecessor proof.

## Buffer, capture and crash

Run from the repository root. These values are public metadata, not credentials:

```bash
state=/private/tmp/bower-validation/state.json
phase=wec-restart-01
plan_sha256=REPLACE_WITH_FROZEN_RESTART_PLAN_SHA256
candidate_sha256=REPLACE_WITH_PINNED_WINDOWS_EXECUTABLE_SHA256
sqlite_sha256=REPLACE_WITH_PINNED_SQLITE_DLL_SHA256
previous_scope=wec-outage-01
previous_plan_sha256=REPLACE_WITH_HOURLY_PLAN_SHA256

common=(--state "$state" --timeout 180
  --env "BOWER_WEC_PHASE=$phase" --env "BOWER_PLAN_SHA256=$plan_sha256"
  --env "BOWER_CANDIDATE_SHA256=$candidate_sha256" --env "BOWER_SQLITE_SHA256=$sqlite_sha256"
  --env "BOWER_PREVIOUS_SAMPLE_SCOPE=$previous_scope"
  --env "BOWER_PREVIOUS_PLAN_SHA256=$previous_plan_sha256")
run_restart() {
  python3 lab/aws/monitoring/run.py Windows lab/aws/monitoring/wec-buffered-restart.ps1 \
    "${common[@]}" --env "BOWER_WEC_RESTART_ACTION=$1"
}

run_restart prepare > restart-fault-on.json
python3 lab/aws/monitoring/run.py Windows lab/aws/monitoring/wec-qualification.ps1 \
  --state "$state" --timeout 600 --no-wait \
  --env BOWER_WEC_ACTION=phase --env "BOWER_WEC_PHASE=$phase" \
  --env BOWER_WEC_PROFILE=process-explicit --env BOWER_WEC_RATE=10 \
  --env BOWER_WEC_SECONDS=60 > restart-generator-dispatch.json
```

`prepare` refuses a nonempty baseline, reused scope, active hourly fault, missing
successful hourly restoration, or incomplete predecessor 301-sample export.
Retain the actual guard next-run time. Poll the exact generator command ID and
instance from the dispatch report. Require terminal success and `nativeVerified`
with all 600 native/forwarded/accepted IDs before continuing. If generation or any
proof fails, run `run_restart off` immediately and preserve the failed attempt.

```bash
run_restart before > restart-before.json
run_restart crash > restart-crash.json
run_restart off > restart-fault-off.json
run_restart export > restart-export.json
```

The crash action takes an additional immutable snapshot, rechecks SCM's exact PID,
process start and executable path, kills only that process, and waits for SCM.
It checks the enabled, owned fault immediately before and after the after-restart
snapshot. A missing, disabled or changed rule fails the recovery proof, including
an independent guard that fires during that snapshot. Its `finally`
restores connectivity even when the recovery proof fails. The independent guard
covers an interrupted SSM command or a failure before the kill stage. The explicit
`off` also removes the owned guard; it never deletes another rule.

Require `verification.acceptedQueueRecoveryVerified=true` and
`restoration.removed=true`. `deliveryQualified` remains false: these are queue and
host observations. Recovery errors and every restoration attempt are retained;
snapshot files cannot be overwritten.

## Reconcile and retain

Wait for the queue to drain without dead letters. Use the phase exporter and
strict destination query in [WEC reconciliation](WEC-RECONCILIATION.md) for this
new phase. Download every restart export, validate its exact byte size and SHA-256,
and retain the before/pre-kill/after metadata and ID files, fault/restoration
records, native phase files, destination report and sanitized screenshots.
Do not claim delivery from a healthy service or an empty queue alone.

Only then perform the campaign's owned AWS/Azure teardown and independent absence
checks. A failed attempt remains failed even if a later fresh phase passes.

The focused fixture mocks every host action:

```bash
pwsh -NoProfile -File lab/aws/tests/test_wec_buffered_restart.ps1
```
