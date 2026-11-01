# Windows WEC → Bower → Sentinel qualification

This is the **disposable single-host Windows qualification** procedure. It uses
real Security 4625 events, a collector-initiated WEC subscription into
`ForwardedEvents`, the signed Windows pack and the final native Windows build.
It does not replace the earlier multi-host WEF evidence or qualify domain/GPO,
Kerberos or remote-source deployment. No script here provisions cloud resources.
Setup alone never establishes production readiness or Sentinel delivery.

## 1. Prepare an owned, fresh host and exact artifacts

Use the Windows output of the reviewed monitoring stack in AWS account
`959038055523`, Sydney. It must have SSM, AWS CLI v2 at
`C:\Program Files\Amazon\AWSCLIV2\aws.exe`, and Windows PowerShell 5.1. Use
`run.py` for every command: it verifies the account, exact instance ID, running
state, `Project=bower-lab`, `RunId`, `Role=windows-wec` and Windows platform.
Do not add public addresses or inbound rules. The installer disables WinRM's
external firewall rules after enabling the local WEC service.

The base Windows AMI may omit AWS CLI. Before uploading/downloading artifacts,
bootstrap it through the already ownership-checking operator runner:

```bash
python3 lab/aws/monitoring/run.py Windows \
  lab/aws/monitoring/bootstrap-windows-awscli.ps1 \
  --state <owned-state.json> --timeout 900
```

The bootstrap downloads only `https://awscli.amazonaws.com/AWSCLIV2.msi`, refuses
redirects, bounds the transfer to 128 MiB and validates its actual byte count.
Windows Authenticode must report `Valid`, the signing certificate's common name
and organization must both be exactly `Amazon Web Services, Inc.`, and the
certificate must include code-signing EKU. Only then does it install quietly
with `/norestart`. It reports installer SHA-256, public signer thumbprint, parsed
CLI v2 version and restart requirement; it neither configures credentials nor
prints installer/version error bodies. Staging is SYSTEM/admin-only and removed
on exit. TLS verification remains enabled; TLS1.2 is enabled only for this process.
A retry over an existing installation still downloads and validates the official
MSI before rerunning its installer; it never skips signature validation. Version
reporting accepts the bounded CLI v2 prefix and emits only the numeric version,
allowing AWS to change its OS/runtime suffix. Verified installer metadata is
retained in a failure result if a later installation/version step fails.
A publisher change or unsupported signature fails closed for review. Record the
actual installer hash/version as evidence because the official download is a
mutable latest-version URL. If restartRequired is true, perform the owned host
restart and verify SSM readiness before setup.

Use the reviewed final commit's `bower-win-x64` CI artifact. Repackage
only its native `collector/` directory as `collector.zip`; preserve its bytes.
Record the CI run, commit, original artifact digest and repackaged archive digest
in the campaign evidence. The script validates the pinned manifest and archive;
that does **not** independently attest that an arbitrary archive came from CI.

Create a private local directory outside Git:

```text
<staging>/qualification/<RunId>/windows/
```

Include exactly these nine files plus `manifest.json`:

| File | Content and limit |
|---|---|
| `collector.zip` | Only `collector/` native Windows publish files, including `collector/Bower.Collector.exe`. At most 512 MiB compressed, 1 GiB expanded, 4,096 entries. No links, traversal, case collisions, ADS or reserved Windows names. |
| `sentinel.json` | Public destination settings below; at most 64 KiB. |
| `ingest.pem` | Ingestion application's certificate and private key accepted by Azure.Identity; at most 64 KiB. Privately fetched on the host. |
| `ingest-token` | Local collector API token, at most 4 KiB. |
| `hmac.key` | Random key of at least 32 bytes, preferably base64 encoded; at most 4 KiB. Keep it stable for the campaign. |
| `windows-security-logon-1.0.2.bowerpack` | Reviewed, signed Windows pack; at most 16 MiB. |
| `pack-signing.pub.pem` | Trusted pack public key only; at most 64 KiB. |
| `collector-health.yaml` | Exact `examples/policies/collector-health/collector-health.yaml`; at most 64 KiB. |
| `Test-BowerCollectorHealth.ps1` | Exact `deploy/sentinel/monitoring/host/Test-BowerCollectorHealth.ps1`; at most 1 MiB. |

`sentinel.json` accepts exactly these four fields. Use the selected subscription
`945092a0-2500-4b25-85a4-99f1c3135906` and its actual tenant. The application's
ingestion role must be scoped to this run's DCR, and destination query validation
must use the separate verifier identity.

```json
{
  "tenant": "f4f33fb1-b681-40d1-a854-6f888d45b891",
  "client": "<ingestion-application-uuid>",
  "dcr": "dcr-<32-lowercase-hex-immutable-id>",
  "dce": "https://<run-endpoint>.ingest.monitor.azure.com"
}
```

The stream is fixed to `Custom-BowerSecurity`. The output is fixed to
`azure-logs-ingestion`, using the certificate environment credential. There is
no CLI credential or local-spool fallback.

Use the same manifest schema as [the firewall setup](FIREWALL-SETUP.md), with
`role: "windows"`, the exact run ID and all nine file entries. Each entry has
only `sha256` (64 lowercase hex characters) and `bytes` (positive integer).
Manifest size is at most 64 KiB. Hash the completed manifest and retain that
public SHA-256 separately. Do not include secrets, the CA/pack private signing
key, staging directory or manifest in evidence/screenshots.

```bash
bash lab/aws/monitoring/upload.sh <owned-state.json> <staging>
python3 lab/aws/monitoring/run.py Windows \
  lab/aws/monitoring/setup-wec-qualification.ps1 \
  --state <owned-state.json> --timeout 900 \
  --env BOWER_ARTIFACT_MANIFEST_SHA256=<windows-manifest-sha256>
```

All command parameters are public. Secrets are downloaded on-host using the
instance role from `artifacts/qualification/<RunId>/windows/`. Never copy them
into SSM text, command output, Git or reports. Apply the separate sender role's
restricted S3 permissions **before** uploading Windows/collector credentials.

The installer refuses an existing Bower directory/service. It validates every
artifact before installation, installs the service as `NT SERVICE\Bower`, grants
read/execute access to binaries/configuration/secrets and modify access only to
the queue directory. SYSTEM and administrators retain control. It configures
service restart recovery, a 1 GiB queue and 24-hour retention, 1 GiB native and
forwarded event channels, one-second source polling and a 256-event batch.
The queue limit is a test configuration, not proof of one-hour capacity.

WEC selects only the run's nonexistent synthetic account. The account name is
derived from the run ID and is never created. The signed pack still checks
original Security channel, provider, 4625, network logon type 3 and valid source
IP. No source/parser policy is weakened to make the test pass. A scheduled
health check writes metadata-only verdicts to Application every minute.

On setup failure the service is stopped and private staging removed. The owned
installation remains for diagnosis/teardown; do not rerun over it or delete an
unrelated installation. Provision a fresh owned host when necessary.

## 2. Prove the native generator before the pilot

The generator attempts real SMB authentication to `127.0.0.1\IPC$` with the
nonexistent local account. Each of at most 64 dedicated background workers first
creates a separate `LogonUser(LOGON32_LOGON_NEW_CREDENTIALS=9,
LOGON32_PROVIDER_WINNT50=3)` token with a synthetic invalid password held only in
memory. It impersonates that token and calls `WNetAddConnection2` with null
explicit credentials, so SMB uses that worker's isolated outbound credentials.
The workers do not share authenticated SMB sessions or conflicting passwords,
and never return impersonated threads to the shared thread pool. Each worker
unconditionally cancels its own `127.0.0.1\IPC$` connection **while still
impersonating that worker's new LUID**, including partial/failed attempt paths,
then reverts and closes its token. Cleanup accepts only native success or 2250
(no connection); other cleanup outcomes invalidate the phase. Setup,
impersonation, revert and handle-close failures also invalidate it. The script
never disconnects an existing caller/other-user SMB session and keeps the
preflight refusal for any existing loopback session. If a prior failed attempt
left a session, preserve its evidence and reset the dedicated owned host through
a separately reviewed reboot; do not bypass the guard or broadly run `net use`
cleanup. NewCredentials itself does not
validate the account or prove a failed logon: only the real SMB request and
native Security 4625 evidence do. Result code 1219 is explicitly disallowed.
At most 64 attempts execute concurrently, with a bounded 64-item work queue. It refuses an existing loopback SMB session
or existing account, allows only one phase at a time, and never overwrites a
phase report. Preserve previous failed phase files and use a new name for every
retry; never rewrite the original failed baseline. Each phase is bounded to 1–3,600 seconds and 50,000 attempts.
Native SMB throttling may prevent the target rate: that is a failed preflight,
not permission to substitute HTTP injection or fabricated event XML.

```bash
python3 lab/aws/monitoring/run.py Windows \
  lab/aws/monitoring/wec-qualification.ps1 \
  --state <owned-state.json> --timeout 600 \
  --env BOWER_WEC_ACTION=phase --env BOWER_WEC_PHASE=preflight \
  --env BOWER_WEC_RATE=100 --env BOWER_WEC_SECONDS=10
```

Require all 1,000 attempts completed, zero unexpected successes, measured rate
at least 99/sec, exactly 1,000 valid native network failures, identical original
native and forwarded identity sets, exactly 1,000 collector source accepts, and the identical accepted queue identity set.
The script waits up to three minutes for WEC/collector lag. It records the
actual attempt interval as `startedAt`/`endedAt`, separately from
`eventWindowEndedAt=endedAt+5 seconds`. The fixed five-second audit window accounts
for a real Security event timestamp assigned just after an SMB call returns;
it does not lengthen or relabel the requested traffic interval. All phase
identity sets must still match exactly, and the phase lock remains held through
reconciliation. The native `firstEventAt`/`lastEventAt` must independently prove
at least 99% of the requested rate using `(count-1)/(last-first)`; a fast call
rate cannot hide slow or missing actual audit events. It fails on missing,
duplicate, malformed or rejected records, cursor gaps/resets or inadequate rate.
Inspect result codes and counts; do not infer generated events from scheduled
attempts. `nativeVerified=true` is only source-to-durable-queue proof. The script also
opens the queue read-only through the Windows inbox `winsqlite3.dll` API and
projects only `event_id`/`received_at`, with a 200,000-row bound. It rejects stale
expected IDs, malformed/duplicate IDs and extra accepted identities in the phase
window. It never loads or exports event payloads. Windows Server 2016 or newer
must provide that inbox API; the owned Server 2022 host must exercise it under
PS5.1 before this path is qualified. No new runtime package is installed.

`winevt-…` identities use Bower's exact original XML channel/computer/record ID/
microsecond timestamp hash. The ForwardedEvents receiving bookmark is separate;
never compare it directly to the Security record number. Only identity strings
and aggregate metadata are written; XML/payloads remain transient in memory.

## 3. Steady traffic, burst and one-hour outage

Run phases sequentially with unique names. Reuse the command above with:

| Phase | Rate | Seconds | Expected native events |
|---|---:|---:|---:|
| `steady` | 10/sec | 600 | 6,000 |
| `burst` | 100/sec | 60 | 6,000 |
| `destination-outage` | 10/sec | 3,600 | 36,000 |
| `drain-live` | 10/sec | 600 | 6,000 |

Use `--timeout 4200` for the one-hour phase. Immediately before that phase:

```bash
python3 lab/aws/monitoring/run.py Windows \
  lab/aws/monitoring/wec-destination-outage.ps1 \
  --state <owned-state.json> --timeout 120 \
  --env BOWER_WEC_OUTAGE_ACTION=on
```

This adds an outbound TCP 443 block for **only Bower.Collector.exe**. WEC, SSM
and other applications remain available. A SYSTEM task removes the exact
run-specific rule after 70 minutes even if the session is interrupted. The
independent task validates the rule's program/direction/port before removing it
and writes `outage-restored.json` plus an `automatic-off` entry in `outage.jsonl`.
It records UTC, boot time and high-resolution monotonic counter values: require
`removed=true`, `bootUnchanged=true`, `clockFrequencyUnchanged=true` and
`minimumDurationPassed=true`. The lower bound runs from completed installation
to restoration start; it must reach 3,600 seconds. Missing applied evidence still
allows owned-rule cleanup but invalidates qualification. A changed boot, missing
rule, early restoration or failed removal cannot pass. Record
the active firewall rule, timestamp, actual destination failures and undelivered
queue growth; rule presence alone does not prove an outage. Health warnings are
expected during this deliberate fault and must recover afterward.

Capture status before, during and after using `wec-qualification.ps1` with
`--env BOWER_WEC_ACTION=snapshot`; output includes source counters, queue metadata
and delivery activity. Use `wec-destination-outage.ps1` with action `status` to
record the rule. The automatic rollback must not fire before the full hour has
elapsed; otherwise fail and repeat with a fresh phase name. If any command fails,
remove the fault promptly with action `off` and preserve the failed evidence.

No reboot belongs in this destination-outage phase. Rule/status snapshots and
an unchanged boot complement, but do not alone prove, continuous destination
failure. Independently ensure no scoped Sentinel events were ingested before
actual restoration. Preserve both automatic and manual failure evidence.

After the one-hour phase finishes, run the outage command with action `off`,
then run `drain-live`. Confirm the exact rule and rollback task are gone, queue
backlog returns to zero, health recovers, and Sentinel receives the complete
expected native identity sets. Do not delete the queue to force recovery.

To request early cancellation, send `wec-qualification.ps1` with
`--env BOWER_WEC_ACTION=cancel` through a separate SSM invocation. It stops new
attempt scheduling, waits at most 30 seconds for existing workers, and marks the
phase failed. Cancel does not remove the destination fault; run action `off` too.

## 4. Export proof, query Sentinel and clean up

Use [WEC-RECONCILIATION.md](WEC-RECONCILIATION.md) for the independent verifier
query and exact four-way identity comparison.

```bash
python3 lab/aws/monitoring/run.py Windows \
  lab/aws/monitoring/export-wec-evidence.ps1 \
  --state <owned-state.json> --timeout 300 \
  --env BOWER_WEC_PHASE=<completed-or-failed-phase>
```

This exports the four fixed phase files: `<phase>.json`, `<phase>-native.ids`,
`<phase>-forwarded.ids` and `<phase>-queue.ids`, plus the optional immutable
`<phase>-generator.json` checkpoint. The checkpoint is capped at **32 KiB**;
other phase files and optional `outage.jsonl`, `outage-applied.json` and
`outage-restored.json` are capped at 4 MiB each. The destination remains
`results/qualification/<RunId>/windows/<phase>/` in the owned bucket.

If generation failed before the phase JSON or identity files were written, run
the same exporter: it permits a valid owned checkpoint plus whatever fixed phase
files exist. Missing phase files without a valid checkpoint are rejected. The
checkpoint must match the run/phase, declare `recordType=generator-checkpoint`,
retain all qualification flags as false, and contain only the reviewed generator
counters, enums, numeric code maps and offset timestamps. Unknown fields or free
text are rejected. All selected paths and their ancestors must be ordinary,
non-reparse paths. Unrelated logs/files are never selected.

After the per-file hashes, the exporter emits a fresh summary schema:

```json
{
  "schemaVersion": 1,
  "recordType": "wec-evidence-export",
  "runId": "bower-ws6-YYYYMMDD-HHMMSS",
  "phase": "failed-phase",
  "partialEvidence": true,
  "checkpointOnly": true,
  "checkpointIncluded": true,
  "warmupIncluded": false,
  "missingWarmupFiles": [],
  "missingPhaseFiles": ["failed-phase.json", "failed-phase-native.ids", "failed-phase-forwarded.ids", "failed-phase-queue.ids"],
  "files": [{"file": "failed-phase-generator.json", "bytes": 1234, "sha256": "<file-sha256>"}],
  "destinationQueryVerified": false,
  "deliveryQualified": false
}
```

`partialEvidence` reports missing phase or partially present warm-up files, not pass/fail of the traffic test;
a structurally complete export can still contain a failed phase. `checkpointOnly`
means no phase report/identity files exist (optional warm-up or outage evidence may still be
included). The exporter never creates missing IDs or upgrades a checkpoint into
proof. `query-wec.py` still requires the complete successful phase and exact ID
sets; it rejects checkpoints and export summaries as qualification input.
Never upload the queue, credentials, registry environment, settings or event XML.

Query the actual Sentinel table using the independent verifier for the exact
collector ID `<RunId>-windows` and event IDs from every native ID file. Compare
native, forwarded, accepted queue and Sentinel full sets and row multiplicities, not just totals. Require zero missing/extra
IDs and zero unexpected duplicates. Exclude periodic health events from the
authentication identity comparison. Reject partial/oversized query results;
preserve query window, UTC time, sanitized query text/result and set hashes.
`query-firewall.py` is tailored to firewall accounting and must not be assumed
to implement Windows reconciliation without review.

Capture screenshots of the native/forwarded/accepted phase summary, the active
outage with retry/backlog metadata, recovery, and the independently queried
Sentinel result. Include timestamps, commit and artifact hashes in the campaign
README. Screenshots supplement the machine-readable evidence; neither a local
health response nor this setup's `deliveryQualified=false` output is destination
proof. Document any failed or unexecuted phase as failed/blocked.

Finally follow the monitoring README's owned-resource teardown and independent
absence checks: remove all run EC2 instances/volumes, stack, temporary S3 objects
and bucket, Azure resources and application/service-principal credentials. Keep
only approved sanitized evidence locally/in Git. Remove private local staging.
An expiry guard that merely stops or terminates hosts is not full cleanup.

## Local validation

```bash
pwsh -NoProfile -File lab/aws/tests/test_windows_awscli_bootstrap.ps1
pwsh -NoProfile -File lab/aws/tests/test_wec_setup.ps1
pwsh -NoProfile -File lab/aws/tests/test_wec_evidence.ps1
pwsh -NoProfile -File lab/aws/tests/test_wec_export.ps1
```

These tests parse scripts, compile the Windows generator and exercise manifest,
destination and adversarial archive validation without executing Windows host
actions. Evidence tests additionally exercise mocked owned-rule restoration,
foreign-rule refusal, early/reboot/missing-evidence failures, and exact queue
identity selection; they compile the inbox SQLite declarations without calling
Windows APIs. Actual PS5.1 ACLs, SMB generation, WEC forwarding, rate, outage buffering
and Sentinel delivery must all be exercised on the owned Windows host before
qualification can pass.

For a reviewed native CI candidate change during the same session, use
[CANDIDATE-UPDATE.md](CANDIDATE-UPDATE.md) to replace only the two native files
while retaining the existing configuration, credentials, queue and bookmarks.

The exporter also retains optional `<phase>-warmup.json` (32 KiB) and
`<phase>-warmup-native.ids`, `<phase>-warmup-forwarded.ids`, and
`<phase>-warmup-queue.ids` (4 MiB each). Warm-up JSON and checkpoint warm-up
metadata use strict field/type/enum bounds; warm-up identity files contain only
`winevt-` identifiers. A partial warm-up attempt lists absent warm-up filenames
in `missingWarmupFiles` and sets `partialEvidence=true`. `warmupIncluded` says
that at least one optional warm-up artifact exists. Completely absent legacy
warm-up artifacts remain optional. These files never count toward measured
traffic, and their export never asserts destination delivery.
