# Bounded resource and queue evidence

Use these samplers alongside the Windows WEC and firewall/syslog outage campaign.
They retain the full 15-second series needed to report collector CPU, resident
memory, actual queue-volume free disk, queue growth and source counters during a
one-hour destination outage. They do not inject events, modify delivery, or query
Sentinel. `deliveryQualified` is always `false`; exact destination reconciliation
remains mandatory in [WEC-RECONCILIATION.md](WEC-RECONCILIATION.md) and
[FIREWALL-RECONCILIATION.md](FIREWALL-RECONCILIATION.md).

## 1. Freeze the scope and check prerequisites

Use the existing owned three-host drill and `monitoring/run.py`; it verifies the
account, exact instance IDs, Project/RunId/Role tags and running state before each
SSM command. Never target hosts through broad tags. The sampler requires the
installed collector, its loopback status API and local ingest token. The Windows
collector must run as `NT SERVICE\Bower`, and its local `qualification.json` must
match the current run. Linux requires root and systemd; Windows requires the
SYSTEM SSM agent, Windows PowerShell 5.1+, ScheduledTasks/CimCmdlets and the
installed AWS CLI v2 for export. Neither sampler needs inbound access.

In the operator shell, use public values only:

```bash
state=/private/tmp/bower-final-qualification/monitoring-state.json
scope=final-outage-resources
plan_sha256=REPLACE_WITH_THE_64_LOWERCASE_HEX_DIGEST_OF_THE_FROZEN_CAMPAIGN_PLAN
```

Replace the state path with the actual file created by this run's `stack.py`.
Hash the exact frozen campaign plan with `shasum -a 256 PLAN.json`; record this
same hash with the source/fault and destination evidence. The hash binds the
sampler's scope to that plan; the sampler does not independently inspect the
plan. Use a new scope for every attempt. Existing local scopes are never reused.
All environment values sent through SSM are public scope metadata. Do not send
tokens or credential material in an environment argument.

## 2. Smoke-test both hosts before the long run

Start a separate 60-second scope first, changing `scope` to e.g.
`sampler-smoke-01`. Use the start commands below with `BOWER_SAMPLE_SECONDS=60`.
Check status after the duration has elapsed, then export. Require five samples,
`samplingComplete=true`, zero failed samples and correct process/queue/disk
values before using this implementation in the long campaign. Local unit tests
exercise projection and summary logic; they do not establish Windows native API
or scheduler behavior. A failed smoke test must remain failed in the evidence.

For a single Windows diagnostic sample without creating a scheduled task or
writing a series, use a fresh public scope label:

```bash
python3 lab/aws/monitoring/run.py Windows lab/aws/monitoring/sample-resources-windows.ps1 \
  --state "$state" --timeout 90 \
  --env BOWER_SAMPLE_ACTION=probe --env BOWER_SAMPLE_SCOPE=resource-probe-01 \
  --env "BOWER_PLAN_SHA256=$plan_sha256"
```

Retain the `resource-probe` JSON from SSM output. The probe exits unsuccessfully
when metadata is unavailable; it always reports `samplingComplete=false` and
`deliveryQualified=false`. It cannot replace a full-duration series. Failed
samples now include `errorDetails` with an allow-listed step, exception type,
HResult, optional numeric Win32 error code, error category and script line.
Steps distinguish boot identity, process lookup, actual queue volume, queue-file
sizes, local token read, status HTTP/parsing and status projection. Health-only
failures use the same safe metadata in `healthError`. Error messages, position
text, response bodies, headers and token values are never included.

The Windows disk helper uses fully qualified `System.UInt64` output arguments;
the `ulong` PowerShell type accelerator is unavailable on Windows PowerShell
5.1. It retains the dynamically resolved native type and actual queue-directory
query. Do not substitute the C: root or treat an unavailable disk as healthy.
Preserve any earlier five-sample `metricsAvailable=false` smoke result as failed
evidence, then run a new probe and a new 60-second scope after repair.

## 3. Start independent background collection

Start before denying destination egress. A 5,400-second collection gives a
one-hour outage plus 30 minutes for baseline and recovery. The default is 4,200
seconds; choose sufficient recovery margin for the frozen plan.

```bash
python3 lab/aws/monitoring/run.py Linux lab/aws/monitoring/sample-resources-linux.sh \
  --state "$state" --timeout 90 \
  --env BOWER_SAMPLE_ACTION=start --env "BOWER_SAMPLE_SCOPE=$scope" \
  --env "BOWER_PLAN_SHA256=$plan_sha256" --env BOWER_SAMPLE_SECONDS=5400

python3 lab/aws/monitoring/run.py Windows lab/aws/monitoring/sample-resources-windows.ps1 \
  --state "$state" --timeout 90 \
  --env BOWER_SAMPLE_ACTION=start --env "BOWER_SAMPLE_SCOPE=$scope" \
  --env "BOWER_PLAN_SHA256=$plan_sha256" --env BOWER_SAMPLE_SECONDS=5400
```

The start commands return promptly after starting an independent systemd unit or
SYSTEM scheduled task. The SSM request does not remain open for the sampling
window. On Windows the task has no automatic/reboot trigger; it is started once
explicitly. On Linux it is a transient unit. Neither resumes after a host reboot.
A duplicate start is rejected rather than overwriting the previous series.

Duration must be a multiple of 15 between 60 and 7,140 seconds. The worker has at
most 60 additional seconds to finish, and the scheduler enforces a total lifetime
of at most 7,200 seconds. Each sample is flushed to disk. The JSONL file is capped
at 4 MiB, each row at 8 KiB, and the reader at 481 records. A scheduler hard stop
can leave incomplete evidence; it never converts missing data into a pass.

## 4. Observe status without disturbing the outage

```bash
python3 lab/aws/monitoring/run.py Linux lab/aws/monitoring/sample-resources-linux.sh \
  --state "$state" --timeout 90 \
  --env BOWER_SAMPLE_ACTION=status --env "BOWER_SAMPLE_SCOPE=$scope" \
  --env "BOWER_PLAN_SHA256=$plan_sha256"

python3 lab/aws/monitoring/run.py Windows lab/aws/monitoring/sample-resources-windows.ps1 \
  --state "$state" --timeout 90 \
  --env BOWER_SAMPLE_ACTION=status --env "BOWER_SAMPLE_SCOPE=$scope" \
  --env "BOWER_PLAN_SHA256=$plan_sha256"
```

Status returns only aggregated metadata, never the token, status body, raw events
or queue contents. A read concurrent with the first write or an incomplete JSONL
line can fail closed; retry status later. The worker keeps running independently.

Every row includes UTC time, monotonic elapsed time, boot identity, collector PID
and process start identity, CPU seconds, CPU percent of one logical core, resident
bytes, the queue directory's volume size/free bytes, database+WAL+SHM bytes,
queue-state counts, payload byte counters, and allow-listed source counters.
Queue `pending` means queued+retrying+uploading; `count` also includes delivered
and dead-lettered rows. These are snapshots; peak values can occur between
samples. CPU percent can exceed 100 for a multithreaded process and is not host
CPU utilization. Database allocation and queued payload bytes measure different
things and are reported separately.

Linux reads `/var/lib/bower/queue.db`'s filesystem with `statvfs`. Windows queries
`C:\ProgramData\Bower\data\` using `GetDiskFreeSpaceExW`, including mounted
volumes; it never substitutes the C: root. Tokens are read locally from
`/etc/bower/secrets/token` or
`C:\ProgramData\Bower\secrets\ingest-token`. The status client disables proxies
and redirects, permits only fixed loopback URLs, and caps responses at 1 MiB.
Exceptions become a fixed category without exception text. Failed status reads
can still retain already collected process/disk observations.

## 5. Export the completed series and verify hashes

After the planned duration and recovery have elapsed, run:

```bash
python3 lab/aws/monitoring/run.py Linux lab/aws/monitoring/sample-resources-linux.sh \
  --state "$state" --timeout 300 \
  --env BOWER_SAMPLE_ACTION=export --env "BOWER_SAMPLE_SCOPE=$scope" \
  --env "BOWER_PLAN_SHA256=$plan_sha256"

python3 lab/aws/monitoring/run.py Windows lab/aws/monitoring/sample-resources-windows.ps1 \
  --state "$state" --timeout 300 \
  --env BOWER_SAMPLE_ACTION=export --env "BOWER_SAMPLE_SCOPE=$scope" \
  --env "BOWER_PLAN_SHA256=$plan_sha256"
```

A running sampler cannot export an unfinished series. A worker stopped by its
hard limit can export an incomplete series after the scheduler confirms it has
stopped. Export recomputes the report from retained samples and the current boot
identity. Boot changes, missing samples, shortened coverage or excessive gaps
keep `samplingComplete=false`. A stopped worker without any readable samples
cannot export a usable report.

Each host uploads exactly three files with SSE-S3 to its owned run bucket:

```text
results/resource-sampling/<runId>/<linux|windows>/<scope>/<planSha256>/scope.json
results/resource-sampling/<runId>/<linux|windows>/<scope>/<planSha256>/samples.jsonl
results/resource-sampling/<runId>/<linux|windows>/<scope>/<planSha256>/export-summary.json
```

The command reports each object's exact key, size and SHA-256. Download these
exact keys using the explicit account profile/region and compare `shasum -a 256`
with the reported digests. Preserve that command metadata next to the downloaded
series. `scope.json` includes the frozen plan digest, worker digest, boot identity
and intended duration. Do not upload the worker, token, queue or any staging
manifest as proof. Export failure can be retried for the same immutable series;
check all three uploads and digests before treating export as complete.

The summary reports observed peaks, minimum available disk, maximum sample gap,
failed sample count, process restart count, source counter maxima, positive
counter deltas and counter reset count. A reset count is per counter decrease;
it is not a count of host restarts. Deltas across unavailable samples cannot
prove that no reset or drop occurred between observations. Use source identity
reconciliation as the loss check. `samplingComplete=true` means a finalized,
same-boot series with all metadata available, a first sample within 15 seconds,
coverage within 15 seconds of the requested duration, and no gap above 30
seconds. It does not grade CPU/memory/disk limits or prove successful delivery.
Compare timestamps explicitly with the fault and source windows; a complete
sampler outside the outage window is not outage evidence.

## 6. Retain sanitized proof, then clean up

Before teardown, retain all three files and verified hashes in the sanitized
run evidence directory, update the README with observed peaks/gaps and any
limitations, and include the source/destination reconciliation reports. Keep
failed attempts clearly labeled rather than replacing them with successful ones.

The Linux transient unit is collected on exit. The Windows task remains defined
but has no triggers and cannot start automatically. It and local series are
removed when the disposable host and its volumes are deleted. If a host must be
retained temporarily, remove only the exact stopped task/unit and exact scope
directory recorded by the start output, after exporting and verifying evidence;
never stop unrelated collector services or remove shared paths.

Follow [README.md](README.md)'s complete AWS/Azure teardown and private staging
removal procedure. Successful export is not cleanup. Remove the temporary bucket
(including versions), hosts/volumes and Azure resources after sanitized proof is
retained; verify absence independently. No sampler resource should remain
billable after this testing session.
