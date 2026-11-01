# Replace the native candidate without replacing lab state

These helpers update the already owned, configured qualification hosts. They
replace exactly two native files, preserving the service definition, destination,
credentials, signed packs, policies, queue and source bookmarks. This is a lab
candidate change, not a production upgrade qualification or a new delivery claim.
Run it between scenarios, never during traffic generation or an outage. Preserve
all earlier baseline/failure evidence and record the new commit/artifact hashes
on every subsequent scenario.

## 1. Prepare one exact two-file ZIP per platform

Download the passing CI native AOT artifacts for the exact reviewed commit and
record the CI run, commit and original artifact SHA-256. The candidate must use
the same queue schema as the installed build; these helpers do not back up,
restore, migrate or downgrade the database. A build with database schema changes
requires a separately reviewed upgrade/migration procedure.

Normalize the ZIP contents to **exactly** these entries, with an optional empty
`collector/` directory entry:

| Platform | Allowed file entries |
|---|---|
| Linux x64 | `collector/Bower.Collector`, `collector/libe_sqlite3.so` |
| Windows x64 | `collector/Bower.Collector.exe`, `collector/e_sqlite3.dll` |

Retain each file's exact CI bytes. Do not include secrets, environment files,
configuration, packs, queues, symlinks, alternate streams or other publish files.
The helpers reject other names, case variants, duplicate entries, traversal,
links and archives above 512 MiB compressed or expanded. Extraction is bounded
again against actual decompressed bytes. Record the normalized archive hash;
it is distinct from the original CI download hash. The helpers verify the
public pinned hash, but do not independently attest an arbitrary ZIP's CI origin.

Use a private staging directory outside Git with this layout:

```text
<staging>/qualification/<RunId>/candidate/<40-lowercase-hex-commit>/linux/collector.zip
<staging>/qualification/<RunId>/candidate/<40-lowercase-hex-commit>/windows/collector.zip
```

Upload with the existing owned uploader:

```bash
bash lab/aws/monitoring/upload.sh <owned-state.json> <staging>
```

Each helper downloads only its exact platform archive under
`artifacts/qualification/<RunId>/candidate/<Commit>/<platform>/collector.zip`.
The separate sender role remains unable to read this candidate directory.

## 2. Replace the Linux pair

```bash
python3 lab/aws/monitoring/run.py Linux \
  lab/aws/monitoring/update-candidate-linux.sh \
  --state <owned-state.json> --timeout 900 \
  --env BOWER_CANDIDATE_COMMIT=<full-commit> \
  --env BOWER_CANDIDATE_SHA256=<normalized-linux-zip-sha256>
```

The helper rechecks the AWS account and collector owner marker, active service
user, actual running executable and root-owned install path below this run's
`/opt/bower/releases/` directory. It refuses symbolic links, writable install
paths and an active destination-outage table. Its local update lock prevents
concurrent updates; the operator must also ensure the separate sender is idle.

After validating and extracting the pinned archive, it makes a protected
`.rollback-<commit>-<unique>` directory inside the existing release directory.
Only the two old native files enter it. It stops `bower.service`, atomically
renames each new native file over the old path, then starts the service and
checks authenticated local status. A failed replacement/start/readiness check
stops the service again, restores both old native files from the protected
copies and attempts to restart the old candidate. Rollback success requires
old hashes and authenticated readiness to match.

## 3. Replace the Windows pair

```bash
python3 lab/aws/monitoring/run.py Windows \
  lab/aws/monitoring/update-candidate-windows.ps1 \
  --state <owned-state.json> --timeout 900 \
  --env BOWER_CANDIDATE_COMMIT=<full-commit> \
  --env BOWER_CANDIDATE_SHA256=<normalized-windows-zip-sha256>
```

The helper verifies the account, owner marker, `NT SERVICE\Bower`, fixed service
executable and running state. It rejects reparse points, an existing outage rule,
and a concurrently held WEC phase lock. Staging and rollback directories under
`C:\Program Files\Bower` grant access only to SYSTEM and administrators.

Before download/replacement, it validates each existing file's ACL has exactly
SYSTEM and Administrators FullControl plus the known `NT SERVICE\Bower` SID
ReadAndExecute, with a trusted SYSTEM/Administrators owner and group. Both the
original inherited ACL and the repaired protected/explicit ACL are supported.
Additional identities, denied/split grants, missing service access, service write
access or an untrusted owner/group fail closed without changing the baseline.
It saves original SDDL in the protected rollback directory and reports only ACL
fingerprints. ACL drift before the swap is rejected.

It stops service `Bower` and waits for `Stopped`, then uses Windows `ReplaceFile`
for each file. **Real Windows testing showed that ReplaceFile can drop inherited
Bower RX when staging is private; it must not be trusted to preserve that grant.**
The helper first applies the exact known grants as explicit, protected file ACLs
to candidate and backup files. It then reapplies and verifies those ACLs on each
live replacement before starting either binary. Owner/group remain the validated
baseline values; no Users/Everyone grant is added. Restoration temporary files
and restored destinations receive the same verified protection. A failure to
apply/verify ACLs prevents service startup and triggers rollback.

The service remains stopped until both native files and their ACLs are ready.
It starts the service and checks authenticated status. Failed replacement/start/
readiness restores both old files and verifies hashes, exact ACLs and old-service
readiness. Safe failure metadata includes exception types, HResult, category,
line number and allowlisted static codes; arbitrary exception text is omitted.
No registry environment, credentials, WEC subscription, audit policy, queue or
bookmark is rewritten. No host reboot is performed.

## 4. Assess the report and preserve recovery material

Successful output has `updated=true`, exact old/new per-file SHA-256 values,
archive hash, candidate commit, protected rollback path and bounded queue counts
before/after. Queue counts may change while the service processes existing data;
this report is not an assertion that the database file is byte-identical or that
backlog has reached Sentinel. The token is read only into memory for loopback
status and is never output. No payloads, registry environment, file contents or
native error bodies appear in the report.

A failed attempt returns `updated=false`, `rollbackPerformed=true` and an honest
`rollbackSucceeded` value when the swap phase was reached. If rollback fails,
preserve the report and protected native copies, inspect the exact owned host,
and recover only this candidate before any further generation. Never delete or
replace its queue to force a healthy result. Staging is cleaned; rollback copies
remain until the test host is torn down.

Replacement is atomic **per file while the service is stopped**, not a
power-loss transaction across both files. A terminated SSM process or host crash
may leave the service stopped between replacements; protected rollback copies
are retained for reviewed recovery. These helpers make no crash/reboot upgrade
claim. Likewise, local status does not prove native source correctness or
Sentinel delivery: rerun the native WEC/firewall preflight and independent
identity reconciliation on the new build. Preserve old failed evidence and use
new phase names/sequence offsets.

## Local validation

```bash
python3 -m unittest discover -s lab/aws/tests -p 'test_candidate_update.py'
pwsh -NoProfile -File lab/aws/tests/test_candidate_update.ps1
# Required on the owned Windows host, including Windows PowerShell 5.1:
powershell.exe -NoProfile -File lab/aws/tests/test_candidate_update_native_acl.ps1
```

Tests exercise archive rejection, exact two-file extraction, real temporary-file
replacement, rollback after failure between replacements, readiness rollback,
and honest failure when rollback cannot become healthy. The cross-platform
transaction test explicitly mocks ACL callbacks; it cannot qualify NTFS behavior.
The separate native fixture uses real Windows ACLs and ReplaceFile, specifically
inherited Bower RX on destination files and SYSTEM/admin-only staging directories.
It verifies protected explicit grants after success, failed startup and a failure
between replacements, plus rejection of untrusted ACL baselines. It uses only
unique temporary files and never invokes AWS or live host services. Run that
fixture successfully before retrying a candidate update. Actual Windows file
locking/service startup, Linux
systemd startup, actual AOT/SQLite loading, queue preservation and live source
recovery still require the owned-host run.

### Native Windows ACL regression validation (2026-11-01)

The owned Server 2022 host ran the genuine ACL fixture under Windows PowerShell
`5.1.20348.5773`: all 19 checks passed, covering inherited service RX with private
candidate/rollback parents, successful replacement, failed readiness, failure
between file replacements, unsuccessful readiness after rollback, and rejection
of extra Users access, missing service RX and service Modify rights.

- Fixture SSM command: `5de5c5a4-f9d9-4956-8dc4-2e13f9239e06`.
- Reviewed updater SHA-256: `516cb9c70de27a81997eb00f3682a7f9e97b339bda5f54bd8bd0fc97801c92a8`.
- Actual candidate update SSM command: `d40df5c0-7bae-4e81-9b3e-9f306d2f5a0e`.
- Candidate commit: `733eb7448a98e3ac449c8427753b799ad3fec5c1`.

The subsequent real update reported `updated=true`, `serviceReady=true`, matching
expected protected ACL fingerprints, and retained configuration/queue state.
Retain the complete command reports alongside the campaign evidence for full
old/new binary and archive hashes and before/after queue counts. These results
validate this native replacement/ACL path; they do not qualify source traffic,
Sentinel delivery, arbitrary future artifacts or database schema migration.
