# Independent firewall identity reconciliation

This procedure proves synthetic identity delivery for one exact run and scenario.
It does not by itself qualify a fault, network topology, Windows WEC, or a
production rollout. Preserve separate fault/reboot, queue capacity, TLS and
configuration evidence. Never infer Sentinel delivery from `delivered_at`, a
successful ingestion HTTP response, or the old `deliveredToSpool` label.

## 1. Freeze the scenario plan

Use the separate sender setup in [FIREWALL-SETUP.md](FIREWALL-SETUP.md). Build a
plan from the exact reviewed helper directory. The public monitoring state must
contain the owned run ID and the exact LinuxIp/SenderIp addresses:

```bash
python3 lab/aws/monitoring/syslog-plan.py a-steady \
  --source lab/aws/scripts --state <owned-state.json> \
  --collector-ip <LinuxIp> --sender-ip <SenderIp> \
  --start-epoch <future-UTC-epoch> --sequence-offset 900000 > <new-plan.json>
shasum -a 256 <new-plan.json>
```

Allow at least 120 seconds to dispatch. Do not modify a plan after dispatch.
Execute its `steps[].command` argument arrays; these use the ownership-checking
SSM runner, not arbitrary role-tag targeting. After `collectNotBeforeEpoch`,
execute the `collect` commands. Keep each native generator JSON result as its
own file, in `generations` order. Strip SSM status wrappers when saving that
JSON, but preserve the original command record separately. No credentials occur
in the plan. Its helper digests and exact generator ranges bind the artifacts
and identities being tested.

`--sequence-offset` defaults to zero for the original ranges. A new candidate
can use a disjoint offset such as `900000`: it is frozen as `sequenceOffset`
and added consistently to every generator `--first` and every expected and
measurement `nft:A:first:count` block, including all idle-gap phases. Counts,
rates, fault timing and the source runtime remain unchanged. The planner rejects
negative/non-integer offsets, ranges exceeding 200,000 events per block, and
offsets whose final identity is outside `[0, 2000000)`. The deployed Track A
firewall rule logs only UDP destination ports `4400..4449`, with 40,000 source-port
identities per destination port. Track B begins at `4450`; other valid UDP ports
do not produce Track A denial evidence. The final index must therefore be below
`50 * 40000`, even though the UDP protocol permits larger port values.

With offset `900000`, steady uses `1100000:600`, burst uses `1700000:6000`, and
the one-hour outage uses `1900000:36000`. These fit the actual Track A rule and
are disjoint from the earlier baseline steady (`200000:600`) and burst
(`800000:6000`). Check every earlier identity range before choosing an offset;
this is a bounded namespace. The former `10000000` example was invalid and is
now rejected before dispatch. Preserve its failed plan, zero native deny-counter
result and associated reports as failed evidence; do not rewrite them as a new
plan or count sent packets alone as logged firewall denials.

Run scenarios sequentially. The 5/30/65-minute idle schedule must remain free
of other source generation. A fresh plan must use an unambiguous window and
fresh expected identities: reusing port ranges in the same collector queue
fails reconciliation when old expected rows remain. Preserve failed and passed
baseline plans/reports/screenshots in their existing directories. Export earlier
host reports before dispatching another run with the same scenario/unit labels,
then use a new output directory, future time window and disjoint sequence offset.
The existing queue can remain intact; do not delete rows to make a rerun pass.

## 2. Distinguish the two outage tests

`a-blackhole` is the original 120-second **source transport** interruption.
`a-destination-outage` is a separate accounting plan: 36,000 native nftables
denials at 10 events/second over 3,600 seconds, base range `nft:A:1000000:36000`
plus the frozen `sequenceOffset` (for offset `900000`: `nft:A:1900000:36000`).
The latter includes `externalFaultRequirement` and intentionally does **not**
install a network block. Before its first event, the operator must install a
reviewed block of only the collector service UID's outbound TCP443, with an
independent timed restoration guard. The inet-family rule covers IPv4 and IPv6
and blocks ingestion plus credential token refresh, avoiding DNS/IP rotation
bypasses. Root/SSM traffic and inbound sender TLS are unaffected. A host-wide
port 443 block is not an acceptable substitute.

Record the service UID and exact rule hashes, activation/restoration times,
proof of at least 3,600 seconds without destination ingress, queue peak depth
and bytes, accepted identities, and absence of drops. Restore egress only after
the full outage; allow the 1,800-second settle period for recovery. Then run the
independent query below. An identity pass without this separate fault evidence
is not a one-hour buffer qualification. Reconciliation also requires actual
source rate within 5% of the requested rate, matching timestamps and exact
native counter deltas; it does not silently pass an underloaded generator.

Install the guard using the frozen outage plan, 30–900 seconds before its start:

```bash
python3 lab/aws/monitoring/run.py Linux \
  lab/aws/monitoring/destination-outage.sh \
  --state <owned-state.json> --timeout 300 \
  --env BOWER_PLAN_SHA256=<outage-plan-sha256> \
  --env BOWER_GENERATION_START_EPOCH=<plan-startEpoch>
```

The script verifies account, collector ownership and `User=bower`, rejects root
UID and overlapping outage tables, creates a unique owned inet OUTPUT table,
and arms an independent systemd timer **before** installing its drop rule. It
restores at least five seconds after the generation's 3,600-second window.
Setup failure removes the rule immediately and invalidates the attempt. The
restorer verifies the table ownership comment and removes only that table;
it never flushes a shared ruleset. No reboot belongs in this outage scenario:
a changed boot ID or absent rule invalidates duration evidence. The transient
timer is independent of SSM, not a guarantee across host reboot.

Applied/restored reports are uploaded under
`results/firewall/a-destination-outage/<planSHA>/fault/`. The restorer also retains
its local JSON if upload fails. Retrieve both files plus `systemctl status` of
the reported guard unit; require `removed=true`, `bootUnchanged=true`, and
`minimumDurationPassed=true`. The monotonic lower bound measures from completed
rule installation to the start of restoration, so it cannot overstate the
blocked duration. These reports do not replace destination queries showing no
ingress during the outage, queue-capacity sampling, and final identity proof.
If restoration fails, use SSM to inspect the exact owned table/guard, restore
only that rule, and record the failed attempt before teardown.

## 3. Export queue identities safely

The normal SSM response is too small for full identity evidence. The exporter
reads SQLite in read-only mode and projects only event ID and generated/received
timestamps. It does not export payloads, raw envelopes, queue state, or secrets.
It includes current-window extra identities and any old expected identities;
stale rows cause the independent verifier to reject the attempt.
The timestamp parser accepts explicit ISO offsets with up to seven fractional
digits and truncates to microseconds before parsing, including .NET round-trip
queue timestamps on Amazon Linux's Python 3.9. Offset-free, malformed or longer
fractional forms fail; original timestamps remain in the evidence artifact.

Calculate values from the frozen plan:

- `BOWER_PLAN_SHA256`: SHA-256 of the complete plan file bytes.
- `BOWER_SCENARIO`: `scenario` from that plan.
- `BOWER_EXPECTED_BLOCKS`: `expectedBlocks` joined with commas.
- `BOWER_SCOPE_START_EPOCH`: `startEpoch - 2` (timestamp rounding allowance).
- `BOWER_SCOPE_END_EPOCH`: `collectNotBeforeEpoch`.

Run the exporter on the owned Linux collector after source collection settles:

```bash
python3 lab/aws/monitoring/run.py Linux \
  lab/aws/monitoring/export-firewall-queue.sh \
  --state <owned-state.json> --timeout 300 \
  --env BOWER_SCENARIO=<scenario> \
  --env BOWER_PLAN_SHA256=<plan-sha256> \
  --env BOWER_EXPECTED_BLOCKS=<comma-joined-blocks> \
  --env BOWER_SCOPE_START_EPOCH=<start-minus-two> \
  --env BOWER_SCOPE_END_EPOCH=<collect-not-before>
```

The result contains only a unique S3 `key`, SHA-256, byte/row counts, and malformed
row count. The artifact goes under `results/firewall/<scenario>/<planSHA>/` in
the run's bucket. Download that exact key with the configured operator profile
and explicit `ap-southeast-2` region; verify the bytes against the returned hash
before using it. Keep all artifacts under the owned run's local evidence root.
Do not pass thousands of identities through SSM stdout. The complete scoped
history is bounded to 200,000 rows; overflow is a failure, not a truncated pass.

## 4. Query with the separate verifier identity

The Azure preparation must already have created `azure-state.json` and the
private `verifier-identity.pem` in one owner-only state directory. This command
uses only `azure-cli-verifier` in that directory. It logs in with that verifier's
certificate path and checks its app ID, tenant, subscription and workspace scope.
It never uses the operator/ingestion CLI cache or prints token/CLI error bodies.
The certificate must be a non-symlink private file; the cache cannot be a symlink.
No credentials belong in the evidence directory or repository.

The approved target is subscription `945092a0-2500-4b25-85a4-99f1c3135906`,
tenant `f4f33fb1-b681-40d1-a854-6f888d45b891`. The Azure run name may differ from
the AWS run name. The latter determines trusted CollectorId `<RunId>-linux`.

```bash
python3 lab/aws/monitoring/query-firewall.py \
  --plan <new-plan.json> --queue <downloaded-queue-identities.json> \
  --native <first-generator.json> \
  --pack-sha256 <signed-pack-sha256-from-reviewed-collector-manifest> \
  --azure-state-dir <private-azure-state-directory> \
  --output <new-reconciliation-report.json>
```

Repeat `--native` once per generation in plan order (including all idle pulses).
The report path must not exist. Allow ingestion delay before querying, and save
any repeat query to a new path; never overwrite failed evidence.

The query includes the exact trusted CollectorId, application/environment,
event type and source-time window, with a fixed ingestion cutoff. It retrieves
aggregate counts for every identity, not a sample. HTTP redirects, partial
errors, pagination/continuation indications, excessive rows, unexpected schema
and responses above 64 MiB fail closed. A limit of 200,001 aggregate identities
lets the verifier detect the 200,000-identity bound rather than silently accept
truncation.

Reports contain native totals/rates, expected/accepted/Sentinel distinct counts,
missing and extra counts, duplicate Sentinel row count, and SHA-256 hashes of
sorted identity sets. Each hash uses UTF-8 identities sorted lexically, joined
with LF, without a trailing LF (including the empty-set hash). `identityComplete`
requires exact equality across all three sets. `strictPass` additionally
requires zero duplicate destination rows. Duplicates are explicitly retained
as evidence even though the delivery model is at-least-once. Exit 0 means that
strict identity check passed, 1 means incomplete/extra/duplicate identities,
and 2 means malformed evidence, invalid scope, or a failed query. The report's
`scope` remains identity reconciliation only; the parent qualification report
must assess the actual outage, idle, restart and topology evidence separately.
For the one-hour destination outage, compare `sentinel.firstIngested` against
the independently recorded restoration time: any scoped destination row ingested
before restoration invalidates the outage claim, even when all IDs arrive.

## 5. Preserve evidence and remove resources

Keep the plan, native reports, queue metadata, query report, source/artifact
hashes, safe fault evidence and command records. Never retain Azure certificates,
CLI token caches, ingestion environment files or TLS private keys as evidence.
After the full testing session, use the owned AWS and Azure teardown procedures
and verify absence of the run's resources, identities, storage and log workspaces.
The expiry guard alone is not proof of full cleanup.

### Retain sanitized destination identities

Add `--destination-evidence <new-destination-evidence.json>` to the query command
to retain the independently queried aggregate rows before private/cloud cleanup.
Use a distinct, new filename beside the reconciliation report. Both paths must
not exist; repeated delayed-ingestion queries need fresh filenames. Omitting
this option preserves the original report-only behavior.

The optional artifact retains the exact query text/hash and time bounds,
workspace/verifier IDs, plan/pack/verifier hashes, fixed column names, and only
validated synthetic EventId/copy-count/generation/ingestion timestamp rows. It
never copies HTTP headers, tokens, response errors or arbitrary response fields.
The same complete-response/schema/identity/time-window/row-count guards apply;
its serialized size is capped at 64 MiB. The file is created privately (0600),
without overwriting prior evidence, and its byte count/hash is linked from the
reconciliation report. A retained query response does not itself claim delivery:
use the separate reconciliation report's `strictPass` and keep failed attempts.
Public reports may split these already sanitized rows into hashed JSONL sidecars
and keep counts/hashes/query metadata in the readable summary.
