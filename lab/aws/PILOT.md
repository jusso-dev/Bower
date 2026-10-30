# Native WEC and firewall pilot

This operator-sequenced campaign qualifies the envelope in
[`pilot-envelope.json`](pilot-envelope.json) **per collector**. It uses a real
Windows domain controller, WEF/WEC, and nftables kernel logging through rsyslog
mutual TLS. The seven-host relay/local-spool lab described in `README.md` is a
different topology. The pilot scripts do not create infrastructure or establish
production release readiness.

## Prerequisites

- Disposable, ownership-tagged private hosts, SSM access, encrypted disks, and an
  independent expiry guard. Keep the source running only for the testing session.
- An installed, hash-recorded collector package and trusted, signed packs. Record
  whether the installer itself is signed; development package checksums are not
  production release signatures.
- A separately authorized Sentinel query identity. Ingestion and query identities
  must fail each other's access tests. Never export credentials or queue files.
- Windows `Security` and `ForwardedEvents` log capacity of 1 GiB. WEC must allow
  the actual source computer; a domain controller needs the Domain Controllers
  group in the subscription ACL. Complete a native preflight before measuring.
- On WEC, `NT SERVICE\Bower`, read access to `ForwardedEvents`, source batch size
  256, and the `windows-security-logon` profile selecting network-type 4625 failures
  with a valid source IP. The synthetic nonexistent `bower-probe` account prevents
  locking a real account. Use only the isolated `172.31.240.0/24` lab.
- On Linux, the restricted `bower` service user, the `bower-client` namespace and
  `bower_validation` nftables table. The generator sends actual packets to the
  namespace's local firewall peer; it does not inject directly into the collector.
  Build the isolated [`nftables-validation`](packs/nftables-validation/pack.yaml)
  pack with an ephemeral lab signing key and explicitly trust its public key.
  Its source files reproduce the deployed parser/policy/privacy/sample bytes;
  it is a lab fixture, not a generic appliance pack or a production signing identity.
- Delivery lease 90 seconds and output deadline 60 seconds on both collectors.
  This campaign deliberately blocks only collector HTTPS, preserving source flow.

## Sender capacity matters

The initial sender used authenticated TLS with `RebindInterval="1"`, a disk-assisted
action queue (`queue.type="LinkedList"`, `queue.filename="bower-firewall"`,
`queue.saveOnShutdown="on"`) and unlimited action retries. Reconnecting for every
event avoided an earlier idle-close loss in a short run, but failed the full pilot.
The second attempt lost 43 of 59,400 native events before Bower frame acceptance,
despite no reported Bower parser errors or frame drops. TLS reconnect diagnostics
also flooded the journal. Preserve both failures.

The next candidate uses `RebindInterval="0"` (a persistent connection) and
`idleTimeoutSeconds: 3600` on the Bower listener. Certificate/name validation and
client certificate authentication remain enabled. A 1,100-event preflight,
including a 75-second idle gap, passed before the complete pilot was repeated.
Consult the recorded final result; this preflight alone is not qualification.
The longer idle timeout is bounded but keeps inactive connections open longer.
This profile does not cover an idle gap of an hour, process crashes or transport
resets. Neither TLS nor a disk-assisted queue adds a durable application-level
syslog acknowledgement, and `saveOnShutdown` is not a power-loss guarantee.

The first pilot attempt encountered the rsyslog `imjournal` default of 20,000
messages per 600 seconds. TLS reconnect diagnostics also consume that input budget.
For subsequent fixtures, the existing `imjournal` module declaration includes
`Ratelimit.Interval="600" Ratelimit.Burst="200000"`. This is a bounded increase,
not disabling source limits. Run `rsyslogd -N1` before restarting the sender.
Size the actual appliance's source buffers, diagnostic volume and replay policy;
do not copy the value into a production sender without measuring its traffic.

## Timed sequence

| Phase | Rate | Duration | Events per collector |
| --- | ---: | ---: | ---: |
| Connected steady | 10/sec | 600 sec | 6,000 |
| Connected burst | 100/sec | 60 sec | 6,000 |
| Outage burst | 100/sec | 60 sec | 6,000 |
| Outage steady | 10/sec | 3,540 sec | 35,400 |
| Recovery with live traffic | 10/sec | 600 sec | 6,000 |

The complete run generates 59,400 events per collector. Require at least a real
hour of destination isolation, retention of the 41,400-event outage population,
and draining the retained backlog within ten minutes while new traffic continues.
Do not shorten the hour, reset the queue, or discard failed attempts to pass.

Before **each** Linux, Windows source, WEC or probe command, verify the expected
AWS account with `aws sts get-caller-identity` using the intended profile and
region. Describe each explicit target instance ID from the current run's recorded
stack outputs and require both `Project=bower-lab` and `RunId=RUN_ID` tags, plus
the expected instance state. Refuse execution on any missing or mismatched tag,
account, ID or state. Issue SSM commands to those verified instance IDs; never
select targets by a broad Role tag alone. Repeat ownership checks before apply
and teardown. The host scripts' service-account, namespace and nftables checks
are additional checks, not proof of AWS ownership.

Run `scripts/pilot-native-linux.py --run-id RUN_ID` as root on the disposable
firewall. It checks the service identity and owned source fixtures, records its
initial counters, installs/removes a dedicated outage table, and writes bounded
metadata to `/var/lib/bower-pilot/`. Validate the nft rule with `nft -c` before
starting; a syntax failure invalidated the first attempt.

Run `scripts/pilot-native-windows.ps1 -Target DC_IP -StartAt UTC -RunId RUN_ID
-Preflight` on the separate Windows source first. It must complete 1,000 native
LDAP authentication failures in ten seconds, return only LDAP result 49 and
produce matching native/WEC/queue/destination identities. The full generator
uses the same command without `-Preflight`; run `scripts/pilot-wec-monitor.ps1`
on WEC with the same future `-StartAt` and `-RunId`. Both reject stale starts.
The monitor requests isolation near the source outage window and checks the actual
blocked duration; its five-second sampling cadence and forwarding delay affect
phase boundaries. Keep clock synchronization enabled and record measured timing
rather than assuming that scheduled source phases equal network fault timestamps.

## Independent proof

Publish `probes/Bower.PilotProbe/Bower.PilotProbe.csproj` for `win-x64` and record
the archive hash. Run the executable with `source UTC_START` on the domain
controller and `wec UTC_START` on WEC. The probe reads native event records,
reconstructs source identities, scans queue payloads and DB/WAL for the synthetic
username, and reports only counts/digests and privacy booleans. It does not export
raw payloads. Run the final probe after the generator and backlog drain finish;
its database and native-log reads are not an atomic live snapshot.

The probe deliberately caps **all examined records**, including records before
`UTC_START`, at 150,000 per native-log or queue scan; each database/WAL file scan
is capped at 1 GiB. The date filter limits the reported campaign population, not
the work budget. A large retained history can therefore block a probe even when
the current campaign has fewer records. Use a fresh disposable lab for another
campaign and preserve the earlier evidence. Do not clear history or move the cap
after the filter to make a run pass: that would remove the bound on parsing old
records. A limit failure is unavailable evidence, never successful qualification.

This probe is specific to the tested signed profile: default privacy detectors
plus `actor.username` HMAC. It applies those default detectors to reconstructed
event identities before comparing them with persisted identities. The default
detectors can mask a generated ID as a false positive. Retain the original native
digest and transformed digest, report the number changed, and require no identity
collisions. Do not bypass redaction to make digests match. Different privacy
profiles require a corresponding verifier and new evidence.

Independently query Sentinel for `EventId`, `EventType`, `PolicyHash`,
`TimeGenerated`, ingestion time, and boolean privacy-sentinel matches. Reject
partial query results. Compare exact distinct counts and SHA-256 of the sorted
IDs joined by `\n`, without a trailing newline. Count duplicates separately;
`dcount()` is approximate and must not establish exact identity equality.
Scope the Windows campaign to its recorded UTC start, excluding bootstrap trials.
Linux's final digest includes its recorded initial accepted population; subtract
that baseline for the new source population and preserve any earlier failed run.

`scripts/query-pilot.py` implements this query and records exact hashes and
p50/p95/p99 latency. Authenticate the separate verifier beforehand in an isolated
Azure CLI cache, then pass `--azure-config-dir`, `--workspace-id`, `--tenant-id`,
`--verifier-client-id`, `--windows-since` and `--output`. It verifies the active
service-principal identity, rejects the operator's default cache, bounds response
size and emits metadata only. It never writes the retrieved access token or raw
envelope to the report. Keep the publisher/query cross-role access evidence
alongside the result; a supplied identity name alone does not prove least privilege.
For final qualification also pass `--linux-since` from the Linux report's
`startedAt`. This separates the corrected campaign from earlier failed attempts.
Connected-steady latency covers the first 600 seconds of each campaign's source
timestamps; whole-campaign latency intentionally includes the destination outage.

Use `scripts/assess-pilot.py` with the six measurement reports (`--linux`,
`--generator`, `--monitor`, `--source`, `--wec`, `--destination`) and a required
`--policies` JSON file containing nonempty `linux` and `windows` arrays of expected
`sha256:...` policy hashes. Pin these from the manifests of the installed packs
after `bower pack verify FILE --trusted-key PUBLIC.pem` succeeds. Record the
archive and trusted-key hashes; do not derive the expected values from the queue
or destination being checked. See the recorded
[policy pins](../../docs/evidence/pilot-native-20261030/expected-policies.json).
The assessor requires exact policy sets in both Linux destination scopes and in
the Windows queue and destination. It rejects
missing evidence, incomplete phases, mismatched windows, loss, collisions,
duplicates, privacy failures and missing resource measurements. Supplemental
`destinationObservations` compare distinct identities under at-least-once delivery
and report duplicate rows; they never override the strict zero-duplicate verdict.
An acknowledgement can be ambiguous during destination failure, so production
queries and detections must handle replay explicitly. Its result covers
the declared pilot only. Retain CPU/RSS/disk extrema, p95/p99 ingestion latency,
source and queue digests, failures, and the exact executed artifact hashes.

For a query over a declared window, collapse retries by collector and event identity:

```kusto
BowerSecurity_CL
| where TimeGenerated >= datetime(2026-10-30T09:28:00Z)
| where EventType == "authentication_failure"
| extend BowerIngested = ingestion_time()
| summarize arg_max(BowerIngested, *) by CollectorId, EventId
```

This is query-time deduplication, not exactly-once storage or alert execution.
Scheduled detections also need outage-aware lookback and suppression across their
overlapping runs. A duplicate arriving after an hour can fall into another ingestion
window; validating one query does not qualify that alerting design.

Finally remove the owned AWS stack, artifact objects, Azure resource group and
temporary app identities. Verify their absence independently. Preserve shared
networking and the operator's normal cloud login. The expiry guard is a fallback,
not cleanup proof.
