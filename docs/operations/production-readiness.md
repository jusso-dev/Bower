# Production readiness

Status: **not production-ready**. This is a release qualification record, not a
certificate. A successful unit test, HTTP upload or local spool write cannot close
a real destination or operating-system validation gate.

> **Current status (3 November 2026).** The [production-readiness index](../production-readiness/index.md)
> is the current summary of all seven gaps and what is still open. This page keeps the
> history. Since it was first written, firewall delivery over RELP (rsyslog 8.2610.0 as
> the tested sender) closed the forced-kill, reset and collector-stop-plus-sender-reboot
> losses listed under Evidence and blockers ([gap 1](../production-readiness/01-syslog-delivery-reliability.md)).
> Plain TCP/TLS syslog is still not crash-lossless, and other losses recorded on this page
> stand. Storage pressure, upgrades, credential rotation, monitoring and replay-safe
> detections have live evidence with the limits listed in the index. The 24-hour soak
> [failed on both collectors](../production-readiness/07-soak-and-release-validation.md).

## First release candidate

The initial qualification scope is the C# collector on Windows Server 2022
for allow-listed WEF → WEC events, and a Linux collector receiving signed-pack-routed
firewall syslog over mutual TLS. Delivery uses Azure Monitor Logs Ingestion into a
tenant-owned Microsoft Sentinel / Log Analytics workspace, with independent query
verification. The deployment owner has selected this path for the first production
rollout. The owner confirmed subscription `945092a0-2500-4b25-85a4-99f1c3135906`
in tenant `f4f33fb1-b681-40d1-a854-6f888d45b891` for isolated validation.
The selected pilot envelope is **10 events/sec per collector, 100/sec bursts of
60 seconds, and a real one-hour destination outage**. The
[native pilot report](../evidence/pilot-native-20261030/README.md) measures this
synthetic workload on the recorded hosts; it is not a sustained production soak
or approval of arbitrary payloads and appliance implementations.

The Rust runtime, the queue-less Azure Functions endpoint, management UI deployment,
additional sources and optional developer tooling need their own qualification.
Their roadmap features do not by themselves prevent qualifying this smaller path.
Do not generalize an approval of this path to the whole platform.

## Evidence and blockers

The [1 November final-candidate campaign](../evidence/ws6-20261101-final/README.md)
completed its planned final tests, evidence export and session cleanup. Its idle
schedule reconciled all 6,300 native/queue/Sentinel identities with zero missing,
extra or duplicate rows; observed gaps were 299.952, 1,804.015 and 3,903.945 seconds.
The nominal five-minute gap was about 48 ms short of 300 seconds. Windows steady,
burst, one-hour outage and already-admitted queue restart scopes also passed.
Native firewall completeness remains failed for forced kill (21 missing of 6,000),
reset (4 of 1,200), and combined collector stop / sender reboot (2 of 600), despite
every admitted identity reaching Sentinel. The exact pre-admission loss location
is unproven. These failed gates remain open; cleanup does not establish production
readiness. Plain TCP/TLS
cannot acknowledge durable application admission; production requirements that
include crash-lossless firewall delivery need a qualified retained-source replay
workflow or an application-acknowledged transport. See the
[syslog reliability runbook](../production-readiness/01-syslog-delivery-reliability.md).

Initial audit baseline: main `9eb7af047702dbde60e4e49773784e0db4704f59`, including PR #157.
Existing AWS results are from the documented `473c6ec` backport artifact, not a test
of every subsequent main change. Re-run against the release candidate hashes.

| Gate | Existing evidence | Required before release |
| --- | --- | --- |
| Native source ingestion | [Prior AWS report](../evidence/aws-native-20261030/README.md) plus [packaged Sentinel campaign](../evidence/sentinel-native-20261030/README.md): real WEF and nftables traffic, with the syslog idle-loss finding retained. | Test the final production sender profile, source log rollover and source outages; establish source retention/replay. |
| Sentinel delivery and privacy | [Live campaign](../evidence/sentinel-native-20261030/README.md) queries the confirmed tenant using a separate reader, reconciles native/queue identities, checks privacy sentinels and rejects cross-role access. | Repeat for the signed release and intended workspace/configuration. Broaden adversarial privacy coverage beyond the synthetic sentinels used here. |
| Crash and restart recovery | [#154](https://github.com/jusso-dev/Bower/issues/154) remains the failed five-minute-lease baseline. The live campaign records accepted-event crash recovery with the 90/60-second profile and independently queried ingestion timestamps. | Repeat under sustained load, throttling and the declared outage budget; preserve at-least-once duplicate accounting. |
| Windows service reboot | #154 measured 130.6–131.9 seconds with delayed startup. The candidate MSI disables that delay; live campaign evidence records service startup and accepted-event arrival after reboot. | Repeat with the signed production package and populated upgrade state. |
| Queue and disk pressure | [Storage pressure](../production-readiness/03-storage-pressure.md): free-space watermarks, settlement room, pressure retention and `storage` status, with AWS runs on 1 GiB and 2 GiB queue volumes that found and fixed a drain deadlock. Syslog TCP loses frames held in socket buffers if the collector restarts while backpressured. | Repeat with the signed release; qualify each syslog sender's replay. Port watermarks, pressure retention and `storage` status to the Rust collector (the page limits are ported). Spool and archive volumes, power loss and restore remain unproven. |
| Sustained capacity and outage budget | [Native pilot](../evidence/pilot-native-20261030/README.md): 10/sec, 100/sec bursts for 60 sec, one-hour outage on each collector; 59,400 distinct source events reconciled per final campaign, 48.5/55.8-sec firewall/WEC drain. Four Windows replayed rows fail the retained strict zero-duplicate check. Two earlier firewall source-loss attempts remain recorded. | Repeat the measured envelope with the signed release and actual sender/payload distribution. Qualify longer operation, production retention and query/alert replay handling. The 81-minute campaigns do not establish multi-day soak or exactly-once delivery. |
| Authentication, keys and privacy | Default-deny routing, redaction before persistence, signed packs and client-certificate rejection have local/AWS evidence. The [credential and security-failure campaign](../evidence/ws5-20261031-074543/README.md) exercised expired/revoked/disabled Entra credentials, role removal, wrong tenant, secret/certificate/HMAC/CA/CRL rotation, rejected packs and adversarial payloads against a disposable Sentinel workspace and AWS syslog host ([runbook](../production-readiness/05-credential-rotation-and-security-failures.md)). | Test expired/revoked credentials, certificate and HMAC-key rotation, malicious payloads, unsigned/untrusted packs and incorrect policy on the release deployment. Check durable files and reports for raw privacy sentinels. |
| Signed distribution and upgrades | Installer and optional signing machinery exist. [Populated upgrade, crash, power-loss and restore evidence](../evidence/ws4-20261031-074918/README.md) on unsigned dev.264 → 270 → 277 RPM/MSI/Docker reconciles every accepted event at Sentinel, including the WEC v1 → v2 migration. The [recovery guide](../production-readiness/04-upgrade-backup-recovery.md) documents downgrades and limits. | Verify actual signed release artifacts and trusted pack provenance. Release versions must bump `major.minor.patch` (MSI cannot block dev-build downgrades). Kubernetes, Azure VM and DEB upgrades were not run live. |
| Operations and reproducible evidence | Source/queue reports, screenshots and [AWS cleanup proof](../evidence/aws-native-20261030/cleanup.json) are committed. [Alerts and runbooks](../production-readiness/06-monitoring-and-runbooks.md) were exercised live ([evidence](../evidence/ws6-20261031-074751/README.md)); the drill found a queue page-ceiling delivery stall. | Validate actionable alerts for source silence, destination failure, queue age/capacity and disk pressure. Exercise audited replay (queue restore is [exercised](../evidence/ws4-20261031-074918/README.md)). Publish the release manifest, configuration hashes, query results, measurements and final resource cleanup. |

## Current recovery work

The C# delivery worker now requests output cancellation before lease expiry. Defaults keep
the five-minute lease and use a four-minute output deadline. Qualification can set
`BOWER_DELIVERY_LEASE_SECONDS=90` and `BOWER_DELIVERY_TIMEOUT_SECONDS=60`.
The live campaign below measures this profile; changing the settings alone is not
recovery evidence for another deployment.
Timeouts preserve events and their retry budget. Live leases are never reset at
startup. See [deadline semantics and regression coverage](queue-v5-durability.md#c-delivery-deadlines-and-restart-recovery).

## Qualification procedure

1. Confirm the intended Azure tenant/subscription/workspace, deployment owner and
   workload envelope. A cached CLI login does not select the production target.
   Choose explicit pass/fail latency, capacity, outage and recovery limits before
   running the campaign; retain failed measurements.
2. Freeze source commit, binaries, packages, trusted packs, schemas, DCR and
   configuration hashes. Record OS/runtime versions and all resource identifiers.
   Use isolated resources and test identities; keep secrets out of evidence.
3. Run repository build, formatting and regression checks, including the native
   Windows tests. Verify signatures and install those same artifacts in the lab.
4. Exercise real WEF and firewall traffic through the intended delivery path.
   Persist a bounded manifest of expected identities before fault injection.
   Run restart/reboot, storage pressure, destination failure, upgrade, credential
   rotation and sustained-load scenarios. Capture reports and screenshots that
   identify which observations are live and which render recorded evidence.
5. Use an independently authorized query identity to reconcile destination events
   after the declared ingestion window. Any inaccessible evidence, missing event,
   unexplained duplicate or privacy leak leaves its gate open. An upload 2xx alone
   cannot pass this step. Document the inherent at-least-once delivery boundary.
6. Review the evidence and remaining operational risks for the exact release and
   workload. Remove temporary infrastructure at the end of the testing session and
   verify cleanup. Only then change the readiness statement to name the supported
   deployment and limits. Expand support through additional qualification runs.

## Live Sentinel qualification

The [30 October campaign](../evidence/sentinel-native-20261030/README.md) deployed
the packages from commit `26446690fae7d123e2dfaf117d63467f1f55d37d` (PR #158,
merged as `2250bd190e326db99bb5333cbbdfde04ff9f8801`). It used the MSI virtual service
account and RPM `bower` user, signed parser packs, and a separate query-only identity.
The report records native-event identity reconciliation, pre-persistence privacy,
destination ingestion timestamps, recovery, failed attempts and cleanup.

Live Azure deployment exposed a case-sensitive schema mismatch: DCR stream timestamp
types must be `datetime`, while Log Analytics table columns use `dateTime`.
The Bicep correction and an exact-case regression now cover this difference.

The syslog campaign also found two events lost before collector acceptance after an
idle TLS connection closed. A sender reconnect profile passed subsequent tests, but
this does not add durable application acknowledgements to syslog. Preserve the loss
finding and qualify each actual appliance/sender and its replay behavior. The
short campaign does not close the capacity, disk-pressure, key-rotation, upgrade,
release-signing, restore or operational-alert gates in the table above.

## Native pilot envelope

The [pilot profile and reproduction guide](../../lab/aws/PILOT.md) add complete
native-source, one-hour outage, resource and destination measurements. Windows
retained 45,090 pending events for a 3,606.15-second outage; the final firewall
attempt retained 41,681 for 3,600.34 seconds. Both recovered while new traffic
continued at 10/sec. Connected steady ingestion p95/p99 were 8.23/9.08 seconds for
Windows and 5.79/6.65 seconds for the firewall.

Two firewall attempts lost 768 and 43 native events before durable acceptance.
Increasing the bounded journal input allowance alone did not remove the loss.
The final persistent mutual-TLS connection, with a 3,600-second listener idle
timeout, accepted and delivered all 59,400 campaign events. This comparison does
not establish the exact mechanism of the earlier loss or qualify long idle gaps,
transport resets, power loss or another appliance's retention/replay behavior.

Windows delivered all 59,400 distinct campaign identities, with four extra rows
at the outage boundary and after recovery. The strict assessment remains failed;
separate at-least-once identity observations do not override it. A tested
query-time deduplication example is included, but scheduled-alert suppression and
outage-aware lookback still need qualification.

The packages remain unsigned development artifacts. Release-signing identities
are not configured. Populated upgrades, key rotation, storage pressure, restore,
operational alerts and a sustained soak remain open; this pilot does not authorize
changing the production-readiness status.
