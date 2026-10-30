# Production readiness

Status: **not production-ready**. This is a release qualification record, not a
certificate. A successful unit test, HTTP upload or local spool write cannot close
a real destination or operating-system validation gate.

## First release candidate

The initial qualification scope is the C# collector on Windows Server 2022
for allow-listed WEF → WEC events, and a Linux collector receiving signed-pack-routed
firewall syslog over mutual TLS. Delivery uses Azure Monitor Logs Ingestion into a
tenant-owned Microsoft Sentinel / Log Analytics workspace, with independent query
verification. The deployment owner has selected this path for the first production
rollout. The tenant target and supported workload envelope still need confirmation.

The Rust runtime, the queue-less Azure Functions endpoint, management UI deployment,
additional sources and optional developer tooling need their own qualification.
Their roadmap features do not by themselves prevent qualifying this smaller path.
Do not generalize an approval of this path to the whole platform.

## Evidence and blockers

Audit baseline: main `9eb7af047702dbde60e4e49773784e0db4704f59`, including PR #157.
Existing AWS results are from the documented `473c6ec` backport artifact, not a test
of every subsequent main change. Re-run against the release candidate hashes.

| Gate | Existing evidence | Required before release |
| --- | --- | --- |
| Native source ingestion | [AWS native report](../evidence/aws-native-20261030/README.md): 22 real Windows 4625 events from two origins, 8 recovered after outage; 10 actual nftables drops through mutual TLS syslog. | Repeat on the exact signed candidate with the production allow-list and parser packs; test source log rollover, source outage and malformed input. |
| Sentinel delivery and privacy | Prior AWS evidence ends at a local AMA spool. Query-verification code exists, but this deployment has no tenant-verified run. | Confirm subscription/workspace, DCR and least-privilege identities. Query for every expected event ID and privacy sentinel; record missing, unexpected and duplicate counts independently of upload responses. |
| Crash and restart recovery | [#154](https://github.com/jusso-dev/Bower/issues/154): process health recovered in 6.04 seconds but delivery waited for five-minute leases. Configurable C# deadlines and restart regressions now provide a candidate recovery profile. | Kill a process with in-flight accepted events, restart and measure arrival, not only health. Keep the 120-second lab recovery target and its original failed result. Prove no accepted loss; report any at-least-once duplicates. |
| Windows service reboot | #154 measured 130.6–131.9 seconds with delayed automatic startup. The candidate MSI now disables that delay; installer CI checks the installed setting. | Build/install the candidate package and repeat the Windows reboot and destination-arrival measurement. Removing a startup delay alone is not evidence that the recovery target passed. |
| Queue and disk pressure | WAL, explicit `synchronous=FULL`, transactional acknowledgements, lease fencing, a DB/WAL cap and acknowledged-row retention exist. Parts of [#138](https://github.com/jusso-dev/Bower/issues/138) predate these fixes. | Verify source backpressure under a full queue and low free space on queue/spool/archive volumes. Add early alerts and safe recovery before the hard cap. Never discard unacknowledged data to pass a capacity test. Power-loss certification remains unproven. |
| Sustained capacity and outage budget | [#153](https://github.com/jusso-dev/Bower/issues/153) records local-output throughput/latency limits on small AWS instances; short synthetic runs are not a soak. | Declare event rate, burst size, payload distribution, host size, retention and outage budget. Run sustained WEC/syslog traffic, destination outage and backlog drain; report p95/p99 latency, loss, duplicate counts, CPU, memory and disk growth. |
| Authentication, keys and privacy | Default-deny routing, redaction before persistence, signed packs and client-certificate rejection have local/AWS evidence. | Test expired/revoked credentials, certificate and HMAC-key rotation, malicious payloads, unsigned/untrusted packs and incorrect policy on the release deployment. Check durable files and reports for raw privacy sentinels. |
| Signed distribution and upgrades | Installer and optional signing machinery exist. WEC v1 → v2 bookmark migration has local/CI coverage; fresh AWS databases did not test that migration. | Verify actual signed release artifacts and trusted pack provenance; install, upgrade a populated queue/bookmark store, restart and uninstall without losing accepted data. Document the supported recovery path and incompatible downgrades. |
| Operations and reproducible evidence | Source/queue reports, screenshots and [AWS cleanup proof](../evidence/aws-native-20261030/cleanup.json) are committed. | Validate actionable alerts for source silence, destination failure, queue age/capacity and disk pressure. Exercise restore and audited replay. Publish the release manifest, configuration hashes, query results, measurements and final resource cleanup. |

## Current recovery work

The C# delivery worker now requests output cancellation before lease expiry. Defaults keep
the five-minute lease and use a four-minute output deadline. Qualification can set
`BOWER_DELIVERY_LEASE_SECONDS=90` and `BOWER_DELIVERY_TIMEOUT_SECONDS=60`; this is a
test profile, not a claim that AWS or Windows has passed a new recovery campaign.
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

No Azure infrastructure has been provisioned by this readiness audit. The existing
AWS validation resources were removed. Destination qualification remains blocked
on selecting the intended tenant target; no production-readiness approval is implied.
