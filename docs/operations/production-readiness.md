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
rollout. The owner confirmed subscription `945092a0-2500-4b25-85a4-99f1c3135906`
in tenant `f4f33fb1-b681-40d1-a854-6f888d45b891` for isolated validation.
A short 10-events/second firewall qualification is not a supported workload envelope
or a sustained production soak.

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
| Native source ingestion | [Prior AWS report](../evidence/aws-native-20261030/README.md) plus [packaged Sentinel campaign](../evidence/sentinel-native-20261030/README.md): real WEF and nftables traffic, with the syslog idle-loss finding retained. | Test the final production sender profile, source log rollover and source outages; establish source retention/replay. |
| Sentinel delivery and privacy | [Live campaign](../evidence/sentinel-native-20261030/README.md) queries the confirmed tenant using a separate reader, reconciles native/queue identities, checks privacy sentinels and rejects cross-role access. | Repeat for the signed release and intended workspace/configuration. Broaden adversarial privacy coverage beyond the synthetic sentinels used here. |
| Crash and restart recovery | [#154](https://github.com/jusso-dev/Bower/issues/154) remains the failed five-minute-lease baseline. The live campaign records accepted-event crash recovery with the 90/60-second profile and independently queried ingestion timestamps. | Repeat under sustained load, throttling and the declared outage budget; preserve at-least-once duplicate accounting. |
| Windows service reboot | #154 measured 130.6–131.9 seconds with delayed startup. The candidate MSI disables that delay; live campaign evidence records service startup and accepted-event arrival after reboot. | Repeat with the signed production package and populated upgrade state. |
| Queue and disk pressure | WAL, explicit `synchronous=FULL`, transactional acknowledgements, lease fencing, a DB/WAL cap and acknowledged-row retention exist. Parts of [#138](https://github.com/jusso-dev/Bower/issues/138) predate these fixes. | Verify source backpressure under a full queue and low free space on queue/spool/archive volumes. Add early alerts and safe recovery before the hard cap. Never discard unacknowledged data to pass a capacity test. Power-loss certification remains unproven. |
| Sustained capacity and outage budget | [#153](https://github.com/jusso-dev/Bower/issues/153) records local-output throughput/latency limits on small AWS instances; short synthetic runs are not a soak. | Declare event rate, burst size, payload distribution, host size, retention and outage budget. Run sustained WEC/syslog traffic, destination outage and backlog drain; report p95/p99 latency, loss, duplicate counts, CPU, memory and disk growth. |
| Authentication, keys and privacy | Default-deny routing, redaction before persistence, signed packs and client-certificate rejection have local/AWS evidence. | Test expired/revoked credentials, certificate and HMAC-key rotation, malicious payloads, unsigned/untrusted packs and incorrect policy on the release deployment. Check durable files and reports for raw privacy sentinels. |
| Signed distribution and upgrades | Installer and optional signing machinery exist. WEC v1 → v2 bookmark migration has local/CI coverage; fresh AWS databases did not test that migration. | Verify actual signed release artifacts and trusted pack provenance; install, upgrade a populated queue/bookmark store, restart and uninstall without losing accepted data. Document the supported recovery path and incompatible downgrades. |
| Operations and reproducible evidence | Source/queue reports, screenshots and [AWS cleanup proof](../evidence/aws-native-20261030/cleanup.json) are committed. | Validate actionable alerts for source silence, destination failure, queue age/capacity and disk pressure. Exercise restore and audited replay. Publish the release manifest, configuration hashes, query results, measurements and final resource cleanup. |

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
