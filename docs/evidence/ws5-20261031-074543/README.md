# Credential rotation and security failures — 31 October 2026

**Every credential failure tested kept its events and delivered them exactly once
after the fix. Five defects were found and fixed. Refused syslog senders lose frames
at the sender, and that limit is retained.** Release packages are unsigned
development builds; this is not production approval. Runbook:
[05 — credential rotation and security failures](../../production-readiness/05-credential-rotation-and-security-failures.md).

Run `bower-ws5-20261031-074543`, branch
`prod-readiness/05-credential-rotation-and-security-failures` from `main` @ `9d1bbcd`.
[Artifact hashes](artifact-manifest.json) · [infrastructure](infrastructure.json) ·
[cleanup audit](cleanup.json) (34/34 checks passed) · [local checks](local-checks.json).

## Where it ran

- **Azure** (subscription `945092a0-2500-4b25-85a4-99f1c3135906`, tenant
  `f4f33fb1-…`, `australiaeast`): new resource group `rg-bower-ws5-20261031-074543`.
  It held a new Log Analytics workspace and the repository Bicep (`deploy/bicep/main.bicep`:
  `BowerSecurity_CL`, DCE, DCR). There were six publisher applications, each with
  Monitoring Metrics Publisher on the DCR only, plus one verifier with Log Analytics
  Reader on the workspace only. Every destination count below comes from the verifier,
  in an isolated Azure CLI cache.
- **Collectors for the Azure cases** ran on the operator's macOS arm64 host, one process
  per case with its own queue. Two builds were used:
  - **baseline**: unchanged `main` build. It ran the long-lived expire, revoke, role and
    disable processes started before the fix.
  - **candidate**: built from this branch. It ran every later process.
  Delivery lease 90 s, timeout 60 s.
- **AWS** (account `959038055523`, `ap-southeast-2`): one private `t4g.small` Amazon Linux
  2023 host.
  - Network: SSM only, no public address, no inbound rule, HTTPS egress only. Its own
    `/24` subnet routed through the existing default-VPC NAT gateway, which was
    referenced and not modified.
  - Hardening: encrypted 10 GiB disk, IMDSv2, terminate on shutdown, and a persistent
    8-hour systemd power-off timer.
  - Software: the linux-arm64 candidate collector and rsyslog 8.2204 (`ossl` driver) on
    loopback mutual TLS. OpenSSL 3.5 `openssl ca` issued every certificate and CRL on
    the host, so no private key left it.
  - No local Docker runtime was available, so containers were not exercised live.

## Azure ingestion credential failures

Each case:
1. Started a collector.
2. Sent 20 baseline events (all delivered).
3. Changed the credential.
4. Started a **fresh** process, because a running process hides the fault behind its
   cached token, and sent 20 more.
5. Watched the queue and logs.
6. Fixed the credential.
7. Reconciled exact IDs at the destination.

Long-lived processes received 5 more events every 5 minutes to measure the cached-token
window. [Per-case timelines and measurements](azure-credential-cases.json).

| Case | Code while broken (candidate) | Measured | Recovery | Destination |
| --- | --- | --- | --- | --- |
| (a) Secret expired (end 08:14:22Z) | `destination-azure-credential-failed` | Entra still issued tokens at 08:17:30 and 08:18:31; refused from 08:21:33 (**4–7 min lag**) | New secret + restart: held events delivered 41 s later | 30/30 fresh, 120/120 long-lived |
| (b) Secret deleted 07:53:15 | same | Fresh process failed at once; long-lived delivered until **08:50:38 (57 min)** | New secret + restart | 20/20, 120/120 |
| (c) Role removed 07:53:21 | `destination-azure-http-403` | Last success 08:04:56, first refusal 08:10:03 (**11.6–16.7 min**) | Re-assigned 08:59:39 → 50 held events delivered 09:05:19, **no restart** | 120/120, 20/20 |
| (d) Service principal disabled 07:53:23 | `credential-failed` | As (b) for cached tokens | Re-enabled 08:59:36 → delivered 5–31 s later, **no restart** | 120/120, 20/20 |
| (e) Wrong tenant | `credential-failed` (attempt ~10 s) | 30 s cadence | Corrected tenant + restart | 20/20 |
| (e) Reader identity used to ingest | `destination-azure-http-403` | 30 s cadence | Publisher identity + restart | 20/20 |
| (f) Certificate overlap rotation | none | cert1 → cert2 added → fresh process on cert2 → cert1 removed: all delivered | — | 40/40 |
| (f) Certificate file swapped in place, no restart | `credential-failed` at **09:28:38**, when the cached token expired | The process kept cert1 from start and ignored the valid cert2 file | Restart → drained | 105/105 |
| (g) Secret overlap rotation | none | s1 → add s2 → restart on s2 → delete s1 | — | 80/80 |
| (g) Secret rotation without overlap | `credential-failed` | 20 events held | New secret + restart → delivered 25 s later | 40/40 |

The baseline binary logged nothing for (a), (b), (d) and (e). It recorded
`destination-azure-unavailable`, the same code as a network outage. That was the defect.
The candidate logs event 1008 every 30.1–30.2 s (median) per held batch.

Other results:
- **Exact reconciliation:** all 17 collector IDs, 1,090 delivered events. The delivered
  ID set equals the destination ID set (SHA-256), with **0 missing and 0 duplicate
  rows**. [Reconciliation](destination-reconciliation.json).
- **Leak scan:** across every case's queue DB, WAL and SHM, collector log and status
  output there were **0 matches** for any configured secret value and **0 JWT-shaped
  strings**.
- **Access separation:** publisher query denied (`InsufficientAccessError`); verifier
  query allowed; verifier ingestion `http-403`. [Access check](azure-access-check.json).

## HMAC key rotation

The collector restarted with key ID `k2` on the same queue. 7 synthetic accounts went
under each key:
- 21 rows per key, 7 distinct pseudonyms per key, prefixes `hmac-sha256:k1:` and
  `hmac-sha256:k2:`;
- **0 pseudonyms join across the keys**;
- 0 raw usernames at the destination.

[HMAC evidence](hmac-rotation.json).

## Syslog mutual TLS on Amazon Linux

rsyslog (persistent session, octet counting, `x509/name`, disk-assisted queue) sent
sequence-numbered frames at 10/sec. Bower's queue was reconciled by sequence.
[Campaign report](syslog-tls-rotation.json).

| Phase | Sent | Accepted | Notes |
| --- | ---: | ---: | --- |
| Baseline | 100 | 100 | One session |
| Server certificate replaced during traffic | 100 | 100 | `tlsReloads` 1; new handshake served the new certificate; **0 sender reconnects** |
| Client CA overlap → sender moved to new CA → old CA removed | 100 | 100 | Old-CA handshake refused after removal; new-CA accepted |
| Emergency revocation of the connected sender (CRL) | 100 | 60 | Session closed (`tlsSessionsClosed` 1); reconnects refused (`tlsRevoked` 39); **all 40 frames sent while revoked lost at rsyslog**; 30/30 after re-issue |
| Same with the sender capped at TLS 1.2 ([report](syslog-tls12-refusal.json)) | 100 | 60 | Also 40 lost with the sender configured for TLS 1.2 at most (the negotiated version was not captured): rsyslog 8.2204 `ossl` writes one frame into each refused session in both runs |
| Refused certificates | — | — | Expired, untrusted CA, revoked, server-purpose-only, removed-CA and no certificate: all refused |
| Wrong server name | 30 | 30 | rsyslog refused (`peer name not authorized`), queued, delivered after the right certificate returned; 1 replayed frame deduplicated |
| Key not matching certificate | — | — | `tlsReloadFailures` 1; old certificate still served |
| Collector `systemctl restart` under load | 100 | 99 | **1 frame lost** (sequence 461): why rotation must not need a restart |

## Malicious payloads and privacy sweep

**Syslog**, on the live host against a fuzz listener (5 s idle, 8 connections, 8 KiB
frames). [Report](syslog-adversarial.json).
- Bounded rejections:
  - invalid UTF-8 → `malformed`;
  - oversize, octet-count overflow and huge structured data → `oversized`;
  - an octet count larger than sent → `timeouts`;
  - zero, negative and garbage counts → `framingErrors`;
  - slow-loris closed after 6.0 s.
- Floods: 32 of 40 TLS connections were refused at the limit and legitimate traffic
  continued; 6 incomplete handshakes were closed.
- A 1,000-frame burst was fully queued.
- NUL, control and ANSI characters and injection strings were queued as data.
- **CRLF injection in an LF-framed message produced a second, forged frame.**
- Raw markers (AWS key, JWT, GitHub token, card, TFN, password, sentinel) placed in
  hostname, proc-id, msg-id, structured data and message: **0 matches** in queue
  DB/WAL/SHM, collector journal and status. RSS afterwards was 141 MiB.

**HTTP ingest to Sentinel.** 40 redaction-detector samples went into every free-text
field, plus 3 allowed-by-policy identifiers and 11 injection strings.
[Report](http-adversarial.json).
- Outcomes:
  - Masked identifiers were accepted (`redactandaccept`).
  - Secret-bearing events whose redaction removed every actor field were quarantined
    (400, default deny).
  - Depth-40 attributes, lone-surrogate escapes and duplicate top-level keys were
    quarantined.
  - Invalid JSON returned 400.
  - A body over 1 MiB closed the connection.
- **0 raw markers** in queue DB/WAL/SHM, log and status, and **0 in 28 of the 29
  accepted Sentinel rows**. The 29th row (its event ID masked, see below) fell outside
  the destination query's ID-prefix scope. It was checked only in the local queue, whose
  stored payload is the uploaded body.
- Allowed identifiers (ABN, ACN, SWIFT) arrived as configured.
- The 11 injection strings arrived **byte-exact**, including NUL, ESC, CRLF, U+202E
  and `=HYPERLINK(…)`.
- Findings:
  - A 70,000-character value repeated across fields was **dead-lettered** by schema
    preflight (`preflight-field-too-large`).
  - The driver-licence detector masked digits inside an event ID containing "licence".
    The row arrived under the masked ID; this is a known identity false positive.

**Windows mapping** (unit tests; no Windows host in this run): hostile EventData in
every field persisted only the account HMAC, a validated address and a fixed reason.
Before the fix, a control character or unpaired surrogate in the account name dropped
the event as `winevt-xml-invalid`.

**Packs** (unit tests in C# and Rust):
- The `reload` command is refused, keeping the running packs, for: unsigned,
  untrusted-key, tampered, malformed-manifest, missing-pack, missing-trusted-key and
  short-HMAC-key.
- Trusted-key overlap rotation works.
- Two keys in one file fail closed.
- There is no version pinning.

## Failed attempts and harness corrections (retained)

- The first collector start posted events without single-trust-domain scoping and got
  `403 producer not authorized`, then `400 Unsupported schemaVersion` (`1.0` instead of
  `1.0.0`). These were harness errors, corrected before any measurement.
- Host setup failed twice:
  - `rsyslog-gnutls` is not packaged on AL2023, so `rsyslog-openssl` was used;
  - the collector extracted with macOS `0700` permissions could not be executed by
    `bower`, so permissions were normalised.
  Neither changed the product.
- The first adversarial HTTP run aborted on the over-1 MiB case (client broken pipe when
  the server closed early). The rerun used new event IDs (`adversarial2`) so no
  destination row is double counted. Both runs' events are in the reconciliation.
- The Rust delivery-log test failed when run in parallel: tracing's callsite interest
  cache raced other tests. It moved to its own test binary; the product code is
  unchanged.
- The first in-process Windows hostile test could not use a NUL character reference in
  the fake channel. This led to the real finding above.

## Changes after this campaign

Review of the pull request changed behaviour that this campaign measured. These changes
are covered by unit and integration tests in both collectors (see
[local checks](local-checks.json)); none was re-run against AWS or Azure, and no cloud
resource was created for them.

- **Token failures:** an unreachable token service, or one answering 5xx/408/429, is now
  `destination-azure-unavailable`. The campaign's credential cases (expired, deleted or
  wrong secret, disabled service principal, wrong tenant) were rejections and keep
  `destination-azure-credential-failed`.
- **Revocation lists:** selected by the issuing CA's key and by their issuing
  distribution point, identically in C# and Rust. The revocation rows above used one list
  per CA, CAs with distinct names, and no distribution points, so their outcome is
  unchanged.
- **TLS reload:** a background task reads the files once a second (the campaign's reload
  ran on the next connection, frame or status read); non-regular files are refused;
  superseded certificates are released after their last handshake.
- **`reload`:** the pre-check now also covers source configurations and routes, syslog
  TLS files, expectations, scopes, tokens and relay files, and a refused reload does not
  use the rate limit. The pack and HMAC key cases above are unchanged.
- **Windows:** unpaired surrogates are escaped reversibly so distinct account names keep
  distinct pseudonyms.

## Limits

- Collectors for the Azure cases ran on macOS, not on the packaged Linux/Windows
  services. The syslog host ran a self-contained managed publish, not the RPM.
- Managed identity, workload identity, Key Vault, CSI driver and Secrets Manager
  procedures are documented, not exercised. Only secrets and certificates were rotated
  live.
- Only rsyslog 8.2204 was qualified as a sender.
- No live Windows host was used.
- Sovereign clouds and Conditional Access for workload identities were not tested.
- Event counts are small (functional qualification, not load).
- The Resource Groups Tagging API still indexed the terminated instance and deleted
  volume after teardown. The EC2 APIs confirm both are gone or terminated (see
  [cleanup](cleanup.json)).

## Cleanup

Removed, each verified independently in [cleanup.json](cleanup.json):
- **AWS:** the CloudFormation stack (instance terminated; volume, security group,
  subnet, route table, role and instance profile not found) and the artifact bucket.
  No Secrets Manager secret, schedule, state machine or log group was created.
- **Azure:** the workspace (force-deleted, no soft-delete), the resource group, and all
  role assignments.
- **Entra:** all seven applications and service principals, deleted and purged from
  deleted items.
- **Local:** secrets, keys, queue databases and Azure CLI caches deleted from the
  operator host.

**Zero resources with this RunId remain in AWS or Azure.** The operator's Azure CLI
login is unchanged. The CLI auto-installed the `monitor-control-service` extension
during the run. The shared default VPC and NAT gateway were not modified.
