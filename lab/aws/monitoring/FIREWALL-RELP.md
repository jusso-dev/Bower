# RELP firewall qualification (collector + sender, Sentinel)

This runbook reproduces the RELP qualification in
[`docs/evidence/fw-20261101-111911`](../../../docs/evidence/fw-20261101-111911/README.md).
It reuses the [separate-sender setup](FIREWALL-SETUP.md) and the
[identity reconciliation](FIREWALL-RECONCILIATION.md) unchanged except where noted. Only
synthetic events, only resources tagged with this run's `Project=bower-lab` and `RunId`.

## 1. Topology and resources

- RunId `bower-fw-<UTCyyyymmdd-HHMMSS>`. `stack.py` with `EnableSyslogSender=true` and
  `EnableWindows=false`: one Amazon Linux 2023 collector and one sender (t3.small, encrypted
  gp3, IMDSv2, SSM only, no inbound administration) in a new private /24 of the default VPC
  routed through the existing NAT gateway, plus the run bucket and an EventBridge Scheduler
  expiry (≤ 12 hours) that terminates exactly the two instances.
- Azure: `azure-environment.py prepare --run-id <RunId>` names the resource group
  `rg-<RunId>`, the workspace `<RunId>-logs` and the applications `<RunId>-ingest` and
  `<RunId>-verifier`; then `plan`, `apply` (repository Bicep) and `sentinel`.
- The collector is the CI-built NativeAOT `linux-x64` artifact of the exact commit
  (`gh run download <run> -n bower-linux-x64`), without `.pdb`/`.dbg` files.

## 2. Collector and sender setup

```bash
python3 lab/aws/monitoring/run.py Linux lab/aws/monitoring/setup-firewall-collector.sh \
  --state <state.json> --timeout 900 --env BOWER_ARTIFACT_MANIFEST_SHA256=<collector-manifest> \
  --env BOWER_SYSLOG_SENDER_IP=<SenderIp> --env BOWER_SYSLOG_PROTOCOL=relp
python3 lab/aws/monitoring/run.py Sender lab/aws/monitoring/setup-firewall-sender.sh \
  --state <state.json> --timeout 1800 --env BOWER_ARTIFACT_MANIFEST_SHA256=<sender-manifest> \
  --env BOWER_SYSLOG_COLLECTOR_IP=<LinuxIp> --env BOWER_SYSLOG_TRANSPORT=relp
```

- `BOWER_SYSLOG_PROTOCOL=relp` gives listener `a13` (port 6514, so the existing fault
  rules apply) `protocol: relp` with the same mutual-TLS material.
- `BOWER_SYSLOG_TRANSPORT=relp` builds librelp 1.12.0 (OpenSSL) and rsyslog 8.2204.0's
  `omrelp` from upstream tarballs pinned by SHA-256 (`syslog-host.py install-relp`), because
  Amazon Linux 2023 packages neither, and writes the `omrelp` action of the recommended
  profile (`RSYSLOG_RELP_ACTION`): mutual TLS with name check, `windowSize=128`,
  `timeout=90`, the unchanged disk-assisted queue.
- Upgrading the sender to rsyslog 8.2610.0 (the fixed profile, see the evidence): upload
  the reviewed helper as `artifacts/qualification/<RunId>/sender/syslog-host.py.next`, then
  between scenarios run `update-sender-rsyslog.sh` with `BOWER_TOOL_SHA256=<helper sha>`. It
  builds rsyslog 8.2610.0 (pinned) into `/usr/local` with `omrelp`, `imjournal`, `imfile`,
  `impstats`, points `rsyslog.service` at it with a drop-in and keeps the configuration,
  queue files and imjournal state. Install the same helper on the collector
  (`syslog-host.sh` with `BOWER_STEP=fetch`) so plan and queue exports bind one helper hash.

## 3. Scenarios

`relp-scenario.py <scenario> --state … --azure-state-dir … --evidence <private-root>
--pack-sha256 <signed-pack sha> [--sequence-offset N]` plans with `syslog-plan.py`, installs
the scenario's destination block when the plan requires one (`destination-outage.sh` with
`BOWER_OUTAGE_SECONDS` and `BOWER_SCENARIO`), dispatches the steps, waits for collection,
saves generator, fault, measurement and snapshot reports, exports queue identities and
queries Sentinel with the verifier. Every attempt is a new directory; `--reconcile-only
<attempt>` re-exports and re-queries into new file names. Use a disjoint
`--sequence-offset` for every rerun in the same queue (the campaign used 0, then 900000).

| Scenario | Events | Fault |
|---|---|---|
| `a-steady`, `a-burst` | 600 at 10/s; 6,000 at 100/s | none |
| `a-sigkill` | 6,000 at 100/s | collector `kill -9` at 20 s |
| `a-reset` | 1,200 at 10/s | collector rejects with TCP reset for 10 s |
| `a-restart`, `a-collector-reboot` | 6,000 at 100/s; 3,000 at 10/s | restart; host reboot |
| `a-blackhole` | 1,800 at 10/s | collector drops sender traffic for 120 s |
| `a-sender-stop-start` | 1,800 at 10/s | rsyslog stopped 60 s |
| `a-sender-reboot` | 600 at 10/s | collector stopped 240 s; sender rebooted at 80 s |
| `a-sender-reboot-only` | 600 at 100/s | sender rebooted 2 s after generation |
| `b-idle-gaps` | 100+100+100+6,000 | idle gaps of 5, 30 and 65 minutes |
| `a-destination-outage-15m` | 9,000 at 10/s | Bower UID TCP 443 blocked 900 s |
| `a-capacity-refusal` | 20,000 at 100/s | `queue-cap.sh` before; TCP 443 blocked 600 s; `raise-cap` at 640 s |

For `a-capacity-refusal`, run `queue-cap.sh` on the collector first
(`BOWER_CAP_HEADROOM_MIB=24`): it sets `BOWER_QUEUE_MAX_BYTES` just above the queue's size and
restarts Bower, so the queue reaches its page limit during the block. The scenario's
`raise-cap` step removes the override and restarts Bower (the operator recovery).

## 4. Evidence and duplicates

- `relp-dedup-proof.py --azure-state-dir … <attempt>…` runs the documented deduplication
  query per attempt (raw rows, rows after `arg_min(ingestion_time(), *) by EventId`,
  distinct ids) and writes `dedup-proof.json`.
- `relp-evidence.py <private-root> docs/evidence/fw-<run>` publishes sanitized copies: plans
  with operator paths replaced (original and public hashes recorded), reports, JSONL identity
  sidecars and `public-manifest.json`. It refuses any file still containing a local path.
  After adding the README, `cleanup.json` and operational records, regenerate
  `public-manifest.json` over every file so it covers them too.
- `sender-shutdown-diag.sh` (read only) prints rsyslog's own service messages around the
  previous boot, the queue directory and the version; it located the 8.2204.0 shutdown loss.

## 5. Cleanup

As in the [monitoring README](README.md#clean-up-the-drill-after-use): empty and delete the
run bucket, delete the stack, run `azure-environment.py cleanup --apply` (forced workspace
delete, application and service-principal deletion and purge), remove the private staging
directory, then record independent absence checks in the evidence `cleanup.json`.
