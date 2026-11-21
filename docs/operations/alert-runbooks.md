# Console alert runbooks

Every condition surfaced on the console **Alerts** page (`/alerts`) and in collector
operational logs has a plain-language explanation, verification steps, and a recovery path
below. All examples use synthetic hosts (`collector-01.example.gov.au`).

## Fleet and collector alerts

### Collector offline (`offline`)

- **What it means:** The collector has stopped sending heartbeats to the management API.
- **How to check:** Run `systemctl status bower` (Linux) or `Get-Service BowerCollector`
  (Windows) on the host, and run `bower doctor` to test outbound HTTPS connectivity to the
  management endpoint.
- **How to fix:** Start the service, verify proxy/firewall rules allow outbound port 443 to
  the management API, and check disk space on `/var/lib/bower`.
- **Safe to mute?** Only during planned host maintenance (set an expiry matching the
  maintenance window).

### Collector history changed (`history-changed`)

- **What it means:** The collector's queue ledger hash chain reported tampering, truncation,
  or an unexpected reset.
- **How to check:** Inspect `/v1/status` (`ledger` and `recovery` blocks) and run
  `bower queue verify --queue /var/lib/bower/queue.db`.
- **How to fix:** Treat as a security incident until explained. Preserve a backup copy of
  the queue database (`bower queue backup`) before re-initialising.
- **Safe to mute?** No — investigate immediately.

### Collector not sending (`not-sending`)

- **What it means:** Events are queued locally, but no batch has been acknowledged by the
  destination recently.
- **How to check:** Run `bower doctor` against the DCE/DCR endpoint and inspect `/v1/status`
  (`deliveryActivity.lastFailureCode`).
- **How to fix:** Verify managed identity / workload identity RBAC (`Monitoring Metrics
  Publisher` on the DCR), check network egress and TLS trust, and verify the DCR stream name
  matches `Custom-BowerSecurity`.

### Collector stale (`stale`)

- **What it means:** The collector's last heartbeat is older than the staleness threshold,
  though not yet marked fully offline.
- **How to check:** Check host CPU/disk load and outbound management proxy latency.
- **How to fix:** Resolve host congestion or proxy timeouts; check `management-heartbeat`
  status in `/v1/status`.

### Queue full or storage pressure (`queue-full`, EventId `1500` / `1501`)

- **What it means:** The queue database or its underlying volume (or AMA spool / archive
  volume) has crossed the warning or critical free-space watermark.
- **How to check:** Check `df -h /var/lib/bower` (Linux) or volume free space on Windows,
  and inspect `/v1/status` (`storage` and `volumes`).
- **How to fix:** Restore destination delivery so the backlog drains, expand the volume, or
  increase `BOWER_QUEUE_MAX_BYTES` only when volume headroom allows. See
  [storage pressure](../production-readiness/03-storage-pressure.md).

### Delivery trouble (`send-trouble`, EventId `1008`)

- **What it means:** Repeated transient or permanent HTTP errors occurred when delivering to
  Azure Logs Ingestion, S3, or an HTTP sink.
- **How to check:** Inspect `deliveryActivity.lastFailureCode` and collector logs for the
  metadata-only failure code (`azure-http-403`, `azure-http-429`, `azure-http-400-isolated`).
- **How to fix:** Fix DCR permissions for `403`, allow adaptive backoff to absorb `429`, or
  inspect dead-letter counts for `400`.

### Events set aside in dead-letter queue (`set-aside`)

- **What it means:** One or more events could not be delivered after retries or failed a
  permanent validation check and were moved to the dead-letter queue.
- **How to check:** Run `bower queue dead-letter --queue /var/lib/bower/queue.db` (metadata
  only — never raw payloads).
- **How to fix:** Fix the underlying schema or destination issue, then replay with
  `bower queue replay`.

### Delivery backlog (`backlog`)

- **What it means:** Queued events waiting for delivery exceed the expected steady-state
  backlog.
- **How to check:** Compare `/v1/status` queued depth against `delivery.concurrency`.
- **How to fix:** Verify destination reachability and check for throttling (`429`).

### Quiet source (`quiet-source`)

- **What it means:** An application or WEC subscription listed in `BOWER_SOURCE_EXPECTATIONS`
  has emitted no accepted events within its expected silence window.
- **How to check:** Verify the upstream producer or WEC forwarder is running (`bower doctor
  --wec-channel ForwardedEvents` on Windows) and confirm events are not being quarantined by
  a policy change (`bower top`).
- **How to fix:** Restart the upstream forwarder or fix producer credentials/TLS.

### Policy or privacy profile not applied (`policy-not-applied`, `privacy-not-applied`, EventId `1702`)

- **What it means:** The collector's active policy hash or privacy profile hash does not match
  the approved desired hash, or a hot reload failed validation (`EventId 1702`).
- **How to check:** Inspect `/v1/status` (`reload.errorType` and active hashes) and run
  `bower validate` on the policy directory.
- **How to fix:** Correct the invalid YAML/signature, verify trusted signing keys, and
  trigger a reload (`POST /v1/reload` or `SIGHUP`).

### Pending approval (`pending`) or suspended collector (`suspended`)

- **What it means:** A newly enrolled collector is waiting for an Approver decision, or an
  Approver has suspended the collector.
- **How to check:** Open **Approvals** (`/approvals`) or **Fleet** (`/collectors`).
- **How to fix:** Have a second person with `Bower.Approver` review and approve or
  re-activate the collector.

### Background job failed (`job-failed`, EventId `1600`)

- **What it means:** A scheduled maintenance or health job (such as retention, heartbeat, or
  alert notifications) threw an error.
- **How to check:** Open **Jobs** (`/jobs`) or inspect collector EventId `1600` metadata.
- **How to fix:** Resolve the failing dependency (disk permissions, management connectivity,
  or webhook/SMTP endpoint).

### Redaction failure (`EventId 1302`) and configuration error (`EventId 2101`)

- **What it means:** `1302` indicates the Privacy & Secret Protection Engine rejected or
  quarantined an event before persistence (fail-closed). `2101` indicates invalid startup or
  source configuration.
- **How to check:** Run `bower privacy test` on synthetic fixtures or `bower doctor` to
  validate local files.
- **How to fix:** Fix the invalid privacy rule or source configuration and reload.

### Sentinel proof missing or expired (`sentinel-proof`)

- **What it means:** No recent destination-verified evidence bundle confirms rows landed in
  `BowerSecurity_CL` in Microsoft Sentinel.
- **How to check:** Run `bower evidence run` with read access to the Log Analytics workspace.
- **How to fix:** Verify end-to-end delivery and upload the signed evidence bundle in the
  console. Remember that simulated evidence never counts as production proof.
