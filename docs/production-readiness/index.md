# Production readiness

**Status (3 November 2026): not production-ready.** The scoped rollout is Windows WEF/WEC
(`ForwardedEvents`) and firewall syslog → Bower collector → Microsoft Sentinel through the
Logs Ingestion API. All seven readiness gaps have a guide and live evidence, but the 24-hour
soak failed on the WEC path, and release check 7 stays open. Release packages are unsigned;
signing is deferred.

Each guide is the step-by-step operator procedure for its gap, covering every supported
environment: Linux packages, Windows MSI and WEC hosts, Docker, Kubernetes, AWS, Azure VMs
and on-premises. Each one ends with how it was tested and its known limits. Treat the
evidence as covering only the build and scope it names.

| # | Gap | Guide | Current result | Evidence | Still open |
| --- | --- | --- | --- | --- | --- |
| 1 | Reliable firewall delivery | [Syslog delivery reliability](01-syslog-delivery-reliability.md) | **Qualified for the tested scope over RELP.** Forced kill, TCP reset, sender reboot, restart, collector reboot, blackhole, idle gaps of 5, 30 and 65 minutes, a 15-minute outage and queue-full refusal all had 0 missing events from source to Sentinel. Requires rsyslog 8.2606.0 or later. Plain TCP/TLS syslog is **not** crash-lossless. | [fw-20261101-111911](../evidence/fw-20261101-111911/README.md), [ws1 baseline](../evidence/ws1-20261031-075451/baseline-artifact-provenance.json) | A real firewall appliance and the appliance → relay hop; sender power loss with an unacknowledged RELP window; the Rust collector live. |
| 2 | Duplicate (replay) handling | [Replay-safe detections](02-replay-safe-detections.md) | **Qualified live at commit `4dabe15`**: zero duplicate incidents and zero missed late events. Later content checks were partial. | [ws2b](../evidence/ws2b-20261102-003156/README.md), [ws2c](../evidence/ws2c-20261102-024502/README.md), [ws2d](../evidence/ws2d-20261102-065107/README.md) | The firewall rule, catch-up path and scheduled monitor on the final content; query cost at production volume. |
| 3 | Full queues and low disk | [Storage pressure](03-storage-pressure.md) | **Qualified live on Linux and Windows at `261f61a`**: every accepted event reached Sentinel, and the drain-deadlock and stall fixes were proven. Later review fixes are unit-tested only. | [ws3b](../evidence/ws3b-20261102-005001/README.md), [ws3](../evidence/ws3-20261031-081023/README.md) | `ForwardedEvents` overflow when Bower stalls; Rust watermarks and pressure retention. |
| 4 | Upgrades and recovery | [Upgrade, backup and recovery](04-upgrade-backup-recovery.md) | **Qualified live**: RPM, MSI and Docker upgrades under load, crash, forced stop/start and backup/restore lost no accepted events. | [ws4](../evidence/ws4-20261031-074918/README.md) | MSI downgrade blocking and release versioning; WEC host loss and disaster-recovery replay; Kubernetes, Azure VM and DEB live runs. |
| 5 | Credential rotation and security failures | [Credential rotation and security failures](05-credential-rotation-and-security-failures.md) | **Qualified live** for client-secret and certificate credentials, syslog mutual-TLS rotation, HMAC and pack rotation, and an adversarial privacy sweep. | [ws5](../evidence/ws5-20261031-074543/README.md) | Managed identity, workload identity, Key Vault and Secrets Manager live; HMAC dual-key period; pack version pinning. |
| 6 | Monitoring and runbooks | [Monitoring and runbooks](06-monitoring-and-runbooks.md) | **Drilled live**: alerts fired for silent sources, failed delivery, backlog, storage and collector down, and recovered. The TLS-expiry false positive the soak found is fixed (#171). | [ws6](../evidence/ws6-20261031-074751/README.md), [final campaign](../evidence/ws6-20261101-final/README.md) | Alerts marked "unverified" in the guide; management API with Entra sign-in. |
| 7 | 24-hour soak and release validation | [Soak and release validation](07-soak-and-release-validation.md) | **Failed 3 of 6 criteria.** 896,400 events per collector matched exactly across source, Bower and Sentinel, with no restarts and no privacy leaks. The WEC reader's cost grows with `ForwardedEvents` size (p99 882 s), there were small memory and handle growth slopes, and there were alerts. | [soak-20261102-015614](../evidence/soak-20261102-015614/README.md) | A fix for WEC reader scaling and hourly retention contention. A re-soak on current `main` is not planned, so release check 7 stays open. |

## Before you release

1. Work through the [release checklist](07-soak-and-release-validation.md) for the exact build
   you are shipping, and record its version and artifact hashes.
2. Confirm every "Still open" item above is either closed by new evidence or accepted as a
   documented risk for your deployment.
3. Re-run the parts of gaps 1–6 that your build or configuration changes, using the
   procedure in each guide, and keep failed attempts.
4. Remove every temporary cloud resource and keep the cleanup audit.

The [operations qualification record](../operations/production-readiness.md) keeps the
history of earlier gates and campaigns.
