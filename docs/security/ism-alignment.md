# ISM alignment

Mapped against the *Security monitoring* section of the *Guidelines for security
assurance*, Information Security Manual (ISM), September 2026. Bower is one component
of an organisation's security monitoring and does not meet any control by itself. The
table shows which Bower capability supports each control and what the organisation
still owns. Evidence bundles record the subset Bower can observe directly; see
[evidence bundles](../operations/evidence-bundles.md).

| Control | Requirement (summary) | Bower support | Organisation responsibility |
|---|---|---|---|
| ISM-0580 | Security monitoring policy developed, implemented and maintained | Versioned, hashed policies and signed packs state which events are collected; `bower policy diff` shows the population effect of each change; evidence bundles observe central logging of a canary | Own and approve the policy; review at least annually |
| ISM-1405 | Centralised event logging facility | Delivers to Microsoft Sentinel through AMA spool or the Logs Ingestion API | Operate Sentinel |
| ISM-1983 | Logs sent as soon as possible | Delivery is a continuous lease-based loop; `/v1/status` reports `oldestUndelivered` | Alert on delivery backlog |
| ISM-1984 | Encrypted in transit with ASD-approved cryptography | Logs Ingestion output and management heartbeat require HTTPS | Enforce approved TLS versions and cipher suites on hosts |
| ISM-1985 | Logs protected from unauthorised access | Queue and archive files are owner-only on Unix; `/v1/status` needs the ingest token; management API never receives payloads | Host hardening, disk encryption, Windows ACLs, Sentinel RBAC |
| ISM-1815 | Logs protected from unauthorised modification and deletion | Hash-chained queue ledger with recorded purges; management witnesses each collector's ledger head and flags regressions; the archive continues the ledger chain and `bower archive verify --anchor` proves it against a witnessed head | Restrict administrator roles; write-once storage for the archive; Sentinel immutability |
| ISM-0988 | Accurate, consistent time source | UTC `receivedAt` and `timeObserved`; events more than five minutes in the future are quarantined | NTP on every host |
| ISM-0585 | Date and time, user or process, filename, description, equipment | Policies require investigation fields per event type and quarantine events without them; the envelope has no dedicated filename field (use `target` with type `file`) | Instrument applications to supply the fields |
| ISM-1959 | Consistent, structured format | One versioned envelope schema for every event | None |
| ISM-1986, 1906, 1907, 0109, 1987, 1960, 1961, 1228 | Timely analysis by source class | Source expectations flag applications that stop delivering, in `/health`, `/v1/status` and the console; suppression summaries keep high-volume activity visible as counts | Detection rules, triage and response times in Sentinel |
| ISM-0120, 2116, 2117 | Tools, threat intelligence and AI support for detection | Consistent fields and correlation ids for analytics | Provide the tools, intelligence feeds and models |
| ISM-2153 | Threat hunting at least every three months | Consistent fields support hunting queries; the archive and replay restore events beyond Sentinel retention | Conduct and record hunts |
| ISM-1988 | Searchable for at least 12 months | Evidence bundles check workspace retention settings | Keep 12 months searchable in Sentinel |
| ISM-1989 | Retained per AFDA Express v2 | Optional ledger-verified archive (`BOWER_ARCHIVE_PATH`) keeps every stored event and never deletes segments | Place the archive on write-once storage for the AFDA period |

Selection itself is visible: `/v1/status` reports events and bytes received, queued,
deduplicated and suppressed per stage, policy and decision.
