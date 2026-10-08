# Make proof, not volume, Bower's edge

Bower's biggest opportunity is the one its competitors leave open. None of Elastic, Azure Monitor Agent (AMA) or Cribl proves that a specific event reached a specific Sentinel table, and none of them does deterministic, Australian-aware redaction on the host before data is written anywhere. So the best improvements make those two strengths into features a buyer can see and an assessor can check. They do not add breadth. The Logs Ingestion API returns HTTP status codes but no per-record receipt, and its error table is rate-muted and incomplete ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-monitor)). Microsoft's own Logstash-to-Sentinel plugin offers log files as its monitoring ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/connect-logstash-data-connection-rules)). Cribl tells users to check delivery by hand with KQL ([Cribl](https://cribl.io/blog/integrating-cribl-stream-with-the-built-in-tables-of-microsoft-sentinel/)). ASD's Essential Eight assessment guide rates "testing a control with a simulated activity" as **excellent** evidence and screenshots as only **fair** ([ASD](https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-assessment-process-guide)). Query-verified evidence bundles are therefore the single highest-value item on Bower's backlog. The next most valuable steps are:

- making Sentinel plumbing self-provisioning and self-diagnosing (schema-to-DCR generation, Logs Ingestion API hardening, a "doctor" command);
- shipping signed, versioned "packs" that bundle policy, redaction, mappings, detections and DCR templates;
- copying Elastic Fleet's control-plane features (per-collector credentials, policy revision acknowledgement, staged rollout).

Bower should copy the control planes of these products and leave their canvases alone. Cribl's JavaScript expressions, Elastic's `script` processor, Edge's auto-discovery and Guard's ML detection would all break Bower's invariants of determinism and default-deny.

## Every competitor stops at "accepted", and auditors want "arrived"

The three reference products share one blind spot. They track whether data was sent, but nobody checks that it can be queried.

**Microsoft's Logs Ingestion API has no per-record acknowledgement.** Failures surface only as HTTP codes, in DCR metrics, and in a `DCRLogErrors` table. That table is rate-muted after a few occurrences per hour, and some 404s and 500s "may not be logged" ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-monitor)). Microsoft notes that the DCR "Bytes Out" metric "doesn't represent bytes persisted in the destination" ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-monitor)). This research could not confirm whether the API's success code is 204, or whether a batch is all-or-nothing, because the REST reference page could not be retrieved. That uncertainty is one more reason not to treat a 2xx response as proof.

**AMA's offline cache defaults to 10 GB.** In Microsoft's own words, "the agent loses data that exceeds the cache limit" ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/agent-settings)). Renaming a monitored file ingests duplicates, and overwriting one loses data ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/vm/data-collection-log-text)).

**Elastic's route to Sentinel is a closed-source plugin.** Agent hands off to Logstash, which runs Microsoft's plugin, still in public preview at v2.5.0. The plugin defaults to **three retries** and has no dead-letter queue for the Sentinel output. Its version history includes fixes for "silent worker thread death" and for numeric types being turned into strings ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/connect-logstash-data-connection-rules)).

**Cribl documents a test-by-KQL workflow and nothing automated** ([Cribl](https://cribl.io/blog/integrating-cribl-stream-with-the-built-in-tables-of-microsoft-sentinel/)).

Bower already has an invariant that it never claims Sentinel delivery without validating it with a destination query. The improvement is to turn that invariant into a product. A Bower evidence bundle should contain:

- a per-batch `x-ms-client-request-id` (the API accepts one for troubleshooting ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview)));
- a Bower event-ID column in every table;
- a canary event per source and event type;
- a KQL query that confirms arrival by count and by a hash of event IDs within a time window;
- `ingestion_time()` latency;
- a correlated check against `DCRLogErrors` and the DCR "Rows Dropped" metric;
- for AMA spool mode, a reference to the AMA `Heartbeat` row.

The bundle should be signed, contain metadata only, and be labelled `simulated` whenever it is simulated. Proof queries should run under a separate read-only "verifier" identity, kept apart from the ingest identity that holds Monitoring Metrics Publisher ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview)).

This matters beyond engineering, because the format of the evidence is what Australian assessors grade. The Essential Eight requires centralised logging at Maturity Level Two ([ASD](https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-maturity-model-changes)). It also says privileged-access use and MFA outcomes must be "centrally logged and protected from unauthorised modification and deletion" ([ASD](https://www.cyber.gov.au/sites/default/files/2023-11/PROTECT%20-%20Essential%20Eight%20Maturity%20Model%20(November%202023).pdf)). The ISM requires searchable retention of **at least 12 months** (ISM-1988) ([Microsoft Learn PSPF](https://learn.microsoft.com/en-us/compliance/anz/pspf-audit-log)). ASD publishes the ISM as machine-readable OSCAL ([GitHub](https://github.com/AustralianCyberSecurityCentre/ism-oscal/releases)). That lets Bower attach control IDs to every item in a bundle, giving assessors a crosswalk from Bower's evidence to ISM-0580, ISM-1988 and the E8 logging requirements.

The bundle should also read each table's retention configuration. Retention proof is the artefact auditors already ask for ([Microsoft Learn PSPF](https://learn.microsoft.com/en-us/compliance/anz/pspf-audit-log)). ISM-0580 now refers to a "security monitoring policy" ([ASD via search summary](https://www.cyber.gov.au/sites/default/files/2026-06/ISM%20June%202026%20changes%20(June%202026).pdf)), so Bower could also produce a draft policy annex from its approved policy bundle: event types, destinations and retention.

Bower's spool mode needs to state its limits plainly. Once AMA reads a spool file, Bower loses sight of the event. Spool delivery is therefore at-least-once with a handoff Bower cannot verify, unless the evidence bundle reconciles it by querying Sentinel. Elastic sets a useful example here. It lists its own loss and duplicate windows (rotation faster than reading, files deleted during an outage, inode reuse, unacknowledged resends after restart) ([Elastic](https://www.elastic.co/docs/reference/beats/filebeat/how-filebeat-works)). Bower should publish an equivalent page covering Docker json-file rotation, duplicates after a sidecar restart, the SQLite fsync mode and the AMA handoff.

## Redaction on the host is the real moat, and Australia's sovereignty facts sharpen it

The competitors each place redaction somewhere Bower does not:

- **Microsoft: hand-written KQL in the cloud.** DCR transformations can `replace`, `extract` and `hash_sha256`, but they run per row in the cloud, after the data has left the customer network, and there are no PII detectors ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-transformations-kql)). Client-side "multi-stage" processors on AMA are in public preview ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-transformations)).
- **Elastic: a licensed processor on the server.** Its redact processor runs in Elasticsearch ingest pipelines and is a **commercial feature**. Its `skip_if_unlicensed` option silently skips redaction ([Elastic](https://www.elastic.co/docs/reference/ingest-processor/redact-processor)), which is the opposite of Bower's rule that a redaction failure is a security failure.
- **Cribl: probabilistic detection.** Cribl Guard combines more than 200 regex and ML rules with human approval ([Cribl](https://cribl.io/blog/introducing-cribl-guard/)). Since March 2026 it adds AI "background detection" that runs on Cribl Workers ([Cribl](https://cribl.io/news/new-background-detection-for-cribl-guard-uncovers-sensitive-data/)). Its marketing is framed around GDPR, CCPA and HIPAA ([Cribl](https://cribl.io/news/cribl-unveils-cribl-guard-to-protect-sensitive-data/)). This research found no evidence that Guard ships Australian identifier detectors. That is unverified, not confirmed absent.

Australian data residency makes Bower's position stronger. Microsoft states that for workspaces outside Europe and Israel, Sentinel "processes customer data in a US region". Raw storage stays in the workspace region, and the Sentinel data lake is available in **Australia East only** ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/geographical-availability-data-residency)). APP 11.3, in force since 10 December 2024, requires "technical and organisational measures" to secure personal information ([Clyde & Co](https://www.clydeco.com/en/insights/2024/10/key-privacy-reforms-the-new-app-11-3-and-toms)). Removing TFNs, Medicare numbers and IHIs before they leave the tenant is therefore a compliance control that can be stated as fact, not a marketing claim. Each evidence bundle should record it, with counts per detector: "no unredacted AU identifiers left the tenant boundary". A cheap companion check would confirm that the workspace, DCR and DCE all sit in Australian regions. It would also warn when a workspace in Australia Southeast or Central cannot use lake tiering.

The competitors still have deterministic ideas worth taking:

- **Pseudonymisation actions.** Elastic's `fingerprint` processor and Guard's hash action suggest an **HMAC pseudonymisation** action. Hashing user identifiers with a tenant key keeps events joinable across tables without exposing the identifier ([Elastic](https://www.elastic.co/docs/reference/beats/filebeat/defining-processors)).
- **Field-length bounds.** Elastic's `truncate_fields` processor points to deterministic field bounds. These matter because the Logs Ingestion API silently truncates field values over **64 KB** ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/service-limits)). Bower should truncate or redact before the API does.
- **A redaction trace.** Elastic's `trace_redact` flag stamps an event when it has been redacted ([Elastic](https://www.elastic.co/docs/reference/ingest-processor/redact-processor)). Bower should stamp a privacy trace on every event: which detectors fired, how many times, and the policy hash.
- **A quarantine outcome.** Guard can route events to quarantine ([Cribl](https://cribl.io/blog/introducing-cribl-guard/)). Bower could add a matching outcome that rejects an event while keeping metadata-only evidence of the rejection.
- **Rule suggestions instead of live AI.** Guard's step from "background detection" to a one-click rule is worth copying in a deterministic form. An opt-in scanner would run over an in-memory sample and never persist it. It would propose a new regex-plus-validator detector, and that proposal would go through Bower's existing versioning, population-diff and approval gates. That gives buyers the discovery benefit with no AI in the runtime path. SACR reports that practitioners want "explainable" automation, "not autonomous decision-making" ([SACR](https://softwareanalyst.substack.com/p/the-rise-of-security-data-pipeline)).

## Sentinel plumbing is where Bower can out-engineer everyone

Owning the event contract gives Bower a structural advantage that Cribl and Elastic lack. Cribl has **no built-in DCR wizard**. Users build DCRs by hand, match field names to the DCR schema themselves, and configure one destination per table ([Cribl](https://docs.cribl.io/stream/destinations-sentinel/)). Cribl's own migration answer is a separate PowerShell script and an eight-phase cutover lasting one to four weeks ([Cribl Community](https://knowledge.cribl.io/microsoft-47/azure-monitor-to-sentinel-migration-1768)). Microsoft's guidance for AMA custom JSON tables says: "Only use the PowerShell script below to create the table. No other method works." ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/vm/data-collection-log-json)).

Bower can **generate the table schema, `streamDeclarations` and `transformKql` directly from its versioned event schemas**. It can check at build time that every approved event type maps to a stream, and detect drift against the live DCR. Its DCR optimiser should lint for traps Microsoft documents:

- in transformations, `parse kind=regex` must match the *entire* string, so a regex that works in a query can silently fill nothing at ingestion;
- `parse` handles at most 10 columns per statement;
- transformations are capped at 15,360 characters;
- `geo_location` adds latency ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-transformations-kql)).

The generator and optimiser should also support DCR API `2025-05-11`, which multi-stage transformations require ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-transformations)). Finally, they should detect conflicts with Sentinel's preview "filter and split" rules, which Microsoft warns "may conflict" with DCR transformations ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/transformation-filter-split)).

The direct output should encode the documented limits instead of finding them out in production:

- default to `kind: Direct` DCR endpoints, and use a DCE only for Private Link;
- keep each call under **1 MB** after gzip;
- honour `Retry-After` (the soft limits are **2 GB/min and 12,000 requests/min per DCR**);
- reject reserved column names (`TenantId`, `Type` and others) and names that do not start with a letter or exceed 45 characters;
- require TLS 1.2 or higher, which Microsoft has enforced since 1 March 2026 ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview); [service limits](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/service-limits)).

The Logstash plugin's history shows the cost of getting type fidelity wrong ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/connect-logstash-data-connection-rules)). Bower should add contract tests proving that numeric and boolean columns arrive with their types intact.

A `bower doctor` command would replace the AMA CEF troubleshooting routine. Today that routine involves tcpdump, the `mdsd` port, config-cache greps and a Python troubleshooter, with up to 20 minutes before data appears ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/cef-syslog-ama-troubleshooting)). The doctor command would check:

- DCR association;
- that the stream and table schemas match;
- Monitoring Metrics Publisher RBAC on the DCR;
- that the endpoint is reachable;
- TLS;
- region.

Identity is a quieter but real differentiator:

- **Cribl** uses client ID and secret ([Cribl](https://docs.cribl.io/stream/destinations-sentinel/)).
- **CCF push connectors** generate an Entra app and give the sender a **client secret** ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/isv/create-push-codeless-connector)).
- **The Logstash plugin** shows the better pattern: it falls back to `DefaultAzureCredential`, which covers managed identity, workload identity and Azure Arc ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/connect-logstash-data-connection-rules)).

Bower should make managed identity, workload identity federation and certificates the documented defaults, and treat secrets as a fallback. It should also add per-leg proxy settings, one for Entra and one for the ingestion endpoint, as the plugin did in 2.5.0.

The table landscape is moving, and Bower should move with it:

- **ASIM.** Sentinel has 10 native ingest-time ASIM tables, including `ASimAuthenticationEventLogs`, `ASimAuditEventLogs` and `ASimUserManagementActivityLogs` ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/normalization)). Bower's OCSF engine should gain OCSF-to-ASIM mappings and ship ASIM parsers, so that Bower events feed Microsoft's built-in analytics. This research did not confirm which ASIM tables the Logs Ingestion API can write to directly.
- **Lake tiering.** The Sentinel data lake went GA in September 2025. Since 23 September 2026 it is part of standard onboarding and is enabled per table ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/whats-new)). The DCR optimiser should recommend Analytics or lake tier per event type, and price the choice using lake meters. Those meters charge processing on all input for lake-only and Auxiliary tables, while transformations to Analytics tables are free on Sentinel workspaces ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-transformations)).
- **Row-level scoping.** Scoping is in preview and depends on a DCR-populated `SentinelScope_CF` column ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/scoping)). Bower should set and validate that column so MSSPs can scope Bower data.
- **Portal and legacy API retirements.** Sentinel leaves the Azure portal after 31 March 2027 ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/billing)), so Bower's documentation should be Defender-portal-first. Support for the HTTP Data Collector API ended on 14 September 2026, which opens a migration-helper opportunity for apps still built around it ([Cribl Community](https://knowledge.cribl.io/microsoft-47/azure-monitor-to-sentinel-migration-1768)).
- **Content Hub.** Bower should eventually ship as a Content Hub solution. It would bundle ASIM parsers, a delivery-and-health workbook, and analytics rules translated from Bower's Sigma engine. CCF push itself is still preview and depends on the Azure portal ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/isv/create-push-codeless-connector)), so Bower's own Bicep/ARM provisioning remains the primary path and the hedge.

## Borrow Fleet's control plane and Cribl's packs, not their canvases

Elastic Fleet is the most mature reference for Bower's console. Its features fall into two groups.

**Credentials and lifecycle.** Agents exchange an enrolment token for a **per-agent API key** that can be revoked individually. An unenrolment timeout invalidates the keys of inactive agents, which suits ephemeral hosts. Secrets appear as `${SECRET_0}` placeholders in exported policies ([Elastic](https://www.elastic.co/docs/reference/fleet/agent-policy)). Fleet's connections are pull-only: there is "no inbound connection from the Fleet Server to the Elastic Agent" ([Elastic](https://www.elastic.co/docs/reference/fleet/fleet-server)).

**Health and upgrades.** Fleet uses a fuller status enum: Healthy, Unhealthy, Updating, Offline and Inactive, plus status per component. It records status changes as their own data stream (since 9.3), ships built-in health alert rules (since 9.2), and collects remote diagnostics bundles kept for 7 days ([Elastic](https://www.elastic.co/docs/reference/fleet/monitor-elastic-agent)). Upgrades roll out to a percentage of agents, with a **7-day rollback window** since 9.1 ([Elastic](https://www.elastic.co/docs/release-notes/elastic-agent)).

Bower's approval-and-heartbeat model already matches the shape of Fleet. The concrete gaps are:

- per-collector credentials, revoked automatically after a period of inactivity;
- a policy revision number that each collector acknowledges, so the console can show "revision N applied / pending";
- an Offline-versus-Inactive distinction and status per source;
- a metadata-only diagnostics bundle;
- console alert rules on queue depth, oldest unacknowledged event, redaction failures, policy-reject rate and the last successful Sentinel validation;
- a status-change stream written to a dedicated Sentinel table. Cribl does the same with its own internal logs ([Cribl](https://cribl.io/blog/sending-cribl-internal-logs-to-microsoft-sentinel-using-a-custom-table/)).

Two Elastic weaknesses are openings for Bower. First, **tamper protection is paywalled at Platinum** and tied to Elastic Defend ([Elastic](https://www.elastic.co/guide/en/security/current/agent-tamper-protection.html)). Bower could include a console-issued uninstall or disable token for the EC2 agent at no extra cost. Second, Elastic Agent runs privileged by default. Unprivileged mode breaks Windows Security log collection, auditd and FIM, and several 2026 releases patched privilege-escalation bugs in Windows unprivileged installs ([Elastic](https://www.elastic.co/docs/reference/fleet/elastic-agent-unprivileged); [release notes](https://www.elastic.co/docs/release-notes/elastic-agent)). Bower's non-root, read-only sidecar is the stronger default. Bower should adopt Fleet's habit of having each input declare the privileges it needs, so the console can flag a mismatch before rollout.

Resource use is Elastic's most persistent complaint. One user saw memory drop by about **200–250 MB per agent** after disabling self-monitoring ([GitHub](https://github.com/elastic/beats/issues/35234)). Bower should publish measured CPU and memory budgets per collector and keep heartbeats cheap. Elastic 9.5's per-input hot reload without restarts ([Elastic](https://www.elastic.co/docs/release-notes/elastic-agent)) sets the bar for Bower's policy reloads.

Three queue features from Elastic and Cribl are worth taking, all bounded:

- **A visible queue-full policy.** Cribl's Sentinel destination exposes "block or drop" when the queue is full ([Cribl](https://docs.cribl.io/stream/destinations-sentinel/)), and Filebeat warns that an unbounded disk queue can make "the system inoperable" ([Elastic](https://www.elastic.co/docs/reference/beats/filebeat/configuring-internal-queue)). Bower should set an explicit byte cap per source and show its full-queue behaviour in the console.
- **A dead-letter queue with replay.** Logstash's DLQ stores the original event with error metadata and supports replay and age-based retention ([Elastic](https://www.elastic.co/docs/reference/logstash/dead-letter-queues)). Bower needs the same for 4xx responses from the Logs Ingestion API, holding only redacted data.
- **Compression at rest.** Logstash added queue compression in 9.2 ([Elastic](https://www.elastic.co/docs/reference/logstash/persistent-queues)), a cheap gain for SQLite payloads.

**Replay is the major Cribl capability Bower lacks** ([Cribl](https://docs.cribl.io/stream/4.9/collectors-s3/)). A bounded version would re-deliver a time window from a local archive of already-redacted, policy-approved events, for example to a new DCR or table. That would help with table migrations without weakening the rule to redact before persisting.

Cribl's best user-experience ideas are **Data Preview** and **Packs** ([Cribl](https://docs.cribl.io/stream/basic-concepts/); [Cribl](https://cribl.io/blog/cribl-packs-dispensary/)). Bower's planned signed policy bundles should grow into **Bower Packs**. Each pack would be a signed, hash-pinned unit containing:

- policy and redaction profile;
- parser and OCSF-to-ASIM mapping;
- Sigma rules with their KQL translations;
- versioned sample events;
- a DCR and table template.

This mirrors Elastic's integration packages, which ship inputs together with assets such as ingest pipelines and dashboards ([Elastic](https://www.elastic.co/guide/en/fleet/8.19/hints-annotations-autodiscovery.html)). The difference is that Bower's packs would be signed. Cribl packs are configuration bundles, and the sources reviewed say nothing about signing them. Data Preview maps to a before-and-after view that is held in memory only, never persisted. It would show redaction and policy decisions side by side against the pack's sample corpus, along with the population diff that Bower's policy invariants already require. Cribl's Fleet inheritance ([Cribl Edge](https://docs.cribl.io/edge/)) suggests environment-level pack sets (prod versus non-prod, or per business unit) with an "effective config" view for each collector.

## New ISM controls hand Bower ready-made semantic event families

The ISM's September 2026 update added controls that read like a backlog for an SDK built around semantic application events:

- **ISM-2125** requires that all service-provider access is "independently logged by the organisation in a manner that the service provider cannot modify or delete". This is confirmed in two secondary summaries ([TERESEC](https://teresec.com.au/blog/2026-09-17-ism-september-2026-update); [Cipher Projects](https://www.cipherprojects.com/blog/posts/asd-ism-september-2026-update/)).
- **ISM-2139** covers logging of OAuth consent grants and token use.
- **ISM-2159** requires that tool invocations and outputs of agentic AI applications are centrally logged.

ISM-2139 and ISM-2159 appear only in the TERESEC summary and should be verified against ASD's OSCAL release before Bower markets them ([TERESEC](https://teresec.com.au/blog/2026-09-17-ism-september-2026-update)). Each control maps cleanly to a Bower event type with a schema, a default-deny policy entry and SDK helpers:

- service-provider/MSP session access;
- OAuth consent and token issuance;
- AI agent tool invocation, with prompts redacted before persistence.

Cribl's August 2026 launch of AI observability, which tracks "sensitive data exposure in prompts and traces" ([Cribl](https://cribl.io/news/cribls-ai-platform-debuts-powerful-new-security-capabilities/)), confirms demand for the AI-agent family.

ISM-2125 also makes tamper evidence worth building. Hash-chaining queue batches, and including chain verification in evidence bundles, answers the E8 and ISM requirement that logs be "protected from unauthorised modification and deletion" on the path Bower controls. Immutability on the Sentinel side still depends on Azure controls, and Bower should say so. Bower fits this control because it is customer-run and vendor-neutral. The pipeline market is consolidating into SIEM vendors: SentinelOne bought Observo AI ([SEC](https://www.sec.gov/Archives/edgar/data/1583708/000158370825000159/s-20251031.htm)), and CrowdStrike agreed to buy Onum ([SACR](https://softwareanalyst.substack.com/p/the-rise-of-security-data-pipeline)). Practitioners already worry about "everything re-bundled" ([SACR](https://softwareanalyst.substack.com/p/the-rise-of-security-data-pipeline)).

The ACSC's 2024 event-logging guidance recommends:

- structured JSON with a consistent schema;
- UTC ISO 8601 timestamps with millisecond precision;
- a unique event ID ([Axoflow summary](https://axoflow.com/blog/asd-acsc-best-practices-event-logging-threat-detection)).

Bower's contracts already fit this, and a published mapping of ACSC baseline fields to Bower event types would be cheap to produce. One caution: AMA text-mode collection does not support ISO 8601 with fractional seconds as a record delimiter ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/vm/data-collection-log-text)). The spool contract should therefore stay strict JSONL, which avoids text mode. It should also be date-stamped, never renamed, UTF-8 and append-only, and retained for at least 48 hours before deletion ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/vm/data-collection-log-json)). Conformance tests should enforce all of this.

AI belongs at authoring time, not at runtime. Cribl's Copilot Editor sells "review before apply" ([Cribl](https://cribl.io/news/cribl-unveils-copilot-editor-ai-powered-capability-to-translate-telemetry-data-into-business-insights/)), and Cribl Search offers bring-your-own-model ([Cribl](https://cribl.io/news/cribl-unveils-agentic-ai-enhancements-to-cribl-search/)). Bower can let an assistant draft parsers, OCSF mappings or Sigma rules from redacted samples, using a model in the customer's own tenant by default. Every draft would pass through the same version-bump, hash, test and approval gates as human-written changes. Bower should also publish an explicit statement of how data flows to the AI. The Cribl sources reviewed here do not describe what data reaches the LLM ([Cribl](https://cribl.io/blog/cribl-copilot-2/)).

## The prioritised roadmap

The order below weighs four things: buyer value (assessor-grade evidence, Sentinel fit), how unique the item is compared with the three reference products, fit with Bower's invariants, and dependencies. Sizes are this report's engineering judgement, not sourced estimates.

| Priority | Improvement | Borrowed from / gap in | Why it fits Bower | Size |
|---|---|---|---|---|
| P0-1 | **Query-verified evidence bundles**: per-table canary, request ID, KQL arrival count/hash, latency, `DCRLogErrors`/Rows Dropped correlation, retention readout, separate verifier identity, signed, `simulated` label, ISM/E8 crosswalk via OSCAL | Gap in all three; E8 "excellent" evidence | Productises the "Prove" stage and an existing invariant | L |
| P0-2 | **Logs Ingestion API hardening + `bower doctor`**: `kind: Direct`, <1 MB gzip batches, `Retry-After`, 64 KB/reserved-name/type-fidelity pre-validation, managed/workload identity and certificates first, per-leg proxy, AU region check | Logstash plugin fragility; AMA troubleshooting pain | Prevents silent server-side truncation and drops | M |
| P0-3 | **Schema-to-DCR generator + drift check + transformation lint** (DCR API 2025-05-11, regex full-match trap, 10-column `parse`, 15,360-char cap, filter/split conflicts); AMA spool conformance tests | Cribl's manual DCRs; Microsoft's "PowerShell only" | Uses Bower's ownership of the contract | M |
| P0-4 | **Signed Bower Packs** (extends the planned signed policy bundles): policy, redaction profile, parser, OCSF→ASIM map, Sigma+KQL, samples, DCR template, population diff | Cribl Packs; Elastic integrations | Signing and hash-pinning go beyond what the sources show for Cribl packs | L |
| P1-5 | **Fleet control plane**: per-collector revocable credentials, inactivity revocation, acknowledged policy revision, richer status enum, status-change stream to Sentinel, alert rules, metadata-only diagnostics | Elastic Fleet | Hardens existing approvals/heartbeats | M |
| P1-6 | **Queue upgrades**: per-source byte cap with visible full-queue policy, DLQ for ingestion 4xx with replay, age-based purge with evidence, compression at rest, hash-chained batches, published loss/duplicate windows | Logstash PQ/DLQ; Cribl PQ; Elastic's documentation | Keeps acknowledgement semantics; adds tamper evidence for ISM-2125 | M |
| P1-7 | **Deterministic privacy actions**: HMAC pseudonymisation, field truncation, quarantine outcome, per-event privacy trace, in-memory before/after preview | Elastic `fingerprint`/`trace_redact`; Cribl Guard actions | Stays deterministic; covers the 64 KB limit | S–M |
| P1-8 | **New semantic event families**: service-provider access (ISM-2125), OAuth consent/token (ISM-2139), AI-agent tool invocation (ISM-2159), MFA/privileged use (E8) | ISM Sept 2026; Cribl AI observability | Semantic events, not generic logs | M |
| P1-9 | **Tier, ASIM and scope awareness**: Analytics vs lake routing per event type with cost estimate, ASIM parsers/tables, `SentinelScope_CF` | Sentinel 2025–26 changes | Signal density over volume reduction | M |
| P2-10 | Staged percentage rollout and rollback for agents and policies; console uninstall token; privilege declarations per input | Elastic upgrades and tamper protection (paywalled there) | Safe change control | M |
| P2-11 | Content Hub solution (workbook, ASIM parsers, analytics rules); optional CCF push packaging | Sentinel CCF/Content Hub | Discoverability; keep Bicep as primary | M |
| P2-12 | Bounded replay from a local archive of redacted data | Cribl Replay | Table migrations without breaking redact-first | M |
| P2-13 | Deterministic sensitive-pattern suggestions and authoring-time AI (customer-tenant model, gated by approval) | Cribl Guard background detection; Copilot Editor | Suggestion only; no runtime AI | M |
| P2-14 | Narrow Windows Event Log source: security channels only, XPath/event-ID allow-list, per-channel bookmarks, WEC `forwarded` mode; OTLP log input mapped through default-deny | Winlogbeat; EDOT/AMA OTLP | Covers non-Arc hosts without competing with AMA's breadth | L |
| P2-15 | Declarative suppress / rate-limit / aggregate policy actions with deterministic tests | Cribl Suppress/Aggregate; Elastic `rate_limit` | Bounded noise control | S |

Some features should be declined outright. Elastic's `script` processor runs arbitrary JavaScript ([Elastic](https://www.elastic.co/docs/reference/beats/filebeat/defining-processors)), and Cribl's expression-driven routing draws "not beginner-friendly" reviews ([PeerSpot](https://origin.peerspot.com/products/cribl-pros-and-cons)). Both would break the rule that configuration cannot execute code.

Cribl Edge's Auto mode "discovers files that are open for writing" ([Cribl Edge](https://docs.cribl.io/edge/4.10/explore-edge/)). That contradicts default-deny, though discovery recast as *suggestion*, where the operator approves each proposed source, does fit. Runtime ML redaction would give up Bower's reproducible audits. Volume-reduction claims, such as Cribl's 62.5% Palo Alto case ([Cribl](https://cribl.io/blog/cribl-to-the-rescue-for-siem-migrations)), are the wrong scoreboard for low-volume semantic events. Bower should report signal density instead.

Syslog/CEF fan-in and broad Windows Event collection belong to AMA and the Azure Monitor pipeline, which is GA for Syslog in Australia East ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/pipeline-overview)). That is why the planned Windows Event Log source sits at P2 and is deliberately narrow.

## Conclusion

The research reframes Bower's competitive question. The market argues about how much data to drop and how cleverly to route the rest. Elastic, AMA and Cribl all leave two questions unanswered for a Sentinel customer in Australia: *did this exact event arrive*, and *did any identifiable Australian personal data leave my tenant*. Bower can answer both with evidence an assessor grades as "excellent", and that is a more defensible position than parity on features. Elastic and Cribl are moving toward OTel collectors and AI platforms, and Microsoft keeps shipping preview-grade ingestion features (client-side transforms, filter/split, CCF push). Those shifts make Bower's deterministic, contract-first design more distinctive over time.

The open risks are execution and verification, not strategy. Several Microsoft behaviours that the evidence bundle depends on are unconfirmed: the API's success code, whether batches are atomic, and which ASIM tables can be written to directly. Two of the ISM controls that would anchor new event families are known only from secondary summaries. Those should be checked first, because the case for the P0 work rests on proof, and Bower cannot sell proof built on claims it has not checked.
