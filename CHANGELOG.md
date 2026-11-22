# Changelog

All notable changes to Bower are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Microsoft cloud pull source (`Bower.Source.MicrosoftCloud`, collector `BOWER_MICROSOFT_CONFIG`): Intune audit events and a daily device compliance snapshot from Microsoft Graph with least-privilege read-only permissions, a token host allow-list, capped retry honouring `Retry-After`, and durable per-page cursors in the queue database. Signed `microsoft-intune` pack (two parsers, two policies, four detections) and the `deploy/privacy/microsoft-cloud.yaml` pseudonymisation profile.

## [1.0.0] - 2026-11-21

Initial v1.0.0 release of Bower, a self-hosted security telemetry privacy gateway for Microsoft Sentinel following the Collect, Select, Arrange, Deliver and Prove model.

### Added

#### Core platform, contracts and versioning

- Immutable semantic security event contracts (`Bower.Contracts`, envelope schema `1.0.0`) and developer SDK (`Bower.Sdk`) multi-targeted for .NET 10 and .NET 11.
- .NET 11 Native AOT self-contained executables (`bower`, `Bower.Collector`, `Bower.Management.Api`, `Bower.Agent.Docker` and `Bower.Agent.Cloud`) across Linux, Windows and macOS (`x64` and `arm64`).
- Single-source release versioning driven by `VERSION` across assemblies, CLI, collector, containers, deb, rpm and MSI packages, with semantic downgrade guards on every package platform.

#### Privacy and Secret Protection Engine

- Deterministic, pre-persistence inspection (`Bower.Redaction`) covering Australian-regulated identifiers first (checksum-validated TFN, Medicare, IHI, ABN and ACN; pattern-matched Centrelink CRN, passports, driver licences and DVA numbers), payment cards, financial identifiers, cloud credentials, JWT/OAuth tokens, API keys, PEM/SSH/PGP keys and optional protective security markings.
- Configurable per-detector actions (`Allow`, `Remove`, `Replace`, `Mask`, `SHA-256`, `HMAC` with key IDs, `Encrypt` and `AlertOnly`), custom redaction rules and secret field names via YAML privacy profiles, fail-closed quarantine on redaction failure, and first-class `sensitive_data_detected` SOC alert events.

#### Deterministic policy engine and durable queue

- Default-deny YAML telemetry policy evaluation (`Bower.PolicyEngine`) with canonical parsing, stable policy hashing, required/recommended field checks, per-key suppression and `aggregate` rules with `telemetry_aggregation_summary` reporting.
- Offline policy verification (`bower policy test`) and complete bundle population comparison (`bower policy diff`).
- Durable SQLite WAL queue (`Bower.Persistence`) with event deduplication, bounded undelivered-byte caps, storage-pressure purging and admission refusal, attempt-limited dead-lettering and replay, hash-chained tamper-evident ledger, verified backup/restore (`bower queue backup` / `restore`) with forward-schema refusal, unclean-shutdown detection, and ledger-verified long-term archiving with replay.
- In-process cron scheduler (`Bower.Jobs`) for queue retention, maintenance, management heartbeats, managed privacy profile sync, source activity tracking, archiving and collector staleness detection.

#### Sources and cloud or host agents

- Local HTTP collector (`Bower.Collector`) with loopback defaults, bearer-token ingest authentication, revocable per-producer tokens, explicit producer identity scopes (`BOWER_PRODUCER_SCOPES_FILE` and `BOWER_PRODUCER_SCOPES_JSON`), rate limiting, `collector_health` records, and bounded post-redaction live inspection (`bower tap` and `bower top`).
- Syslog source (`Bower.Source.Syslog`) supporting RFC 5424/3164 over TCP, TLS, UDP and RELP with sender allow-lists and signed pack parser routing.
- Windows Event Log and WEC source (`Bower.Source.WindowsEventLog`) with channel/event ID allow-lists, durable receiving-log bookmarks, group commit and `bower wec subscription generate`.
- Security-selected local file tail source (`Bower.Source.File`) and read-only Docker json-file sidecar (`Bower.Source.Docker`, `Bower.Agent.Docker`).
- AWS and Google Cloud telemetry sources (`Bower.Source.Aws`, `Bower.Source.Gcp`, `Bower.Agent.Cloud`, `Bower.Agent.Aws`) for GuardDuty, Security Hub, CloudTrail, CloudWatch Logs via Firehose/S3, GCP Cloud Audit Logs and Security Command Center via Pub/Sub, with `Origin` tracking and at-least-once queue acknowledgement.
- Read-only EF Core SQL Server audit table adapter (`Bower.Source.SqlServer`) with durable keyset and overlap cursors, plus Azure Monitor Agent companion discovery (`Bower.Source.Ama`).

#### Delivery outputs and relays

- Azure Monitor Logs Ingestion API output (`Bower.Output.AzureLogsIngestion`) with adaptive request concurrency, back-pressure handling and managed or workload identity authentication.
- Azure Monitor Agent JSONL spool output (`Bower.Output.AmaSpool`) and Linux local syslog output (`Bower.Output.AmaSyslog`) with matching Bicep Data Collection Rule templates.
- Relay mode (`Bower.Collector` relay role and `Bower.Forwarding`) over mutual TLS with pinned downstreams, end-to-end management tunnelling and Private Link support.
- Additional non-Sentinel sinks: Amazon S3 gzip NDJSON objects (`Bower.Output.S3`) and HTTPS Splunk HEC or NDJSON endpoints (`Bower.Output.Http`).

#### Signed packs, normalisation, detections and evidence

- ECDSA-signed, versioned content packs (`Bower.Packs`, `Bower.Integrity`) with bounded deterministic parser transforms (`Bower.Pipeline`), post-redaction field assertions and JUnit test output (`bower pack build` / `test`).
- Included packs: `linux-ssh-gateway`, `linux-journald-ssh`, `linux-authlog-ssh`, `windows-security-logon`, `aws-security`, `gcp-security` and `owasp-asvs-app-logging`.
- OCSF normalisation engine (`Bower.Ocsf`), Sigma-compatible detection engine (`Bower.Detection`), telemetry quality and coverage scoring (`Bower.Analytics`), and Data Collection Rule generation, drift checking and deployment diagnostics (`Bower.Dcr`, `bower dcr`, `bower doctor`).
- Sentinel KQL query-verified signed evidence bundles (`Bower.Evidence`, `bower evidence run`), ISM and Essential Eight alignment mapping, replay-safe Sentinel analytics rules, reconciliation queries and health-record sequence-gap detection.

#### Management API and Web Console

- Self-hosted ASP.NET Core Management API (`Bower.Management.Api`) and React console (`ui/Bower.Management.Web`) protected by Microsoft Entra ID SSO and app-role RBAC (`Bower.Viewer`, `Bower.Operator`, `Bower.Approver`, `Bower.Administrator` and `Bower.Collector`).
- First-run onboarding wizard with canary proof, plain-English Home posture view, fleet inventory, collector enrolment approvals, one-time token enrolment and key-bound credential rotation, heartbeat v2 with signed outbound commands, two-person managed privacy profile review and signed assignment, custom log parser generator and visual pipeline builder, background job controls, and audit history.
- Verified WCAG 2.2 AA accessibility across console routes in light and dark themes.

#### Serverless hosting, PowerShell, SDK and developer harness

- Native C# Azure Functions collector (`Bower.Functions.Collector`) for Flex Consumption with Entra `Bower.Producer` authentication and managed identity delivery.
- Cross-platform PowerShell 7.4+ modules (`Bower`, `Bower.Events`, `Bower.Management`, `Bower.Deployment`, `Bower.Privacy` and `Bower.Policy`) with plan-first deployment wrappers and `SecureString` token handling.
- `bower developer init` project scaffolding and OWASP ASVS 5.0 logging examples across .NET, Node.js (Express, Fastify, NestJS, Next.js), Python, Go, Ruby, PHP and Java.
- Aspire local development and integration-test harness (`Bower.AppHost`, `Bower.DevSinks`, `Bower.AppHost.Tests`) and opt-in OpenTelemetry defaults (`Bower.ServiceDefaults`).

#### Packaging, infrastructure and documentation

- Native installers built in CI: deb, rpm, Windows MSI (`NT SERVICE\Bower`), offline bundles with pre-seeded enrolment tokens, and an Ansible role.
- Multi-architecture (`amd64`, `arm64`) container images (`bower-collector`, `bower-management`, `bower-web`, `bower-sidecar`, `bower-cloud`) published to GHCR with SBOMs and build provenance attestations.
- Plan-first infrastructure templates: Azure Bicep (Sentinel DCRs, AMA syslog DCR, Azure Functions, private Azure Web App, Private Link, analytics and monitoring), AWS CloudFormation, Google Cloud Terraform, Docker Compose and Kubernetes manifests.
- Docusaurus documentation site with console tour, quick-start guides, generated CLI reference and glossary.

### Notes

- Native packages, MSIs and release artefacts remain unsigned until signing secrets are configured; verify artefacts by SHA-256 digest.
- Production qualification for the native Windows WEC and firewall syslog path remains tracked against the open 72-hour soak gate in `docs/operations/production-readiness.md`.

[Unreleased]: https://github.com/jusso-dev/Bower/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/jusso-dev/Bower/releases/tag/v1.0.0
