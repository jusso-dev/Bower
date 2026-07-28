# Bower contributor instructions

## Purpose

Bower is a self-hosted security telemetry bridge. It follows
`Collect → Select → Arrange → Deliver → Prove`: semantic application security
events become validated, redacted, durable Microsoft Sentinel signal.

Bower is not a generic log shipper, APM system, SIEM, AMA replacement, hosted
control plane, or runtime AI filter.

## Architecture and repository map

- `src/Bower.Contracts`: immutable event contracts and serialization.
- `src/Bower.PolicyEngine`: deterministic, explainable event selection.
- `src/Bower.Redaction`: local data minimisation before persistence.
- `src/Bower.Persistence`: SQLite queue, cursors, delivery state and evidence.
- `src/Bower.Core`: source-to-policy-to-queue orchestration.
- `src/Bower.Sdk`: semantic developer API and transports.
- `src/Bower.Collector`: local HTTP collector host.
- `src/Bower.Management.Api`: Entra-protected fleet, approval and audit API.
- `ui/Bower.Management.Web`: tenant-controlled operational console.
- `src/Bower.Output.*`: bounded delivery adapters.
- `src/Bower.Source.Aws`: AWS security telemetry parsers (CloudTrail, GuardDuty, Security Hub, CloudWatch).
- `src/Bower.Ocsf`: OCSF normalisation engine and source mappers.
- `src/Bower.Detection`: Sigma-compatible detection rules engine.
- `src/Bower.Pipeline`: declarative telemetry pipeline model, templates and validation.
- `src/Bower.Analytics`: telemetry quality and coverage scoring.
- `schemas`, `policies`, `deploy`, `docs`, `tests`: versioned product assets.

Inspect nearest `AGENTS.md` before editing.

## Commands

```bash
dotnet restore
dotnet build --configuration Release
dotnet test --configuration Release
dotnet format --verify-no-changes
docker compose build
```

## Invariants

- Keep evaluation deterministic. Configuration cannot execute arbitrary code.
- Default deny unknown events. Never weaken tests or bypass policy validation.
- Redact before persistence. Treat redaction failure as security failure.
- Never log secrets, credentials, tokens, cookies, unrestricted bodies, or raw
  payloads. Status commands return metadata only.
- Preserve cursor correctness, queue durability, idempotency and acknowledgement
  semantics. Never delete before acknowledgement.
- Never claim Sentinel delivery without destination query validation. Simulated
  evidence must say `simulated`.
- Use supported Azure Monitor ingestion APIs only, least privilege, and no
  persisted access tokens.
- Schemas evolve additively by default. Required-field changes need explicit
  approval, version bump, compatibility tests and migration notes.
- Policy changes need version bump, stable hash, population diff and tests.
- New adapters require bounded input, cancellation, durable cursor tests,
  malformed-input tests, backpressure and scoped `AGENTS.md`.
- Queue or redaction changes require crash/recovery or adversarial tests.
- Do not add dependencies without written justification.
- Update docs, schemas and event catalogue with behavior changes.

## Pull requests and definition of done

Keep changes focused. Explain security and compatibility impact. Add tests before
marking work complete. Run build, tests and formatting. Report limits honestly;
inaccessible evidence cannot pass. Do not turn Bower into general logging.
