# Adversarial remediation tracker

Baseline: `473c6ec6ffb9c195d49c54caae1267bd069c548f`. All 26 remediations implemented and locally validated. One independent Claude/Codex implementation review completed; follow-up fixes integrated. No live tenant delivery proven.

| Finding | Scope | State |
|---|---|---|
| AZ-01 | Concurrent Azure uploads acknowledge the failed event and reject a different event | Implemented; local gates passed |
| AZ-02 | Current Sentinel schema still omits target, change and event-specific context | Implemented; local gates passed |
| AZ-03 | Identity or DCR configuration failures dead-letter valid records | Implemented; local gates passed |
| SEC-01 | Secrets survive change values and request URLs | Implemented; local gates passed |
| SEC-02 | Documented management Entra audience mismatches v2 tokens | Implemented; local gates passed |
| SEC-05 | Producer authentication does not authorize application or tenant identity | Implemented; local gates passed |
| DUR-01 | SDK reports dropped events as accepted and hides sender failure | Implemented; local gates passed |
| DUR-02 | Fingerprint merges distinct security events | Implemented; local gates passed |
| DUR-03 | SQL timestamp cursor stalls on a saturated timestamp | Implemented; local gates passed |
| COV-01 | Defaults reject role-change and export SDK events | Implemented; local gates passed |
| COV-02 | Cloud mappings lose permission-change investigation context | Implemented; local gates passed |
| AZ-04 | Final Retry-After is lost when SDK-level retries exhaust | Implemented; local gates passed |
| AZ-05 | Evidence control mappings claim more than canary query establishes | Implemented; local gates passed |
| AZ-06 | Entra ingestion is implemented but provisioning remains partly manual | Implemented; local gates passed |
| SEC-03 | Unchecked heartbeat counts persistently crash fleet overview | Implemented; local gates passed |
| SEC-04 | Revoked collectors can rewrite protected inventory | Implemented; local gates passed |
| DUR-04 | Conflicting event ID returns duplicate success | Implemented; local gates passed |
| DUR-05 | Stale worker can settle a newer lease | Implemented; local gates passed |
| DUR-06 | Legitimate replay after retention reports false ledger corruption | Implemented; local gates passed |
| DUR-07 | Unresolved event pins unbounded ledger history | Implemented; local gates passed |
| DUR-08 | Delivery health reports healthy when output disabled or stalled | Implemented; local gates passed |
| COV-03 | Signed pack parser/detection assets never activate in collector | Implemented; local gates passed |
| COV-04 | Sigma subset silently changes Boolean and equality semantics | Implemented; local gates passed |
| COV-05 | High-value filtering relies on upstream subscription remaining narrow | Implemented; local gates passed |
| OPS-01 | SQL size checks follow unrestricted row allocation | Implemented; local gates passed |
| OPS-02 | UI token cache contradicts repository security requirement | Implemented; local gates passed |

Release gates: byte-level privacy; exact event acknowledgement; outage storage/backpressure; populated database migration and recovery; source/policy/DCR field preservation; supported parser/detection activation; independent destination query. Unsupported evidence dimensions remain not-assessed.


## Regression evidence map

These tests establish local/simulated behavior only. Final gate results must bind
to the combined commit, runtime versions and production defaults. Focused child
results do not replace integration validation.

- AZ-01/03/04: `AzureLogsIngestionOutputTests` and both runtimes' delivery-worker
  suites cover reordered concurrent responses, exact acknowledgement ownership,
  bounded isolation, persisted outages and final server retry deadlines.
- SEC-01/05: `SemanticPrivacyTests`, `ProducerAuthorizationTests` and Rust
  redaction/host suites cover canaries across SQLite/WAL/spool/captured requests
  and producer identity mismatches before persistence.
- DUR-01: `SdkDeliveryTests` covers overflow, permanent/transient failures,
  timeouts, sender faults and bounded shutdown accounting.
- SEC-02/03/04: `ManagementEntraTokenTests` and `ManagementBoundaryTests` cover
  signed offline token rejection, counter bounds, legacy overflow and revoked
  inventory writes.
- DUR-08: `DeliveryHealthTests` and Rust heartbeat tests cover disabled output,
  retrying/stalled/backpressure states. Historical receipts cannot prove the
  currently configured destination worked; an empty backlog reports idle.
- AZ-02/05: `SchemaAssetTests`, `IntegrityAndDcrTests`, `PackAndEvidenceTests`
  and Rust parity fixtures pin additive fields and restricted evidence claims.
- AZ-06: `deploy/entra/test_plan_ingestion.py` plus Bicep compilation cover
  deterministic offline identity/federation plans and exact DCR role scope.
- COV-01/02/05: `DefaultSignalCoverageTests`, `CloudPermissionContextTests`,
  Rust policy tests and the versioned population notes cover shipped SDK events,
  IAM grant/revoke context and default denial of routine inventory traffic.
- DUR-02–07/OPS-01: `DurabilityAdversarialTests`, `SqlServerAdversarialTests`,
  Rust adversarial/compatibility tests and bidirectional queue fixtures cover
  identity conflicts, fenced settlement, retention incarnations, compacted
  history, DB/WAL admission bounds and populated v4-to-v5 migration rollback.
  SQL tests inspect generated server projection and keyset behavior locally.
  `SqlServerReplayTests` also covers fair bounded overlap across restart, and
  `QueueMigrationPreflightTests` verifies read-only collision reports and unchanged
  DB/WAL bytes before a failed-closed upgrade.
- AZ-03 recovery: `tools/audited-replay/test_replay.py` covers exact-ID bounds,
  durable intent/outcome, audit failure before mutation and ambiguous crash state.
- COV-03/04: `PackActivationTests`, `DetectionSemanticsTests`, Rust host tests
  and 89 shared semantic vectors cover signed raw intake, component status,
  Boolean precedence/negation/equality, malformed input, restart and backpressure.
  Combined replay tests exclude changing local detection evidence from source identity.
- OPS-02: console auth tests pin in-memory MSAL cache and popup flows.

## External acceptance gates

The following remain unexecuted until an authorised test target is supplied:

1. Actual Entra token acquisition for each supported machine identity, management
   login/heartbeat, correct-DCR success and unrelated-DCR denial.
2. Destination query of unique application fixture IDs in the intended LAW/table,
   with exact sanitised target/change/export fields. See
   [deployment acceptance checks](../deployment/entra-ingestion-plan.md).
3. Live SQL Server tied-timestamp/restart/late-arrival exercise. Predicate and
   local queue tests do not certify a production database or its permissions.
4. Any historical reconciliation or replay on a deployed queue. Production loss
   is conditional, not established by the simulated misattribution probe.

No live delivery, historical completeness, regulatory control or universal
software-support claim follows from local green checks. Generic raw-log shipping
remains outside scope; unsupported events remain denied.

## Implementation council follow-up

One independent Claude/Codex round reviewed combined implementation `2999b65`.
Both returned **SHIP WITH CHANGES**. Their review was source-based; final tests
below remain the lead's responsibility. No second approval round is implied.

| Objection | Disposition and local regression |
|---|---|
| Unbounded server retry deadline pauses every lease | Fixed at client and durable-worker boundaries. Long headers return without SDK sleep; deadlines cap at one hour with fixed metadata. Huge date/millisecond and restart tests in both runtimes. |
| Isolated HTTP 400 continually pauses healthy backlog | Selectively rejected singleton retained in dead letters when another record succeeds in the same delivery call; healthy backlog continues. All-failing/configuration-wide 400 remains recoverable destination fault. Immediate audited recovery is safer than reclassifying every singleton as poison. |
| v4 identity collisions abort upgrade without diagnostics | Added bounded read-only canonical-identity preflight, collision pairs and backup/reconciliation instructions. Populated v4, malformed/future schema, unchanged DB/WAL and transactional upgrade tests. |
| Producer metadata suppresses detection without failure | Ambiguous or excessive fields now cause explicit evaluation failure and quarantine before source persistence. Matching/repaired/boundary host tests in C# and Rust. |
| Forward SQL pages skip/starve overlap | Cursor v3 pins replay bounds and alternates bounded forward/replay pages. Backlog, late rows, timestamp ties and restart regressions; v1/v2 migration documented. |
| Global event IDs can collide across producers | Implemented HTTP 409 with repair guidance, bounded authenticated producer counters, and forwarding tests proving no source acknowledgement/discard/cursor advance. On-disk primary key remains unchanged. |

The 400 decision is deliberately narrower than classifying every failed singleton
as poison: a wrong DCR may reject every valid record. Without a successful sibling,
Bower preserves those records pending operator repair and applies bounded storage
backpressure. Dead letters are retained, never counted as delivered.

## Final combined validation

Validated source revision: `ebd19267ce956359dd06dcd51b7dc18e7e520332` (2026-10-24 local date).
The final reporting commit changes only this tracker; source/build assets remain
identical to the validated revision. Every gate ran against the same committed,
clean source tree, with production defaults covered by the targeted adversarial
fixtures. Fixtures use synthetic data and simulated transports.

- .NET SDK 10.0.402: locked restore, Release build, **839 tests**, Debug reference
  build and full `dotnet format --verify-no-changes` passed.
- Rust 1.99.0 / Cargo 1.99.0: fmt, workspace **487 tests passed; 4 existing manual
  tests ignored**, Clippy `--all-targets -- -D warnings`, Release build passed.
  Pinned `DOTNET_ROOT`/PATH enabled actual C#/Rust interoperability tests.
- Node 22.23.2: clean install, lint, **11 UI tests**, production build passed.
  Existing bundle-size warning remains informational.
- Python 3.11.6: **13 audited replay tests**, **3 Entra planner tests** passed.
- Bicep compilation and Docker Compose Native AOT build on explicit local
  `orbstack` context passed. No containers deployed or cloud resources changed.

All **17 gates passed**. Exact commands, runtimes, timing and logs are preserved in
`artifacts/remediation/verified-gates/manifest.json` in the remediation worktree.
Earlier runs remain separately retained: `final-gates` records the initial Rust
fixture compile failure; `rust-followup-gates` records its successful correction;
`council-final-gates` records the combined whitespace-only formatting failure.
The final run repeats all gates after that formatting correction. A focused
intermediate MSBuild run also exited prematurely; the bounded-parallelism build
and both full combined Release builds subsequently passed without warnings.

Council reviewed implementation `2999b65`, not the post-review fixes. Both verdicts
were SHIP WITH CHANGES. The lead implemented and regression-tested the objections;
no second reviewer approval is claimed. Full replies and disposition transcript:
`~/.council/20261023-221225-bower-implementation/transcript.md`.

This is a local remediation result, not a production release certification. Live
Entra acquisition, correct/wrong-DCR authorization, LAW field-preservation query,
SQL Server exercise and conditional historical reconciliation remain external
acceptance gates above. Generic file/REST/Windows Event Log adapters, additional
language SDKs and collector SQL polling orchestration remain roadmap work; no
universal software support is asserted.
