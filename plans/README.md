# Bower direction: design and spike plans

Prepared 2026-11-12 against `64859aa7d620cec2538aa74fed647e4076e83490` using shadcn/improve `next`. The user selected all five ideas. These are design/spike assignments, not approval to deploy or a claim of implemented capability. Each plan produces a reviewable decision document under `plans/`; production implementation requires a separately scoped follow-up.

| Order | Plan | Priority | Effort | Risk | Depends on | Status |
|---|---|---|---|---|---|---|
| 1 | [Expected inventory](001-expected-inventory.md) | P1 | L | High | None | DONE: [design](001-expected-inventory-design.md) |
| 2 | [Source-specific evidence probes](002-source-evidence-probes.md) | P1 | M–L | Medium | None; inventory informs future scheduling | DONE: [design](002-source-evidence-probes-design.md) |
| 3 | [Stateful policy preview](003-stateful-policy-preview.md) | P2 | M–L | Medium | None | DONE: [design](003-stateful-policy-preview-design.md) |
| 4 | [SQL Server integration](004-sql-server-integration.md) | P2 | L | High | None | DONE: [design](004-sql-server-integration-design.md) |
| 5 | [Delivery gap investigation](005-delivery-gap-investigation.md) | P2 | M–L | Medium | 001 for fleet-wide coverage; standalone investigation can be designed independently | DONE: [design](005-delivery-gap-investigation-design.md) |

Design status, 2026-11-12: all five designs written at `64859aa`, with gates (`test -s`, `git diff --check`) passing. None is implemented or validated against live Sentinel. Outcomes: 001 recommended a tenant-owned offline inventory file (overridden on 2026-11-13: the management console owns the list); 002 selects `windows-security-logon`; 003 reuses the production queue on throwaway SQLite files; 004 is **go**: build a separate non-AOT forwarder now, with unverified demand accepted as a product owner risk; 005 recommends an on-demand KQL workbook plus runbook.

Decisions recorded 2026-11-13: the product owner decided the open questions in all five designs. Each design has a `Decisions (2026-11-13)` section. Three went against the recommendation: 001 D1 (option B, management-owned declarations), 004 GO (build now) and 004 Q4 (Entra managed identity sign-in in the first version, gated on a dependency justification). Decisions are not implementation; nothing is built or validated yet.

Effort estimates refer to possible eventual implementation, not the bounded design task. Run design tasks independently; do not assume an inventory design is implemented. Validate live Sentinel claims separately in an authorised tenant. Do not deploy or modify infrastructure as part of these plans.

## Considered and rejected

- Plain syslog as a lossless transport: documented lack of application acknowledgement; RELP already covers the qualified scenario (`docs/deployment/syslog-source.md`).
- Generic new log shipping or AI runtime filtering: conflicts with Bower's product boundaries (`AGENTS.md`).
- Generic fleet canary as proof of every source: generic probe exercises HTTP intake only (`docs/operations/evidence-bundles.md`).
