# Plan 001: Design expected collector and source inventory

**Status:** DONE (design: [001-expected-inventory-design.md](001-expected-inventory-design.md)) · **Category:** direction · **Priority:** P1 · **Eventual effort:** L · **Risk:** high · **Depends on:** none · **Planned at:** `64859aa7d620cec2538aa74fed647e4076e83490` (2026-11-12)

## Outcome and boundaries

Produce `plans/001-expected-inventory-design.md`, a decision-ready design, not implementation. An independent expected inventory can identify collectors and sources that have never emitted, rather than infer completeness from the data that happened to arrive. No source, infrastructure, schema or production data changes; no live cloud calls. Update this plan's index status only after the artifact passes its gates.

Bower is tenant-controlled and collector delivery must continue if optional management is unavailable (`PRODUCT.md:19-29`). Health can indicate local observations, not prove Sentinel receipt. Expected inventory is a declaration, not a claim that a source exists or is healthy.

## Current state and evidence

- `docs/production-readiness/06-monitoring-and-runbooks.md:1071-1089`: health records cap reported listeners and subscriptions; explicit expected collector IDs are needed to detect never-seen collectors; independently maintained expected-source inventory is a release blocker.
- `deploy/sentinel/monitoring/monitoring.bicep:48-57`: `absenceWindow` is `P2D`; `expectedCollectorIds` defaults to `[]`.
- `src/Bower.Management.Api/FleetModels.cs` models observed fleet states; inspect the API's storage and authorisation before choosing where declarations live. Management inventory alone may not be independent from a missing collector.
- `docs/production-readiness/06-monitoring-and-runbooks.md:1106-1122`: late-arrival and health-authenticity limitations remain. No design may quietly declare these resolved.

## Steps and checks

1. Run `git diff --stat 64859aa7d620cec2538aa74fed647e4076e83490..HEAD -- PRODUCT.md docs/production-readiness/06-monitoring-and-runbooks.md deploy/sentinel/monitoring src/Bower.Management.Api` and inspect changed files if any. STOP if above facts no longer hold.
2. Read `deploy/sentinel/monitoring/queries/collector-health-missing.kql`, `destination-freshness.kql`, monitoring Bicep and management fleet models. Record current collector/source identifiers, data provenance, freshness windows, unknowns and trust boundaries. Verify cited paths exist: `test -f deploy/sentinel/monitoring/queries/collector-health-missing.kql && test -f deploy/sentinel/monitoring/queries/destination-freshness.kql` (exit 0).
3. In the design artifact compare versioned offline inventory, management-owned declarations and external inventory integration. For each specify owner, source identity and uniqueness, independent authorisation, tenant scope, approved changes, audit, bootstrap, updates, decommissioning, stale inventory, lost management, scaling, privacy and reconciliation with observed data. Recommend one bounded first slice; identify decisions that require product owner input. Do not treat heartbeats as independent inventory.
4. Define a test matrix including never-seen collector/source, missing after lookback, decommissioning, delayed events, absent/truncated health, duplicate IDs, cross-tenant isolation and management outage. Specify synthetic local fixtures and separate live Sentinel validation; list what each can and cannot prove. Include RBAC and offline operation, query size and cost limits, stale-state and partial-query outcomes.
5. Verify: `test -s plans/001-expected-inventory-design.md && git diff --check && git status --short` exits 0 and shows only intended plan files. Review artifact for every scenario above and explicit unvalidated claims before setting index to DONE.

## STOP conditions and maintenance

STOP if identity cannot be made unambiguous, an expected source cannot be declared independently, required schema compatibility is unresolved, or validation would need real cloud access. Report unresolved choices, never invent proof. Downstream fleet investigations and scheduled probes must preserve the resulting declaration lifecycle and distinguish missing, unknown, stale and healthy.
