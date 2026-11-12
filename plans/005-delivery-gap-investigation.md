# Plan 005: Design delivery-gap investigation

**Status:** DONE (design: [005-delivery-gap-investigation-design.md](005-delivery-gap-investigation-design.md)) · **Category:** direction · **Priority:** P2 · **Eventual effort:** M–L · **Risk:** medium · **Depends on:** plan 001 for fleet-wide completeness; independent per-collector design can proceed · **Planned at:** `64859aa7d620cec2538aa74fed647e4076e83490` (2026-11-12)

## Outcome and boundaries

Write `plans/005-delivery-gap-investigation-design.md` for an operator investigation surface using existing destination signals. No implementation, alert deployment, cloud query or inference that all records arrived. Fleet-wide completeness requires separately established expected inventory.

## Current state

`docs/deployment/ama-syslog-output.md:186-201` describes a deliberate loss missed by count reconciliation but seen by health sequence gaps, and at-least-once duplicates. `deploy/sentinel/monitoring/queries/delivery-sequence-gaps.kql` groups by `CollectorId` and `collectorStartedAt`, allows ingestion lag, and detects missing sequence numbers within the observed range. `src/Bower.Collector/Jobs/DeliveryHealth.cs` calls queue observations local observations, never destination proof. `docs/production-readiness/06-monitoring-and-runbooks.md:1081-1089,1106-1122` lists missing inventory, late arrival and authenticity limits.

## Steps and checks

1. `git diff --stat 64859aa7d620cec2538aa74fed647e4076e83490..HEAD -- deploy/sentinel/monitoring/queries docs/deployment/ama-syslog-output.md docs/production-readiness/06-monitoring-and-runbooks.md src/Bower.Collector/Jobs/DeliveryHealth.cs` and inspect any drift.
2. Read `delivery-sequence-gaps.kql`, `delivery-reconciliation.kql`, and the runbook. Verify both files exist: `test -f deploy/sentinel/monitoring/queries/delivery-sequence-gaps.kql && test -f deploy/sentinel/monitoring/queries/delivery-reconciliation.kql` (exit 0). State exactly what each detects, its lookback and lag, and which losses each can miss; do not equate a missing health record to a counted number of lost security events.
3. Propose an operator workflow with per-collector/run evidence, time windows, current versus stale query results, data provenance, clear unknown and incomplete states, duplicates and restart handling, recommended next checks and least-privilege access. Compare a KQL workbook/runbook with a management-console integration; assess cost and dependency on independently declared inventory.
4. Specify synthetic fixtures and expected results for known gap, no gap, duplicates, reordered or late records, restart, a missing first/last record, no health records, incomplete query, and non-Sentinel outputs. Include security and privacy of metadata and a separate authorised live Sentinel qualification plan. Local fixture success is not live evidence.
5. `test -s plans/005-delivery-gap-investigation-design.md && git diff --check && git status --short` exits 0. Review whether every state distinguishes absence of evidence from evidence of absence and update index status.

## STOP and maintenance

STOP if the design treats local acknowledgement as arrival, assumes complete inventory before plan 001 is implemented, or can only function with broad write privileges. Revalidate query limits, ingestion delay and health sequence semantics whenever schema or collector restart behaviour changes.
