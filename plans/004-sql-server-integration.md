# Plan 004: Design SQL Server polling integration

**Status:** DONE (design: [004-sql-server-integration-design.md](004-sql-server-integration-design.md)) · **Category:** direction · **Priority:** P2 · **Eventual effort:** L · **Risk:** high · **Depends on:** none · **Planned at:** `64859aa7d620cec2538aa74fed647e4076e83490` (2026-11-12)

## Outcome and boundaries

Produce `plans/004-sql-server-integration-design.md` assessing demand and an executable integration boundary. Do not connect to a SQL Server, change source code, add dependencies, publish a package or deploy. A library is not evidence of an installed source.

## Current state

`README.md:184` identifies the SQL Server adapter as a library with no collector polling orchestration. `README.md:984-1010` states that runtime-configured EF Core mappings require reflection, so no shipped Native AOT executable references it; batch size and SQL identifiers are bounded; checkpoints advance only after every selected batch event is durable. `src/Bower.Source.SqlServer/SqlServerSourceAdapter.cs:29-33,57-73` returns records and a checkpoint after bounded polling. Existing Windows source is allow-listed, with signed parsers and bookmark after durable processing (`docs/deployment/windows-event-log-source.md:3-25`).

## Steps and checks

1. Run `git diff --stat 64859aa7d620cec2538aa74fed647e4076e83490..HEAD -- README.md src/Bower.Source.SqlServer src/Bower.Collector tests` and inspect changes; STOP on mismatch.
2. Inspect `src/Bower.Source.SqlServer/AGENTS.md`, adapter options, cursor store, mapping, tests and collector deployment modes. Verify `test -f src/Bower.Source.SqlServer/SqlServerSourceAdapter.cs && test -f src/Bower.Source.SqlServer/AGENTS.md` exits 0. Inventory what is genuinely wired and any existing retry/idempotency mechanisms; do not assume the checkpoint can be atomic with event enqueue.
3. Compare a separate non-AOT forwarder with a non-AOT collector variant, explaining packaging, credentials, least privilege, network, managed identity feasibility, failure isolation and support cost. Recommend only one narrow event/table mapping; explicitly classify unverified customer demand and avoid inventing it. Specify no free SQL, bounded records, default deny, redaction before persistence, and a durable acknowledgement boundary.
4. Specify crash/restart and concurrent polling matrix: crash before/after enqueue and checkpoint, duplicate replay, stale checkpoint, partial batch refusal, overlap saturation, out-of-order commits, cancellation, DB outage, malformed/oversized rows, storage pressure, secrets and redaction failures. Describe local disposable DB test requirements and separate real SQL Server qualification. Specify testable at-least-once semantics without claiming exactly once.
5. `test -s plans/004-sql-server-integration-design.md && git diff --check && git status --short` exits 0. Record an explicit go/no-go and unresolved demand, AOT and operational trade-offs; update index status.

## STOP and maintenance

STOP if cursor advancement cannot be tied safely to durable outcomes, deployment would silently change Native AOT support, or credentials must be logged or persisted. Future implementation requires a scoped adapter `AGENTS.md`, cancellation, malformed-input, backpressure and durable cursor tests, and dependency justification for any new dependency.
