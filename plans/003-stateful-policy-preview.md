# Plan 003: Design a stateful policy rollout preview

**Status:** DONE (design: [003-stateful-policy-preview-design.md](003-stateful-policy-preview-design.md)) · **Category:** direction · **Priority:** P2 · **Eventual effort:** M–L · **Risk:** medium · **Depends on:** none · **Planned at:** `64859aa7d620cec2538aa74fed647e4076e83490` (2026-11-12)

## Outcome and boundaries

Produce `plans/003-stateful-policy-preview-design.md` for a deterministic, bounded, synthetic sequence comparison. No source changes, live queue access or production payloads. Existing policy diff remains unchanged until a separately approved implementation.

## Current state

`docs/operations/suppression-archive-and-source-silence.md:17-48` describes persistent window counts, duplicated suppressed attempts, and explicitly says `bower policy diff` does not exercise stateful suppression (`notExercisedOffline`). `src/Bower.Cli/Commands/PolicyCommands.cs:125-133` loads baseline and candidate bundles and compares their policy decisions at a fixed time. Existing diff uses metadata only and reports bundle hashes (`docs/operations/suppression-archive-and-source-silence.md:75-87`). Queue state and redaction are security boundaries.

## Steps and checks

1. `git diff --stat 64859aa7d620cec2538aa74fed647e4076e83490..HEAD -- src/Bower.Cli src/Bower.Core src/Bower.Persistence docs/operations/suppression-archive-and-source-silence.md tests` and inspect drift; STOP if premises changed.
2. Trace actual suppression transaction, duplicate handling, window closure and policy bundle loading; cite exact current locations in the artifact. Verify starting references: `test -f src/Bower.Cli/Commands/PolicyCommands.cs && test -f docs/operations/suppression-archive-and-source-silence.md` exits 0. Do not substitute a second approximate algorithm without assessing parity.
3. Specify bounded synthetic input format, independent baseline/candidate state, pinned clock and ordering, row/byte/window limits, cleanup, deterministic output and privacy-safe identifiers. Explain whether a disposable queue reuses production logic and how secrets or unredacted events remain outside persisted output. Explain what preview does not model: actual traffic, retries not included, destination delivery and production capacity.
4. Specify tests for boundary times, per-key windows, aggregate versus suppress, duplicates before and after suppressed attempts, restart/window closure, summary policy denial, queue pressure and redaction failure. Require comparable hashes, deterministic repeated runs and unchanged current diff output. Require adversarial/crash tests before any real queue change.
5. `test -s plans/003-stateful-policy-preview-design.md && git diff --check && git status --short` exits 0. Check artifact explicitly identifies non-exercised behaviour and update index status.

## STOP and maintenance

STOP if reuse of queue logic requires access to an existing queue, if the preview cannot keep redaction before persistence, or if simulation cannot be distinguished from production evidence. Any later suppression change must update preview parity tests and population-diff documentation.
