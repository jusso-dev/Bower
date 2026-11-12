# Plan 002: Design source-specific evidence probes

**Status:** DONE (design: [002-source-evidence-probes-design.md](002-source-evidence-probes-design.md)) · **Category:** direction · **Priority:** P1 · **Eventual effort:** M–L · **Risk:** medium · **Depends on:** none; plan 001 informs any later fleet scheduler · **Planned at:** `64859aa7d620cec2538aa74fed647e4076e83490` (2026-11-12)

## Outcome and boundaries

Write `plans/002-source-evidence-probes-design.md` selecting one next safe probe and describing a bounded implementation and qualification plan. Do not change code, run a cloud query, use production samples, or issue credentials. A query-confirmed synthetic event proves only the exact path exercised, not all real source traffic.

## Current state

`src/Bower.Evidence/ParserProbe.cs` defines `ProbeProfiles.ResolveParser`, trusted `ParserProbeFixtures.All` and one `LinuxSshGateway` fixture; unknown profiles fail before send. `docs/operations/evidence-bundles.md:82-98` says generic HTTP probe does not prove a parser and documents only that parser profile. Fixture identity is used in destination matching; outcomes include `verified`, `accepted-not-verified` and `parser-inactive`. `src/Bower.Evidence/EvidenceRunner.cs` consumes the profile. Preserve existing bytes and semantics for generic evidence, signed packs and simulated/non-Sentinel outcomes.

## Steps and checks

1. `git diff --stat 64859aa7d620cec2538aa74fed647e4076e83490..HEAD -- src/Bower.Evidence docs/operations/evidence-bundles.md packs tests` and compare current state if changed; STOP on material drift.
2. Inspect `ParserProbe.cs`, `EvidenceRunner.cs`, shipped signed pack parser definitions and existing evidence tests. `test -f src/Bower.Evidence/ParserProbe.cs && test -f docs/operations/evidence-bundles.md` must exit 0. Rank at least two candidate parser paths by operator value, actual available fixture, supported parser runtime and selection/policy readiness; select one or document why none qualifies.
3. Specify a repo-owned synthetic fixture, stable fixture version and unique event identity, expected type, destination query match, redaction expectations, least-privilege verifier, expiry and timeout. Mark HTTP parser intake versus native source transport explicitly: no claim that a synthetic HTTP record verifies syslog, Windows, cloud queue or sender.
4. Specify tests for trusted fixture allowlist, unknown profile rejection before send, stable rendering, signed pack/parser inactive, policy rejection, duplicate or suppressed event, wrong event and configuration hash, permission failure, incomplete query, simulated mode, non-Sentinel output and successful exact destination match. Specify local and authorised live validation separately and define fail-closed behaviour.
5. `test -s plans/002-source-evidence-probes-design.md && git diff --check && git status --short` must succeed. Review exact evidence wording and update the index status.

## STOP and maintenance

STOP if the proposed parser cannot preserve a unique probe ID or safely accept a synthetic fixture, if it needs production payloads, or if any path claims delivery without a destination query. Maintain fixture versions, pack and policy compatibility, and outcome semantics as parsers change.
