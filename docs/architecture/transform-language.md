# Decision record: safe, deterministic parser transforms

Status: accepted (issue #87, epic #114). Reference:
[transform language](../developer-integration/transform-language.md).

## Context

Signed pack parsers (`packs/*/parsers/*.json`, `CustomLogParserConfiguration`) map one
bounded JSON record to an allowlisted semantic event. Anything beyond picking top-level
string fields needed a new parser kind or a code change. Appliance and host logs need
light reshaping: split a field, coerce a type, pick a nested value, map an enum, pull an
account and address out of a message line. The threat model requires that configuration
never executes code, and both data planes (C# specification and Rust port) must produce
byte-identical events.

Later work builds on this surface: pack-test assertions on transform output (#88),
reduce and aggregation (#95) and the no-code editor (#100).

## Options

**(a) Embed an existing third-party remap language through its Rust crate.** Mature,
type-checked and loop-free. Rejected:

- C# is the specification and must run the same program. Embedding means either a
  native library in every .NET host (FFI, a second toolchain, Native AOT packaging per
  platform, a crash domain outside the managed runtime) or a second implementation of
  someone else's language that we cannot keep byte-identical.
- Its function library is large and grows with upstream releases (network lookups,
  environment access, encoding helpers). We would need an allow-list wrapper, version
  pinning and audit of every release; a single upstream change to number formatting,
  regex semantics or timestamp parsing would break cross-runtime determinism.
- Its regex functions use a general engine whose step costs we cannot count or bound
  identically in .NET.

**(b) A small Bower language implemented in `Bower.Pipeline` and ported to
`bower-pipeline`.** Chosen. The whole language is a few hundred lines per runtime, has
no dependencies, and every behaviour (lexing, Unicode handling, regex priorities, number
and time formatting, step costs) is specified by Bower and pinned by shared vectors.

## Decision

- Statements live in the signed parser document as `runtime.transforms` (array of
  statement strings) with optional static lookup tables in `runtime.tables`. The parser
  file is hashed in the pack manifest and covered by the manifest signature like any
  other content; unsigned or untrusted packs are never loaded. The schema change is
  additive: parsers without transforms behave exactly as before. Older collectors reject
  a parser carrying transforms (`runtime` disallows unknown members), so a pack that
  depends on transforms can never be half-applied.
- The language is total and side-effect free: assignment, `del`, `rename` and `if`/`else`
  only; no loops, user functions, recursion, variables beyond record fields, I/O,
  environment, randomness or clock. The only time input is the explicit evaluation time
  the caller passes (`now()` and the RFC 3164 year).
- Bower ships its own linear-time regex engine (Pike VM over Unicode scalars,
  leftmost-first priorities, no backtracking, backreferences, lookaround or flags), the
  same algorithm in both runtimes, so captures and step counts match.
- Execution is bounded: static limits on statements, nodes, depth, regex size and tables;
  a per-record step budget (1,000,000) and string, array, record and output size limits.
  Overruns fail closed with stable codes.
- Placement: parse, then transform, then match and semantic mapping, then the privacy
  engine (redaction before persistence), then default-deny policy, then the queue.
  Transforms run only inside the collector process on the record it just parsed. Their
  output reaches persistence only as the mapped, allowlisted envelope, after redaction.
- Validation runs wherever a parser is validated: `CustomLogParser.ValidateConfiguration`
  (pack build, pack load, management preview) and `validate_configuration` in Rust, so
  `bower pack build` cannot sign an invalid program and a collector cannot load one.
  `PipelineValidator` documents are graph-only and carry no parser programs, so they need
  no transform check.

## Invariants touched

- Redact before persistence: unchanged. A transform failure quarantines the raw record
  before redaction and persists nothing (collector response `quarantine` with the code,
  selection counter stage `transform`). There is no transform output in logs, errors,
  previews or pack-test problems.
- Default deny: transforms cannot change the policy decision. Write targets reject
  `security`, `security.*`, `bower*` and credential-like names; the semantic mapping still
  reads only allowlisted targets, and policy still decides.
- No arbitrary code in configuration: only the 20 allow-listed functions exist.
- Determinism: identical input, program and evaluation time give byte-identical output in
  both runtimes; `rust/crates/bower-pipeline/tests/fixtures/transform-vectors.json`
  pins validation issues, output bytes, step counts and error codes.

## Failure modes

| Failure | Where | Result |
|---|---|---|
| Invalid program, table or regex | pack build or load, management preview | Metadata-only issue naming statement, column and code; pack not signed or not loaded |
| Sensitive value flows to a non-sensitive field, or a sensitive field is deleted or renamed | build or load | `transform-sensitive-flow` / `transform-sensitive-field` |
| Type mismatch at run time | collector, pack test | Quarantine, `transform-type-error` |
| Step budget exceeded (for example a pathological regex) | collector, pack test | Quarantine, `transform-budget-exceeded` |
| String, array, record or output too large | collector, pack test | Quarantine, `transform-size-exceeded` |
| Record cannot be represented (duplicate keys, too deep) | collector | `pack-record-invalid`, as before |

## Bounds

See [limits](../developer-integration/transform-language.md#limits). All length limits
count UTF-16 code units, as the rest of Bower does, in both runtimes.

## Test plan

- Shared conformance vectors (C# `TransformConformanceTests`, Rust `transform_vectors`):
  every operation, Unicode and escaping edge cases, regex priorities, lazy and empty
  loops, a pathological regex, timestamp formats including year inference and leap
  days, coercions, limits at and over each bound, malformed input, every static error.
- Pack integration in both runtimes (`TransformPackTests`, `transform_pack_tests`):
  the example pack builds and its samples pass (including a transform quarantine), the
  mapped envelope is byte-identical across runtimes and runs, attacks on the security
  decision and sensitive fields fail the build, errors carry no values.
- Collector tests in both runtimes: a budget overrun returns `quarantine` with the code,
  persists nothing and counts stage `transform`; a valid record is accepted with the
  username pseudonymised and the raw message absent from the queue.

## Consequences

The editor (#100) can target the statement grammar directly; a structured form can be
added later as an alternative encoding of the same AST without changing semantics.
Assertions (#88) can compare canonical output JSON and step counts. Aggregation (#95)
should reuse the expression evaluator rather than add a second language.
