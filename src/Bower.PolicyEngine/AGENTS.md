# Bower.PolicyEngine instructions

Deterministic, explainable event selection. Configuration never executes code.

- Policy YAML loads strictly: unknown keys, numeric actions and category-only
  matches are rejected. Keep it that way.
- Scalars are canonical (decimal integers, `true`/`false`, `yyyy-MM-dd`) and
  null sections, lists, items and blank field paths fail the load, so a policy
  means the same on every machine and culture.
- `PolicyParityVectorTests` pins loader and evaluator outcomes in
  `rust/crates/bower-policy/tests/fixtures`. After an intended behaviour change,
  run it with `BOWER_POLICY_VECTOR_OUTPUT=<dir>`, copy the outcomes into the
  fixtures and change the Rust port to match.
- Unknown event types are default-deny (`BWR-POL-DEFAULT-DENY`).
- Policy hashes must stay stable for unchanged content.
- Policy content changes need a version bump, stable hash, population diff and tests.
