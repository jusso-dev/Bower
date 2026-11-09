# Bower.PolicyEngine instructions

Deterministic, explainable event selection. Configuration never executes code.

- Policy YAML loads strictly: unknown keys, numeric actions and category-only
  matches are rejected. Keep it that way.
- Scalars are canonical (decimal integers, `true`/`false`, `yyyy-MM-dd`) and
  null sections, lists, items and blank field paths fail the load, so a policy
  means the same on every machine and culture.
- `PolicyParityVectorTests` pins loader and evaluator outcomes in
  `tests/fixtures/policy-vectors`. After an intended behaviour change,
  run it with `BOWER_POLICY_VECTOR_OUTPUT=<dir>`, review and copy the
  outcomes into the fixtures.
- Unknown event types are default-deny (`BWR-POL-DEFAULT-DENY`).
- Policy hashes must stay stable for unchanged content.
- Policy content changes need a version bump, stable hash, population diff and tests.
