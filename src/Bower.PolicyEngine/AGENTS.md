# Bower.PolicyEngine instructions

Deterministic, explainable event selection. Configuration never executes code.

- Policy YAML loads strictly: unknown keys, numeric actions and category-only
  matches are rejected. Keep it that way.
- Unknown event types are default-deny (`BWR-POL-DEFAULT-DENY`).
- Policy hashes must stay stable for unchanged content.
- Policy content changes need a version bump, stable hash, population diff and tests.
