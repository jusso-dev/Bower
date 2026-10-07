# Bower.Contracts instructions

Immutable event contracts and serialization shared by every component.

- Schemas evolve additively. Required-field changes need explicit approval, a
  version bump, compatibility tests and migration notes.
- Keep `schemas/` and the event catalogue in step with contract changes.
- Field names must not collide with the redaction engine's secret field-name rules
  (for example avoid `*token*`, `*secret*`, `*password*` for non-secret data).
