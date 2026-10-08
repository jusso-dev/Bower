# Bower.Dcr instructions

DCR optimiser, Sentinel schema model, DCR generator, drift checks and ingestion
preflight.

- `SentinelSchema.Default` is the single source of truth for the Bower table. The
  Bicep template must match it (enforced by tests). Evolve additively: never rename
  or retype a column.
- Analyse DCR documents offline. Never call live Azure APIs from unit tests.
- Recommendations must be deterministic and include estimated savings only when
  inputs provide volume signals.
- Preflight must flag every condition Azure handles silently (truncation, type
  coercion, dropped rows) so Bower can dead-letter with a reason instead.
