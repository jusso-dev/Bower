# Bower.Evidence instructions

Query-verified delivery evidence for assessors.

- Never report "verified" without a Sentinel query returning the canary row.
  Without a workspace the bundle is "simulated" and says so in its limitations.
- Bundles are metadata only: no payloads, tokens or query response bodies.
- Use a read-only verifier identity (Log Analytics Reader), separate from the
  ingest identity.
- Control statuses are evidence statements, not compliance determinations.
- Parser probes are opt-in and use only repo-owned synthetic fixtures
  (`ParserProbeFixtures`); keep them byte-identical with `rust/crates/bower-evidence`.
  Only the exact probe EventId with the expected event type verifies; acceptance never
  does. The `probe` bundle field is additive and omitted for the generic probe.
