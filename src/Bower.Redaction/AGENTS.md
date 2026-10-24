# Privacy & Secret Protection Engine

Runtime redaction must stay **deterministic**. No AI, no network lookups, no
arbitrary code from configuration.

## Invariants

- Redact **before** persistence. Treat redaction failure as a security failure.
- Never log original secrets, credentials, tokens, or unrestricted bodies.
- Privacy metadata may list detector ids and actions only — never original values.
- Default-deny field-name secrets (password, token, body, headers, …).
- Prefer checksum validation (TFN, ABN, ACN, Medicare, IHI, Luhn) to cut false positives.
- New detectors implement `ISensitiveDetector` and register via `DetectorCatalog`
  or constructor injection — do not hard-code detector lists inside `PrivacyEngine`.
- Keep detectors independently enable/disable-able through `PrivacyPolicy`.
- Opt-in detectors (IP, hostname, username, address, GPS, markings) stay off unless enabled.
- Add unit tests for every new detector (positive + negative / invalid checksum).
- Add or update micro-benchmarks when changing hot paths.
- Custom detectors (`customDetectors:`) compile only the canonical pattern emitted by
  `CustomPatternTranslator`; never pass user patterns to `Regex` directly. The syntax
  rules, rejection reasons, limits and canonical output are a contract with the Rust
  port (`rust/crates/bower-redaction/src/custom_pattern.rs`): change both and
  regenerate the parity vectors.
- Custom detectors and secret field names live on `PrivacyPolicy`; default engine
  construction (`PrivacyEngine(policy)`, `JsonEventRedactor(policy)`) picks them up.
- Custom detector work is bounded deterministically (`CustomPatternDetector.MaximumScannedLength`,
  `MaximumMatchesPerEvent`; exceeding either quarantines). Never rely on regex timeouts for
  parity: they depend on machine load. Non-redacting custom detectors must never claim spans.
- Do not use capture groups or `\A`/`\z` with .NET NonBacktracking for new features: captures
  are lost next to anchors on input ending in a line feed (see the wholeWord sentinel).

## Layout

- `Privacy/` — engine, policy, interfaces, catalog, applicator
- `Validation/` — checksum algorithms
- `Detectors/` — modular detector implementations by domain
