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

## Layout

- `Privacy/` — engine, policy, interfaces, catalog, applicator
- `Validation/` — checksum algorithms
- `Detectors/` — modular detector implementations by domain
