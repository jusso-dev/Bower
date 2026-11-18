# Bower.AppHost instructions

Aspire local development and integration-test harness (`docs/getting-started/aspire.md`).
Development only: never publish, package or deploy it, and never present it as a deployment
path. Compose, Bicep and the native packages stay the production paths.

- Synthetic data and loopback only. Tokens are generated `AddParameter` secrets kept in the
  AppHost user secrets; never commit a token, key or real credential. The `AWS_*` values
  are placeholders for the S3 emulator and must never be real keys.
- Never weaken a host to make the harness easier: no `BOWER_SINGLE_TRUST_DOMAIN`, no
  unauthenticated ingest, exact producer scopes only (`CanaryEvent.ProducerScopesJson`).
  Development bypasses (`BOWER_AUTH_MODE=development`, `BOWER_DEVELOPMENT_AUTH`) stay the
  hosts' own Development-only modes.
- Add resources by path (`AddDotnetProject`), not `ProjectReference`, so building the
  AppHost does not build or ship the hosts.
- Pin container images by digest and record them in `docs/architecture/dependencies.md`.
- Never claim Sentinel delivery: stand-ins prove local receipt only.
- Keep `tests/Bower.AppHost.Tests` passing with `BOWER_ASPIRE_TESTS=1` when resources,
  commands or wiring change.
