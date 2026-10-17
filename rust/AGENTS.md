# Rust data plane

Rust port of Bower's data plane, alongside (not replacing) the C# implementation.
Root `AGENTS.md` invariants apply unchanged.

## Scope

`bower-collector` and `bower` CLI plus their libraries: contracts, integrity,
packs, policy, redaction, persistence, core, outputs. Agents, Management API and
the console stay C# only.

## Parity rules

- The C# source in `src/` is the specification. Port behaviour, failure codes,
  limits and defaults exactly; when C# and docs disagree, follow C# and note it.
- Serialize events with `bower_contracts::json` (System.Text.Json compatible
  escaping, `DateTimeOffset` text, `MaxDepth = 32`). Never use `serde_json::to_string`
  for anything hashed, signed, queued or delivered.
- Hashes, fingerprints, canonical JSON and signatures must match C# byte for byte.
  Prove it with tests using vectors produced by, or copied from, the C# tests.
- Arbitrary JSON carried in events (`attributes`) uses `bower_contracts::JsonElement`,
  which keeps number text and duplicate keys like `System.Text.Json.JsonElement`;
  never `serde_json::Value` on a path that is queued, hashed or delivered.
- Keep the release profile unwinding: `bower-core` catches redactor panics and
  fails closed. `panic = "abort"` would turn that into a process crash.
- Where C# crashes or throws on bad input, fail closed and record the divergence
  in the test that pins it.
- Read shared assets (`policies/`, `schemas/`, `packs/`, `deploy/`) from the repo;
  never fork copies.
- SQLite schema must stay compatible with `src/Bower.Persistence` so either
  implementation can open the other's queue.

## Conventions

- Edition 2024, `unsafe_code = "forbid"`, clippy clean (`-D warnings`).
- Dependencies come from `[workspace.dependencies]`; justify new ones in
  `docs/architecture/dependencies.md`.
- `DurableEventStore` is synchronous; call it from async code via `spawn_blocking`.
- No secrets, tokens or payloads in logs or errors.

## Commands

```bash
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```
