# bower-persistence instructions

Rust port of `src/Bower.Persistence`. The C# code is the specification; root,
`rust/` and `src/Bower.Persistence/AGENTS.md` rules apply.

- On-disk format is shared with the C# store: never change table, column or index
  names, DDL text, PRAGMAs, enum ordinals or timestamp text (`"O"` round-trip,
  UTC `+00:00`; cursor `UpdatedAt` uses EF Core's `yyyy-MM-dd HH:mm:ss.FFFFFFFzzz`).
- Ledger hashes must match C# byte for byte; `tests/fixtures/csharp-*.db` were
  written by the C# implementation and must keep verifying.
- Queue transitions and cursor updates are transactional (`BEGIN IMMEDIATE`),
  idempotent and crash-safe. Never delete before acknowledgement; purge only
  delivered rows and record the purge in the ledger in the same transaction.
- Errors and logs carry codes and identifiers only, never payloads.
- Schema changes need upgrade, restart and corruption-path tests in both
  implementations.
