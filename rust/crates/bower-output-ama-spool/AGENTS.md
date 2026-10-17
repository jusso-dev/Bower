# bower-output-ama-spool instructions

Rust port of `src/Bower.Output.AmaSpool` (the specification).

- UTF-8 JSON Lines written to an owner-only `CreateNew` temp file, fsynced, then
  moved into the ready directory without overwrite. Never split a record.
- File names, sanitising (`char.IsLetterOrDigit` per UTF-16 unit), roll-over,
  failure codes and acknowledgements must match C#; see
  `tests/fixtures/csharp-vectors.json`.
- I/O failures fail the whole batch as retryable (at-least-once); never
  acknowledge an event before its file is in the ready directory.
