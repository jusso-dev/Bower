# bower-source-file instructions

Rust port of `src/Bower.Source.File` (the specification). Its `AGENTS.md` rules apply
unchanged: default deny through each input's route to a signed pack parser, operator-named
files only (no wildcards, directories or globs), path guards against links and paths
outside the allowed roots, bounded lines, polls and json-lines depth, no line content in
logs or status.

- Keep record fields and order, event ids, cursor JSON, failure codes, limits, defaults
  and configuration messages identical to C#. `tests/fixtures/file-tail-vectors.json` is
  shared with `FileTailSourceTests`; change both runtimes together and regenerate the
  expectations from C# (`BOWER_FILE_TAIL_VECTOR_OUTPUT`).
- Integers in the configuration are `i32` like the C# `int` properties, so out-of-range
  numbers fail as serializer errors in both runtimes. List elements are `Option` so a null
  entry fails with the same validation message as C#.
- Records use `bower_contracts::json` and `JsonElement` (number text and duplicate keys
  kept); never `serde_json::Value` on the record path.
- The sink and cursor store are synchronous; `run` calls `poll_once` on the blocking pool.
  Stopping takes effect between lines (C# also cancels a submission in flight).
- Recorded divergence: Rust refuses a FIFO, socket or device at the path; C# cannot tell
  them from an empty file and never opens them (shorter than the fingerprint).
- Move the cursor past a line only after the sink settled it; never move this into a
  scheduled job.
