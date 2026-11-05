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
- Recorded divergences: Rust refuses a FIFO, socket or device at the path; C# cannot tell
  them from an empty file and never opens them (shorter than 64 bytes). Rust verifies each
  open (`O_NOFOLLOW`, device and inode) on every Unix; C# does so on Linux only.
- Move the cursor past a line only after the sink settled it; never move this into a
  scheduled job. Rotation state lives in the cursor; rewinds use `Batch::rewind_to`.
- Gap counting (`rotation_gaps`) is best effort, as in C#: the drain cap counts only polls
  that reach the end of `path.1` or pass `drain_length`; an abandoned `path.1` is watched
  from any cursor, provisional included; a legacy-cursor gap is counted once the replay
  cursor is stored. Late writes to an abandoned `path.1` rotated away before the next poll
  are neither read nor counted.
