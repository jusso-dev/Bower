# Bower.Source.File instructions

Security-selected local file tail (collector `BOWER_FILE_CONFIG`): a short list of named
files whose lines go through a signed pack parser. Not log shipping: there is no wildcard,
directory, glob or default route, and Bower is not a log forwarder for the estate. The
Rust port (`rust/crates/bower-source-file`) must keep the same record shape, event ids,
cursor format, limits, defaults, failure codes and configuration messages.

- Default deny: a line reaches the queue only through its input's route to an active
  signed pack parser whose match filter selects it, then redaction and policy. Lines the
  parser does not select are counted and dropped.
- Paths: absolute, normalised, no wildcards, strictly below an allowed root (never `/`).
  Refuse symbolic links on the file and on every directory below the root; `allowSymlink`
  permits exactly one link on the file whose target passes the same checks. Check the path
  and `path.1` before and after each read; open through `FileTailHandle` (Linux:
  `O_NOFOLLOW | O_NONBLOCK` plus a `statx` device/inode match) and take identity, length and
  lines from that one handle. Never open a file shorter than 64 bytes (FIFOs and devices
  report empty), and never add a glob form without a hard file-count cap and review.
- Identity is SHA-256 of the first complete line (64–4096 bytes). Inodes check each open
  but are never stored: cursors must stay readable by both runtimes.
- Bound everything: `maxLineBytes` (at most 30 KiB so the record fits the 32 KiB pack
  record limit), lines and bytes per poll, json-lines depth 8, configuration 256 KiB.
  Oversized lines are skipped without being buffered.
- Cursors live in the queue database's `source_cursors` table (`file:<id>`). Move the
  cursor past a line only once it is durably enqueued or definitively dropped; a full
  queue stops reading and rewinds to the start of that line. Never drop for backpressure.
- Rotation state is in the cursor (`drain`, grace counters, `abandoned`), never only in
  memory. While draining, never read the current file. Copytruncate (device/inode where
  known; else same identity and shorter than the cursor) drains the static copy and
  switches at once; only a rename waits `rotationGracePolls` unchanged end-of-file polls.
  Record the abandoned generation only in the committed switch cursor (rewinds use the
  batch's `Origin`). A missed rotation, a vanished drain or later growth of the abandoned
  `path.1` is counted as a gap, never hidden.
- Event ids derive from input id, file fingerprint, line start offset and line bytes so a
  re-read deduplicates; change them only with a migration note.
- Never log or expose line content, records or file contents. Counters, paths and failure
  codes only.
- Changes need malformed-input, oversized-line, rotation, path-guard, cursor
  crash/recovery, backpressure and cancellation tests, mirrored in Rust
  (`rust/crates/bower-source-file/tests/fixtures/file-tail-vectors.json` is shared;
  regenerate with `BOWER_FILE_TAIL_VECTOR_OUTPUT`, then review the diff).
- Follow-up, not in this project: the Docker source keeps its own copy of the tail
  mechanics (`DockerJsonLogReader`); move it onto `FileTailReader` in its own change.
