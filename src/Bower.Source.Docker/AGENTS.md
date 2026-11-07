# Bower.Source.Docker instructions

Read-only Docker source for the sidecar.

- Never use the Docker socket or Engine API. Read `/var/lib/docker/containers`
  (mounted read-only) and only from containers labelled `bower.collect=true`.
- Forward only Bower envelopes and recognised security signals. Unrecognised lines
  are dropped here; Bower is not a generic log shipper.
- Never put raw log lines in labels or attributes. Use digests and offsets.
- Event ids derive from container id, file fingerprint and offset so replays
  deduplicate.
- Keep reads bounded (line, batch and byte limits) and consume only complete lines.
- File identity, rotation, truncation and the start position come from the shared tailer
  (`Bower.Source.File.FileTailFiles.Plan`); this project owns only the json-file decoder
  (entries, 16 KiB chunk join, malformed entries, oversized discard, bounds). Docker keeps
  its own policy: 64-byte identity (`FileTailHandle.OpenWithPrefixIdentity`), every length
  measured again where the old reader measured it (`FileTailLength.Measured`: truncation,
  the start-at-end scan, leaving a drained `.1`), no device or inode use, no rotation grace
  window or drain cap, no copy drain on a same-identity truncation, no abandoned-generation
  tracking, waiting while the current file cannot be identified, the oversized discard
  carried across rotation, and a renamed `.1` taken as final (`RenamedFileIsFinal`).
- Line identity is `(stream, time)`, from moby's copier and json-file writer (cited with
  file, lines and commit on `DockerJsonLogReader`): every chunk of one line, its last too,
  has the same stream and `time`, and a new line gets its own. Keep at most one open line
  per stream (stdout, stderr; any other stream, or a `time` over
  `DockerLogCursor.MaximumTimeLength`, is malformed). An entry joins an open line only on
  a match; another stream's entries never touch it; the same stream with another time
  ends it as a whole line (stream end). A discard consumes only its own key's entries.
  Never go back to joining or discarding "whatever comes next".
- Every open line lives in `DockerLogCursor.Pending` (additive), keyed by stream and time:
  a discard key; a line being assembled (`file`, `start`, `chunks`, `rest`, `length`,
  `digest`: exactly its chunks are read again on the next read, from `.1` after a
  rotation, and must match the length and digest, at most `MaximumChunks`); a head still
  to come (`file`/`start` the cursor's own, `length` 0); or the rest of a line whose head
  is lost (`fragment`). Never store line content there, and never drop a key: a cursor
  without one for an open line lets a gap turn its rest into a whole line. A read that
  ends with lines open commits the last point with none open only while nothing has been
  emitted or counted since (the old reader's position), naming those lines as heads still
  to come; otherwise it records their chunks, so another stream's lines are never
  re-emitted or stalled behind an open one. Re-reading costs a line's own size, never the
  span to the cursor, and counts against the byte budget (each read still takes one new
  entry). A line that began where the read did and is still open, alone, after a whole
  byte budget is discarded, except at the end of a final `.1`, where every open line is
  carried into the new file and joined there. `Deserialize` refuses a cursor whose ranges
  are impossible (past its offset, out of order, shared); the sidecar logs event 3007 for
  a damaged stored cursor. Each record carries `Resume`, a cursor that emits it and every
  later record in its batch again (and may emit again earlier records of the batch that
  ended after it began, with the same ids); the sidecar rewinds there on backpressure,
  never to a bare offset.
- Fragments: never emit a head or a rest of a line as if it were whole. A line is a
  fragment (`DockerLogRecord.Fragment`) when its head cannot be read again (`.1` rotated
  away, removed or changed, or `max-file: 1` deleting the log; counted as a gap), when an
  entry between its chunks cannot be read, and when it was open where a first sight or a
  gap starts reading: any other position than the read's own turns every key in the
  cursor into a fragment and looks back up to one byte budget, in the file then `.1`, for
  each stream's last entry. `DockerLogEventMapper` never maps a fragment, as a
  `SemanticEvent` or a signal; the sidecar drops and counts it. The documented limit: a
  head written after the cursor and lost in the same gap was never seen. Entries up to
  `MaximumEntryBytes` (a 16 KiB chunk escaped six bytes a byte) are read whatever the line
  limit.
- An old cursor with `Discarding` and no `Pending` takes its key from the entries before
  its offset back to the last terminated one, only when they are all one stream and time;
  otherwise (another stream's chunk among them, offset 0 after a rotation, a malformed or
  terminated entry there, or a run past the look-back window) the old rule holds for that
  one line: skip up to the first newline-terminated entry of any stream. Only the rename
  drain may pass `eofEndsLine` to the Docker decoder; any other path throws, as do
  `Append` and `WithCursor`, which Docker's policy never calls.
- `DockerLogCursor` keeps no rotation state, so each read detects a rotation again.
  Changing any of that changes Docker output: `DockerReaderDifferentialTests` compares the
  reader with the frozen pre-refactor copy (`LegacyDockerJsonLogReader`) on single-stream
  histories (one time for every entry, and each line's own time), records without
  `Resume` or `Fragment` and cursors without `Pending`, and must keep passing,
  as must the open-to-decision races in `DockerSharedTailerTests`, which hit both readers
  through matching hooks. The deliberate differences (a split line joined across rotation,
  stream and time keys, fragments, the entry limit) are listed on that class and pinned by
  `DockerLineIdentityTests`.
- Persisted `DockerLogCursor` values must keep loading (`DockerCursorCompatibilityTests`);
  change the schema only with a versioned migration.
- Changes need malformed-input, rotation, interleaved-stream and durable cursor tests.
