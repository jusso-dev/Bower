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
- Match signal patterns with `RegexOptions.NonBacktracking` and no match timeout. A
  timeout makes the mapping depend on machine load (a real failure dropped as
  unrecognised); the line limit bounds the linear engine instead.
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
  a discard key; a line being assembled (`file`, `start`, `chunks`, `through`, `rest`,
  `length`, `digest`: exactly its chunks are read again on the next read, each from the
  file its identity names, the current one or any of `.1` to `.N` (`Generations`), and
  must match the length and digest, at most `MaximumChunks`); a head read once and
  committed before it (`file` the cursor's own, `start` at or after its offset, `length`
  and `digest` checked when it is met again); the rest of a line whose head is lost
  (`fragment`, `lost` when Bower had read part of it); or a stream not proven clean
  (`unproven`, `fragment`, no time). Never store line content there, and never drop a key:
  a cursor without one for an open line lets a gap turn its rest into a whole line. A
  read that ends with lines open commits the last point with none open only while
  nothing has been emitted or counted since (the old reader's position), naming those
  lines by head, length and digest; otherwise it records their chunks, so another
  stream's lines are never re-emitted or stalled behind an open one. Moving into a new
  file turns a line's chunks in the drained file into a `through` run. Only main's
  cursor formats are supported: a `pending` form from an unreleased build that this one
  does not write is refused as damaged, never migrated. Re-reading costs a line's own size, never the
  span to the cursor. The look back, the identities of rotated files after `.1` opened by
  the decoder, and re-reading all count against the byte budget, so a pass stays within
  the budget plus one entry (each read still takes one new entry);
  `LookBackOutsideBudget` exists only for the differential test. A line that began where the read did and is still open, alone, after a whole
  byte budget is discarded, except at the end of a final `.1`, where every open line is
  carried into the new file and joined there. `Deserialize` refuses a cursor whose ranges
  are impossible (past its offset, out of order, shared); the sidecar logs event 3007 for
  a damaged stored cursor. Each record carries `Resume`, a cursor that emits it and every
  later record in its batch again (and may emit again earlier records of the batch that
  ended after it began, with the same ids); the sidecar rewinds there on backpressure,
  never to a bare offset.
- Fragments: never emit a head or a rest of a line as if it were whole. A line is a
  fragment (`DockerLogRecord.Fragment`) when its head cannot be read again (rotated past
  the files Docker keeps, removed or changed, or `max-file: 1` deleting the log; counted
  as a gap), when an entry between its chunks cannot be read, and when it may have been
  open where a first sight or a gap starts reading. `DockerLogEventMapper` never maps a
  fragment, as a `SemanticEvent` or a signal; the sidecar drops and counts it, and counts
  a lost line nothing more of which arrives (`DockerLogBatch.Lost`). Entries up to
  `MaximumEntryBytes` (a 16 KiB chunk escaped six bytes a byte) are read whatever the line
  limit.
- Fail closed after a gap or a first sight (any position other than the read's own):
  every key in the cursor becomes a fragment, and the decoder looks back from the start,
  through the file and then `.1`, `.2` and on, within one byte budget. A stream is clean
  only when the look back reaches its last entry (terminated: clean; open: that line is a
  fragment), the read's own last position in a rotated file (its cursor's keys hold), or,
  at a first sight only, the start of the oldest rotated file there is. Otherwise (the
  window ran out, a file between is missing, unreadable or a repeat, an unreadable entry
  after the stream's last one, or after a gap the oldest file's predecessor is gone) it
  is `unproven`: its next entry keys a fragment, whatever its time. At most one dropped
  line per stream per gap or first sight. Never relax this to "no entry seen means
  clean". The documented limit, at a first sight only: older files Docker deleted before
  Bower first saw the log cannot be known, so a stream with no entry in any kept file is
  taken as clean.
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
