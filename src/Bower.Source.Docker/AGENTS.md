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
- Open lines live in `DockerLogCursor.Pending` (additive): a discard key, a line being
  assembled (`file`, `start`, `length`: re-read from its first chunk on the next read,
  from `.1` after a rotation), or the rest of a line whose head is lost. Never store line
  content there. A read that ends with lines open commits the last point with none open
  only while nothing has been emitted or counted since (the old reader's position);
  otherwise it records them, so another stream's lines are never re-emitted or stalled
  behind an open one. A line open since the read began that spans a whole byte budget is
  discarded, except at the end of a final `.1`, where every open line is carried into the
  new file and joined there. Each record carries `Resume`, the cursor that reproduces it
  and every later record in its batch; the sidecar rewinds there on backpressure, never to
  a bare offset.
- Fragments: a line whose head cannot be read again (its `.1` rotated away or changed) is
  a fragment (`DockerLogRecord.Fragment`, counted as a gap). `DockerLogEventMapper` never
  maps a fragment, as a `SemanticEvent` or a signal; the sidecar drops and counts it.
  Never emit a head or a rest of a line as if it were whole.
- An old cursor with `Discarding` and no `Pending` takes its key from the chunk that ends
  at its offset; without one (offset 0 after a rotation, or a malformed entry there) the
  old rule holds for that one line: skip up to the first newline-terminated entry of any
  stream. Only the rename drain may pass `eofEndsLine` to the Docker decoder; any other
  path throws.
- `DockerLogCursor` keeps no rotation state, so each read detects a rotation again.
  Changing any of that changes Docker output: `DockerReaderDifferentialTests` compares the
  reader with the frozen pre-refactor copy (`LegacyDockerJsonLogReader`) on single-stream
  histories, records without `Resume` and cursors without `Pending`, and must keep passing,
  as must the open-to-decision races in `DockerSharedTailerTests`, which hit both readers
  through matching hooks. The deliberate differences (a split line joined across rotation,
  stream and time keys) are listed on that class and pinned by `DockerLineIdentityTests`.
- Persisted `DockerLogCursor` values must keep loading (`DockerCursorCompatibilityTests`);
  change the schema only with a versioned migration.
- Changes need malformed-input, rotation, interleaved-stream and durable cursor tests.
