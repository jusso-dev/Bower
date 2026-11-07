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
- A final `.1`: Docker never writes it again, so once it is read to its end nothing there
  holds the cursor. A line still open within the limits is emitted as it stands and counted
  in `ClosedAtRotation`; the new file is then read from offset 0 with `Discarding` false.
  Never carry a discard into the new file for such a line: the reader cannot tell a split
  line's continuation from a fresh line (Docker interleaves stdout and stderr, and ends a
  stream with an unterminated entry), and every complete record in the new file must be
  delivered. A split line's rest becomes its own fragment record. A line already being
  discarded (oversized, or filling the byte budget) keeps its carried discard. An
  incomplete entry with no newline at the end of `.1` (torn by a crash or a full disk) is
  counted as malformed. Only the rename drain may pass `eofEndsLine` to the Docker decoder;
  any other path throws.
- `DockerLogCursor` keeps no rotation state, so each read detects a rotation again.
  Changing any of that changes Docker output: `DockerReaderDifferentialTests` compares the
  reader with the frozen pre-refactor copy (`LegacyDockerJsonLogReader`) and must keep
  passing, as must the open-to-decision races in `DockerSharedTailerTests`, which hit both
  readers through matching hooks. Its histories close an open line within the limits before
  rotating (the one deliberate difference, pinned by
  `LineSplitAcrossRotation_IsClosedWhereThePreRefactorReaderLostTheNextFile`) and leave an
  oversized one open, so the carried discard is still compared.
- Persisted `DockerLogCursor` values must keep loading (`DockerCursorCompatibilityTests`);
  change the schema only with a versioned migration.
- Changes need malformed-input, rotation and durable cursor tests.
