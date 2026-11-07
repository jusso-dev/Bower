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
  carried across rotation, and a renamed `.1` taken as final (`RenamedFileIsFinal`): Docker
  never writes it again, so once it is read to its end a line left unfinished there (split
  across the rotation, or a torn entry) moves the cursor to the new file with `Discarding`
  set, and the rest of that line is skipped and counted as oversized (a torn entry as
  malformed) instead of holding the cursor on `.1` until the new file is lost. `DockerLogCursor` keeps no rotation state, so each read detects a
  rotation again. Changing any of that changes Docker output:
  `DockerReaderDifferentialTests` compares the reader with the frozen pre-refactor copy
  (`LegacyDockerJsonLogReader`) and must keep passing (its histories end an open line
  before rotating, the one deliberate difference, pinned by
  `LineSplitAcrossRotation_IsSkippedWhereThePreRefactorReaderLostTheNextFile`), as must the open-to-decision races
  in `DockerSharedTailerTests`, which hit both readers through matching hooks.
- Persisted `DockerLogCursor` values must keep loading (`DockerCursorCompatibilityTests`);
  change the schema only with a versioned migration.
- Changes need malformed-input, rotation and durable cursor tests.
