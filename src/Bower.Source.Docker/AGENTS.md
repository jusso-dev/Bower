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
- Changes need malformed-input, rotation and durable cursor tests.
