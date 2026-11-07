# Docker sidecar

`Bower.Agent.Docker` is a small container you add to an existing Docker or Compose
stack. It reads the logs of containers you opt in, picks out security events, and
forwards them to a Bower collector. The collector then redacts, validates and applies
policy exactly as it does for SDK events.

```
labelled containers ──json-file logs──▶ bower-sidecar ──HTTPS/token──▶ bower-collector ──▶ Sentinel
                       (read-only)       select + map                    redact + policy
```

## What it forwards

The sidecar is deliberately selective; Bower is not a log shipper.

| Line in a container log | Result |
|---|---|
| A Bower event envelope printed as one JSON line (`schemaVersion`, `eventId`, `eventType`, …) | Forwarded as-is, with `docker.*` labels added |
| SSH `Failed password` / `Failed publickey` / `Invalid user` | `authentication_failure` with username and source IP |
| SSH `maximum authentication attempts exceeded` | `account_lockout` |
| PAM `pam_unix(...:auth): authentication failure` | `authentication_failure` |
| nginx basic auth `password mismatch` / `was not found` | `authentication_failure` |
| Anything else | Dropped at the sidecar and counted |

Mapped events never contain the raw line; they carry a SHA-256 of it plus the
container id, name and image. Event ids derive from container id, log file and byte
offset, so replays after a restart are deduplicated by the collector.

For anything not in the table, have the application print Bower events as JSON on
stdout (see [ASP.NET Core integration](../developer-integration/aspnetcore.md) for the
event shape) — they pass straight through.

## Install into an existing stack

1. Use the published image `ghcr.io/jusso-dev/bower-sidecar` (see
   [container images](container-images.md)), or build your own from the Bower
   repository root:

   ```bash
   docker build -f deploy/docker/Dockerfile.sidecar -t bower-sidecar:local .
   export BOWER_SIDECAR_IMAGE=bower-sidecar:local
   ```

2. Label each container whose logs Bower should read:

   ```yaml
   services:
     ssh-gateway:
       image: example/ssh-gateway
       labels:
         bower.collect: "true"
         bower.application: ssh-gateway   # optional; defaults to the container name
         bower.environment: production    # optional
   ```

3. Merge the sidecar into your stack, pointing it at your collector:

   ```bash
   export BOWER_INGEST_TOKEN=<the collector's ingest token>
   export BOWER_COLLECTOR_URL=http://bower-collector:4319   # or https://collector.example.org
   docker compose -f compose.yaml -f /path/to/bower/deploy/docker/compose.sidecar.yaml up -d
   ```

4. Check it: `docker compose logs bower-sidecar` prints one summary line per pass
   with forwarded, rejected and dropped counts. `docker ps` shows the health check.

Try it all locally first with the demo stack (collector, sidecar, a labelled
"legacy" container and an unlabelled one that is ignored):

```bash
export BOWER_INGEST_TOKEN="$(dotnet run --project src/Bower.Cli -- token generate)"
docker compose -f deploy/docker/compose.sidecar-demo.yaml up --build
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `BOWER_COLLECTOR_URL` | `http://bower-collector:4319` | Collector base URL. With a token, plain HTTP is allowed only for loopback or a single-label Compose service name. |
| `BOWER_INGEST_TOKEN` / `BOWER_INGEST_TOKEN_FILE` | — | Collector ingest token. |
| `BOWER_DOCKER_LABEL` | `bower.collect` | Opt-in label (value must be `true`). |
| `BOWER_DOCKER_READ_EXISTING` | `false` | `true` replays existing log history the first time a container is seen. |
| `BOWER_POLL_SECONDS` | `5` | Poll interval (1–600). Backs off up to 2 minutes under backpressure. |
| `BOWER_SIDECAR_ID` | host name | Identifies the sidecar on forwarded events. |
| `BOWER_ENVIRONMENT` | `production` | Default `application.environment` when the container has no label. |
| `BOWER_DOCKER_ROOT` | `/var/lib/docker/containers` | Mounted Docker container directory. |
| `BOWER_SIDECAR_STATE` | `/var/lib/bower-sidecar/cursors.db` | Durable cursors (keep on a volume). |

## Delivery guarantees

- **At least once.** The cursor for each container advances only past lines the
  collector accepted (`200`/`202`), definitively refused (`400`/`413`/`422`), or the
  sidecar intentionally dropped. On `429`, `503`, `5xx`, `401`/`403` or a network
  error it stops, keeps its position and backs off.
- **Restarts.** Cursors live in SQLite on the `bower-sidecar-state` volume, so a
  restarted sidecar resumes where it stopped.
- **Rotation.** Files are identified by their first bytes, so Docker's
  `max-size`/`max-file` rotation is detected. With `max-file` 2 or more Docker renames
  the log to `.1` (and older files to `.2` and on), and the sidecar drains `.1` before
  the new file. With `max-file: 1` (Docker's default when only `max-size` is set) Docker
  deletes the log and creates it again instead: there is no `.1`, so whatever the
  sidecar had not read when the log rotated is lost, the gap is logged (event 3003) at
  every rotation, and the first line of each stream after it is dropped as a possible
  fragment (see **Fragments**). Set `max-file` to 2 or more for collected containers, as
  the example Compose files do (`3`), so fewer lines are lost. If a log rotates more than
  once between passes, the gap is logged too.
- **Lines and streams.** Docker writes a line over 16 KiB as several chunks, and copies
  stdout and stderr into the same file at the same time, so another stream's entries can
  sit between two chunks of one line. Every chunk of one line carries the same stream
  and the same `time` (its first chunk's), and the last one ends with a newline. The
  sidecar therefore joins an entry to an open line only when both match: a stderr line
  between two stdout chunks is read as a line of its own, and an oversized line being
  skipped skips only its own chunks. An entry of the same stream with another `time`
  starts a new line, so the open one ended at stream end (Docker writes what is left
  when a stream ends, for example when the container stops, as an entry with no
  newline) and is read as a whole line. Entries of any other stream, or with a `time`
  longer than Docker writes, are counted as malformed.
- **A line open when the log rotates.** Docker can rotate between two chunks of one
  line, and never writes to `.1` again. Once `.1` is read to its end, the sidecar moves
  to the new file with each line still open there (at most one per stream) recorded in
  its cursor; the next pass reads that line's chunks again, from whichever rotated file
  now holds each of them (found by identity in `.1`, `.2` and on, so a further rotation
  that moves them to `.2` loses nothing), and joins them with the rest in the new file,
  so the line arrives whole. The sidecar logs `Container <name>
  log rotated with <n> line(s) still open` (event 3006) once the move is committed.
  Earlier releases either waited on `.1` until the new file was itself rotated away,
  which lost that whole file, or read the two parts as separate lines. A line already
  being skipped as oversized when `.1` ends (see **Bounds**) is still skipped into the
  new file, up to its final chunk, and counted once. A torn entry at the end of `.1` (no
  newline, possible only after a daemon crash or a full disk) is counted as malformed
  and the sidecar moves on the same way.
- **Fragments.** The cursor names every line still open, so once the sidecar has seen a
  line open it never reads that line's rest as a whole line. If the head cannot be read
  again (it was rotated past the last file Docker keeps, compressed or deleted, or with
  `max-file: 1` the log was deleted and created again), or the saved chunks no longer
  match their length and digest, the gap is logged (event 3003) and the rest is a
  fragment. So is a line an entry the sidecar cannot read sits between the chunks of (it
  may have been one of them), and the next line of each stream after such an entry
  (malformed, over 100 KiB or torn: it may have been that line's head, and its stream is
  unknown; for a line still open then, the next line once another time ends it). A fragment is never mapped, whatever it contains, so it can
  neither become a signal with a cut-off address nor pass as a Bower envelope; it is
  dropped and counted in the pass summary (`fragment(s) dropped`, event 3001), as is a
  line the sidecar had read part of and lost when nothing more of it arrives.
- **After a gap or a first sight, fail closed.** Where the sidecar starts reading
  anywhere but its own last position (it first sees a log, or a gap passed lines it had
  not read), a line may already be open on each stream, its head somewhere the sidecar
  never read. It looks back from where it starts, through the file and then `.1`, `.2`
  and on, within one pass's byte budget (charged to that pass). A stream counts as clean
  only when the look back reaches its last entry and that entry ends its line, or reaches
  the sidecar's own last position in a rotated file (its cursor named every line open
  there), or, at a first sight only, the start of the oldest file Docker kept. If that
  last entry leaves a line open, the rest of that line is a fragment. Otherwise (the
  budget ran out, a file between is missing or unreadable, or after a gap the file
  before the oldest one is gone, as always with `max-file: 1`) the stream's next line,
  whatever it is, is dropped as a fragment; the line after it is read normally. So no
  line that may be the rest of another is mapped, at the cost of at most one dropped
  line per stream after each gap or first sight; gaps are logged and fragments counted.
  The limit, at a first sight only: Bower cannot tell whether Docker deleted older files
  before it first saw the log, so a stream with no entry at all in the files Docker
  kept is taken as clean, and if a deleted file held the head of a line of that stream
  whose rest is still to come, that rest is read as a whole line.
- **When a line's final chunk never arrives.** Until an entry of the same stream with
  another `time` arrives, the sidecar cannot know that an unterminated entry ended its
  line, so it waits for the rest. The final chunk can be missing for good: a stream that
  ended without a newline (read as a whole line once the stream writes again), a daemon
  crash, or `mode: non-blocking`, whose ring buffer drops messages, including chunks,
  when it is full. A line whose final chunk was dropped is read as a whole line when the
  next line of its stream arrives, so use the default blocking mode for collected
  containers. The exception: if the file holding the line was rotated out of the files
  Docker keeps before its stream wrote again, the line cannot be read again, so the gap
  is logged (event 3003) and the line is counted as lost (`fragment(s) dropped`), never
  read as a whole line.
- **Compressed rotation.** With `compress: "true"` Docker gzips `.1` to `.1.gz` shortly
  after each rotation and removes `.1`. The sidecar does not read compressed files, so
  unless a pass drains `.1` before then, whatever it had not read when the log rotated is
  lost, and the gap is logged. Leave `compress` off for collected containers.
- **Bounds.** Lines over 64 KiB are counted and skipped; each pass reads at most
  1,000 lines (one more when an entry both ends one line and is a line itself) or 4 MiB
  per container. Docker's 16 KiB partial chunks are reassembled. A line that is over
  64 KiB, has more than 32 chunks, or still has not ended after a whole pass's byte
  budget read from its first chunk with nothing else completed, is never buffered: its
  chunks are consumed and committed as they are read, across passes and restarts, and
  the line is counted as oversized once when its final chunk arrives or its stream
  starts another line. Only a line open alone is skipped that way: with another stream's
  line open too, both are kept. Other lines are read normally meanwhile. A line still
  open at the end of a pass is read again on the next pass, its saved chunks only (at most
  one line per stream, each within 64 KiB), never what lies between them; those bytes,
  the look back and identifying rotated files after `.1` count against the pass's byte
  budget, and each pass still reads at least one new entry, so a pass reads at most its
  budget plus one entry. Open lines are read again smallest first, after the
  line whose next entry comes first. A line that does not fit what is left of the budget is
  deferred: kept as it is and read in a later pass, with the pass stopping before that
  line's next entry. Only a line that can never be read again within one budget (never with
  the default 4 MiB, which holds two whole lines at their limit) is skipped and counted as
  oversized in the same way.
  An entry over 100 KiB (more than a 16 KiB chunk escaped six bytes a byte) is malformed.

## Cursor format

Each container's cursor is JSON in the state database:
`{"schemaVersion":1,"fingerprint":"<sha256 of first 64 bytes>","offset":<bytes>}`.
Two additive fields, omitted when empty, so cursors written before them read unchanged
and ordinary cursors serialise byte-for-byte as before:

- `"discarding":true` while an oversized line is being skipped.
- `"pending"`: every line open at `offset`, at most one per stream, each named by its
  `stream` and Docker `time`. One being skipped has `"discarding":true`. One being
  assembled has `file` (the fingerprint of the file holding its first chunk, `.1` after a
  rotation), `start` (its first chunk), `chunks` (its later chunks in `file`), `through`
  (its chunks in each file rotated between `file` and the cursor's, as `file` and
  `chunks`), `rest` (its chunks in the cursor's own file when `file` is a rotated one),
  `length` (characters so far) and `digest` (SHA-256 of those characters, 16 bytes,
  base64), so the next pass reads exactly those chunks again and checks them. One read
  once and committed before its head has `file` equal to the cursor's own, `start` at or
  after `offset`, and the `length` and `digest` read so far, checked when the head is
  read again. The rest of one whose head was lost has `"fragment":true` (and
  `"lost":true` when the sidecar had read part of it). A stream not proven clean after a
  gap or a first sight, or after an entry the sidecar could not read, has
  `"unproven":true`, `"fragment":true` and no `time`: its next line is a fragment. An open
  line with `"unproven":true` and its `time` had such an entry come while it was open: if
  another time ends it, the line that time starts is a fragment. Offsets, a length, a digest and the time only, never line content.

A rotation the sidecar drains carries them into the new file. Truncation, a missed
rotation or a lost rotated file turns each open line into the rest of one
(`"fragment":true`), so its rest is a fragment. A cursor that does not pass validation
(another schema, a range past its offset or out of order, chunks shared by two lines) is
refused as a whole: the sidecar logs `Stored cursor for <name> is damaged` (event 3007)
and reads from the start position again, as for a new container. `pending` is new in
this release: only cursors released on main are read as described here, and a
`pending` form written by a pre-release build that this release does not write (such as
an open head with `length` 0 and no `digest`) is refused the same way.

A cursor written before `pending` existed with `"discarding":true` names no line. The
old release skipped every entry up to the first that ends with a newline, whatever its
stream, so the entries before the offset back to the last terminated one are what it
skipped: when they are all one stream and time, that is the key. Otherwise (another
stream's chunk among them, the offset at the start of a file after a rotation, a
malformed entry there, or a run longer than 400 KiB) the old rule holds for that one
line: entries are skipped up to and including the first that ends with a newline,
whatever its stream, and the rest of another stream's line the old release had joined
into the skipped one is read as a line, as it was before the upgrade. Downgrading is not
recommended while a line is open or being skipped: an older sidecar ignores `pending`
and reads the rest of that line as if it were a new line.

## Security model

- **No Docker socket.** The sidecar reads `/var/lib/docker/containers` mounted
  read-only. It cannot list, start, stop or exec containers.
- **Non-root.** The process runs as uid 1654 on a chiseled image (no shell, no
  setuid binaries) with a read-only root filesystem and every capability dropped
  except `DAC_READ_SEARCH`, which only bypasses read and directory-traverse checks.
  Docker's container directory is root-only (`0710`, metadata `0600`), so that one
  capability is required to list containers and read their labels.
- **Why `no-new-privileges` is off.** Docker never grants added capabilities to a
  non-root user directly; the sidecar binary carries `cap_dac_read_search` as a
  file capability instead, and `no-new-privileges` blocks file capabilities. With
  nothing else in the image able to gain privileges, the effective result is one
  read-only capability. Without `cap_add: DAC_READ_SEARCH` the binary refuses to
  start (`operation not permitted`).
- **Opt-in only.** Containers without `bower.collect=true` are never read.
- **Token handling.** The ingest token is sent only as a bearer header and is never
  logged.

## Limitations

- Requires the `json-file` logging driver (Docker's default). Containers using
  `local`, `journald`, `syslog` or other drivers are skipped and counted.
- Docker Desktop and OrbStack keep container logs inside their Linux VM; the bind
  mount works when the daemon resolves `/var/lib/docker/containers` inside that VM
  (verified on Docker 29 with the demo stack).
- Rootless Docker and user-namespace remapping store logs elsewhere; set
  `BOWER_DOCKER_ROOT` accordingly.
- Kubernetes Pod Security "restricted" disallows `DAC_READ_SEARCH`; the sidecar
  targets Docker and Compose hosts.
