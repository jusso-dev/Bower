# File tail source

The collector can tail a short list of local files that carry security signal (for
example sshd failures in `/var/log/auth.log`) and turn selected lines into Bower events.
It is a privacy gateway in front of those files, not a log shipper: there are no
wildcards, directories or globs, and no default route. Broad file collection stays with
the Azure Monitor Agent or your log forwarder.

```
named file ──▶ path guards ──▶ complete lines ──▶ record ──▶ signed pack parser ──▶ redact + policy ──▶ durable queue ──▶ output
              roots, no links   bounded, rotation    flat JSON   transforms + match    (default deny)       (cursor moves here)
```

Both collectors (C# and Rust) implement it with the same configuration rules, record
shape, event ids, cursor format, limits and failure codes. They share test vectors
(`rust/crates/bower-source-file/tests/fixtures/file-tail-vectors.json`).

## What is accepted

A line is queued only when:

1. its input's path resolves below an allowed root without symbolic links (or with the
   one link `allowSymlink` permits);
2. the line is complete, within `maxLineBytes` and valid UTF-8 (and, for `json-lines`, a
   JSON object at most 8 levels deep);
3. the input's signed pack parser runs its transforms and its `match` filter selects
   the record; and
4. redaction succeeds and the policy set accepts the resulting event.

Everything else is counted and dropped. Lines, records and file contents are never
logged, stored or shown; only the fields the pack parser maps reach the envelope, and
they are redacted before persistence.

## Configure

Set `BOWER_FILE_CONFIG` to a JSON file (at most 256 KiB). An invalid file, an unknown
property, or a route that does not name an active parser of a loaded signed pack stops
start-up and refuses a signed `reload`.

```json
{
  "apiVersion": "bower.security/v1",
  "kind": "FileTailSource",
  "allowedRoots": ["/var/log"],
  "pollIntervalMilliseconds": 1000,
  "maxLinesPerBatch": 256,
  "maxBytesPerBatch": 1048576,
  "inputs": [
    {
      "id": "auth",
      "path": "/var/log/auth.log",
      "route": { "pack": "linux-authlog-ssh", "parser": 0 },
      "format": "text",
      "startAt": "end",
      "maxLineBytes": 16384
    }
  ]
}
```

| Property | Default | Rules |
|---|---|---|
| `allowedRoots` | required | 1–8 absolute, normalised directories without wildcards. `/` is refused. Roots are trusted operator configuration and may themselves be links (for example `/var` on macOS). |
| `pollIntervalMilliseconds` | `1000` | 100–60000. Wait between reads once an input has caught up. |
| `maxLinesPerBatch` | `256` | 1–1024 lines per poll. A full poll reads again at once. |
| `maxBytesPerBatch` | `1048576` | 65536–4194304 bytes scanned per poll (one line may run up to its own limit past it). Also bounds the backward scan for `startAt: end`. |
| `rotationGracePolls` | `5` | 1–60 polls `path.1` must stay unchanged (size and write time) before the cursor moves to the new file. See [rotation](#cursors-rotation-and-backpressure). |
| `inputs[].id` | required | 1–63 lowercase letters, digits or hyphens, unique. Names the cursor (`file:<id>`) and the event's source adapter (`file:<id>:<pack>:<parser>`). |
| `inputs[].path` | required | Absolute, normalised (no `.`, `..`, repeated or trailing separators), no wildcard characters (`* ? [ ] { }`) or control characters, strictly below an allowed root, and read by only one input. Paths that differ only in ASCII case count as the same file, and one input's path may not be another's `path.1`. |
| `inputs[].route` | required | `{ "pack": "<id>", "parser": <index> }`: an active parser of a loaded signed pack. Checked at start-up and before a signed reload. |
| `inputs[].format` | `text` | `text` or `json-lines`. |
| `inputs[].startAt` | `end` | `end`: the first start reads only lines written after it. `beginning`: the first start reads the whole file. Either way a restart resumes from the stored cursor. |
| `inputs[].maxLineBytes` | `16384` | 256–30720. A pack parser reads records of at most 32 KiB, so a longer line could never be parsed. |
| `inputs[].allowSymlink` | `false` | Allow the file itself to be one symbolic link whose target is a regular file below an allowed root. Directories on the path are never links. The target may not be another input's file or `path.1` (checked at load and at every read). |

There is deliberately no glob form in this version. List each file. Use one input per
file (for example `auth.log` and `secure` on different hosts are different
configuration files).

## Path guards

At start-up the paths are checked lexically. At every read Bower also checks, before and
after reading:

- every directory between the root and the file exists and is not a symbolic link;
- the file is not a symbolic link, unless `allowSymlink` is set, and then the link is
  followed exactly once and its target must pass the same checks (below an allowed root,
  no linked directories, not itself a link);
- the path is not a directory. A file shorter than 64 bytes is never opened, so a FIFO or
  device (reported as empty) is never read. The Rust collector also refuses any
  non-regular file outright (state `file-path-refused`).

`path.1` gets exactly the same checks (it is never allowed to be a link), before and after
the read; a refused `path.1` fails the poll rather than being skipped.

The open itself is checked too. On Linux (both collectors) and on every Unix (Rust), the
file is opened with `O_NOFOLLOW | O_NONBLOCK`, and the handle must be a regular file with
the same device and inode as the path at that moment, so a link or another file swapped in
after the checks is refused. Elsewhere the C# collector can only re-check that the path is
not a link after opening. Each file is opened once per read: its identity, length and
lines all come from that one handle, so bytes of one generation can never move another
generation's cursor.

A refused path is never read and its state is `file-path-refused`; a missing file is
`waiting` and is read from its start once it appears. A directory on the path swapped for
a link and back between the checks is still not detected: roots should be directories only
trusted operators can write to, as `/var/log` is.

## Run with least privilege

The collector needs read access to the listed files only. On Debian and Ubuntu,
`/var/log/auth.log` is `root:adm 0640`: add the collector's service account to `adm`
or grant a read ACL. On RHEL family hosts the sshd log is `/var/log/secure`
(`root:root 0600`): grant a read ACL, and make it survive rotation (for example a
default ACL on the directory or a logrotate `postrotate` step). Do not run the collector
as root for this.

## The record a pack parser sees

Each line becomes a flat JSON record (at most 6 top-level fields), written in this order:

| Field | Value |
|---|---|
| `id` | `file-` + 32 hex characters of SHA-256 over input id, file fingerprint, line start offset and the line bytes (separated by `0x1F`). |
| `input` | The input id. |
| `path` | The configured path (metadata; never mapped by the shipped pack). |
| `offset` | The line's start offset in the file, as decimal text. |
| `readAt` | When the line was read, UTC with microseconds (`2026-11-05T10:00:01.123456Z`). |
| `message` | `text` only: the line without its newline and one trailing carriage return. |
| `json` | `json-lines` only: the line's object, carried canonically (number text and duplicate keys kept). |

A pack parser reads mapped fields from the top level, so a `json-lines` parser uses its
transform program to lift values out of `json` (for example `.user = .json.user`).
Blank lines are counted and skipped. Lines that are not UTF-8 (or not a JSON object for
`json-lines`) are counted as `malformed` and dropped.

The event id is deterministic: re-reading the same line after a crash, a backpressure
rewind or a restart yields the same id, and the queue drops it as a duplicate. The line
bytes are part of the id so two files that happen to share their first 64 bytes never
merge distinct lines.

### Shipped pack: `linux-authlog-ssh`

[`packs/linux-authlog-ssh`](../../packs/linux-authlog-ssh) 1.1.0 parses plain-text sshd
`auth.log` lines with a signed transform program. Bounded regexes extract the time,
account, source address and method from `Failed password|publickey|keyboard-interactive/pam
for [invalid user] <user> from <ip> port <n> ssh2[: ...]` lines written by `sshd[<pid>]` or
`sshd-session[<pid>]` (OpenSSH 9.8 and later). The match is anchored at the end of the line,
so the last `from <ip> port <n> ssh2` wins: a hostile username such as
`x from 10.9.9.9 port 1 ssh2` cannot change the reported source address. A static table
maps the method to the outcome reason. It produces only `authentication_failure` from
application `linux-sshd`, pseudonymises usernames with HMAC, and never forwards the line,
host name or path. Accepted sign-ins, other programs, `message repeated N times: [...]`
summaries and other lines are not selected. Sign it with your key like any pack
(`bower pack build packs/linux-authlog-ssh --key ...`).

The time comes from the line only: an RFC 3339 prefix (what rsyslog writes with
`RSYSLOG_FileFormat`, the default file template on some current distributions) or a classic
`Mmm dd hh:mm:ss` prefix, with impossible dates and times refused. A line whose time cannot
be parsed is not selected; Bower never substitutes the read time, so a replay after a crash
maps to exactly the same event. Classic syslog times carry no zone or year and are read as
UTC in the evaluation year: on a host whose local time is not UTC every event is off by
the host's offset (in Sydney, AEST, 10 hours, or 11 hours during daylight saving), and an
event near New Year can land in the wrong year. Configure RFC 3339 (`$ActionFileDefaultTemplate
RSYSLOG_FileFormat`) or run the host in UTC.

Any local user can write a line that this pack selects, for example
`logger -t 'sshd[1]' 'Failed password for root from 203.0.113.5 port 22 ssh2'`, because
the system logger records the tag the caller supplies. Treat these events as host
telemetry, not proof that sshd wrote them.

## Cursors, rotation and backpressure

Cursors live in the queue database's `source_cursors` table (`file:<id>`), so a restart
resumes where the queue left off. A cursor holds the file's identity, an offset and
whether an oversized line is being skipped; never line content. The identity is the SHA-256
of the file's first complete line, extended to at least 64 bytes and capped at 4096, so
files whose first 64 bytes are the same (a constant JSON prefix, for example) are still told
apart once their first lines differ. A file whose first line is still being written (and
shorter than 4096 bytes) has no identity yet and waits. Device and inode numbers are used
to check each open, but are not part of the stored identity: they are reused after a file
is deleted, copytruncate keeps them, and the cursor must stay readable by both collectors.

- **Advance rule.** The cursor moves past a line only once it is durably enqueued or
  definitively dropped (not selected, rejected, quarantined, malformed, oversized, too
  large). It is committed after each poll. A crash between enqueue and commit re-reads
  those lines with the same ids; the queue deduplicates them.
- **Backpressure.** When the queue is full (or a managed privacy profile has not
  resolved yet), the poll stops at that line and the cursor rewinds to its start. The
  line is offered again after one second. Nothing is dropped for backpressure; the file
  keeps the data.
- **Complete lines only.** A line still being written is left for the next read.
- **Identity conflicts.** A replayed line whose mapped event differs from the queued one
  (the same event id with other content) is quarantined by the queue
  (`event-identity-conflict`), counted under `rejected`, and the cursor moves on; it never
  blocks the input.
- **Busy queue database.** In both collectors a busy or locked queue database (for example
  during a retention batch) is backpressure: the poll is retried after one second and the
  cursor is unchanged.
- **Oversized lines** are skipped without being buffered, even across polls, and
  counted.
- **Rename rotation** (logrotate's default): when the current file's identity changes and
  `path.1` carries the old identity, Bower drains `path.1` from the cursor. A writer keeps
  writing to `path.1` until it reopens its file (rsyslog until it is sent HUP), so the
  cursor leaves `path.1` only once the new file can be identified and `path.1` has stayed
  unchanged (size and write time) for `rotationGracePolls` polls; only then is an
  unterminated last line of `path.1` taken as complete. Lines written to `path.1` after
  that are counted in `rotationGaps`, never lost silently. Keep `delaycompress` so `path.1`
  stays plain text. The grace window and that late-line watch live in memory: a restart
  starts the window again.
- **copytruncate**: the copy in `path.1` is drained the same way, then the truncated file
  is read from its start. When the truncated file's first line repeats the old one (so the
  identities match) and it is shorter than the cursor, a `path.1` with the same identity
  and at least the cursor's length is drained from the cursor first.
- **startAt: end** scans back from the end for the last complete line within
  `maxBytesPerBatch` bytes (stopping promptly on shutdown). Without a newline in that window
  it starts at the end and skips the rest of the line being written.
- **Missed rotation**: if the file was rotated more than once between reads, renamed
  without a `.1` (for example logrotate `dateext`), or truncated in place, Bower reads the
  current file from its start and counts a `rotationGaps` entry. Lines written to the
  old file after the last read were not seen. Use `nodateext` for tailed files and keep
  the poll interval well below the rotation interval.
- A file rewritten in place with the same first line and at least as long as the cursor
  cannot be detected as replaced. Generations whose first lines are identical (a constant
  header line) are indistinguishable, as are any two files before their first line ends.

## Monitoring

`GET /v1/status` (token required) has a `fileTail` array, one entry per input: `id`,
`path`, `state` (`starting`, `running`, `waiting`, `backpressure`, `stopped` or a failure
code), `offset` (durable position), and counters since start: `linesRead`, `bytesRead`,
`queued`, `duplicates`, `suppressed`, `notSelected`, `rejected`, `parserErrors`,
`tooLarge`, `malformed`, `oversized`, `blank`, `rotations`, `rotationGaps`,
`backpressure`, `readErrors`, `submitFailures`, `cursorConflicts`, `lastLineAt` and
`lastPollAt`. They are metadata only and reset on restart. Failure codes:
`file-path-refused`, `file-read-failed`, `file-cursor-invalid` (a stored cursor this
version did not write; never reset silently), `file-cursor-conflict`,
`file-submit-failed` and `file-source-failed`. A failing input backs off from the poll
interval up to 60 seconds and keeps retrying.

Alert on `rotationGaps` and on a state other than `running` or `waiting`. List the
pack's `applicationName`/`environment` in `BOWER_SOURCE_EXPECTATIONS` to degrade
`/health` when the file goes quiet.

## Residual risks

- Anyone who can write the tailed file can inject lines, and through the system logger
  any local user can (`logger -t 'sshd[1]' ...`). The pack parser's match filter and policy
  still apply, but the source cannot authenticate a line's author.
- Lines lost to a missed rotation are counted, not recovered.
- Path checks run before and after each read, and the open is verified against the path
  (Linux, and every Unix for Rust). A directory on the path swapped for a link and back
  between those steps by someone who can write the root is not detected; neither is a
  link swapped in on a non-Linux platform by the C# collector between its open and its
  re-check.
- The C# collector cannot distinguish a FIFO from an empty regular file; it never opens
  one (shorter than the fingerprint), but reports it as `running` rather than refused.

## Follow-ups

- The Docker source keeps its own copy of the tail mechanics; moving it onto the shared
  reader is a separate change.
- There is no management API source type or console page for the file source yet.
- Periodic `collector_health` records do not include file tail counters yet.
- Each line commits on its own; group commit (as the Windows Event Log source uses) is
  not applied here.
