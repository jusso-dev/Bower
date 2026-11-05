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
| `maxBytesPerBatch` | `1048576` | 65536–4194304 bytes scanned per poll (one line may run up to its own limit past it). |
| `inputs[].id` | required | 1–63 lowercase letters, digits or hyphens, unique. Names the cursor (`file:<id>`) and the event's source adapter (`file:<id>:<pack>:<parser>`). |
| `inputs[].path` | required | Absolute, normalised (no `.`, `..`, repeated or trailing separators), no wildcard characters (`* ? [ ] { }`) or control characters, strictly below an allowed root, and read by only one input. |
| `inputs[].route` | required | `{ "pack": "<id>", "parser": <index> }`: an active parser of a loaded signed pack. Checked at start-up and before a signed reload. |
| `inputs[].format` | `text` | `text` or `json-lines`. |
| `inputs[].startAt` | `end` | `end`: the first start reads only lines written after it. `beginning`: the first start reads the whole file. Either way a restart resumes from the stored cursor. |
| `inputs[].maxLineBytes` | `16384` | 256–30720. A pack parser reads records of at most 32 KiB, so a longer line could never be parsed. |
| `inputs[].allowSymlink` | `false` | Allow the file itself to be one symbolic link whose target is a regular file below an allowed root. Directories on the path are never links. |

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
- the path is not a directory. A file shorter than the 64-byte fingerprint is never
  opened, so a FIFO or device (reported as empty) is never read. The Rust collector also
  refuses any non-regular file outright (state `file-path-refused`).

A refused path is never read and its state is `file-path-refused`; a missing file is
`waiting` and is read from its start once it appears. The checks narrow, but cannot
close, the window for a link swapped in between them: roots should be directories only
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

[`packs/linux-authlog-ssh`](../../packs/linux-authlog-ssh) parses plain-text sshd
`auth.log` lines with a signed transform program: a bounded regex extracts the time,
account, source address and method from `Failed password|publickey|keyboard-interactive/pam
for [invalid user] <user> from <ip> port <n>` lines written by `sshd[<pid>]`, a static
table maps the method to the outcome reason, and the time is parsed from an RFC 3339
prefix (rsyslog's default file format on current distributions) or a classic
`Mmm dd hh:mm:ss` prefix. Classic syslog times carry no zone or year: they are read as
UTC in the evaluation year, so prefer RFC 3339 (`$ActionFileDefaultTemplate
RSYSLOG_FileFormat`). It produces only `authentication_failure` from application
`linux-sshd`, pseudonymises usernames with HMAC, and never forwards the line, host name
or path. Accepted sign-ins, other programs and other lines are not selected. Sign it with
your key like any pack (`bower pack build packs/linux-authlog-ssh --key ...`).

## Cursors, rotation and backpressure

Cursors live in the queue database's `source_cursors` table (`file:<id>`), so a restart
resumes where the queue left off. A cursor holds the file's fingerprint (SHA-256 of its
first 64 bytes), an offset and whether an oversized line is being skipped; never line
content.

- **Advance rule.** The cursor moves past a line only once it is durably enqueued or
  definitively dropped (not selected, rejected, quarantined, malformed, oversized, too
  large). It is committed after each poll. A crash between enqueue and commit re-reads
  those lines with the same ids; the queue deduplicates them.
- **Backpressure.** When the queue is full (or a managed privacy profile has not
  resolved yet), the poll stops at that line and the cursor rewinds to its start. The
  line is offered again after one second. Nothing is dropped for backpressure; the file
  keeps the data.
- **Complete lines only.** A line still being written is left for the next read. At the
  end of a rotated file (which no longer grows) the final unterminated line is read.
- **Oversized lines** are skipped without being buffered, even across polls, and
  counted.
- **Rename rotation** (logrotate's default): when the current file's fingerprint changes
  and `path.1` carries the old fingerprint, Bower drains `path.1` from the cursor, then
  reads the new file from its start. Keep `delaycompress` so `path.1` stays plain text.
- **copytruncate**: the copy in `path.1` is drained the same way, then the truncated file
  is read from its start.
- **Missed rotation**: if the file was rotated more than once between reads, renamed
  without a `.1` (for example logrotate `dateext`), or truncated in place, Bower reads the
  current file from its start and counts a `rotationGaps` entry. Lines written to the
  old file after the last read were not seen. Use `nodateext` for tailed files and keep
  the poll interval well below the rotation interval.
- A file rewritten in place with the same first 64 bytes and at least as long as the
  cursor cannot be detected as replaced.

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

- Anyone who can write the tailed file can inject lines. The pack parser's match filter
  and policy still apply, but the source cannot authenticate a line's author. Tail only
  files written by the service you trust (sshd through the system logger).
- Lines lost to a missed rotation are counted, not recovered.
- Path checks run before and after each read; a link swapped in and out between them by
  someone who can write the root is not detected.
- The C# collector cannot distinguish a FIFO from an empty regular file; it never opens
  one (shorter than the fingerprint), but reports it as `running` rather than refused.

## Follow-ups

- The Docker source keeps its own copy of the tail mechanics; moving it onto the shared
  reader is a separate change.
- There is no management API source type or console page for the file source yet.
- Periodic `collector_health` records do not include file tail counters yet.
- Each line commits on its own; group commit (as the Windows Event Log source uses) is
  not applied here.
