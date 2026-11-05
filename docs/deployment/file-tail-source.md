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
| `rotationDrainMaxPolls` | `300` | `rotationGracePolls` + 2 to 3600 (settling a rename takes `rotationGracePolls` + 1 end-of-file polls, so a lower cap would end every rename drain first and count a static `path.1`'s unterminated last line as a gap). The most counted polls a rename or copytruncate drain may take; then the cursor moves to the new file anyway. A poll counts only once it reaches the end of `path.1` or gets past the length `path.1` had when the drain began, so a backlog of any size is read in full. A writer (or an attacker who can write `path.1`) can delay the switch by at most the time to read that backlog plus this many polls. |
| `inputs[].id` | required | 1–63 lowercase letters, digits or hyphens, unique. Names the cursor (`file:<id>`) and the event's source adapter (`file:<id>:<pack>:<parser>`). |
| `inputs[].path` | required | Absolute, normalised (no `.`, `..`, repeated or trailing separators), no wildcard characters (`* ? [ ] { }`) or control characters, strictly below an allowed root, and read by only one input. Paths that differ only in ASCII case count as the same file, and one input's path may not be another's `path.1`. These rules are applied to canonical paths too (directories resolved through links, so `/var/run/x.log` and `/run/x.log` are the same file), at load and at every read; a directory that does not exist yet is compared as written. An input whose directory did not exist at load keeps that written path as its load-time resolution, so if the directory later appears behind a link that makes it meet another input, both inputs can be refused rather than only one (this fails closed). Canonical paths follow `realpath` in both collectors: a `..` after a linked directory goes to that link's real parent. |
| `inputs[].route` | required | `{ "pack": "<id>", "parser": <index> }`: an active parser of a loaded signed pack. Checked at start-up and before a signed reload. |
| `inputs[].format` | `text` | `text` or `json-lines`. |
| `inputs[].startAt` | `end` | `end`: the first start reads only lines written after it. `beginning`: the first start reads the whole file. Either way a restart resumes from the stored cursor. |
| `inputs[].maxLineBytes` | `16384` | 256–30720. A pack parser reads records of at most 32 KiB, so a longer line could never be parsed. |
| `inputs[].allowSymlink` | `false` | Allow the file itself to be one symbolic link whose target is a regular file below an allowed root. Directories on the path are never links. The target may not be another input's file, another input's link target, or either one's `path.1` (checked at load and at every read). If two inputs come to name one file after load, only the input whose resolution changed is refused (state `file-path-refused`, logged once with its id and the reason `overlaps-another-input`, never a path); the other keeps reading. |

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
after the checks is refused. The C# collector knows the flag values for x86-64 and arm64
only (they differ: `O_NOFOLLOW` is 0x20000 on x86-64 and 0x8000 on arm64); on other Linux
architectures it opens without them and relies on the device and inode check alone.
Elsewhere the C# collector can only re-check that the path is not a link after opening. Each file is opened once per read: its identity, length and
lines all come from that one handle, so bytes of one generation can never move another
generation's cursor.

A refused path is never read and its state is `file-path-refused`; a missing file is
`waiting` and is read from its start once it appears. Only a file or directory that does not
exist is missing: one Bower cannot examine (a directory the service account cannot search,
for example) is `file-path-inaccessible`, counted in `readErrors` and logged, never
`waiting`. A directory on the path swapped for
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

[`packs/linux-authlog-ssh`](../../packs/linux-authlog-ssh) 1.3.0 parses plain-text sshd
`auth.log` lines with a signed transform program. Bounded regexes extract the time,
account, source address and method from lines written by `sshd[<pid>]` or
`sshd-session[<pid>]` (OpenSSH 9.8 and later), with an exact grammar for the whole line.
Selected, and nothing may follow:

- `Failed password|keyboard-interactive/pam|none|gssapi-with-mic for [invalid user ]<user> from <ip> port <n> ssh2`;
- `Failed publickey for [invalid user ]<user> from <ip> port <n> ssh2: <KEYTYPE> <HASH>:<fp>`,
  optionally followed by ` ID <key-id> (serial <n>) CA <KEYTYPE> <HASH>:<fp>` for a
  certificate;
- `Failed publickey for invalid user <user> from <ip> port <n> ssh2` (no key: for an
  invalid user sshd fails before it logs the key). A valid user's public key failure
  must carry its key.

`<ip>` may carry an IPv6 scope (`fe80::1%eth0`, at most 15 letters, digits, `_`, `.` or
`-`); the reported address leaves the scope out.

The username and the certificate key ID are the two fields a client controls, so neither
may contain a space, and every other part of the line is fixed. A hostile username such as
`x from 10.9.9.9 port 1 ssh2` (or `x from 6.6.6.6 port 1 ssh2: k`), a certificate key ID
that imitates a second address, or an interface name that does, therefore makes the line
not selected; it never yields a spoofed source address. A static table maps the method to
the outcome reason. It produces only `authentication_failure` from application
`linux-sshd`, pseudonymises usernames with HMAC, and never forwards the line, host name or
path.

Not selected (counted in `notSelected`, a gap rather than an error):

- the `hostbased` method, because its trailer carries a client user and host name the
  client chooses (`client user "…", client host "…"`), and any other method name;
- usernames or certificate key IDs that contain spaces, and interface scopes longer than
  15 characters or with other characters;
- a key suffix on `password`, `keyboard-interactive/pam`, `none` or `gssapi-with-mic`, and a
  keyless public key failure for a valid user;
- `message repeated N times: [ … ]` summaries, `Invalid user … from …`, `Connection closed by
  authenticating user …`, `Disconnected from …`, `error: maximum authentication attempts
  exceeded …`, `PAM … authentication failure` (pam_unix) and `Accepted …` lines;
- lines from other programs, and lines without a parseable time.

summaries and other lines are not selected. Sign it with your key like any pack
(`bower pack build packs/linux-authlog-ssh --key ...`).

The time comes from the line only: an RFC 3339 prefix (what rsyslog writes with
`RSYSLOG_FileFormat`, the default file template on some current distributions) or a classic
`Mmm dd hh:mm:ss` prefix, with impossible dates and times refused. A line whose time cannot
be parsed is not selected; Bower never substitutes the read time, so a replay after a crash
maps to exactly the same event (classic times across New Year aside, below). Classic syslog
times carry no zone or year and are read as UTC in the evaluation year: on a host whose
local time is not UTC every event is off by the host's offset (in Sydney, AEST, 10 hours, or
11 hours during daylight saving), and an event near New Year can land in the wrong year. The
year comes from the clock when the line is submitted, so a crash replay across New Year can
resolve a different year: the replayed duplicate keeps its event id but not its content, and
is quarantined as `event-identity-conflict` (counted in `rejected`) instead of deduplicated;
the original is already queued, so nothing is lost. Configure RFC 3339 (`$ActionFileDefaultTemplate
RSYSLOG_FileFormat`) or run the host in UTC.

Any local user can write a line that this pack selects, for example
`logger -t 'sshd[1]' 'Failed password for root from 203.0.113.5 port 22 ssh2'`, because
the system logger records the tag the caller supplies. Treat these events as host
telemetry, not proof that sshd wrote them.

## Cursors, rotation and backpressure

Cursors live in the queue database's `source_cursors` table (`file:<id>`), so a restart
resumes where the queue left off. A cursor holds the file's identity, an offset, whether an
oversized line is being skipped, the file's device and inode where known, and the rotation
state described below; never line content. Because the rotation state is in the cursor, a
restart in the middle of a rotation carries on exactly where it stopped. The identity is the SHA-256
of the file's first complete line, extended to at least 64 bytes and capped at 4096, so
files whose first 64 bytes are the same (a constant JSON prefix, for example) are still told
apart once their first lines differ. A file whose first line is still being written (and
shorter than 4096 bytes) has no identity yet and waits. Device and inode numbers check each
open and are stored in the cursor, but only as a hint, never as part of the identity (they
are reused after a file is deleted, and copytruncate keeps them). When `path.1` carries the
cursor's identity they tell rename (the original moved to `path.1`) from copytruncate (the
original truncated in place). A file with the cursor's identity at a new device or inode and
no matching `path.1` is told apart by the cursor's anchor, a SHA-256 of the last 256 bytes
(fewer near the start) before the offset: if the new file has the same bytes there, it is the
same content (restored from a backup or copied) and reading continues from the cursor without
a gap; otherwise it is a new generation with the same first line and is read from its start
with a `rotationGaps` entry. A cursor without an anchor (written by an earlier build, or at
offset 0) is treated the same conservative way. A new file that the file system gives the old
file's inode number again (ext4 reuses freed numbers quickly) looks like the same file: one
with a different first line is still read from its start with a gap, but one with the same
first line, at least as long as the cursor, continues from the cursor, as it does where
inode numbers are not known. Lines may then be delivered twice (the queue
deduplicates what it still holds), never skipped.

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
  counted. A line within `maxLineBytes` whose record would exceed the 32 KiB pack record
  limit once JSON-escaped (heavily escaped text: a control character becomes six bytes) is
  counted in `oversized` too and never submitted.
- **Rotation is a drain.** Once a rotation is detected, the cursor refers to `path.1`
  (`drain` in the cursor) and the current file is not read at all until `path.1` is
  drained, however the current file changes meanwhile. If `path.1` disappears or is rotated
  again before it is drained, that is counted in `rotationGaps` and the current file is
  read from its start.
- **Rename or copytruncate.** On Linux (and every Unix in Rust) device and inode numbers
  tell them apart: copytruncate keeps the original file at the path (truncated) and makes
  `path.1` a copy; rename moves the original to `path.1` and puts another file at the path.
  Without them, a current file shorter than the cursor with the same identity (and a
  `path.1` with that identity at least as long as the cursor) is copytruncate, and a changed
  identity with `path.1` carrying the old one is a rename.
- **copytruncate**: the copy is static, so it is drained from the cursor to its end (its
  last line is complete) and the cursor moves to the current file at offset 0 at once, with
  no grace window. A copy that keeps growing is bounded by the drain cap below.
- **Rename rotation** (logrotate's default): a writer keeps writing to `path.1` until it
  reopens its file (rsyslog until it is sent HUP), so the cursor leaves `path.1` only once
  the new file can be identified and `path.1` has stayed unchanged over `rotationGracePolls`
  end-of-file polls. A poll counts only when it read to the end of `path.1` without hitting
  a line or byte limit and its size and write time are the same as at the previous such
  poll, so a backlog never uses up the window; the count is kept in the cursor. Only then is
  an unterminated last line of `path.1` taken as complete. The generation the cursor left
  (identity and length) is kept in the cursor too, and only once the switch is committed:
  later growth of that `path.1`, before or after a restart, is counted in `rotationGaps`
  when Bower can still see that `path.1` on a later poll (see **Gap counting is best
  effort** below). Keep `delaycompress` so `path.1` stays plain text.
- **Drain cap.** A `path.1` that keeps changing (a writer that never reopens its file, or
  someone appending to it on purpose) would hold the cursor there forever. Polls of a
  rename or copytruncate drain are counted in the cursor (a restart does not reset them),
  but only those that reach the end of `path.1` or get past the length `path.1` had when the
  drain began: a static backlog, however large (the collector stopped across a rotation, or
  long backpressure), is always read in full. A poll that stops part-way for backpressure
  rewinds to the cursor it started from, so that poll's drain count (and a drain length
  first recorded in it) is not kept. After `rotationDrainMaxPolls` counted polls
  the cursor moves to the new file anyway, even if the new file is still missing; whatever
  is still unread in `path.1` then is counted in `rotationGaps`, and so are later writes to
  it, on the same best-effort terms. A writer can delay the switch by at most the time to
  read the backlog plus that many polls.
- **Gap counting is best effort.** `rotationGaps` is an observability signal that lines
  were probably missed, not an exact loss count, and some losses cannot be seen at all.
  Late writes to a `path.1` the cursor has left are counted only when Bower can still
  observe that `path.1` on a later poll. If it is rotated again first (`path.1` becomes
  `path.2`), or if bytes are appended after the poll that took its length for the final
  switch and `path.1` is then moved away before the next poll, those lines are neither read
  nor counted. Bower does not follow `path.2`. Keep the poll interval well below the
  rotation interval, and make the writer reopen its file promptly after a rename (for
  example rsyslog's HUP in `postrotate`).
- **startAt: end** scans back from the end for the last complete line within
  `maxBytesPerBatch` bytes (stopping promptly on shutdown). Without a newline in that window
  it starts at the end and skips the rest of the line being written.
- **Missed rotation**: if the file was rotated more than once between reads, renamed
  without a `.1` (for example logrotate `dateext`, `compress` without `delaycompress`, or
  `rotate 0`), or truncated in place, Bower reads the current file from its start and counts a
  `rotationGaps` entry. That includes a new generation with the same first line (a constant
  header) that is already longer than the cursor: where device and inode numbers are known
  (Linux in C#, every Unix in Rust), it is at a new inode and its bytes before the offset do
  not match the cursor's anchor. Lines written to the old file after the last read were not
  seen. Use `nodateext` and `delaycompress` for tailed files and keep the poll interval well
  below the rotation interval.
- What cannot be detected: a file rewritten in place (same device and inode) with the same
  first line and at least as long as the cursor, and, where device and inode numbers are not
  known (C# outside Linux), a new generation with the same first line that is at least as
  long as the cursor. Any two files are indistinguishable before their first line ends.

## Monitoring

`GET /v1/status` (token required) has a `fileTail` array, one entry per input: `id`,
`path`, `state` (`starting`, `running`, `waiting`, `backpressure`, `stopped` or a failure
code), `offset` (durable position), and counters since start: `linesRead`, `bytesRead`,
`queued`, `duplicates`, `suppressed`, `notSelected`, `rejected`, `parserErrors`,
`tooLarge`, `malformed`, `oversized`, `blank`, `rotations`, `rotationGaps`,
`backpressure`, `readErrors`, `submitFailures`, `cursorConflicts`, `lastLineAt` and
`lastPollAt`. They are metadata only and reset on restart. Failure codes:
`file-path-refused`, `file-path-inaccessible` (the file or a directory on its path cannot be
examined, usually a permission the service account lacks), `file-read-failed`, `file-cursor-invalid` (a damaged cursor of the
current schema; never reset silently), `file-cursor-conflict`,
`file-submit-failed` and `file-source-failed`. A failing input backs off from the poll
interval up to 60 seconds and keeps retrying.

A refused or inaccessible input is logged once when it enters that state (event 1121 in the
C# collector), with its id and a reason code only: `path`, `rotated-path`,
`overlaps-another-input`, `handle` or `inaccessible` (state `file-path-inaccessible`).

Cursors from another build are never interpreted. The cursor schema is 2; a stored cursor
with any other `schemaVersion` (the pre-release builds wrote 1, without the rotation state)
replays the current file from its start and counts one `rotationGaps` entry once the replay
cursor is stored (a poll refused or failed before that counts nothing): lines may be
delivered twice (the queue deduplicates what it still holds), never skipped.

Alert on `rotationGaps` and on a state other than `running` or `waiting` (which includes
`file-path-inaccessible`; `waiting` means only that the file does not exist yet). List the
pack's `applicationName`/`environment` in `BOWER_SOURCE_EXPECTATIONS` to degrade
`/health` when the file goes quiet.

## Residual risks

- Anyone who can write the tailed file can inject lines, and through the system logger
  any local user can (`logger -t 'sshd[1]' ...`). The pack parser's match filter and policy
  still apply, but the source cannot authenticate a line's author.
- Lines lost to a missed rotation are not recovered, and are counted only when Bower can
  still observe the generation they were written to (best effort; see **Gap counting is
  best effort**).
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
