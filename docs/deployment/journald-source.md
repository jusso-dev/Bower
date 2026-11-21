# systemd journald source

`Bower.Source.Journald` reads security-relevant entries directly from the host's
systemd journal (`libsystemd.so.0`) using explicit unit and `SYSLOG_IDENTIFIER`
allow-lists and durable SQLite cursors.

## Selection and default deny

- Configuration (`JournaldSourceOptions`) **requires** at least one explicit systemd
  unit (`Units`, e.g. `sshd.service`) or `SYSLOG_IDENTIFIER` (`Identifiers`, e.g. `sshd`).
- Wildcards (`*`, `?`) and collect-all subscriptions are rejected at validation time.
- Even when `LibSystemdJournalReader` pushes `_SYSTEMD_UNIT=` / `SYSLOG_IDENTIFIER=`
  disjunctions into `libsystemd`, `JournaldSource` enforces the same allow-list in
  managed code before serialising any entry.
- Reading an entry never means delivering it: every record still flows through a signed
  pack parser (such as `packs/linux-journald-ssh`), the Privacy & Secret Protection
  Engine, and default-deny telemetry policies.

## Durability and backpressure

- Cursors are stored in `ISourceCursorStore` under `journald:<subscriptionName>`.
- A cursor advances **only after** the downstream processor acknowledges durable enqueue
  or a definitive drop (unselected unit, malformed or oversized entry).
- If the collector crashes or downstream signals backpressure, polling stops before
  advancing past the unacknowledged entry so restart resumes with zero loss; deterministic
  event IDs derived from `__CURSOR` deduplicate retries.
- Per-record size is capped at 32 KiB and batch sizes are capped at 500 entries.

## Linux prerequisites

- Requires Linux with `libsystemd.so.0` and read access to the system journal (typically
  membership in the `systemd-journal` group for the `bower` service account — no root
  privileges required).
- Keep the `IJournalReader` seam when writing tests on macOS or Windows so unit tests
  exercise cursor recovery, allow-list enforcement, malformed inputs and backpressure
  without a live systemd daemon.
