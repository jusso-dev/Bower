# Bower.Source.Journald instructions

Bounded, allow-listed systemd journald source.

- Default deny: configuration must name at least one explicit systemd unit or
  `SYSLOG_IDENTIFIER`. Wildcards and collect-all subscriptions are refused.
- Enforce unit and identifier allow-lists in managed code even when the underlying
  reader applies native filters.
- Never log raw `MESSAGE` text or raw journal entries. Diagnostics report counters
  and safe metadata codes only.
- Persist the journald cursor in `ISourceCursorStore` strictly **after** the caller
  acknowledges durable enqueue or definitive drop. Never advance past an
  unacknowledged record.
- Bound per-record bytes (at most 32 KiB) and batch counts; honour cancellation.
- Keep `LibSystemdJournalReader` behind `IJournalReader` so cursor, filtering,
  malformed-input and backpressure logic remain platform-neutral and testable.
