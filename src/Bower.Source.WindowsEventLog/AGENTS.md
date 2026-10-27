# Bower.Source.WindowsEventLog instructions

Narrow Windows Event Log intake: a short channel and event ID allow-list per signed
pack parser. Not bulk collection; the Azure Monitor Agent stays the tool for that.
C#-only: the Rust collector refuses `BOWER_WINDOWS_EVENTLOG_CONFIG` (see `rust/AGENTS.md`).

- Default deny: an event reaches the queue only through an active signed pack parser
  whose match filter selects it, then redaction and policy. Never add a collect-all or
  "all Security events" form, free-text XPath, wildcards or level-only filters.
- The Windows query is generated (`WindowsEventQuery.ToXPath`) from validated event IDs,
  provider names and the bookmark, so the event log service returns only allow-listed
  events. Names never contain quotes, brackets or operators. Keep the expression count
  within the Windows limit (16 IDs, 4 providers).
- Bookmarks live in the queue database's `source_cursors` table. Move the bookmark past
  an event only once it is durably enqueued or definitively dropped; a full queue stops
  reading. Event ids derive from channel, computer, record id and creation time so a
  re-read deduplicates; change them only with a migration note.
- Bound everything: 64 KiB event XML, no DTD or resolver, 64 record fields, 2048-character
  values, batch size and poll interval.
- Keep parsing, mapping, the allow-list and the bookmark logic platform-neutral and
  tested from recorded XML fixtures; only `WindowsEventLogReader.cs` touches Windows APIs.
- Never log or expose event content, messages, records or query results. Counters and
  failure codes only.
- Changes need malformed-input, bookmark crash/recovery, backpressure and cancellation
  tests, plus the Windows CI job (`WindowsEventLogWindowsTests`).
