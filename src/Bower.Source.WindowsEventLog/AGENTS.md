# Windows Event Log source instructions

This C# adapter reads explicitly selected Windows channels and event IDs, including
WEC ForwardedEvents. Rust support is outside this backport and must not be claimed.

- Require a verified signed pack parser with an explicit match filter. Never add a
  collect-all option, unrestricted XPath, or arbitrary executable configuration.
- Generate XPath from validated event IDs, providers, and bookmarks. Bound queries
  to 16 event IDs and 4 providers. Boundary queries read record metadata only.
- Advance durable bookmarks only after queue acceptance or definitive rejection.
  Backpressure must retain the unread record. Preserve duplicate-safe event identity.
- Distinguish the receiving channel/bookmark from the original forwarded event's
  computer, channel, record ID, and timestamp. Test this on a real WEC Windows host.
- Bound XML to 64 KiB, forbid DTDs/resolvers, and limit fields, values, batch size,
  and polling intervals. Never log event XML, messages, or field contents.
- Keep XML, selection, bookmark, crash/recovery, backpressure, and cancellation
  tests portable; run native Windows reader tests on Windows.
