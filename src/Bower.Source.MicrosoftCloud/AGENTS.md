# Bower.Source.MicrosoftCloud instructions

Pull source for Microsoft cloud admin and audit APIs that do not integrate cleanly with
Sentinel (collector `BOWER_MICROSOFT_CONFIG`). Each input reads one API (`sourceKind`) for
one tenant and routes to one signed pack parser. Not log shipping and not an audit archive:
there is no collect-everything kind, no default route, and the Unified Audit Log, Entra
sign-in and Entra audit logs are out of scope (a separate archive owns them). Record shape,
event ids, cursor format, limits and failure codes are a contract: change them only with a
migration note.

- Default deny: a record reaches the queue only through its input's route to an active
  signed pack parser whose match filter selects it, then redaction and policy. Readers drop
  out-of-scope items (for example compliant devices) in memory, before any parser, and only
  count them.
- Request only what a record maps. Use `$select` where the API supports it. Never read
  modified property values, change data, hardware identifiers (IMEI, serial, MAC, phone)
  or contact details into a record; keep property names only.
- Tokens: `IMicrosoftCloudTokenProvider`, in memory only. Send a bearer token only to the
  one host the reader allow-lists for the kind, over HTTPS on the default port, with no user
  info. Refuse next links and content URIs on any other host (`mscloud-host-refused`) and
  every redirect (the handler must not follow them). Application permissions only, least
  privilege, read-only; list every scope in `docs/security/microsoft-cloud-sources.md`.
- Retry 429, 408 and 5xx and transport failures with capped exponential backoff and full
  jitter, honouring `Retry-After` up to its cap. Refresh the token once on 401. Never retry a
  403 (`mscloud-permission-denied`); the poll loop backs off.
- Bound everything: response bytes (16 MiB default), JSON depth 32, values to the
  envelope limit of the field they map to (128 or 256), a per-record escaped byte budget
  under the 32 KiB pack limit, joined lists 256, URIs 4,096, records and 100 pages per poll,
  windows 24 hours, overlap 12 hours, look-back 7 days. Canonicalise IP addresses or leave
  them out; never let one odd value drop the whole event.
- Check a next link against the host allow-list before the page that returned it is
  committed. Restart an expired page link at most once per poll and fail on a repeated
  next link, so a poll can never spin.
- Cursors live in the queue database's `source_cursors` table (`mscloud:<id>`), schema 1.
  Store a newly opened window before reading it. Move past a page only once every record
  in it is durably enqueued or definitively dropped; commit after every page. Backpressure
  keeps the page; never drop for backpressure. A damaged or other-kind cursor fails closed
  (`mscloud-cursor-invalid`). A refused stored page link restarts the window from its first
  page (`PageRestarts`). A cursor older than the API's look-back starts at the floor and
  counts a gap; never claim otherwise.
- Event ids: `mscloud-` and 32 hex characters of SHA-256 over input, kind, tenant, source
  record id and record content, written as the record's first field. Overlap and crash
  re-reads must give the same id; change the derivation only with a migration note.
- Never log or expose record content, URLs with queries, response bodies or tokens.
  Failure codes, counters and HTTP status only.
- Unit tests use a fake `HttpMessageHandler`, an in-memory cursor store and a fake clock.
  No live tenant calls. Fixtures in `tests/fixtures/microsoft-cloud` are synthetic; never
  commit captured tenant data. Changes need malformed-response, oversized, host allow-list,
  throttling, cursor crash/recovery, backpressure and cancellation tests.
- Code here must stay trim and AOT safe: source-generated JSON only.
