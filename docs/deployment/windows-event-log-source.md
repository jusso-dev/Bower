# Windows Event Log source

On Windows, the C# collector can read a short allow-list of events from local event
log channels and turn selected ones into Bower events. It is for the on-premises
applications that only write to the Windows event log, and for a few high-value
Security events. It does not do bulk collection: broad Windows event collection stays
with the Azure Monitor Agent.

```
event log service ──generated query──▶ subscription ──▶ parse XML ──▶ signed pack parser ──▶ redact + policy ──▶ durable queue
(channel)             event ID allow-list   bookmark      bounded      match filter          (default deny)       (then bookmark)
                      providers             backpressure
```

Only the C# collector has this source, on Windows. The Rust collector does not target
Windows: it refuses to start with `BOWER_WINDOWS_EVENTLOG_CONFIG` set, and so does the
C# collector on Linux or macOS.

## What is accepted

Subscribing to a channel never means accepting its events. An event is queued only
when:

1. its channel, event ID and (when listed) provider are in the subscription, so the
   event log service returns it for the generated query;
2. its XML is within the size limit and parses;
3. the subscription's signed pack parser selects it (`match` filter); and
4. redaction succeeds and the policy set accepts the resulting event.

Event content outside the allow-list is filtered out by the event log service and is
never rendered into the collector. Range discovery probes only the oldest and newest
record IDs, without rendering XML, messages or event properties. This avoids unreliable
oldest-record/count arithmetic after a Windows log clear. Everything else that is not
queued is dropped and counted. No event XML, message, record or query result is logged,
stored or shown; only the fields
the pack parser maps reach the envelope, and they are redacted before persistence.

## Configure

Set `BOWER_WINDOWS_EVENTLOG_CONFIG` to a JSON file (at most 256 KiB;
[schema](../../schemas/configuration/windows-event-log-source.schema.json)). Invalid
files, unknown properties, or a subscription that does not name an active parser of a
loaded signed pack stop start-up.

```json
{
  "apiVersion": "bower.security/v1",
  "kind": "WindowsEventLogSource",
  "subscriptions": [
    {
      "id": "security-logon",
      "channel": "Security",
      "eventIds": [4625],
      "providers": ["Microsoft-Windows-Security-Auditing"],
      "pack": "windows-security-logon",
      "parser": 0
    }
  ]
}
```

| Setting | Default | Bounds |
|---|---|---|
| `id` | required | 1–63 lowercase letters, digits, hyphens; unique; names the bookmark |
| `channel` | required | 1–255 letters, digits, spaces, `- _ . /` (for example `Microsoft-Windows-Sysmon/Operational`) |
| `eventIds` | required | 1–16 distinct IDs, 0–65535. There is no collect-all form |
| `providers` | all providers | 1–4 distinct names of letters, digits, spaces, `- _ . $` |
| `pack`, `parser` | required | an active parser (index) of a loaded signed pack |
| `readExisting` | `false` | on first start, read events already in the channel; otherwise start at the newest |
| `includeMessage` | `false` | render the publisher message string into the record's `message` field |
| `pollIntervalSeconds` | 2 | 1–300; wait between reads once caught up |
| `batchSize` | 64 | 1–256 events per read; the bookmark is committed after each batch |

One channel and event ID pair belongs to one subscription (channel names compare
case-insensitively). Property names are case-sensitive and a repeated property fails
the file. There is no free-text query and no "all Security events" preset: list the
event IDs a pack actually maps. Set `providers` whenever the channel is shared (for
example `Application`): any program allowed to write to a channel can use any event
ID, but the provider name in the query narrows what is read, and the pack parser
should also match on `provider`.

### The generated query

The collector builds the subscription filter from the validated values only, for
example:

```
*[System[(EventID=4625) and (Provider[@Name='Microsoft-Windows-Security-Auditing'])]]
```

The native reader resumes from a Windows bookmark separately from this filter.
WEF retains the originating EventRecordID, which cannot safely identify a position
in the receiving log. Names are restricted so they cannot change the query, and
16 event IDs plus 4 providers keep it within the Windows query expression limit.

## Run with least privilege

Run the collector as a dedicated low-privilege identity (a virtual service account such
as `NT SERVICE\Bower`, used by the MSI, or a gMSA), never as an administrator or `LocalSystem`.
Add it to the local **Event Log Readers** group, which can read the Security,
Application, System and most operational channels on Windows Server 2019 and later:

```powershell
Add-LocalGroupMember -Group 'Event Log Readers' -Member 'NT SERVICE\Bower'
```

Some channels have their own access list (`wevtutil gl <channel>` shows
`channelAccess`); grant read there rather than widening the account. A channel the
account cannot read reports `winevt-access-denied` and is retried; nothing else is
affected. Keep the queue directory (`BOWER_QUEUE_PATH`) writable by that account only:
it holds the queue and the bookmarks.

## The record a pack parser sees

Each event becomes a flat JSON object of string values (at most 64 fields; values
longer than 2048 characters, and data names a parser cannot address, are left out;
the first of repeated names wins; an event with more fields is dropped as oversized):

| Field | Value |
|---|---|
| `id` | `winevt-` + 32 hex of SHA-256 over channel, computer, record id and creation time |
| `subscription` | the subscription id |
| `channel`, `provider`, `eventId`, `recordId`, `computer` | from the System header |
| `timeCreated` | creation time, UTC, microseconds |
| `version`, `level`, `task`, `opcode`, `keywords` | when present |
| `userSid`, `processId`, `threadId`, `activityId` | when present |
| `message` | with `includeMessage`, when the publisher can render it |
| `data.<Name>` | each named `EventData` value; unnamed values are `data.0`, `data.1`, ... |
| `userData.<Name>` | each leaf value of a `UserData` element |

Map `eventId` to `id` and `timeGenerated` to `timeCreated`, so an event read twice (for
example after a crash) deduplicates in the queue. Message strings are rendered by the
publisher from its metadata and can carry anything the event carries: they are only
present when asked for, reach the envelope only through a pack mapping, and are
redacted like any other mapped field. Extraction from `message` or `data.*` belongs in
the pack parser's `transforms`
([transform language](../developer-integration/transform-language.md)).

### Shipped pack: `windows-security-logon`

Failed network logons (Security event 4625). The parser selects only events from
`Microsoft-Windows-Security-Auditing` with logon type `3` (network) and a source address,
maps the NTSTATUS
`SubStatus` (then `Status`) to an outcome reason (`InvalidCredentials`,
`UnknownAccount`, `AccountLockedOut`, ... or `OtherFailure`) and pseudonymises the
account with HMAC. Workstation, domain, process and the rest of `EventData` are never
forwarded. Interactive logons, other logon types and records without a logon type are
not selected, even when they carry a valid address. Use the configuration example above and enable
**Audit Logon** failure auditing on the host. See the
[pack runtime catalogue](../security/pack-runtime-catalogue.md).

## Bookmarks, restart and backpressure

Version 2 checkpoints store the receiving channel's native bookmark position.
On upgrade, a recognized version 1 checkpoint triggers one replay of all retained
events, even with `readExisting: false`. Old origin IDs are never interpreted as
receiving positions. Existing durable event IDs suppress duplicates; keep the
queue database during upgrade. Backpressure preserves the last handled receiving
position, and the migrated checkpoint is saved atomically. Unknown versions and
channel mismatches still fail closed. Older collector versions cannot read version
2 checkpoints, so do not downgrade against a migrated queue database. Events
already overwritten by Windows cannot be recovered by this migration. In the tested WEC
configuration, collectors before the receiving-bookmark change could not read
`ForwardedEvents` at all, so version 1 checkpoints are expected only for local channels. A receiving position belongs to
one host's log: for restores onto another WEC host, follow the order in
[Upgrades, backup and recovery](../production-readiness/04-upgrade-backup-recovery.md#windows-event-log-and-wec-restores).

- **Bookmark.** Each subscription's position (channel and last record id) is a row in
  the `source_cursors` table of the queue database. The bookmark moves past an event
  only once it is durably enqueued, or definitively dropped (not selected, rejected by
  policy, malformed or oversized). It is committed after each batch, and on stop.
- **Restart.** Reading resumes after the bookmark. If the collector stops between
  enqueueing events and committing the bookmark, those events are read again; their
  deterministic ids make the queue drop them as duplicates. A restart neither loses
  nor duplicates events.
- **First start.** Without a bookmark the subscription starts at the newest event in
  the channel unless `readExisting` is set.
- **Shutdown.** The host requests cancellation and waits for subscription loops until its
  shutdown deadline. If a Windows channel call stalls, the host stops waiting when that deadline
  expires; source cleanup finishes after the call returns if the process is still running.
- **Backpressure.** When the queue is full (or a management-mode collector is waiting
  for its privacy profile), the subscription stops reading and retries the same event
  every second. Events wait in the channel, not in memory. Make sure the channel's
  maximum size covers the longest outage you expect.
- **Cleared or recreated log.** When the channel's newest record id is below the
  bookmark, the log was cleared or recreated: the subscription reads it from the start
  and counts `resets`.
- **Overwritten events.** When the channel's oldest record is past the bookmark, the
  log wrapped before Bower read those events (some may have been allow-listed). The
  subscription carries on from the oldest event and counts `gaps`.
- **Failures.** A missing channel, denied access, invalid query, storage or sink
  failure keeps the bookmark, sets the subscription state to the failure code and
  retries with backoff (up to a minute). A stored bookmark for another channel or an
  unknown version stops that subscription (`winevt-bookmark-invalid`) rather than being
  reinterpreted; give the subscription a new `id` to start a new bookmark.

## Monitoring

`GET /v1/status` (token required) has a `windowsEventLog` array, one entry per
subscription: `id`, `channel`, `state` (`starting`, `running`, `backpressure`,
`stopped` or a failure code: `winevt-channel-not-found`, `winevt-access-denied`,
`winevt-query-invalid`, `winevt-read-failed`, `winevt-bookmark-invalid`,
`winevt-submit-failed`, `winevt-source-failed`), `bookmarkRecordId`, and counters
since start: `eventsRead`, `bytesRead`, `queued`, `duplicates`, `suppressed`,
`notSelected`, `rejected`, `parserErrors`, `malformed`, `oversized`, `retries`,
`submitFailures`, `readErrors`, `gaps`, `resets`, `cursorConflicts`, then
`lastEventAt` and `lastPollAt`. They are metadata only and reset on restart.

Silence detection works through the pack's application: list the parser's
`applicationName`/`environment` in `BOWER_SOURCE_EXPECTATIONS`, and a source that stops
producing selected events degrades `/health` once its allowance passes. Use it for
application events with a steady rate; failed logons (`windows-security-logon`) are
legitimately quiet, so watch the subscription instead: one whose `lastPollAt` stops
moving, or whose `state` is a failure code, is not reading.

## Residual risks

- Any program that can write to a channel can write any event ID and claim any
  provider name it registers. Prefer channels with a restricted writer (Security, or an
  application's own channel), list `providers`, and match on `provider` in the pack.
- A log cleared and refilled past the bookmark while the collector is stopped is not
  detected as a reset; events up to the old bookmark position are skipped.
- Events overwritten before they are read are lost (`gaps`); size the channel for the
  longest queue outage.
- Message strings are rendered from publisher metadata on the collecting host; a
  missing or changed message file changes or removes `message`.
- The collector reads local channels only. Forwarded events (Windows Event Forwarding)
  can be read from the `ForwardedEvents` channel like any other.

## Not verified here

CI runs the real reader on `windows-latest` (a dedicated test log and event source:
allow-list filtering by the service, restart from the bookmark, a cleared log, a
missing channel); everything else is tested on every platform from recorded event XML.
Windows Server 2019 specifically, the Security channel with a non-administrator Event
Log Readers account, and the Native AOT `win-x64` and `win-arm64` builds against a real
event log are not exercised by the automated suite.
