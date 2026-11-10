# Local syslog output instructions

Hand each policy-approved, redacted envelope to the host's local syslog daemon (`/dev/log`, a
Unix datagram socket). Azure Monitor Agent's syslog collection ships it from there into
`BowerSecurity_CL`. Reference: `docs/deployment/syslog-output.md`.

## Wire format (`SyslogOutput.TryFormat`)

- The local `syslog(3)` format, not RFC 5424: `<PRI>Mmm dd hh:mm:ss bower: bower-b64:<base64>`.
  rsyslog's socket input and journald both parse it. The timestamp only keeps it well formed;
  the daemon stamps its own receive time.
- MSG is `bower-b64:` followed by the compact envelope JSON in base64. Azure Monitor removes
  semicolons from syslog messages during ingestion, and syslog has no room for line breaks;
  base64 carries every byte unchanged.
- The marker, the tag (`AppName`, read as `ProcessName`) and the collection rule's transform
  change together: `deploy/bicep/ama-syslog-dcr.bicep` is generated from
  `SentinelSchema.SyslogTransformKql`, and `CloudAgentQuickStartTests` fails when they differ.
  Do not "fix" the format to RFC 5424 or plain JSON: the rule would decode nothing and every
  event would be lost after Bower acknowledged it.
- Facility default `local4` (20), severity `notice` (5). The rule's `facility` parameter and
  `logLevels` (Notice and above) match them. Only `local0` to `local7` are accepted.

## Sizes

- A datagram is all or nothing, so a record is never split. Refuse an envelope that does not
  fit `MaximumMessageBytes` (`payload-too-large`, dead-lettered) rather than truncating it.
- The default limit is 7,680 bytes for the whole datagram: rsyslog forwards at most 8,096
  characters per line including its own header (measured, #230). With the 38-byte header that
  is 5,730 bytes of envelope JSON. Keep the limit at least 512 below rsyslog's `MaxMessageSize`.
- The size is computed from byte counts (`MessageBytes`); every header part is ASCII.

## Send loop and failures

- The socket is non-blocking, so no thread ever blocks on the daemon. When the queue is full,
  one datagram waits for room with `SendAsync`, at most `BusyWait` (default 2 s, below the
  worker's delivery timeout). Past that the rest of the batch is retried as
  `destination-syslog-busy` (5 s retry).
- Each socket error is classified, never lumped together:
  - `MessageSize` (EMSGSIZE): this event cannot be sent. `payload-too-large`, carry on with the
    batch. Not a destination fault, so it dead-letters.
  - `WouldBlock` (Linux EAGAIN): wait as above. `NoBufferSpaceAvailable` (macOS ENOBUFS)
    cannot be waited on: retry in 10 ms steps within the same budget.
  - `AccessDenied`: `destination-syslog-access-denied`, stop the batch.
  - Connection refused, missing path, reset and anything else:
    `destination-syslog-unavailable`, reset the socket, stop the batch (30 s retry).
- Cancellation (shutdown or the delivery deadline) stops the loop and returns what was sent as
  acknowledged; only the unsent rest is retried as `destination-syslog-cancelled`. Never throw
  away acknowledgements: the worker would send them again.
- Every code above must be on both allow-lists in `QueueDeliveryWorker`
  (`SafeFailureCode`, `SafePersistedFailureCode`).
- `Dispose` cancels a delivery in progress and waits at most `BusyWait` for it.
- The same record checks as the Logs Ingestion output run first (`IngestionPreflight`, the
  same `preflight-*` codes), since both feed the same table.

## Rules

- Local Unix socket only. No network syslog, no TCP, no TLS: that is the syslog source's job
  in the other direction, and remote syslog would bypass the collector's delivery guarantees.
- Never log payloads. Failure codes are bounded constants.
- Delivery means the local daemon accepted the datagram, not that Sentinel has the row. The
  path is at-least-once; queries deduplicate on `EventId`.
- Any local account can write to `/dev/log`, so the table's integrity on this path depends on
  every local account. Say so wherever this output is recommended.
- Linux only. Windows has no datagram Unix sockets; settings refuse the output there.
- Tests that fill a queue use datagrams under 2,048 bytes, so macOS exercises back-pressure and
  not its size limit. Run the adapter's tests on Linux (CI, or a container) before trusting them.
