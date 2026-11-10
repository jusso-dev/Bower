# Local syslog output instructions

Hand each policy-approved, redacted envelope to the host's local syslog daemon
(`/dev/log`, a Unix datagram socket) as one RFC 5424 message whose MSG is the compact
envelope JSON. Azure Monitor Agent (or any agent reading syslog) ships it from there.

- Local Unix socket only. No network syslog, no TCP, no TLS: that is the syslog source's job
  in the other direction, and remote syslog would bypass the collector's delivery guarantees.
- A datagram is all or nothing, so a record is never split. Refuse an envelope that does not
  fit `MaximumMessageBytes` (non-retryable) rather than truncating it.
- A full or missing socket is a destination fault: retry, never drop.
- Never log payloads. Failure codes are bounded constants.
- Delivery means the local daemon accepted the datagram, not that Sentinel has the row.
