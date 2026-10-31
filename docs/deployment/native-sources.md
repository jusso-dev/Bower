# Native Windows and syslog intake on the 473c6ec base

This C# backport adds opt-in Windows Event Log/WEC and RFC 3164/5424 syslog
sources. It does not add these sources to the Rust collector. Existing HTTP and
cloud intake settings retain their configuration hash when both sources are off.

Both sources resolve parsers only from verified, trusted signed packs. Raw
records are parsed in memory, mapped to the existing event envelope, selected by
policy and redacted before entering the durable queue. Unknown routes, parser
failures and unselected records are rejected without storing raw input. Status
contains counters and positions, not event payloads. Sentinel delivery still
requires independent destination query validation.

## Windows Event Log and WEC

Set `BOWER_WINDOWS_EVENTLOG_CONFIG` to a JSON configuration file:

```json
{
  "apiVersion": "bower.security/v1",
  "kind": "WindowsEventLogSource",
  "subscriptions": [{
    "id": "wec-security",
    "channel": "ForwardedEvents",
    "eventIds": [4625],
    "providers": ["Microsoft-Windows-Security-Auditing"],
    "pack": "windows-security-logon",
    "parser": 0,
    "readExisting": true,
    "includeMessage": false
  }]
}
```

Run the managed collector on Windows with permission to read the selected log.
Configure Windows Event Forwarding and a WEC subscription separately; pointing
Bower at `ForwardedEvents` does not configure forwarding. The original event's
channel remains `Security`, which the signed Windows logon parser verifies.
The included `windows-security-logon` pack selects failed network logons (4625,
logon type 3, valid source address), normalizes the failure code and pseudonymizes
usernames. Build and sign the pack and configure its trusted public key normally.

Bookmarks share the queue database and advance only after durable enqueue,
duplicate acknowledgement or a terminal rejection. Backpressure retains the
position. Native Windows bookmarks address the receiving log, independently of
the original EventRecordID retained by WEF. Log clear/rollover is counted; events
already overwritten by Windows cannot be recovered. Default first start tails
new events; `readExisting` explicitly opts into the retained log. The native
reader fails closed on non-Windows systems. Keep publisher message rendering off
unless a narrowly scoped parser requires it.

## Syslog

Set `BOWER_SYSLOG_CONFIG` to JSON with `apiVersion: bower.security/v1`,
`kind: SyslogSource`, and a `listeners` array. Each listener requires `id`,
`protocol` (`tls`, `tcp` or `udp`), `port`, `allowedSenders` and `routes`.
A route chooses a signed `pack` and zero-based `parser`; optional `appName`,
`hostname` and `allowedSenders` narrow the match. Routes are first-match and
unmatched messages are dropped. Hostname and app-name are untrusted sender claims.

TLS listeners specify `tls.certificateFile` and `tls.privateKeyFile`. Optional
`tls.clientCertificateAuthorityFile` requires a trusted client certificate.
Use real deployment certificates; repository fixture keys are public test data.
Sender address allow-lists remain mandatory. Plain TCP/UDP is loopback-only
unless `allowInsecureNonLoopback` explicitly permits an isolated network.

Frames, concurrent connections, idle time and input sizes are bounded. TCP/TLS
supports octet counting and newline framing and pauses intake on queue pressure.
TCP receipt is not an application-level durable acknowledgement: syslog has no
end-to-end acknowledgement or durable receiver cursor. Sender queues, TLS and
appropriate source retention reduce loss; UDP is best effort and drops on
pressure. Do not claim exactly-once delivery or lossless replay.

The [live Sentinel campaign](../evidence/sentinel-native-20261030/README.md) observed
two missing messages when rsyslog reused a TLS connection after Bower's then-default
60-second frame/idle timeout closed it. The cause is now known: rsyslog never reads the
TLS 1.3 session tickets the .NET listener sends, so its pre-send check cannot see the
close. Bower no longer closes established idle connections by default; a TLS
connection must start its handshake within `handshakeStartTimeoutSeconds` (60 seconds
by default). Test senders that delay the TLS handshake. Per-event reconnects
(`RebindInterval="1"`) are **not** recommended. Use the candidate configuration in the
[delivery-reliability guide](../production-readiness/01-syslog-delivery-reliability.md).
Monitor source counts separately from Bower acceptance and destination counts;
zero missing accepted events does not imply zero source loss.

## Signed runtime mappings

Parser configuration gains optional `runtime` metadata and field mappings.
Runtime transforms and lookup tables are a bounded deterministic language, not
general code: no file/network access, reflection or arbitrary execution.
Evaluation time is supplied explicitly. The parser schema documents the mapping
shape. Raw pack samples (`raw` plus `parser`) now exercise mapping, privacy and
policy before signing; `expectFields` checks the redacted envelope. Transform
failure is a terminal rejection at intake and `quarantine` in pack sample results;
no raw quarantine payload is persisted.
