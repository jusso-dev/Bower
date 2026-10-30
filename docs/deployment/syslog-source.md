# Syslog source

The collector can listen for syslog from a few high-value senders (network
appliances, legacy Linux services) and turn selected messages into Bower events. It is
a privacy gateway in front of those senders, not a syslog server for the estate:
broad syslog fan-in stays with the Azure Monitor Agent.

```
sender ──TLS (or loopback TCP/UDP)──▶ listener ──▶ parse ──▶ route ──▶ signed pack parser ──▶ redact + policy ──▶ durable queue
                                       allow-list   RFC 5424   host/app   match filter          (default deny)       (acknowledgement)
                                       limits       RFC 3164
```

Both collectors (C# and Rust) implement it with the same parser, limits, failure codes,
record shape and event ids.

## What is accepted

Accepting a sender never means accepting its events. A message is queued only when:

1. the sender's address is in the listener's `allowedSenders`;
2. the frame is within the size limit and parses as RFC 5424 or RFC 3164;
3. a route matches its hostname and app-name (first match wins);
4. the routed signed pack parser's `match` filter selects the record; and
5. redaction succeeds and the policy set accepts the resulting event.

Everything else is dropped and counted. No raw message, record or sender payload is
logged, stored or shown; only the fields the pack parser maps reach the envelope, and
they are redacted before persistence.

## Configure

Set `BOWER_SYSLOG_CONFIG` to a JSON file (at most 256 KiB). Invalid files, unknown
properties, or a route that does not name an active parser of a loaded signed pack
stop start-up.

```json
{
  "apiVersion": "bower.security/v1",
  "kind": "SyslogSource",
  "listeners": [
    {
      "id": "edge-tls",
      "protocol": "tls",
      "address": "0.0.0.0",
      "port": 6514,
      "allowedSenders": ["10.20.0.0/24", "2001:db8:20::/64"],
      "tls": {
        "certificateFile": "/etc/bower/syslog/server.pem",
        "privateKeyFile": "/etc/bower/syslog/server-key.pem",
        "clientCertificateAuthorityFile": "/etc/bower/syslog/senders-ca.pem"
      },
      "routes": [
        { "appName": "sshd", "pack": "linux-ssh-gateway", "parser": 0 }
      ]
    },
    {
      "id": "local",
      "protocol": "udp",
      "port": 5514,
      "allowedSenders": ["127.0.0.1"],
      "routes": [{ "hostname": "fw01", "pack": "edge-firewall", "parser": 0 }]
    }
  ]
}
```

| Setting | Default | Bounds |
|---|---|---|
| `id` | required | 1–63 lowercase letters, digits, hyphens; unique |
| `protocol` | required | `tcp`, `tls` or `udp` |
| `address` | `127.0.0.1` | an IP address (canonical text) |
| `port` | required | 0–65535 (0: chosen by the OS, for tests) |
| `allowedSenders` | required | 1–64 addresses or CIDR ranges (host bits zero) |
| `maximumMessageBytes` | 65536 | 480–65536 |
| `maximumConnections` | 64 | 1–1024 (TCP and TLS) |
| `idleTimeoutSeconds` | 60 | 1–3600 |
| `tls` | none | required for `tls`, refused otherwise; PEM files |
| `allowInsecureNonLoopback` | false | allow `tcp`/`udp` beyond loopback |
| `routes` | required | 1–64; `pack`, `parser` (index), optional `hostname`, `appName`, `allowedSenders` (1–64 addresses or CIDR ranges) |

A non-loopback address needs `protocol: tls` unless `allowInsecureNonLoopback` is set;
use the override only on an isolated network you control. With
`clientCertificateAuthorityFile`, senders must present a client certificate issued by
one of those CAs (mutual TLS); a sender may present intermediates between its
certificate and those CAs. TLS 1.2 and 1.3 only. Certificates, keys and CA files are
read at start-up: rotating them needs a collector restart.

Addresses are canonical IP text: no brackets, ports, IPv6 scopes or whitespace.
Property names are case-sensitive and a repeated property fails the file.

The hostname and app-name a route matches are claimed by the sender, not verified:
any allowed sender can claim `hostname: fw01`. Give a route its own
`allowedSenders` to pin it to the addresses that may use it:

```json
{ "hostname": "fw01", "allowedSenders": ["10.20.0.5"], "pack": "edge-firewall", "parser": 0 }
```

Senders should use RFC 5425-style TLS (octet-counted frames) on port 6514, RFC 5424
format, and send the security-relevant values as structured data.

## The record a pack parser sees

Each message becomes a flat JSON object of string values (at most 64 fields; values
longer than 2048 characters are left out because a pack parser cannot read them):

| Field | Value |
|---|---|
| `id` | `syslog-` + 32 hex of SHA-256 over listener, sender and the exact frame |
| `listener`, `protocol`, `senderAddress` | where it arrived; `senderAddress` is IPv4 for IPv4-mapped IPv6 and never carries an IPv6 scope (`fe80::1`, not `fe80::1%2`) |
| `receivedAt` | receive time, UTC, microseconds |
| `format` | `rfc5424` or `rfc3164` |
| `facility`, `severity` | decimal |
| `timestamp` | the message time in UTC, or `receivedAt` when absent |
| `hostname`, `appName`, `procId`, `msgId`, `message` | when present |
| `sd.<SD-ID>.<PARAM-NAME>` | each structured-data parameter |

Map `eventId` to `id` and `timeGenerated` to `timestamp`, so a retransmitted frame
deduplicates. (Without a message timestamp the receive time is part of the id, so
retransmits of such frames are not deduplicated.) Byte-identical messages from one
sender with the same timestamp are one event. A pack parser for RFC 5424 sshd
structured data:

```json
{
  "version": "1.0",
  "format": "Json",
  "fields": [
    { "sourceName": "id", "type": "Text", "ocsfPath": "metadata.uid", "asimField": "EventOriginalUid", "sensitive": false },
    { "sourceName": "timestamp", "type": "DateTime", "ocsfPath": "time", "asimField": "TimeGenerated", "sensitive": false },
    { "sourceName": "appName", "type": "Text", "ocsfPath": "metadata.product.name", "asimField": "EventProduct", "sensitive": false },
    { "sourceName": "sd.auth@32473.user", "type": "Text", "ocsfPath": "actor.user.name", "asimField": "TargetUsername", "sensitive": true },
    { "sourceName": "sd.auth@32473.src", "type": "IpAddress", "ocsfPath": "src_endpoint.ip", "asimField": "SrcIpAddr", "sensitive": false },
    { "sourceName": "sd.auth@32473.result", "type": "Text", "ocsfPath": "status", "asimField": "EventResult", "sensitive": false }
  ],
  "runtime": {
    "applicationName": "ssh-gateway", "environment": "production",
    "eventCategory": "authentication", "eventType": "authentication_failure",
    "eventAction": "authentication.attempt", "eventResult": "failure",
    "match": { "appName": "sshd", "sd.auth@32473.result": "failure" },
    "fields": {
      "eventId": "id", "timeGenerated": "timestamp",
      "actor.username": "sd.auth@32473.user", "source.ipAddress": "sd.auth@32473.src"
    }
  }
}
```

Free-text extraction from `message` (for example classic sshd lines) belongs in the
routed parser's `transforms`
([transform language](../developer-integration/transform-language.md)), not in this
source. A run-time transform failure quarantines the record without persisting it, as
`/v1/packs/.../events` does: it counts under `rejected` and the pipeline `transform`
stage, and a TCP connection keeps reading. CEF and LEEF are not parsed.

## Parsing rules

Strict and fail closed, with stable codes:

- The whole frame must be valid UTF-8 (`syslog-invalid-utf8`); a leading BOM in MSG is
  removed.
- PRI is 1–3 digits, no leading zero, 0–191 (`syslog-priority-invalid`).
- RFC 5424 when PRI is followed by `1 `; other versions are refused
  (`syslog-version-unsupported`). Timestamps: uppercase `T` and `Z`, at most six
  fraction digits, no leap second, offset within ±14:00 (`syslog-timestamp-invalid`).
  Header fields are printable ASCII within RFC lengths (`syslog-header-invalid`).
  Duplicate SD-IDs or parameter names are refused (`syslog-structured-data-duplicate`);
  malformed structured data is `syslog-structured-data-invalid`.
- Otherwise RFC 3164: `Mmm dd hh:mm:ss` (read as UTC; the year is the receive year, or
  the previous year when the date would be more than a day ahead) or an RFC 3339
  timestamp, then an optional hostname and `TAG[pid]:`. A message without a timestamp
  is refused.

## Framing, limits and backpressure

- TCP and TLS accept RFC 6587 octet counting (`MSG-LEN SP MSG`) and LF-terminated
  frames (a trailing CR is removed), chosen per frame. An oversized length, a bad
  count or any other framing error closes the connection; framing cannot be
  resynchronised safely. UDP is one message per datagram.
- The whole next frame must arrive within `idleTimeoutSeconds`, so slow senders that
  trickle bytes are closed like idle ones. The TLS handshake has the same bound.
- Connections beyond `maximumConnections`, and senders outside `allowedSenders`, are
  closed immediately. At most 16 submissions run at once across all listeners.
- **Acknowledgement point (TCP and TLS).** A frame counts as accepted only once it is
  durably enqueued. Each connection reads its next frame only after the current one
  is enqueued or definitively dropped. When the queue is full (or a management-mode
  collector is waiting for its privacy profile) the connection stops reading and
  retries the same frame every second, so TCP flow control pushes back on the sender.
  A storage error closes the connection.
- **UDP is best effort.** Datagrams wait in a buffer of 256 per listener; when it is
  full, or the queue is at capacity, they are dropped and counted. There is no way to
  push back on a UDP sender.
- **On crash or stop.** Plain syslog has no application acknowledgement. Frames
  already in the kernel socket buffer or Bower's read buffer, and a frame waiting for
  queue space, are lost unless the sender retransmits; everything enqueued before the
  stop is durable. TCP/TLS with a sender-side disk queue reduces exposure but does
  not prove end-to-end lossless delivery: the sender can consider bytes sent before
  Bower durably accepts them. Qualify source retention and replay, idle/reconnect
  behavior, crashes and queue pressure for the actual sender.

## Monitoring

`GET /v1/status` (token required) has a `syslog` array, one entry per listener, with
counters since start: `activeConnections`, `connectionsAccepted`,
`connectionsRejected`, `sendersDenied`, `tlsHandshakeFailures`, `framesReceived`,
`bytesReceived`, `queued`, `duplicates`, `suppressed`, `notRouted`, `notSelected`,
`rejected`, `parserErrors`, `malformed`, `oversized`, `framingErrors`, `timeouts`,
`dropped` (UDP and backpressure), `retries` (TCP waits for queue space),
`submitFailures`, `receiveErrors` (UDP socket receive errors; the listener backs off
100 ms to 1 s and keeps listening) and `lastFrameAt`. They are metadata only and reset
on restart.
Selected syslog events also appear in the pipeline and intake counters like any other
source.

Silence detection works through the pack's application: list the routed parser's
`applicationName`/`environment` in `BOWER_SOURCE_EXPECTATIONS` and a silent syslog
sender degrades `/health` once its allowance passes.

## Residual risks

- UDP senders can be spoofed; the allow-list checks only the source address. Prefer
  TLS with client certificates beyond loopback.
- Hostname and app-name are claimed by the sender. Without a per-route
  `allowedSenders`, any allowed sender can reach any route (and its pack parser) by
  claiming its hostname or app-name; the parser filter, redaction and policy still
  apply.
- Certificate rotation needs a restart; an expired server certificate fails every
  handshake until then.
- Plain TCP beyond loopback (with the override) is unauthenticated and unencrypted.
- A sender allowed to connect can occupy up to `maximumConnections` slots; the idle
  timeout bounds how long.
- Lost frames on crash, as above.

## Not verified here

Interoperability tests against a real sender daemon in a container are not part of
the automated suite; the RFC example vectors, framing and TLS tests run against
in-process clients.

The manual [native AWS pilot](../evidence/pilot-native-20261030/README.md) uses
nftables and rsyslog over mutual TLS. It retains source-loss findings from both
idle connection closure and per-event reconnect configurations. A passing measured
traffic window does not establish durable application acknowledgements or qualify
another appliance's buffering and replay behavior.
