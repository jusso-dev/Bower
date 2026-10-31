# 01 — Reliable firewall syslog delivery

**Gap.** The native pilot lost firewall events *before* Bower accepted them: 768
events in the first attempt, 43 of 59,400 with rsyslog `RebindInterval="1"`, and a
smaller loss when Bower closed an idle connection. The final profile passed one
81-minute run but was never tested against idle gaps over an hour, reconnects,
transport resets, sender or collector outages, crashes or log rollover.

**Status: incomplete.** The AWS campaign was interrupted. This draft records
observations from the run, proposed changes to Bower and the sender, and a
procedure for qualifying a firewall or appliance. The profile is not yet qualified.
It covers every environment where the
syslog source runs. The measured boundary is **acceptance into the Bower queue**
(and the local AMA spool). Sentinel delivery is covered by the other gaps.

> **Read this first.** Syslog over TCP or TLS has **no application-level
> acknowledgement**. A sender writes into a socket and assumes success. Nothing in
> this document makes syslog exactly-once or lossless. The configuration below is
> a candidate for reducing loss; its final failure windows have not been qualified.
> Measure loss for your own sender and failure scenarios before deciding whether it
> is acceptable.

## Contents

1. [Summary of results](#1-summary-of-results)
2. [What syslog delivery can and cannot guarantee](#2-what-syslog-delivery-can-and-cannot-guarantee)
3. [Root causes of the pilot losses](#3-root-causes-of-the-pilot-losses)
4. [What changed in Bower](#4-what-changed-in-bower)
5. [Candidate configuration](#5-candidate-configuration)
6. [Certificates for the listener and senders](#6-certificates-for-the-listener-and-senders)
7. [Step-by-step deployment by environment](#7-step-by-step-deployment-by-environment)
8. [Monitoring pre-acceptance loss](#8-monitoring-pre-acceptance-loss)
9. [Qualifying your firewall or appliance](#9-qualifying-your-firewall-or-appliance)
10. [Troubleshooting](#10-troubleshooting)
11. [How we tested this](#11-how-we-tested-this)
12. [Known limits](#12-known-limits)

---

## 1. Summary of results

Run `bower-ws1-20261031-075451`, AWS Sydney, separate Amazon Linux 2023 sender and
collector hosts, mutual TLS with certificate and name validation on both sides.
Every event carries a sequence key, so "lost" means a key that never reached the
Bower queue, not an estimate. The evidence export and reconciliation are pending.

**Qualification incomplete.** The campaign was interrupted before its final
evidence export and reconciliation. Its retained scenarios include both passing
and failing results; the final profile must not be treated as qualified until the
reports are reviewed, published and independently reconciled.

**Verdict.**

Not qualified. Reset, reboot, process termination and restart scenarios recorded
failures. Review each retained attempt and rerun the unfinished validation before
claiming the target delivery envelope.

## 2. What syslog delivery can and cannot guarantee

The acceptance point is the moment Bower durably enqueues a frame. Before that, an
event passes through places Bower cannot see:

```
appliance log buffer ─▶ sender queue (memory/disk) ─▶ sender socket buffer ─▶ network
   ─▶ collector socket buffer ─▶ Bower frame reader ─▶ parser/policy/redaction ─▶ queue (accepted)
```

| Window | Who can lose it | Avoidable? | What closes it |
|---|---|---|---|
| Appliance input limits (rate limiting, local buffer overflow) | Sender | Partly | Size the appliance's limits and watch its own drop counters (section 9). The exact cause of the pilot's 768-event loss was not established. |
| Sender queue on disk while the collector is down | Sender | Mostly | Disk-assisted queue with `saveOnShutdown`. Not proof against power loss unless the queue is synced to disk on every write. |
| Sender socket buffer when the collector closes the connection and the sender does not notice | Sender | Not established | Qualify the sender's reconnect and replay behavior with the selected collector and TLS settings. |
| Collector socket and frame buffer when the Bower process is **killed** (crash, OOM, `SIGKILL`, power loss) | Both | **No** | Plain syslog does not acknowledge durable acceptance. Measure the loss window for the actual sender and failure. |
| Bytes in flight when a TCP connection is **reset** by a middlebox | Both | **No** | Plain syslog does not acknowledge durable acceptance. Measure the loss window for the actual network and sender. |
| Network outage shorter than the sender's TCP retransmission limit (about 15 minutes on Linux) | — | Yes | TCP retransmits; Bower keeps the connection open (keepalive gives up after about 17 minutes). Measured: no loss over a 120-second blackhole. |
| Network outage longer than that | Sender | Partly | The sender's kernel discards its socket buffer when it gives up. Keep the sender's queue on disk; the socket buffer is lost. |

Plain syslog is **at most once** for whatever sits in socket buffers when a
connection dies. A sender that retransmits its last message after reconnecting
(rsyslog `ResendLastMSGOnReconnect`) may send that message more than once. Bower's
current identity includes the listener, sender and frame bytes. For timestamped
frames, two distinct but byte-identical messages from the same sender can therefore
share an ID and be treated as a duplicate. For frames without a timestamp, receive
time is also included, so a retransmission may have a different ID. The protocol
does not provide enough information to distinguish these cases reliably; qualify
the actual sender's unique event identity and replay behavior before deployment.

The signed-pack parser can map a sender sequence into `eventId`, as the synthetic
sequence fixture demonstrates. A production mapping needs a bounded unique
namespace per authenticated appliance and sequence epoch, a sequence that survives
retries without reuse, and a stable original event time. The syslog hostname and
sender address are not automatically bound to the client certificate; shared
relays, NAT or certificates therefore require additional identity controls. A
timestamp-less retry with a later receive time can conflict even if its mapped ID
is stable. Qualify the pack, retention period, sequence reset, replay, upgrade and
rollback behavior in both runtimes; this fixture does not establish those properties
for a real firewall.

Avoid the pilot's `RebindInterval="1"` profile unless it is separately qualified
for the actual sender. It reconnects every message and produced 52,339 reconnect
diagnostics in the pilot; the recorded run still lost events.

## 3. Root causes of the pilot losses

The six retained baseline artifacts linked below were copied byte-for-byte from
local campaign evidence; their sizes and SHA-256 hashes are recorded in the
[baseline artifact provenance](../evidence/ws1-20261031-075451/baseline-artifact-provenance.json).
They describe baseline observations, not a completed production qualification.

| Pilot loss | Mechanism | Evidence | Fixed by |
|---|---|---|---|
| 768 of 12,000 (first attempt) | rsyslog's `imjournal` input rate limit (default 20,000 messages per 600 s) dropped events **before** they reached any action queue. rsyslog logged 769 dropped input messages. | [Pilot diagnostics](../evidence/pilot-native-20261030/README.md) | Bounded `Ratelimit.Burst` sized to the source (section 5). Not a Bower defect. |
| Idle-close loss (preflight) | Bower closed a connection after the 60 s idle timeout. The .NET listener, through OpenSSL, sends two **TLS 1.3 session tickets** (1,566 bytes) right after every handshake. rsyslog never reads from a forwarding connection, so those bytes stay unread. Before each send rsyslog checks for a closed connection with a one-byte non-blocking `MSG_PEEK`; the unread ticket bytes make the check report "data", never "end of stream". rsyslog keeps writing into the closed connection and loses the first event(s) after every idle close. | Reproduced on the pilot build: TLS 1.3 lost 4 of 200 over five idle closes; TLS 1.2 on the same sender lost 0 ([`base-idle-close.json`](../evidence/ws1-20261031-075451/base-idle-close.json), [peek probe](../evidence/ws1-20261031-075451/baseline-peek.json)). | Bower no longer closes idle connections by default (`idleTimeoutSeconds: 0`); collector stops sending tickets or sender pins TLS 1.2. |
| Idle close **plus a firewall** (newly found) | After the close, the collector's kernel answers rsyslog's late writes with a TCP reset. A stateful firewall or security group that has already forgotten the closed flow, and allows only HTTPS outbound, **drops the reset**. rsyslog then retransmits into a dead connection for about 15 minutes (backoff 11, 365,744 bytes queued in the socket) and loses its socket buffer when the kernel gives up. | Packet captures on both hosts: the collector sends `RST`, the sender never receives it ([collector](../evidence/ws1-20261031-075451/base-stuck-capture-collector.txt), [sender](../evidence/ws1-20261031-075451/base-stuck-capture-sender.txt)). | No idle closes; sender TCP keepalive detects the dead connection first; collector egress rule for resets (section 7). |
| 43 of 59,400 with `RebindInterval="1"` | **Not reproduced.** Per-event reconnects at 100 events/s lost 0 of 6,000 on both TLS versions, and 13 forced journal rotations during load lost 0 of 6,000. The pilot ran rsyslog on the same host as Bower and logged 52,339 reconnect messages, three `imjournal` journal reloads and a failed `imjournal.state.tmp` write; the loss happened before Bower frame acceptance. The exact mechanism remains unproven. | [`base-rebind1.json`](../evidence/ws1-20261031-075451/base-rebind1.json), [`base-journal-rotate.json`](../evidence/ws1-20261031-075451/base-journal-rotate.json) | Do not use `RebindInterval`. The candidate profile uses one persistent connection. |
| Restart under load (newly found) | On a graceful stop the old build cancelled every connection immediately. With TLS 1.3 tickets a sender cannot see the close, keeps writing, and loses what is in flight. | Pilot build: restart at 100/s left the TLS 1.3 action stuck for minutes ([`base-restart.json`](../evidence/ws1-20261031-075451/base-restart.json)); fixed build without tickets lost 0 (section 1). | Half-close and drain on stop; no tickets or TLS 1.2. |

Other facts established while root-causing:

- **A reset does not discard what Bower's kernel already received on Linux.** Data
  received before a peer's reset is still returned by the next read (tested on
  Amazon Linux 2023 with .NET 10). The window that a reset loses is on the
  sender's side and in flight.
- **`AllowTlsResume = false` does not stop TLS 1.3 tickets.** With .NET 10 on
  OpenSSL 3, `SslServerAuthenticationOptions.AllowTlsResume = false` turns off
  resumption but OpenSSL still sends two stateful tickets. .NET has no API for the
  ticket count. OpenSSL's own `NumTickets = 0`, set only for the Bower service, does
  stop them (measured: 2 tickets → 0).
- **syslog-ng reads its sockets.** Its TLS 1.3 connections to the .NET listener
  showed 0 unread bytes, so it sees Bower's close whichever TLS version is used.

## 4. What changed in Bower

Both runtimes (C# collector and the Rust port) change the same way unless noted.

| Change | Before | After | Why |
|---|---|---|---|
| `idleTimeoutSeconds` default | 60 (range 1–3600) | **0** = never close a healthy idle connection (range 0–3600) | A sender that cannot see the close loses what it writes next. |
| Idle timeout semantics | Whole next frame within the timeout, then the socket was closed | Time **between** frames only. At expiry Bower half-closes (TCP FIN, no TLS `close_notify`) and keeps reading what the sender already sent until it closes or is quiet for 5 s | Attempts to drain in-flight frames; delivery is not guaranteed. |
| `handshakeStartTimeoutSeconds` | — | 1–3600, default 60: TLS must send its first handshake byte in time | Bounds pre-handshake idle; test lazy TLS senders. |
| `frameTimeoutSeconds` (new) | — | 1–3600, default 60: a started TLS handshake or frame must complete in time | Keeps the slow-loris bound independent of established-session idle. |
| Stop (service restart, upgrade, reboot) | Every connection cancelled at once | Stop accepting, half-close and attempt to drain before cancellation | In-flight delivery is not guaranteed; final shutdown requires cooperative cancellation. |
| TCP keepalive on accepted connections | Operating-system default (off) | On: first probe after 120 s idle, every 30 s, 30 probes (about 17 minutes) | Detects dead peers and keeps load balancer flow state alive (AWS NLB 350 s, Azure Load Balancer 4 minutes by default) without giving up before a Linux sender's own ~15-minute retransmission limit. |
| New counters in `GET /v1/status` → `syslog[]` | — | `halfCloses`, `drainedFrames`, `peerResets` | Make closes, rescued frames and sender resets visible. |
| TLS 1.3 session tickets (Rust only) | Two tickets per handshake | **None** (`send_tls13_tickets = 0`, no session storage) | Removes the unread bytes that defeat rsyslog's close detection. C# cannot do this in-process; see section 5.3. |

**Compatibility.** Configuration files that set `idleTimeoutSeconds` keep working.
A value of 0 was previously refused and is now valid. Files that relied on the old
default (60) now keep idle connections open: each still counts against
`maximumConnections` (default 64), and keepalive closes dead ones. Status JSON
gains three fields (additive). Event ids, framing, parsing and the queue are
unchanged. The Rust listener's missing TLS 1.3 tickets are a deliberate, recorded
divergence from C#.

## 5. Candidate configuration

### 5.1 Collector listener (`BOWER_SYSLOG_CONFIG`)

```json
{
  "apiVersion": "bower.security/v1",
  "kind": "SyslogSource",
  "listeners": [
    {
      "id": "firewall-tls",
      "protocol": "tls",
      "address": "0.0.0.0",
      "port": 6514,
      "allowedSenders": ["10.20.0.5", "10.20.0.6"],
      "idleTimeoutSeconds": 0,
      "frameTimeoutSeconds": 60,
      "maximumConnections": 64,
      "tls": {
        "certificateFile": "/etc/bower/syslog/server.pem",
        "privateKeyFile": "/etc/bower/syslog/server-key.pem",
        "clientCertificateAuthorityFile": "/etc/bower/syslog/senders-ca.pem"
      },
      "routes": [
        { "appName": "kernel", "allowedSenders": ["10.20.0.5", "10.20.0.6"], "pack": "your-firewall-pack", "parser": 0 }
      ]
    }
  ]
}
```

| Setting | Value | Reason |
|---|---|---|
| `protocol` | `tls` | Encryption and sender authentication beyond loopback. |
| `clientCertificateAuthorityFile` | your sender CA | Mutual TLS: only senders with a certificate from this CA can connect. |
| `allowedSenders` (listener and route) | exact sender addresses | Senders claim hostnames and app-names; pin each route to the addresses allowed to claim them. |
| `idleTimeoutSeconds` | `0` | Do not close a healthy established idle connection (section 3). |
| `handshakeStartTimeoutSeconds` | `60` | Bounds the wait for the first TLS byte; qualify lazy senders and reconnects. |
| `frameTimeoutSeconds` | `60` | Bounds a started handshake and partial frames (slow loris). |
| `maximumConnections` | at least 2 × senders + headroom | Reconnects briefly overlap with half-open connections that keepalive has not yet closed. |

### 5.2 Network rule every environment needs: let resets reach senders

A collector must be able to send **TCP resets back to a sender**, or a sender that
writes into a dead connection waits about 15 minutes before it notices. Stateful
firewalls allow replies only while they still track the flow. Add one of:

- an egress rule from the collector to the senders' ephemeral ports
  (TCP 1024–65535, destination = sender addresses only); or
- for host firewalls (nftables, firewalld, Windows Firewall) that are stateless for
  outbound traffic by default, no change.

The rule allows packets *to* senders, never connections *from* the internet. Section
7 has the exact rule for each environment.

### 5.3 Remove TLS 1.3 session tickets on the collector (Linux, C# collector)

Pick **one** of 5.3 or 5.4. Prefer 5.3 when you control the collector host: it keeps
TLS 1.3 for every sender.

The collector reads OpenSSL configuration at start-up. Give the Bower service its
own copy of the system configuration with `NumTickets = 0` in the section that
`system_default` names. Distribution crypto policies stay in force because the copy
still includes them.

```bash
# Run as root on the collector host.
src=/etc/pki/tls/openssl.cnf                 # RHEL, Amazon Linux, Rocky, Alma
[ -f "$src" ] || src=/etc/ssl/openssl.cnf    # Debian, Ubuntu
section=$(awk -F= '/^[[:space:]]*system_default[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$src")
echo "system_default section: ${section:?no system_default in $src}"
python3 - "$src" "$section" <<'PY'
import re, sys
source, section = sys.argv[1], sys.argv[2]
text = open(source).read()
text, n = re.subn(r"(^\[\s*" + re.escape(section) + r"\s*\][^\n]*\n)", r"\1NumTickets = 0\n", text, count=1, flags=re.M)
assert n == 1, "section not found"
open("/etc/bower/openssl.cnf", "w").write(text)
PY
chmod 0644 /etc/bower/openssl.cnf
install -d /etc/systemd/system/bower.service.d
printf '[Service]\nEnvironment=OPENSSL_CONF=/etc/bower/openssl.cnf\n' > /etc/systemd/system/bower.service.d/openssl.conf
systemctl daemon-reload && systemctl restart bower
```

If the distribution has no `system_default` section (for example a minimal
container), use this whole file instead; .NET still enforces TLS 1.2 and 1.3:

```ini
openssl_conf = bower_init
[bower_init]
ssl_conf = bower_ssl
[bower_ssl]
system_default = bower_tls
[bower_tls]
NumTickets = 0
```

**Verify** from a sender (expect `0`; `2` means tickets are still sent):

```bash
openssl s_client -connect COLLECTOR:6514 -tls1_3 -cert sender.pem -key sender-key.pem \
  -CAfile collector-ca.pem -verify_return_error -msg </dev/null 2>&1 | grep -c NewSessionTicket
```

**Rollback:** `rm /etc/systemd/system/bower.service.d/openssl.conf && systemctl daemon-reload && systemctl restart bower`.

The Rust collector sends no tickets and needs none of this. On Windows (SChannel)
this is not tested; use 5.4 for rsyslog senders there.

### 5.4 Or pin TLS 1.2 on rsyslog senders

When you cannot change the collector, pin the rsyslog action to TLS 1.2. TLS 1.2
leaves no unread bytes after the handshake, so rsyslog's close check works. Keep
modern ciphers; TLS 1.2 with ECDHE and AES-GCM remains acceptable under NIST SP
800-52r2.

- `ossl` driver: `gnutlsPriorityString="MinProtocol=TLSv1.2\nMaxProtocol=TLSv1.2"`
- `gtls` driver: `gnutlsPriorityString="NORMAL:-VERS-TLS1.3:-VERS-TLS1.1:-VERS-TLS1.0"`

### 5.5 rsyslog candidate (rsyslog 8.2204, `ossl` driver, Amazon Linux 2023)

`/etc/rsyslog.d/60-bower.conf`:

```
global(
  DefaultNetstreamDriverCAFile="/etc/pki/bower/collector-ca.pem"
  DefaultNetstreamDriverCertFile="/etc/pki/bower/sender.pem"
  DefaultNetstreamDriverKeyFile="/etc/pki/bower/sender-key.pem")
module(load="impstats" interval="60" severity="7" log.syslog="off"
       log.file="/var/log/rsyslog-stats.log" format="json")

ruleset(name="bower") {
  action(name="bower" type="omfwd"
         target="bower-collector.example.internal" port="6514" protocol="tcp"
         TCP_Framing="octet-counted" template="RSYSLOG_SyslogProtocol23Format"
         StreamDriver="ossl" StreamDriverMode="1" StreamDriverAuthMode="x509/name"
         StreamDriverPermittedPeers="bower-collector.example.internal"
         RebindInterval="0" ResendLastMSGOnReconnect="on"
         KeepAlive="on" KeepAlive.Time="60" KeepAlive.Interval="10" KeepAlive.Probes="6"
         queue.type="LinkedList" queue.filename="bower_fwd" queue.saveOnShutdown="on"
         queue.size="200000" queue.highWatermark="150000" queue.lowWatermark="100000"
         queue.maxDiskSpace="2g" queue.timeoutEnqueue="86400000"
         queue.discardMark="200000" queue.discardSeverity="8"
         queue.checkpointInterval="100" queue.syncQueueFiles="off"
         action.resumeRetryCount="-1" action.resumeInterval="5" action.reportSuspension="on")
}

# A full queue must block the input (the journal keeps the events) rather than drop.
main_queue(queue.timeoutEnqueue="86400000")

# Route only what the Bower pack parses; everything else stays local.
if $programname == "kernel" and $msg contains "YOUR_DENY_PREFIX" then { call bower stop }
```

In `/etc/rsyslog.conf`, size the journal input instead of leaving the default
20,000 messages per 600 seconds:

```
module(load="imjournal" StateFile="imjournal.state" Ratelimit.Interval="600" Ratelimit.Burst="200000")
```

Add the 5.4 line to the action if you did not apply 5.3. Validate and restart:

```bash
rsyslogd -N1 && systemctl restart rsyslog
```

| Setting | Why |
|---|---|
| `protocol="tcp"`, `StreamDriver="ossl"`, `StreamDriverMode="1"` | TLS over TCP. Use `gtls` if your distribution ships `rsyslog-gnutls`; both drivers check the connection the same way. |
| `StreamDriverAuthMode="x509/name"`, `StreamDriverPermittedPeers` | Validates the collector's certificate and name. Never use `anon`. |
| Sender certificate in `DefaultNetstreamDriverCertFile`/`KeyFile` | Mutual TLS: the collector requires it. |
| `TCP_Framing="octet-counted"`, `RSYSLOG_SyslogProtocol23Format` | RFC 5425 framing and RFC 5424 format: a message containing a newline cannot split into two frames. |
| `RebindInterval="0"` | One persistent connection. Never reconnect per message. |
| `ResendLastMSGOnReconnect="on"` | After an immediate successful reconnect, resend the message most likely lost; Bower removes the duplicate. Does not help while the collector is down. |
| `KeepAlive*` (60 s, 10 s × 6) | Finds a dead connection within about 2 minutes, **before** the next write, so rsyslog reconnects instead of writing into it (measured in `a-restart-quiet-sg-strict`). Also keeps load balancer flow state alive. |
| Disk-assisted `LinkedList` queue, `queue.filename`, `queue.maxDiskSpace` | Holds events while the collector is unreachable; spills to disk under pressure. Size `maxDiskSpace` for your longest planned outage × peak rate × message size. |
| `queue.size="200000"`, `queue.highWatermark`, `queue.lowWatermark` | rsyslog's action-queue default is **1,000** messages in memory (high watermark 900). Above the high watermark the queue spills to disk. Size the memory part for a few minutes of peak traffic. |
| `queue.timeoutEnqueue="86400000"` (action and `main_queue`) | **The setting that prevents silent sender-side loss.** When a queue counts as full, rsyslog waits `timeoutEnqueue` (default **2,000 ms**) and then **drops** the message (`discarded.full`). A long timeout makes a full queue block its input instead: imjournal stops reading and the journal keeps the events. `0` means drop immediately. There is no "wait forever" value. |
| `queue.discardMark`, `queue.discardSeverity="8"` | Discarding by severity above the discard mark (default 98 % of `queue.size`) is off only while `discardSeverity` is 8 (the default). Set both explicitly so a copied configuration cannot enable discarding by accident. |
| `queue.maxDiskSpace="2g"` | The disk part's limit; when reached the queue is full (see `timeoutEnqueue`). Unlimited by default, which can fill the file system. Size it: longest outage × peak rate × ~400 bytes. |
| `queue.saveOnShutdown="on"` | Persists the in-memory part on a clean stop or reboot. Sender-reboot loss has not been established for this candidate profile. |
| `queue.syncQueueFiles="off"`, `queue.checkpointInterval="100"` | As tested. `on` fsyncs every write and survives power loss better at a large throughput cost; measure before enabling. |
| `action.resumeRetryCount="-1"`, `action.resumeInterval="5"` | Retry forever, every 5 s; never discard on a long outage. |
| `action.reportSuspension="on"` | Logs suspension and resumption, which section 8 alerts on. |
| `impstats` | Queue size, enqueued, discarded and action failure counters (section 8). |
| imjournal `Ratelimit.Burst` | The pilot's first loss. Size it from the source's peak rate, do not disable it. |

### 5.6 syslog-ng candidate (syslog-ng 4.12.0, official container)

```
@version: current
@include "scl.conf"
options { keep-hostname(no); chain-hostnames(no); stats(freq(60)); log-fifo-size(20000); };
log { source { internal(); }; destination { file("/var/log/syslog-ng-internal.log"); }; };

source s_firewall { file("/var/log/firewall.log" program-override("firewall") flags(no-parse) follow-freq(1)); };

destination d_bower {
  syslog("bower-collector.example.internal" port(6514) transport("tls")
    tls(ca-file("/etc/pki/bower/collector-ca.pem")
        cert-file("/etc/pki/bower/sender.pem") key-file("/etc/pki/bower/sender-key.pem")
        peer-verify(required-trusted))
    so-keepalive(yes) time-reopen(5)
    disk-buffer(reliable(yes) dir("/var/lib/syslog-ng") disk-buf-size(1073741824) mem-buf-size(16777216)));
};
log { source(s_firewall); destination(d_bower); };
```

| Setting | Why |
|---|---|
| `syslog()` driver, `transport("tls")` | RFC 5424 with RFC 5425 octet counting over TLS. |
| `peer-verify(required-trusted)`, `ca-file`, `cert-file`, `key-file` | Validates the collector and presents the sender certificate. |
| `disk-buffer(reliable(yes) …)` | Every message is written to disk before sending and survives restarts. It still cannot know whether Bower accepted bytes it wrote to the socket. |
| `so-keepalive(yes)`, `time-reopen(5)` | Detects dead connections; reconnect every 5 s. |

Measured results for syslog-ng are in section 1.

## 6. Certificates for the listener and senders

Use your organisation's PKI where you have one. The commands below create a
dedicated syslog CA. Keep the CA key offline after issuing certificates.

**Prerequisites:** OpenSSL 3, the collector's DNS name (`bower-collector.example.internal`
below) and IP address, one name per sender.

```bash
# 1. CA (keep ca-key.pem offline).
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca-key.pem
openssl req -x509 -new -key ca-key.pem -days 825 -subj "/CN=Bower syslog CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem

# 2. Collector server certificate (key generated on the collector).
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server-key.pem
openssl req -new -key server-key.pem -subj "/CN=bower-collector.example.internal" \
  -addext "subjectAltName=DNS:bower-collector.example.internal,IP:10.20.1.10" -out server.csr
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 397 \
  -copy_extensions copy -extfile server.ext -out server.pem

# 3. One certificate per sender (key generated on the sender).
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out sender-key.pem
openssl req -new -key sender-key.pem -subj "/CN=fw01.example.internal" \
  -addext "subjectAltName=DNS:fw01.example.internal" -out sender.csr
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' > client.ext
openssl x509 -req -in sender.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 397 \
  -copy_extensions copy -extfile client.ext -out sender.pem
```

PowerShell (Windows administration workstation with OpenSSL for Windows on `PATH`)
uses the same `openssl` arguments; write the extension files with
`Set-Content -Path server.ext -Value "basicConstraints=critical,CA:FALSE","keyUsage=critical,digitalSignature","extendedKeyUsage=serverAuth"`.

Install on the collector (Linux package):

```bash
install -d -o root -g bower -m 0750 /etc/bower/syslog
install -o root -g bower -m 0640 server.pem server-key.pem /etc/bower/syslog/
install -o root -g bower -m 0644 ca.pem /etc/bower/syslog/senders-ca.pem
```

**Verify** (expected `Verify return code: 0 (ok)` and the listener's `tlsHandshakeFailures` unchanged):

```bash
openssl s_client -connect bower-collector.example.internal:6514 -cert sender.pem -key sender-key.pem \
  -CAfile ca.pem -verify_hostname bower-collector.example.internal -verify_return_error </dev/null
```

**Rotation.** Bower reads certificates at start-up. Issue the new server certificate
from the same CA, replace the files, then `systemctl restart bower`. Senders see the
half-close, reconnect and validate the new certificate. Restart loss with 5.3 or
5.4 applied has not been established. To change the CA, add the new CA to
`senders-ca.pem` (concatenate both) before reissuing sender certificates, then
remove the old CA after every sender has moved.

## 7. Step-by-step deployment by environment

Each procedure assumes the collector is installed and delivering (see
[installers](../deployment/installers.md)) and that the signed pack for your
firewall is loaded. Port 6514 is used throughout.

### 7.1 Linux package (RPM/DEB, systemd)

**Purpose:** a TLS syslog listener on a Linux collector host.
**Prerequisites:** `bower-collector` package, certificates (section 6), the pack's
public key in `BOWER_PACK_TRUSTED_KEYS`.

1. Write `/etc/bower/syslog.json` (section 5.1), then
   `chown root:bower /etc/bower/syslog.json && chmod 0640 /etc/bower/syslog.json`.
2. Add `BOWER_SYSLOG_CONFIG=/etc/bower/syslog.json` to `/etc/bower/bower.env`.
3. Apply section 5.3 (TLS 1.3 tickets off) or plan 5.4 on the senders.
4. Open the port to senders only:
   - firewalld: `firewall-cmd --permanent --new-zone=bower-syslog && firewall-cmd --permanent --zone=bower-syslog --add-source=10.20.0.5/32 && firewall-cmd --permanent --zone=bower-syslog --add-port=6514/tcp && firewall-cmd --reload`
   - nftables: `nft add rule inet filter input ip saddr { 10.20.0.5, 10.20.0.6 } tcp dport 6514 accept`
   - ufw: `ufw allow from 10.20.0.5 to any port 6514 proto tcp`
5. `systemctl restart bower`.

**Expected output:** `journalctl -u bower | grep "Syslog listener"` shows
`Syslog listener firewall-tls (tls) listening on 0.0.0.0:6514`.

**Verify:**

```bash
token=$(sudo cat /etc/bower/secrets/token)   # or your ingest token file
curl -s -H "Authorization: Bearer $token" http://127.0.0.1:4319/v1/status | jq '.syslog[] | {id, activeConnections, framesReceived, queued, tlsHandshakeFailures}'
```

```powershell
$token = Get-Content /etc/bower/secrets/token
(Invoke-RestMethod -Headers @{ Authorization = "Bearer $token" } http://127.0.0.1:4319/v1/status).syslog |
  Select-Object id, activeConnections, framesReceived, queued, tlsHandshakeFailures
```

**Pass:** each sender holds one connection (`activeConnections` = number of
senders), `queued` rises with traffic, `tlsHandshakeFailures`, `malformed`,
`framingErrors` and `peerResets` stay flat. Run the section 9 test.
**Fail:** `tlsHandshakeFailures` rising (certificate/name problem), `sendersDenied`
rising (allow-list), `notRouted` rising (route app-name/hostname).
**Rollback:** remove `BOWER_SYSLOG_CONFIG` from `bower.env` and restart; senders
queue on disk until the listener returns.
**Limits:** `maximumConnections` per listener, 64 KiB maximum message, one frame at
a time per connection (about 100 events/s per connection measured with headroom).

### 7.2 Docker

**Purpose:** the same listener in the collector container.

1. Mount configuration, certificates and the ticket-free OpenSSL file read-only,
   and publish the port:

   ```yaml
   services:
     bower:
       image: ghcr.io/your-org/bower:VERSION
       read_only: true
       restart: unless-stopped
       stop_grace_period: 30s
       ports:
         - "6514:6514"
       environment:
         BOWER_SYSLOG_CONFIG: /etc/bower/syslog.json
         OPENSSL_CONF: /etc/bower/openssl.cnf
       volumes:
         - ./syslog.json:/etc/bower/syslog.json:ro
         - ./syslog-tls:/etc/bower/syslog:ro
         - ./openssl.cnf:/etc/bower/openssl.cnf:ro      # the minimal file from 5.3
         - bower-data:/var/lib/bower
   ```

2. Files must be readable by the container user (UID 1654): `chown -R 1654 syslog-tls && chmod 0640 syslog-tls/*-key.pem`.
3. `docker compose up -d` (name the context explicitly, for example `docker --context prod compose up -d`).

**Source addresses.** Docker's default bridge NATs published ports, so Bower sees
the bridge gateway as the sender. Use `network_mode: host` on Linux, or add the
bridge gateway (for example `172.17.0.1`) to `allowedSenders` **and** rely on mutual
TLS for identity. With NAT, route-level `allowedSenders` cannot tell senders apart.

**Verify / pass / fail / rollback:** as 7.1, using `docker compose exec bower` for
the status call. `docker stop` sends SIGTERM and waits `stop_grace_period`. Size it
for the graceful drain and cooperative cancellation in the actual workload; 5 seconds
does not guarantee completion. `docker kill` is a crash (section 2).

### 7.3 Kubernetes (Service or LoadBalancer with TLS passthrough)

**Purpose:** expose the listener from the `deploy/kubernetes` deployment.

1. Add the port and configuration to the container:

   ```yaml
   ports:
     - name: syslog-tls
       containerPort: 6514
   env:
     - name: BOWER_SYSLOG_CONFIG
       value: /etc/bower/syslog/syslog.json
     - name: OPENSSL_CONF
       value: /etc/bower/syslog/openssl.cnf
   volumeMounts:
     - name: syslog
       mountPath: /etc/bower/syslog
       readOnly: true
   ```

   with a `Secret` holding `syslog.json`, `server.pem`, `server-key.pem`,
   `senders-ca.pem` and the minimal `openssl.cnf` (mode `0440`).
2. Expose it with **TCP passthrough**; TLS terminates in Bower:

   ```yaml
   apiVersion: v1
   kind: Service
   metadata:
     name: bower-syslog
     annotations:
       # AWS Load Balancer Controller: NLB, TCP, client IP preserved.
       service.beta.kubernetes.io/aws-load-balancer-type: external
       service.beta.kubernetes.io/aws-load-balancer-nlb-target-type: ip
       service.beta.kubernetes.io/aws-load-balancer-scheme: internal
       service.beta.kubernetes.io/aws-load-balancer-target-group-attributes: preserve_client_ip.enabled=true
       # Azure: internal Standard Load Balancer.
       service.beta.kubernetes.io/azure-load-balancer-internal: "true"
       service.beta.kubernetes.io/azure-load-balancer-tcp-idle-timeout: "30"
   spec:
     type: LoadBalancer
     externalTrafficPolicy: Local
     loadBalancerSourceRanges: ["10.20.0.0/24"]
     selector:
       app.kubernetes.io/name: bower-collector
     ports:
       - name: syslog-tls
         port: 6514
         targetPort: syslog-tls
         protocol: TCP
   ```

   Never enable PROXY protocol: Bower reads the TLS handshake directly. Never use an
   ingress controller that terminates TLS.
3. Extend the `NetworkPolicy`: ingress TCP 6514 from the sender CIDR, and egress TCP
   1024–65535 to the sender CIDR (section 5.2).
4. Set `terminationGracePeriodSeconds` to at least 30. The deployment uses
   `strategy: Recreate` with one replica and a `ReadWriteOnce` queue volume, so a
   rollout has a short window with no endpoint; senders queue on disk and reconnect.

**Verify:** `kubectl --context CONTEXT -n NAMESPACE port-forward deploy/bower-collector 4319` then the 7.1 status call.
**Pass:** `activeConnections` equals the number of senders and the sender addresses
in Bower's records are the senders' real addresses (not node addresses).
**Fail:** sender addresses are node IPs → `externalTrafficPolicy` is not `Local` or
client IP preservation is off; `allowedSenders` must not be widened to node CIDRs.
**Rollback:** delete the `bower-syslog` Service; senders queue.

### 7.4 AWS EC2 (security groups, NLB TCP passthrough)

1. **Collector security group, inbound:** TCP 6514 from the sender security group
   or the sender CIDRs only.
2. **Collector security group, outbound:** TCP 1024–65535 to the sender security
   group or CIDRs (section 5.2), plus TCP 443 for delivery and management.

   ```bash
   aws ec2 authorize-security-group-egress --group-id sg-COLLECTOR \
     --ip-permissions 'IpProtocol=tcp,FromPort=1024,ToPort=65535,UserIdGroupPairs=[{GroupId=sg-SENDERS,Description="TCP resets to syslog senders"}]'
   ```

   ```powershell
   $perm = @{ IpProtocol='tcp'; FromPort=1024; ToPort=65535; UserIdGroupPairs=@(@{ GroupId='sg-SENDERS' }) }
   Grant-EC2SecurityGroupEgress -GroupId sg-COLLECTOR -IpPermission $perm
   ```

   This was the rule that turned the measured 15-minute stall into a prompt reconnect
   (`a-restart-quiet-sg-strict` versus `-open`; both lost 0 because sender keepalive
   also caught the dead connection).
3. **Through an NLB (optional):** TCP listener on 6514 (not TLS), target group TCP
   6514, client IP preservation on, cross-zone as needed. Set the NLB TCP idle
   timeout above Bower's keepalive interval (default 350 s is fine: Bower probes every
   120 s idle). Do not enable PROXY protocol v2. Register the collector as a target;
   health check TCP 6514 only (a TLS health check would count as handshake failures).
4. Apply 5.3 on the instance.

**Verify:** as 7.1, plus `aws ec2 describe-security-groups --group-ids sg-COLLECTOR --query 'SecurityGroups[0].IpPermissionsEgress'` shows the reset rule.
**Rollback:** `aws ec2 revoke-security-group-egress` with the same permission.

### 7.5 Azure VM (NSG, Load Balancer)

1. **NSG inbound:** allow TCP 6514 from the sender address prefixes, priority above
   the deny rules.

   ```bash
   az network nsg rule create -g RG --nsg-name NSG -n allow-syslog-tls --priority 200 \
     --direction Inbound --access Allow --protocol Tcp --source-address-prefixes 10.20.0.0/24 \
     --destination-port-ranges 6514
   az network nsg rule create -g RG --nsg-name NSG -n allow-resets-to-senders --priority 210 \
     --direction Outbound --access Allow --protocol Tcp --destination-address-prefixes 10.20.0.0/24 \
     --destination-port-ranges 1024-65535
   ```

   ```powershell
   $nsg = Get-AzNetworkSecurityGroup -ResourceGroupName RG -Name NSG
   Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg -Name allow-syslog-tls -Priority 200 -Direction Inbound `
     -Access Allow -Protocol Tcp -SourceAddressPrefix 10.20.0.0/24 -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 6514
   Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg -Name allow-resets-to-senders -Priority 210 -Direction Outbound `
     -Access Allow -Protocol Tcp -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix 10.20.0.0/24 -DestinationPortRange 1024-65535
   $nsg | Set-AzNetworkSecurityGroup
   ```

   Azure's default outbound rules already allow VNet-to-VNet traffic; the explicit
   rule matters when you have added a deny-all outbound rule.
2. **Azure Load Balancer (optional):** Standard SKU, internal, TCP rule 6514→6514,
   **floating IP off**, **TCP reset on idle enabled**, idle timeout 30 minutes.
   Health probe TCP 6514. The default 4-minute idle timeout is above Bower's 120 s
   keepalive, but enabling TCP reset makes a timed-out flow fail fast instead of
   silently.
3. Apply 5.3 on the VM. **Verify / rollback:** as 7.1 and `az network nsg rule delete`.

### 7.6 On-premises

1. Put the collector in a network segment the firewalls can reach on TCP 6514; allow
   collector-to-sender TCP for resets (section 5.2) on any firewall between them.
2. If a firewall between sender and collector has a TCP idle timeout, set it above
   10 minutes or rely on keepalive (Bower 120 s, rsyslog 60 s). Never let a middlebox
   drop idle flows silently.
3. For appliances that cannot do TLS or mutual TLS (section 9), place a relay
   (rsyslog or syslog-ng on a hardened host next to the appliance) that receives
   locally and forwards with the candidate configuration.
4. Apply 5.3 on the collector.

## 8. Monitoring pre-acceptance loss

Bower can only count what reaches it. Watch the sender and Bower together.

| Signal | Where | Alert when |
|---|---|---|
| rsyslog action `failed`, `suspended`, `suspended.duration`, `resumed` | impstats record with `origin` `core.action` and `name` = the action name (`bower`) | `suspended` increases, or `suspended.duration` > 300 s |
| rsyslog queue `size`, `maxqsize`, `full`, `discarded.full`, `discarded.nf` | impstats records `bower queue` and `bower queue[DA]` (`origin` `core.queue`) | any `discarded.*` > 0; `size` growing for 10 minutes |
| rsyslog `imjournal` `ratelimit_discarded_in_interval`, `discarded`, `failed` (and `imuxsock` `ratelimit.discarded`) | impstats records `imjournal`, `imuxsock` | > 0 |
| rsyslog bytes sent per destination | impstats record `TCP-<ip>-<port>` (`origin` `omfwd`), `bytes.sent` | flat while the source is active |
| Disk-queue files `/var/lib/rsyslog/bower_fwd.*` | file size | growing while the collector is healthy |
| `omfwd: remote server … closed connection`, `TCPSendBuf error`, `Broken pipe` | rsyslog journal | any: each is a possible lost-in-flight event |
| syslog-ng `dropped`, `queued` for `d_bower` | `syslog-ng-ctl stats` | `dropped` > 0 |
| Bower `peerResets` | `/v1/status` → `syslog[]` | increases: a sender or middlebox reset a connection |
| Bower `halfCloses`, `drainedFrames` | same | `halfCloses` without a planned stop; `drainedFrames` > 0 shows frames rescued at a close |
| Bower `activeConnections` vs senders; `connectionsAccepted` | same | fewer connections than senders for 5 minutes; `connectionsAccepted` climbing (reconnect loop) |
| Bower `tlsHandshakeFailures`, `sendersDenied`, `notRouted`, `malformed`, `framingErrors`, `timeouts`, `retries`, `submitFailures` | same | any sustained increase |
| Source silence | `BOWER_SOURCE_EXPECTATIONS` + `/health` | a firewall goes silent beyond its allowance |
| Appliance's own drop counters | section 9 | any increase |

Reconcile counts end to end at least daily: appliance count of forwarded events,
sender queue counters, Bower `queued` (per listener), destination rows.

## 9. Qualifying your firewall or appliance

Bower's configuration above is necessary but not sufficient: each appliance buffers,
frames and reconnects differently, and **none** offer an application-level
acknowledgement over plain syslog. Qualify the exact model and version you deploy.

### 9.1 General requirements

| Requirement | Why |
|---|---|
| TCP with TLS (RFC 5425) to port 6514, server certificate validated | Integrity and confidentiality; UDP is best effort. |
| Client certificate (mutual TLS) if the appliance supports it | Otherwise rely on `allowedSenders` plus a dedicated listener. |
| RFC 5424 format; octet-counted framing preferred, LF framing accepted | Bower accepts both; octet counting survives embedded newlines. |
| One persistent connection; no reconnect per message | Section 2. |
| A local buffer that survives the collector being down; a known size | Determines the longest outage you can survive. |
| Keepalive or a short idle-retry if offered | Detects dead connections before writing into them. |
| A counter of forwarded and dropped log messages | You cannot measure loss without it. |

### 9.2 Test procedure (run before production, repeat after upgrades)

1. **Prepare:** a dedicated listener (`idleTimeoutSeconds: 0`), the appliance's pack,
   section 5.2 network rule, collector tickets off (5.3). Record the appliance model,
   software version, configuration export hash and Bower version.
2. **Generate countable events:** create a rule that logs and denies traffic from a
   test host to an unused port. From the test host send N connection attempts with
   distinct source ports, for example
   `for p in $(seq 40000 40999); do nc -z -w1 -p $p FIREWALL_IP 4444; done`,
   or `Test-NetConnection` in a loop on Windows. N = 1,000 at a time.
3. **Count at three points:** the appliance's deny-rule hit counter (native),
   the appliance's syslog forwarded/dropped counters, and Bower `queued` for the
   listener plus the distinct event ids in the destination.
4. **Run these scenarios**, each with N events, and record lost and duplicate counts:
   steady 10/s; 100/s burst; collector `systemctl restart` mid-burst; collector
   `kill -9` mid-burst; collector host reboot; network drop (blackhole) for 2 minutes
   then restore; idle for 65 minutes then a burst; appliance syslog service restart
   or failover; appliance reboot with events generated while the collector is down.
5. **Pass:** 0 lost in every scenario except `kill -9` and resets, where the loss is
   below a window agreed for the deployed sender (the kill-loss bound has not been established).
   Reconcile with independent sender counts: identical timestamped events may collapse, and
   timestamp-less retries may be delivered twice. A zero queue-duplicate counter does not prove no loss.
6. **Record** the results with the configuration and versions. A pass qualifies that
   combination only.

### 9.3 Vendor notes

These are starting points; confirm every command and option against the
documentation for your exact software version. None of these appliances were
available in this test.

| Vendor | Transport and framing | Buffering and replay | Counters to reconcile | Watch out for |
|---|---|---|---|---|
| **Palo Alto Networks (PAN-OS)** | Syslog server profile: transport **SSL**, format **IETF** (RFC 5424), port 6514. Import Bower's CA into the certificate store; configure a client certificate for secure syslog if your version supports it. | Logs stay in the firewall's log database; syslog forwarding does not generally replay an outage. Reconcile against the firewall's own logs or Panorama. | Rule hit count; `debug syslog-ng stats` (forwarded and dropped per destination) on versions that expose it; `show logging-status`. | Management-plane load at high log rates; certificate chains that omit intermediates. |
| **Fortinet (FortiOS)** | `config log syslogd setting` → `set mode reliable` (TCP, RFC 6587), `set enc-algorithm high` (TLS), `set format rfc5424`, `set port 6514`, `set certificate <client cert>` for mutual TLS. | Memory or disk log queue; size depends on model. | Policy hit counters; `diagnose test application miglogd …` statistics (option numbers vary by release); `diagnose log test` for a synthetic message. | `mode udp` is the default; FortiGate may drop log messages under CPU pressure before syslog. |
| **Cisco ASA** | `logging host <if> <ip> tcp/6514 secure`, `logging timestamp rfc5424`, trustpoint for the collector CA. | `logging queue` (default 512 messages, raise it); buffered logging is local only. | `show logging` (messages logged, dropped, queue statistics); ACL hit counts. | **Without `logging permit-hostdown`, an ASA blocks new connections through the firewall when its TCP syslog server is down.** Decide deliberately. |
| **Cisco FTD (FMC)** | Platform settings → Syslog → syslog server over TCP with secure syslog; RFC 5424 timestamps. | As ASA (LINA). | `show logging` on the device CLI; access-control rule hit counts in FMC. | "Allow user traffic to pass when TCP syslog server is down" is the FTD equivalent of `permit-hostdown`. |
| **pfSense** | Built-in remote logging is UDP only. | None for remote syslog. | Firewall rule states/hits; `clog` local logs. | Relay through a local rsyslog/syslog-ng host (section 7.6) to get TLS, a disk queue and counters. |
| **OPNsense** | System → Settings → Logging → Remote: transport TLS (TCP), RFC 5424, certificate. Uses syslog-ng. | syslog-ng memory buffer by default; add a disk buffer only through custom configuration. | `syslog-ng-ctl stats` on the console; rule counters. | Check the generated syslog-ng destination for `so-keepalive` and the disk buffer. |
| **Check Point** | Log Exporter: `cp_log_export add name bower target-server <ip> target-port 6514 protocol tcp format syslog` with TLS (`--security`/certificate options as documented for your release). | Log Exporter reads the gateway's log files and tracks its position, so it can resume after an outage — stronger than streaming-only senders. | `cp_log_export status`; log server counts in SmartConsole. | Read mode (semi-unified/raw) changes event counts; qualify with the mode you deploy. |

## 10. Troubleshooting

| Symptom | Likely cause | Check | Fix |
|---|---|---|---|
| Events missing after quiet periods; rsyslog logs nothing | Collector closed an idle connection and the sender did not notice | Bower `halfCloses` > 0 with `idleTimeoutSeconds` > 0 | Set `idleTimeoutSeconds: 0`; apply 5.3 or 5.4. |
| rsyslog stalls for ~15 minutes, then `Connection timed out` | Collector's resets are dropped by a firewall/security group | `ss -tnoi` on the sender: `CLOSE-WAIT`, large `Send-Q`, `backoff` rising; `tcpdump` on the collector shows `Flags [R]` leaving, sender never sees it | Section 5.2 egress rule; enable rsyslog `KeepAlive`. |
| `Recv-Q` ≈ 1,566 on rsyslog's TLS socket | TLS 1.3 session tickets from the .NET listener | `ss -tn dport = :6514` on the sender | 5.3 or 5.4. |
| A burst of loss at every collector restart | Sender cannot see the half-close (TLS 1.3 tickets) | Missing ids contiguous around the restart time; `TCPSendBuf error`/`Broken pipe` in rsyslog | 5.3 or 5.4. |
| `tlsHandshakeFailures` rising | Wrong CA, name mismatch, expired certificate, plain TCP to the TLS port, or a TLS health check | `openssl s_client` (section 6) | Fix the certificate or health check. |
| `sendersDenied` rising | Sender address not in `allowedSenders` (often NAT) | Compare with the sender's real address | Fix NAT/source preservation, then the allow-list. |
| `notRouted` rising | App-name/hostname does not match a route | Inspect the sender's template | Fix the route or sender template. |
| `peerResets` rising | A middlebox idle timeout or reset, or the sender closing with unread data | Load balancer idle timeout, firewall logs | Raise idle timeouts, keep keepalive on. |
| `connectionsAccepted` climbing quickly | Reconnect loop (`RebindInterval`, failing sender) | rsyslog configuration | `RebindInterval="0"`. |
| imjournal "messages lost due to rate-limiting" | Input rate limit | rsyslog journal | Size `Ratelimit.Burst`. |
| Sender queue files grow, Bower healthy | TLS failures, allow-list, or a stuck connection | rsyslog journal, Bower counters | See rows above. |

## 11. How we tested this

The interrupted AWS run used separate sender and collector hosts and generated
sequence-labelled synthetic messages. Local results are retained for review; the
complete sanitized evidence and final artifact provenance have not yet been exported.
No Sentinel delivery conclusion follows from this campaign.

## 12. Known limits

Syslog has no application-level acknowledgement: frames in transport buffers can
be lost on a reset or process termination. A passing local run cannot qualify a
different appliance, sender or production configuration. The interrupted campaign
and the remaining long-duration and destination checks must be completed before
production readiness is claimed.

The C# shutdown path now waits for listener loops before taking connection-task
snapshots; deterministic local tests cover a late registration and a cancelled
listener. Live qualification remains outstanding. Its 20-second `StopTimeout` bounds
only graceful drain: the final wait requires listener and sink cancellation to be
cooperative and can last indefinitely. Resources remain alive until those tasks end.
In Rust, aborting async connection tasks does not stop an already-running
`spawn_blocking` sink: it may complete after the source returns, and runtime
shutdown can wait for it. Test the actual sink and host grace period; neither
implementation gives a hard end-to-end shutdown deadline.

`peerResets` is best-effort: C# and Rust can see different error forms through
TLS or the operating system. Rust does not count a reset before the first TLS byte.
A scripted Rust regression covers a connection reset while reading an incomplete
frame, but actual sender and platform behavior still needs validation. A zero
counter does not prove no reset occurred.
Revocation is rechecked before each sink attempt, but cannot undo a sink submission
already in progress; revocation detection also depends on the TLS reload interval.

Before rollout, test senders that open TCP before starting TLS, including their
maximum handshake delay and reconnect behavior. `handshakeStartTimeoutSeconds`
closes a connection that sends no TLS byte within its configured 1–3600-second
window even when established-session `idleTimeoutSeconds` is zero. Validate this
with the actual sender, proxy and load balancer; the candidate is not qualified.

For compatibility with older collectors that reject unknown fields, leave
`handshakeStartTimeoutSeconds` absent when using its 60-second default. A non-default
value requires an updated collector that supports the field; verify every target
collector version before adding it. Guided setup omits the field at its default;
older collectors retain their existing pre-handshake behavior when it is absent.
