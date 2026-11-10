# Syslog output for Azure Monitor Agent

`BOWER_OUTPUT=syslog` hands each redacted, policy-approved envelope to the local syslog
daemon on a Linux server, for Azure Monitor Agent (AMA) to collect
(`Bower.Output.Syslog`). The steps are in
[Quick start: Azure Monitor Agent](../getting-started/azure-monitor-agent.md); this page is
the reference.

It is not a network syslog sink. It writes only to a local Unix socket, in a format only the
matching collection rule
([`deploy/bicep/ama-syslog-dcr.bicep`](https://github.com/jusso-dev/Bower/blob/main/deploy/bicep/ama-syslog-dcr.bicep))
reads. To receive syslog from other systems, see the [syslog source](syslog-source.md), which
works in the other direction. The pipeline builder's `syslog` output type is this same output.

The whole path was run once with real Azure Monitor Agents on 10-11-2026 (agent 1.45.1, on
Oracle Linux 9.8 with SELinux enforcing and Ubuntu 24.04, both from the Bower packages): see
[#249](https://github.com/jusso-dev/Bower/issues/249). Facts on this page marked "live" come
from that run. Facts marked "tested" come from local containers with journald, rsyslog and a
stand-in for the agent.

## Which Azure path

| | `azure-logs-ingestion` | `syslog` (this page) | `ama-spool` |
|---|---|---|---|
| Credential on the server | Managed identity or workload identity with the Monitoring Metrics Publisher role on the rule | None (the agent's managed identity uploads) | None (the agent uploads) |
| Delivery confirmation | Each upload is confirmed by the API; refusals are dead-lettered by name | Only that the local daemon took the datagram; arrival is proved only by a Sentinel query | Only that the file was written; arrival is proved only by a Sentinel query |
| Largest event | 1,000,000 bytes per record (the API limit, checked before upload) | 5,730 bytes of envelope JSON at the default | Set by the agent's custom text log collection |
| Collection rule | `main.bicep` | `ama-syslog-dcr.bicep` (ready-made) | Write your own custom text log rule |
| Platforms | Linux, Windows, containers | Linux only (refused at start-up on Windows) | Wherever the agent collects text files |
| Who can write rows to `BowerSecurity_CL` | Only Bower's identity | Any local account, unless the [origin filter](#who-can-write-to-the-table) is installed (then root and the `bower` account) | Any account that can write the spool's `ready` directory |

Use `azure-logs-ingestion` where local accounts are not trusted, where you need proof of
arrival per upload, or for events larger than 5,730 bytes.

## What is written

One datagram per event to `BOWER_SYSLOG_OUTPUT_SOCKET`, in the local format `syslog(3)` uses:

```text
<165>Nov 10 01:02:03 bower: bower-b64:eyJzY2hlbWFWZXJzaW9uIjoiMS4wLjAiLCJldmVudElkIjoi...
```

- `<165>` is facility `local4` (20) times 8 plus severity `notice` (5). The facility follows
  `BOWER_SYSLOG_OUTPUT_FACILITY`; the severity is always `notice`.
- The timestamp keeps the format well formed; the daemon stamps its own receive time.
- The tag is `bower`. The rule keeps only rows whose process name is `bower`.
- After `bower-b64:` comes the compact envelope JSON in standard base64, with nothing after it.
  Azure Monitor removes semicolons from syslog messages during ingestion, and syslog has no
  room for line breaks, so the envelope is encoded.

A datagram is all or nothing: an event is never split or truncated by Bower.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `BOWER_OUTPUT` | `none` | `syslog` selects this output. Refused at start-up on Windows. |
| `BOWER_SYSLOG_OUTPUT_SOCKET` | `/dev/log` | The daemon's datagram socket. Absolute path, at most 107 bytes. |
| `BOWER_SYSLOG_OUTPUT_FACILITY` | `local4` | `local0` to `local7`; the numbers 16 to 23 are accepted as aliases. Anything else is refused at start-up. Must match the rule's `facility` parameter. |
| `BOWER_SYSLOG_OUTPUT_MAX_BYTES` | `7680` | The whole datagram, header included, 1024 to 65507. Keep it at least 512 below rsyslog's `MaxMessageSize` (see [Size](#size)). |
| `BOWER_SYSLOG_OUTPUT_BUSY_WAIT_SECONDS` | `2` | How long one datagram may wait for the daemon to make room before the rest of the batch is retried. 1 to 30, and below `BOWER_DELIVERY_TIMEOUT_SECONDS`. |

At start-up the collector tries the socket once and logs one warning if it cannot connect. It
still starts: events wait in the durable queue. To check the socket yourself:

```bash
bower doctor --syslog-socket /dev/log   # exists, is a socket, accepts a connection
```

The container images have no `/dev/log` unless you bind-mount it.

## Size

rsyslog's default `MaxMessageSize` is 8 KiB. Tested on Rocky Linux 9 and Debian 12 with stock
rsyslog and the agent's documented forwarding template, sending to a local TCP listener:

| Datagram from Bower | Forwarded line | Result |
|---|---|---|
| 7,680 bytes (the default limit) | 7,696 characters (Rocky), 7,691 (Debian) | whole, decodes |
| 8,190 bytes (the old default) | 8,096 characters | cut short; rsyslog logs `message too long (8162) with configured size 8096` |

Live, through the real agent into `BowerSecurity_CL` (raw datagrams of exact sizes):

| Datagram | Oracle Linux 9.8 (imjournal) | Ubuntu 24.04 (imuxsock) |
|---|---|---|
| 7,678 bytes | row arrives and decodes | row arrives and decodes |
| 8,058 bytes | row arrives | row arrives |
| 8,078 bytes | no row | row arrives |
| 8,090 bytes and over | no row | no row |

The cap is rsyslog's 8,096-character line, header included, and the header differs by
distribution (Oracle Linux's is longer). Bower's default of 7,680 is under both with room to
spare. The agent added no cap of its own below rsyslog's.
The usable size at the default is **5,730 bytes of envelope JSON**: 7,680 minus the 38-byte
header leaves 7,642 base64 characters, rounded down to whole groups of four and times 3/4.
That leaves 444 characters for the header rsyslog or the agent writes in front of the message.
A larger envelope is refused with `payload-too-large` and dead-lettered.

If you raise rsyslog's limit (`global(maxMessageSize="32k")` or `$MaxMessageSize 32k` at the
top of `/etc/rsyslog.conf`, before any input), you can raise `BOWER_SYSLOG_OUTPUT_MAX_BYTES`,
keeping it at least 512 below. The agent did not truncate below rsyslog's cap in the live run;
messages over 8,096 characters were not tested with a raised rsyslog limit.
Compression is not possible: the rule's transform language has no decompression function
([supported functions](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-transformations-kql)).

`collector_health` records travel this output too. Their size grows with the number of
sources listed (at most 25 of each kind). At the default limit a record fits with up to three
overdue sources plus syslog listeners; from four it is refused with `payload-too-large`
(measured, #230).

## Rate limits

Three local limits can drop messages in a burst. All are on the server, before the agent.

| Limit | Default | Tested burst, default | Fix (tested) |
|---|---|---|---|
| journald, per service | 10,000 per 30 s, scaled up by free disk space | 150,000 sent in 1.5 s: 32,500 kept (Rocky), 37,500 (Debian) | [`bower-syslog-ratelimit.conf`](https://github.com/jusso-dev/Bower/blob/main/examples/cloud-agents/azure/bower-syslog-ratelimit.conf) in `/etc/systemd/system/bower.service.d/`: 150,000 kept on both |
| rsyslog `imjournal` (RHEL family) | 20,000 per 600 s for the whole host, about 33 per second sustained | 19,988 of 150,000 forwarded | [`rsyslog-imjournal-ratelimit.conf`](https://github.com/jusso-dev/Bower/blob/main/examples/cloud-agents/azure/rsyslog-imjournal-ratelimit.conf): 150,000 forwarded |
| journald to rsyslog socket (Debian family) | kernel queue of 512 datagrams | 149,529 to 149,830 of 150,000 forwarded | [`sysctl-bower-syslog.conf`](https://github.com/jusso-dev/Bower/blob/main/examples/cloud-agents/azure/sysctl-bower-syslog.conf): 150,000 forwarded |

rsyslog's `imuxsock` (the Debian family input) does not rate-limit by default. If a host has
turned it on, see
[`rsyslog-imuxsock-ratelimit.conf`](https://github.com/jusso-dev/Bower/blob/main/examples/cloud-agents/azure/rsyslog-imuxsock-ratelimit.conf).

Size each burst as your peak events per second times the interval, with headroom. These
lines in the journal show a limit was hit:

```text
imjournal from <host:bower>: begin to drop messages due to rate-limiting
imuxsock[pid: N, name: ...] from <host:bower>: begin to drop messages due to rate-limiting
Forwarding to syslog missed N messages.
```

and journald writes `Suppressed N messages from bower.service` when its own limit applies.

Which input your server uses: RHEL, Rocky and AlmaLinux 9 read the journal with `imjournal`
(`module(load="imjournal"` in `/etc/rsyslog.conf`). Debian 12 and Ubuntu read journald's
forwarded copy with `imuxsock`. rsyslog may not be installed at all (it was absent from the
Rocky 9 and Debian 12 container images used here): check with `systemctl is-active rsyslog`.

## Failures

| Code | Cause | What happens | What to do |
|---|---|---|---|
| `destination-syslog-unavailable` | Socket missing or refusing | Retried every 30 s | Start journald or rsyslog; check `BOWER_SYSLOG_OUTPUT_SOCKET` |
| `destination-syslog-busy` | The daemon took nothing during the busy wait | Retried | Usually a burst; check the rate limits above |
| `destination-syslog-access-denied` | Socket permissions | Retried | Fix the permission on the socket |
| `destination-syslog-cancelled` | Shutdown or delivery timeout part-way | Events already sent are acknowledged; only the rest are retried | None |
| `payload-too-large` | Datagram over `BOWER_SYSLOG_OUTPUT_MAX_BYTES` | Dead-lettered | See [Size](#size); use `azure-logs-ingestion` for large events |
| `payload-invalid-json`, `payload-event-id-mismatch` | Queued payload is not a valid envelope | Dead-lettered | Report it |
| `preflight-time-generated-missing`, `preflight-type-mismatch`, `preflight-field-too-large`, `preflight-record-too-large` | The same checks as the Logs Ingestion output | Dead-lettered | See [Azure ingestion API](logs-ingestion-api.md) |

The newest code is `deliveryActivity.lastFailureCode` in `GET /v1/status` (send the ingest
token if one is set). Dead letters:

```bash
sudo -u bower bower queue dead-letters --database /var/lib/bower/queue.db
```

## What "delivered" means

Bower counts an event delivered when the local daemon accepted the datagram, and then removes
it from its queue. The later hops do not report back:

| Hop | How an event can be lost | Trace |
|---|---|---|
| journald | Rate limit; crash or power loss before the journal is synced; journal kept only in memory (`Storage=volatile`, or no `/var/log/journal`) | `Suppressed N messages` in the journal, at best |
| rsyslog | Input rate limit; journald's forward to it (Debian family); a line longer than `MaxMessageSize` is cut | A line in the journal (see [Rate limits](#rate-limits)) |
| Azure Monitor Agent | Its queue (rsyslog's `omfwd` queue, 1 GB on disk in the agent's file) full during a long outage | Agent log |
| Collection rule transform | A message that does not decode (cut short, extra characters, other `schemaVersion`) | **None**: no row, no error |

Live (#249), counted in `BowerSecurity_CL` with 400 events sent per phase on each host:
restarting rsyslog, journald or the agent mid-stream lost nothing, and stopping the agent for
ten minutes lost nothing either (rsyslog's disk-assisted queue held the events and sent them
when it came back). Each phase arrived 400 of 400; one event arrived twice, which the
deduplication below removes. A deliberate loss (journal emptied while rsyslog was stopped)
lost every event in it, with no error anywhere.

So only a Sentinel query proves arrival. Three queries help:

- [`delivery-reconciliation.kql`](https://github.com/jusso-dev/Bower/blob/main/deploy/sentinel/monitoring/queries/delivery-reconciliation.kql)
  compares the events each collector's `collector_health` records say it queued with the rows
  that arrived for that `CollectorId`, and returns collectors with a gap. Live: with health
  records every 60 s and 300 events per host it reported 304 queued against 306 arrived
  (health records counted on both sides), so it does not raise a false alarm. It did not catch
  a deliberate loss of 100 events: the loss happened inside a short window, and a single
  `collector_health` record lost with them hides the gap. See
  [`delivery-sequence-gaps.kql`](https://github.com/jusso-dev/Bower/blob/main/deploy/sentinel/monitoring/queries/delivery-sequence-gaps.kql),
  which caught that loss.
- [`delivery-sequence-gaps.kql`](https://github.com/jusso-dev/Bower/blob/main/deploy/sentinel/monitoring/queries/delivery-sequence-gaps.kql)
  returns collectors whose `collector_health` sequence numbers have a gap. Live, it caught the
  deliberate loss above, which the reconciliation query missed because the record covering
  those events was lost with them.
- Delivery is at least once (a retried batch can send an event twice), so deduplicate on
  `EventId`:

    ```kusto
    BowerSecurity_CL
    | summarize arg_max(TimeGenerated, *) by EventId
    ```

Use `azure-logs-ingestion` for anything that needs proof of arrival per event.

## Who can write to the table

Every local account can write to `/dev/log`, and the sender chooses the tag, so on this path
any local process can put a row into `BowerSecurity_CL` with any collector, actor or policy
fields. That row never passes through Bower's policy or redaction. The rule's `ProcessName ==
"bower"` check stops accidents only.

An rsyslog filter on a field the sender cannot set closes most of this. Install it as
`/etc/rsyslog.d/09-bower-origin.conf`, so it runs before the agent's forward:

- RHEL family (`imjournal`):
  [`rsyslog-bower-origin-imjournal.conf`](https://github.com/jusso-dev/Bower/blob/main/examples/cloud-agents/azure/rsyslog-bower-origin-imjournal.conf)
  keeps only messages journald recorded from `bower.service`.
- Debian family (`imuxsock`):
  [`rsyslog-bower-origin-imuxsock.conf`](https://github.com/jusso-dev/Bower/blob/main/examples/cloud-agents/azure/rsyslog-bower-origin-imuxsock.conf)
  keeps only messages from the `bower` account's user ID (needs `SysSock.Annotate` and
  `SysSock.ParseTrusted`, see the file). The file says `999`; put in the real ID, or every
  Bower event is dropped too (it was 995 on the Ubuntu 24.04 lab VM):

    ```bash
    sed "s/\$!uid == \"999\"/\$!uid == \"$(id -u bower)\"/" rsyslog-bower-origin-imuxsock.conf \
      | sudo tee /etc/rsyslog.d/09-bower-origin.conf >/dev/null
    ```

Tested on both: 50 messages from `bower.service` forwarded, 50 forged by another account and
5 sent by root outside the unit stopped, ordinary messages unaffected. Without the filter all
50 forged messages were forwarded. Live with the real agent (#249), counted in
`BowerSecurity_CL`: 20 of 20 genuine events arrived on each host, and 0 of 20 forged by
`nobody` and 0 of 5 sent by root. Before the filter, a row forged by `nobody` arrived with the
`CollectorId` it chose. Root can still forge, and anything running as `bower` can. A forged
message stays in the journal.

## What stays on the server

Besides the forward to the agent, the host keeps its own copies:

| Copy | Where | Kept for | Readable by (tested defaults) |
|---|---|---|---|
| Journal | `/var/log/journal` (or `/run/log/journal` when volatile) | Until journald's size limits (`SystemMaxUse=`, `MaxRetentionSec=`) rotate it out | root, `systemd-journal` group (and often `adm`, `wheel`) |
| Local file | `/var/log/messages` (RHEL family), `/var/log/syslog` (Debian, Ubuntu) | Four weekly rotations by default | root only (Rocky); `adm` group (Debian) |
| Agent queue | rsyslog work directory | Until the agent is reachable | root |

Each copy is about a third larger than the JSON (base64). The events are redacted, but they
are still security records, and Bower's retention settings do not reach them.

[`rsyslog-bower-local-copies.conf`](https://github.com/jusso-dev/Bower/blob/main/examples/cloud-agents/azure/rsyslog-bower-local-copies.conf),
installed as `/etc/rsyslog.d/11-bower-local-copies.conf`, stops Bower messages after the
agent's forward so they are not written to the local file. Tested on both families: 50
forwarded, 0 in the local file, ordinary messages still written. It relies on sorting after
the agent's file, `10-azuremonitoragent-omfwd.conf`
([Microsoft](https://learn.microsoft.com/en-us/azure/azure-monitor/vm/data-collection-syslog)).
The journal copy cannot be avoided while journald owns `/dev/log`; limit it with journald's
size settings.

## The collection rule

`ama-syslog-dcr.bicep` collects the Bower facility at `notice` and above, keeps only rows with
`ProcessName == "bower"` whose message is exactly `bower-b64:` followed by base64 (apart from
surrounding white space), decodes them and maps them onto the same columns as `main.bicep`.
It accepts only `schemaVersion` `1.0.0`. When the envelope version changes, deploy the new
rule first, then upgrade the collectors.

| Parameter | Default | Meaning |
|---|---|---|
| `workspaceName` | (required) | The workspace that already holds `BowerSecurity_CL` from `main.bicep`. |
| `workspaceResourceGroup` | the deployment's resource group | Where that workspace is. |
| `location` | the resource group's region | The rule must be in the workspace's region ([Microsoft](https://learn.microsoft.com/en-us/azure/azure-monitor/vm/data-collection)). Pass `location=<workspace region>` when the resource group is in another region. |
| `namePrefix` | `bower` | The rule is named `<namePrefix>-ama-syslog-dcr`. |
| `facility` | `local4` | Must match `BOWER_SYSLOG_OUTPUT_FACILITY`. |
| `dataCollectionEndpointId` | empty | Only for Private Link; see below. |
| `tags` | `{}` | Tags for the rule. |

**Private Link.** Microsoft's guidance for agents behind Azure Monitor Private Link Scope is
that each machine is associated with a data collection endpoint through an association named
`configurationAccessEndpoint`, and the endpoint is added to the Private Link Scope
([Microsoft](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/private-link-vm-kubernetes)).
That is a step per machine, separate from the rule. Microsoft also says a rule that uses an
endpoint must have that endpoint in the scope
([Microsoft](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-endpoint-overview)).
Whether this rule also needs `dataCollectionEndpointId` set is not stated there. Live, the
template accepts an endpoint (`what-if` shows only that property changing), and without Private
Link the agents uploaded with no endpoint at all. Behind Private Link it has not been tested.
Without Private Link, leave both out.

A second rule that collects the same facility into the `Syslog` table stores each event again
there, as base64 (live: the same event arrived in both tables on both hosts, as `local4`,
`notice`). To see whether that is happening:

```kusto
Syslog
| where SyslogMessage has "bower-b64:"
| summarize Rows = count() by Computer, Facility
```

## Relay

A relay collector can use `BOWER_OUTPUT=syslog` as its own output: the relay stores each
downstream envelope in its own queue and delivers it through the configured output, and the
settings do not forbid this one (read from the code, not tested). Everything on this page then
applies to the relay host, including the trust boundary.

## Limits

- Linux with rsyslog only. syslog-ng also reads `/dev/log`, but these limits and snippets are
  for rsyslog.
- Live on Oracle Linux 9.8 with SELinux enforcing, agent 1.45.1 wrote the TCP file
  (`10-azuremonitoragent-omfwd.conf`, port 28330), not the Unix-socket variant
  (`10-azuremonitoragent.conf`). Hosts where it uses the socket file were not tested.
- Live on two distributions and one agent version, once. Private Link, syslog-ng, Arc
  machines and other agent versions were not run.
