# Separate firewall sender qualification setup

For the RELP listener and `omrelp` sender (protocol and transport switches, the pinned
`omrelp` build, the rsyslog 8.2610.0 upgrade and the added scenarios) see
[FIREWALL-RELP.md](FIREWALL-RELP.md).

These scripts configure only the disposable monitoring lab. They do not create
AWS or Azure resources, provision an Azure identity, or establish production
qualification. Use the final reviewed collector and signed pack. Preserve failed
scenario reports and independently query Sentinel before claiming delivery.

## 1. Prepare the three-host stack

Generate and review stack.py; deploy with EnableSyslogSender=true.
The existing Linux and Windows outputs remain; SenderId and SenderIp
identify the separate Amazon Linux nftables/rsyslog source.

Only the sender security group can reach Linux TCP 6514. Windows receives no
new inbound rule. The sender uses SenderProfile, whose S3 read permission is
limited to this run's sender artifact directory. **Apply that role/profile
before uploading any collector credentials.** Expiry terminates all three
instances, but full teardown must also remove the owned stack, bucket contents,
Azure resources and identities.

Use run.py for commands: it checks account 959038055523, exact instance ID,
project, run, role, running state and script platform. Administration is SSM only.

## 2. Build the local artifact directories

Create an owner-only staging root outside the repository:

~~~text
<staging>/qualification/<RunId>/collector/
<staging>/qualification/<RunId>/sender/
~~~

The scripts download only from the corresponding
`artifacts/qualification/<RunId>/<role>/` prefix in the run's bucket.
Do not place tokens, private keys or environment files in Git, SSM command text,
terminal output or evidence bundles.

Each role needs manifest.json with **exactly** its listed files:

| Collector file | Required content |
|---|---|
| collector.tar.gz | Final self-contained Linux x64 publish output under one collector/ directory; includes collector/Bower.Collector. Only regular files/directories; no links or traversal. At most 512 MiB compressed / 1 GiB expanded. |
| sentinel.env | Destination-only environment file, shape below; at most 64 KiB. |
| ingest.pem | Azure application's certificate and private key in the format accepted by AZURE_CLIENT_CERTIFICATE_PATH; at most 64 KiB. |
| ingest-token | Bounded local collector API token, at most 4 KiB. |
| syslog-reliability.bowerpack | Pack built and tested from lab/aws/packs/syslog-reliability, signed by the supplied trusted key; at most 16 MiB. |
| pack-signing.pub.pem | The pack-signing public key only; at most 64 KiB. |
| collector-health.yaml | Reviewed examples/policies/collector-health/collector-health.yaml; at most 64 KiB. |
| server.pem, server-key.pem | Server certificate/private key; SAN collector-a.bower.lab, server-auth purpose, trusted by ca.pem; each at most 64 KiB. |
| ca.pem | Lab syslog CA certificate, at most 64 KiB. Never upload the CA private key. |
| syslog-host.py | Reviewed helper from lab/aws/scripts/syslog-host.py, at most 1 MiB. |

| Sender file | Required content |
|---|---|
| sender-r.pem, sender-r-key.pem | Client-auth certificate and matching private key, signed by the same syslog CA; each at most 64 KiB. |
| ca.pem | Same lab syslog CA certificate, at most 64 KiB. |
| syslog-host.py | The same reviewed helper installed on the collector. |

Do not include the original configure-collector artifacts: that helper selects
ama-spool. Do not grant the sender access to the old exchange/* prefix.
The sender setup reuses the existing recommended configuration function while
serving its public-certificate fetches from the already verified local stage.

The sentinel.env file accepts only the following destination keys. Supply real
IDs and endpoint locally, never through chat or SSM secret arguments:

~~~dotenv
BOWER_OUTPUT=azure-logs-ingestion
BOWER_DCE_ENDPOINT=https://<the-run-dce-endpoint>
BOWER_DCR_ID=dcr-<32-hex-immutable-id>
BOWER_STREAM_NAME=Custom-BowerSecurity
BOWER_AZURE_CREDENTIAL=environment
AZURE_TENANT_ID=<target-tenant-uuid>
AZURE_CLIENT_ID=<ingestion-application-uuid>
AZURE_CLIENT_CERTIFICATE_PATH=/etc/bower/secrets/ingest.pem
~~~

BOWER_STREAM_NAME defaults to Custom-BowerSecurity.
AZURE_CLIENT_SEND_CERTIFICATE_CHAIN is the only additional accepted key.
An existing destination value that differs from this file causes setup to fail;
the setup never silently redirects an existing collector or switches to a spool.

Manifest shape:

~~~json
{
  "schemaVersion": 1,
  "runId": "bower-ws6-YYYYMMDD-HHMMSS",
  "role": "collector",
  "files": {
    "collector.tar.gz": {
      "sha256": "<64 lowercase hexadecimal characters>",
      "bytes": 123456
    }
  }
}
~~~

The abbreviated example shows one entry only. Include every required file for
that role, with its exact byte count and SHA-256; omit manifest.json itself.
No additional names are accepted. The sender manifest uses role "sender".
Keep the manifest at most 64 KiB. Calculate a SHA-256 of the completed manifest
and pass that public digest as BOWER_ARTIFACT_MANIFEST_SHA256.

Upload the staging root with the existing ownership-checking uploader:

~~~bash
bash lab/aws/monitoring/upload.sh <owned-state.json> <staging>
~~~

It validates account and bucket run tags and uploads to artifacts/ with
server-side encryption. Keep the local staging directory owner-only.

## 3. Configure the collector, then the sender

Both hosts must be the fresh Amazon Linux 2023 hosts from this owned run, with
SSM, AWS CLI, Python 3, OpenSSL and package-repository access. The scripts verify
the complete manifest and every artifact before using them. Private staging is
removed on success or failure. Errors report safe categories, not credentials.

~~~bash
python3 lab/aws/monitoring/run.py Linux \
  lab/aws/monitoring/setup-firewall-collector.sh \
  --state <owned-state.json> --timeout 900 \
  --env BOWER_ARTIFACT_MANIFEST_SHA256=<collector-manifest-sha256> \
  --env BOWER_SYSLOG_SENDER_IP=<SenderIp>

python3 lab/aws/monitoring/run.py Sender \
  lab/aws/monitoring/setup-firewall-sender.sh \
  --state <owned-state.json> --timeout 900 \
  --env BOWER_ARTIFACT_MANIFEST_SHA256=<sender-manifest-sha256> \
  --env BOWER_SYSLOG_COLLECTOR_IP=<LinuxIp>
~~~

All arguments above are public metadata. The scripts fetch the token, TLS keys,
Azure certificate and environment file on-host through the instance role.

The collector runs as bower, installs the signed pack and collector-health
policy, keeps the queue at /var/lib/bower/queue.db, and exposes only listener
a13 on TCP 6514 to the exact sender IP. Its local HTTP API remains loopback.
Established idle timeout is zero; handshake-start and frame limits are 60 seconds.
The existing reviewed OpenSSL helper disables TLS 1.3 session tickets for
bower.service only. This avoids unread ticket bytes obscuring a half-close;
the actual negotiated protocol and reconnect behavior still require the campaign.

The sender reuses the reviewed recommended profile unchanged:

- One persistent, certificate/name-verified TLS action to collector-a.bower.lab,
  octet-counted RFC 5424, port 6514.
- Rebind zero, resend on reconnect, keepalive 60 seconds / 10 seconds / six probes.
- Disk-assisted queue: 200,000 messages, 150,000/100,000 watermarks, 2 GiB disk
  limit, 86,400,000 ms enqueue timeout for action and main queues, save on shutdown,
  discard severity eight, retry forever.
- queue.syncQueueFiles="off" and checkpoint interval 100, as in the recommended
  candidate. This is not a claim of power-loss durability.
- imjournal rate bound 200,000 messages per 600 seconds.
- The reusable bower-client namespace and two nftables counters feed
  syslog-plan.py generation and native accounting.

This qualification additionally sets bounded persistent journald storage:
1 GiB disk / 256 MiB runtime, with a 200,000-per-30-second rate bound. Record that
configuration as part of the tested sender profile. The helper's rsyslog work
directory must be /var/lib/rsyslog; setup rejects another location.

Setup outputs only hashes, service/configuration metadata and counters.
destinationQueryVerified/deliveryQualified remain false intentionally.
A healthy local process does not establish Sentinel delivery.

## 4. Run and reconcile

Use syslog-plan.py with the same reviewed helper source. Run only one scenario
at a time; its idle schedule must be free of unrelated syslog events. Preserve
generator result JSON, native counter deltas, queue identity accounting and
actual fault-unit/reboot evidence.

The old helper's deliveredToSpool label describes local delivery state even
when this setup uses Sentinel. Do not use it as destination proof. Independently
query Sentinel for the exact expected IDs from expectedBlocks, compare complete
identity sets, and record missing/extra/duplicate counts and set hashes. Reject
partial or oversized query responses. Qualify only the exact artifacts, TLS
profile, sender configuration and host versions exercised.

Finish with the monitoring README's owned-resource cleanup and independent
absence checks. Remove the local private staging material after evidence export.


The exact queue export, native counter matching and independent verifier query
procedure is in [FIREWALL-RECONCILIATION.md](FIREWALL-RECONCILIATION.md). Its
`a-destination-outage` plan accounts for 36,000 events during a one-hour ingestion
outage; installing and proving the scoped destination block remains a separate,
explicit requirement.

For a reviewed native CI candidate change during the same session, use
[CANDIDATE-UPDATE.md](CANDIDATE-UPDATE.md) to replace only the two native files
while retaining the existing configuration, credentials, queue and bookmarks.
