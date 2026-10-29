# Add a security source

Open **Sources** in the console. Pick a source, choose an approved collector, and
fill in the settings. The form explains what you need and gives a suggested fix
for each invalid value. **Check settings** validates the configuration on the
management server and shows the files and sender instructions it will generate.

The guided forms currently cover syslog, Windows Event Log, Docker containers,
AWS security events, Google Cloud security events, the AMA companion output and
application events through HTTP or the SDK. Windows setup selects the shipped
Security 4625 network-logon parser; it does not enable arbitrary event collection
or configure WEC forwarding. A SQL Server hosted integration, journald,
Kubernetes and Kafka need their corresponding runtime integrations before they
can be offered here.

## Review, approve, install, check

1. Review the generated settings and the **example event after redaction**. This
   is a synthetic example, not a captured event or evidence of arrival. The server
   applies the assigned privacy profile and built-in rules before returning it.
2. Enter a reason and choose **Ask for approval**. This stores the exact plan and
   its content hash. It does not change the collector.
3. A different person with Approver or Administrator access reviews the request
   on **Approvals**, including the files and sender instructions, and records a
   reason for approving or rejecting it. The requester cannot review their own
   request, even if they are an administrator.
4. Once approved, an operator installs or merges the files and configures the
   sender. Keep existing sources when merging generated configuration. The cloud
   infrastructure snippets create plans only; review and deploy those separately.
5. Open **Check it works**. The management server checks the collector's next
   heartbeat for the expected source and an accepted event after approval.
   Missing, old or unhealthy reports show what to check next. Output health is
   reported separately for AMA. These checks never prove Sentinel delivery;
   use the [onboarding canary](console-onboarding.md) to check destination arrival.

Waiting requests refresh automatically. A failed refresh retains the last check
with a warning. You can also check again manually. Viewers can read prerequisites,
requests and their progress but cannot submit or download signed configuration.

## Secrets and trust

Enter the **location** of a credential, never the credential itself: an absolute
file path on the component's host, or a Key Vault secret URL where the form
explicitly permits one. These references are not read by the management server.
It does not connect to a user-supplied address to test connectivity. Source
checks use authenticated heartbeat metadata, avoiding a new outbound network
access path from the management API.

A source request is a configuration plan, not a signed content pack. Collectors
still refuse unsigned packs and packs signed by an untrusted key. Generated
Windows configuration requires the signed `windows-security-logon` pack and
Security channel permissions for the service identity.

For signed downloads, configure `BOWER_MANAGEMENT_SOURCE_SIGNING_KEY_FILE` on the
management API to an ECDSA P-256 private key file with restricted permissions.
The server fails startup if a configured file is invalid. If no key is configured,
approvals still work but signed downloads return 503 with an explanatory message.
The private key never leaves the server.

An approved download uses kind `bower.source-setup/v1`. The signature covers
request ID, collector ID, source type, content hash, files, variables, sender
snippets, verification settings and approval time, in canonical JSON. Verify
using a separately trusted public key and `SourceSetupSigner.SignedBytes` with
`DetachedSigner.Verify`; the download is not applied automatically. A signature
alone does not enrol a collector or bypass its local trust policy.

## API and audit

| Endpoint | Required policy |
| --- | --- |
| `GET /api/sources/types` | View |
| `POST /api/sources/plan` | Operate |
| `GET /api/sources/requests` and `/{id}` | View |
| `POST /api/sources/requests` | Operate |
| `POST /api/sources/requests/{id}/approve` or `/reject` | Approve; different requester |
| `GET /api/sources/requests/{id}/signed` | Operate; request approved |

Requests and decisions write `source-setup.requested`, `.approved` or `.rejected`
audit rows in the same transaction as the change. Self-review attempts write
`.self-review-refused`. Issuing a signed configuration records
`source-setup.signed-config-issued`.

The server limits plan/submission bodies to 64 KiB, rejects unknown fields and
inline credential material, bounds lists to 64 entries, and allows at most 16
pending requests per collector. The request list returns the newest 200 requests;
older requests remain accessible by ID. Configuration can contain only the
validated settings supported by its source type.

Issue #99 remains open for the live first-event preview through tap and additional
source integrations. The synthetic preview and heartbeat check are explicitly
labelled; they are not substitutes for captured-event or destination evidence.
