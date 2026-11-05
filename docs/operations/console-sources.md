# Add a security source

Open **Sources** in the console. Pick a source, choose an approved collector, and
fill in the settings. The form explains what you need and gives a suggested fix
for each invalid value. **Check settings** validates the configuration on the
management server and shows the files and sender instructions it will generate.

The guided forms currently cover syslog, Windows Event Log, security-selected
files, Docker containers, AWS security events, Google Cloud security events, the
AMA companion output and application events through HTTP or the SDK. Windows
setup selects the shipped Security 4625 network-logon parser; it does not enable
arbitrary event collection or configure WEC forwarding. A SQL Server hosted integration, journald,
Kubernetes and Kafka need their corresponding runtime integrations before they
can be offered here.

## Security-selected files

The **Security-selected file** form tails one named file on the collector host
and routes every line to one signed pack parser. Lines the parser does not select
are dropped; this is not log shipping. The form generates `file-source.json`
(`BOWER_FILE_CONFIG`, kind `FileTailSource`) and a source expectation for the
parser's application. For the collector side (path guards, the record a parser sees, least privilege and
rotation), see the [file tail source guide](../deployment/file-tail-source.md).

- **Linux paths only.** The only offered parser reads Linux `auth.log`, so the
  form refuses Windows paths and generates Linux install steps only. A Windows
  file parser, and Windows paths with it, would be a follow-up.
- **One file, one parser.** Enter the exact absolute path of one file and the
  narrowest **allowed directory** that holds it. Wildcards, `..`, `.` and empty
  segments are refused, the file must be inside the allowed directory, and the
  whole disk (`/`) is refused as the allowed directory.
- **Refused directories.** `/proc`, `/sys`, `/dev`, systemd credentials
  (`/run/credentials`, where `LoadCredential` puts the privacy HMAC key) and
  Bower's own directories (`/etc/bower` for configuration and secrets,
  `/var/lib/bower` for the queue and enrolment credential, `/var/spool/bower`,
  and `/var/log/bower`, the service's log directory) are refused both as the
  allowed directory and for the file. A parent such as `/var`, `/etc` or `/run`
  is accepted as the allowed directory only while the file itself is outside
  every refused directory. An allowed directory or file under `/home`, `/root`
  or `/run/user` is allowed with a warning because `bower.service` hides them
  (`ProtectHome=true`). These checks compare path text only; `/var/run` is
  treated as `/run`, because it is a link to it on standard Linux. The server
  cannot see the host's links, so an allowed directory that is a link into a
  refused directory (for example `/opt/x` linked to `/etc/bower`) passes the
  form. Keeping such links out of allowed directories is the host
  administrator's responsibility.
- **Symbolic links.** The collector refuses symbolic links: the file and every
  directory between the allowed directory and the file must be real; the allowed
  directory itself may be a link. The form never generates `allowSymlink`. The
  form, plan and this guide say so.
- **Signed parsers only.** The parser is a choice of shipped signed pack parsers
  written for file tail records, currently `linux-authlog-ssh` parser 0 (sshd
  failures from `auth.log` text lines, application `linux-sshd`). Parsers for
  other sources read different fields and are not offered. Any other pack or
  parser is refused, and there is no catch-all parser. The collector still
  refuses to start if the chosen pack is not loaded and signed by a trusted key.
- **Bounded lines.** Choose where reading starts the first time (new lines only,
  or existing lines first) and the longest line, 256 to 30720 bytes (pack parsers
  read records of at most 32 KiB). Longer lines are dropped and counted, never
  cut and parsed. Poll interval, batch limits and `rotationGracePolls` stay at
  the collector defaults.
- **No duplicates.** An input name or file already used by another file request
  waiting for approval on the same collector is refused. As in the collector, a
  file counts as the same when it differs only in ASCII letter case or is the
  other's rotated file (`auth.log` and `auth.log.1`). The server checks this
  inside the transaction that stores the request, so simultaneous identical
  submissions store one request and refuse the rest, and checks it again when a
  request is approved. Management cannot see what is installed, so every approved
  request that shares the name or file gets an advisory warning. For the latest
  such approval the warning says the new request replaces it; remove the old input
  when merging. An approval that a later approval already replaced is reported as
  possibly still installed: check the collector's `file-source.json`. Requests
  are not marked as replaced. One request adds one input; to add more, ask again
  and merge the approved input and allowed directory into the collector's
  existing `file-source.json` lists.
- **Checking it works.** Every file request for this parser reports as the same
  application (`linux-sshd/production`), and so can another file or a syslog
  listener using the same pack. The heartbeat carries no per-input file tail
  metadata, so **Check it works** never turns a file request green on its own
  (this follows the request's source type, not only its stored plan). When the
  collector already reports this pack's events, the form says the request cannot
  be verified individually.
  After approval it shows **Pack events seen, input not individually verified**
  once the collector reports a new `linux-sshd/production` event, and asks you to
  confirm the request's input in the collector's `GET /v1/status` (`fileTail`,
  running with queued lines).

The generated configuration holds paths and the parser route only, never
credentials. The request detail, which anyone with the View role can open, shows
the requested values and generated files, including the file path. Status pages
(the request list and its checks) show the request state and heartbeat metadata,
not the file path or file contents.

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
Security channel permissions for the service identity. Generated file
configuration requires the chosen signed pack and read access to the file for
the collector's service account.

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
