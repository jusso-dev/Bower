# Microsoft cloud sources: security

This page covers the Microsoft cloud pull source (`Bower.Source.MicrosoftCloud`,
`BOWER_MICROSOFT_CONFIG`): what it may access, how tokens and checkpoints are handled, what
personal information each event type carries, and how to switch a source off. Setup is in
[Microsoft cloud sources](../deployment/microsoft-cloud-sources.md).

## Trust boundary

The collector makes outbound HTTPS requests to Microsoft APIs with a bearer token for one
tenant. This is a new outbound trust boundary: API responses are untrusted input, and the
token must never reach anything other than the API it was issued for.

| Control | How |
|---|---|
| Token destination | Each source kind allow-lists exactly one host (`graph.microsoft.com` for Intune). Requests, `@odata.nextLink` and stored page links must be HTTPS on that host at the default port with no user info, or the poll fails with `mscloud-host-refused` before any request is sent. A refused next link is never stored in the cursor. |
| Redirects | Never followed. A 3xx fails the poll (`mscloud-redirect-refused`). |
| Response size | 16 MiB per response and JSON depth 32; larger fails with `mscloud-response-too-large`. |
| Record size | Values clipped to the envelope limit of the field they map to (128 for actions and target types, 256 for labels and identities), with a per-record budget that keeps the escaped record below the pack parser's 32 KiB limit. IP addresses are canonicalised (a `:port` is stripped) or left out, so an odd address never drops the event. |
| Failure reporting | Status, logs and exceptions carry a stable code and the HTTP status only. Response bodies, URLs with queries and tokens are never logged or shown. |
| Default deny | A record becomes an event only through a signed pack parser's match filter, then the Privacy & Secret Protection Engine and default-deny policy. |

## Permissions

Application permissions, read-only, admin consent required. Use a dedicated app
registration (or the collector's managed identity) for Bower, not one shared with other
tools.

| Source kind | Microsoft Graph application permission | Licence |
|---|---|---|
| `intune-audit` | `DeviceManagementApps.Read.All` | Intune |
| `intune-device-compliance` | `DeviceManagementManagedDevices.Read.All` | Intune |

`DeviceManagementApps.Read.All` is the permission Microsoft documents as least privileged
for `deviceManagement/auditEvents`. It also allows reading Intune app configuration; Bower
reads only `auditEvents`. `DeviceManagementManagedDevices.Read.All` allows reading full
device inventory; Bower requests only the compliance fields with `$select` and never asks
for the device name, IMEI, serial number, phone number, MAC addresses, email address or
hardware details.

## Tokens and credentials

- Tokens come from exactly one credential per input: the collector's
  `BOWER_AZURE_CREDENTIAL` (managed identity preferred), or an input's certificate app
  registration. Azure.Identity caches tokens in memory only. Nothing is written to disk,
  the cursor or status.
- Client secrets are refused in configuration. A certificate file stays on disk with the
  collector account's permissions (mode 0600); rotate it in Entra and replace the file,
  then restart.
- A 401 drops the cached credential and acquires one new token, once per request; the
  retries after it reuse that token. A second 401 fails the poll with
  `mscloud-unauthorised`.

## Checkpoints

- One cursor row per input (`mscloud:<id>`) in the queue database's `source_cursors`
  table, with the same file permissions as the queue. It holds times, the source kind and,
  while a window is open, the next page link (an API URL with a skip token, no credential).
- The cursor moves past a page only after every record in it is durably queued or
  definitively dropped. A crash re-reads at most one page; event ids make the copies queue
  duplicates.
- A damaged cursor or one written for another source kind fails closed
  (`mscloud-cursor-invalid`): the input stops instead of re-reading an unbounded window.
  To reset an input deliberately, stop the collector and delete its `mscloud:<id>` row.
- The API keeps seven days. A collector stopped longer resumes at the seven day floor and
  counts a gap; that data is not recoverable from the API.

## Personal information by event type

Values after the `deploy/privacy/microsoft-cloud.yaml` profile. The profile sets the email
detector to `hmac`: value detectors run before field rules, and the default mask
(`m***@domain`) would otherwise make every user with the same initial and domain share one
pseudonym. Without the profile, the default Australian redaction still masks email
addresses.

| Event type | Personal or sensitive fields kept | Treatment | Never collected |
|---|---|---|---|
| `intune_audit` | Actor user principal name or service principal name, actor object id, actor IP address, resource display name | UPN, object id and resource name are HMAC pseudonyms; IP address kept for detections | Modified property old and new values, actor permissions list |
| `intune_device_compliance` | Primary user principal name and object id, operating system and version, ownership, encryption and jailbreak state | UPN and object id are HMAC pseudonyms; the Entra and Intune device ids identify the device | Device name, IMEI, MEID, serial number, phone number, Wi-Fi and Ethernet MAC addresses, email address, hardware inventory, compliant devices (refused in `complianceStates`) |

IP addresses are personal information under the Privacy Act 1988 when they can identify a
person. They are kept because sign-in and admin anomaly detection depend on them. If your
policy does not allow that, add `- path: source.ipAddress` with `action: hmac` (or
`remove`) to your privacy profile.

## Switch a source off

1. Remove the input from `BOWER_MICROSOFT_CONFIG` (or unset the variable) and restart the
   collector. The cursor row is kept, so turning it back on resumes within the seven day
   floor.
2. To revoke access at once, remove the Graph permission, the admin consent or the app
   registration in Entra. The input reports `mscloud-permission-denied` and reads nothing.
3. To remove the data already delivered, purge it in Log Analytics; Bower keeps queue rows
   only for the delivered retention period (`BOWER_QUEUE_RETENTION_HOURS`).

## Residual risks

- A compromised collector host can use the collector's credential to read what the
  permissions above allow. Keep the identity dedicated and the permissions to this list.
- `DeviceManagementApps.Read.All` is broader than audit read. Microsoft offers no narrower
  permission for Intune audit events.
- Audit records Microsoft writes more than the overlap (10 minutes by default) after their
  activity time are missed. Increase `overlapSeconds` if you see late arrivals.
