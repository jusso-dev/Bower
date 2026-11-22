# Microsoft cloud sources: envelope hand-off contract

Bower's Microsoft cloud sources collect and normalise admin and audit data from Microsoft
APIs that do not integrate cleanly with Sentinel. They do not keep it long term. A
separate archive (owned outside Bower) holds long-term copies of the well-known streams
(Unified Audit Log, Entra sign-in and audit, selected Defender events) for search, legal
hold and evidence packs. This page is the contract that lets a copy forwarded or archived
elsewhere line up with what Bower delivered.

## What Bower guarantees

| Field | Value | Stable across |
|---|---|---|
| `eventId` | `mscloud-` and 32 lowercase hex characters | Every re-read of an unchanged source record by the same input (overlap, crash recovery, restart) |
| `eventOriginalId` | Same as `eventId` | As above |
| `collector.sourceAdapter` | `mscloud:<input id>:<pack>:<parser index>` | The input's configuration |
| `application.name` | Pack defined, for example `microsoft-intune` | Pack major version |
| `eventType` | Pack defined, for example `intune_audit`, `intune_device_compliance` | Pack major version |
| `request.correlationId` | The source's own correlation id when it has one (Intune `correlationId`), else the source record id | Source |
| `labels.intuneAuditEventId` | `intune_audit`: the Intune audit event id (the source record id) | Source |
| `labels.intuneDeviceId`, `labels.snapshotDate` | `intune_device_compliance`: the Intune managed device id and the UTC day of the snapshot (together, the source record id) | Source |
| `target.id` | The source object's GUID (Intune resource id, Entra device id) | Source |
| `timeGenerated` | The source's own activity time; for snapshots, when the snapshot started | Source |

The event id is SHA-256 over `bower-mscloud-v1`, the input id, the source kind, the tenant
id, the source record id (the Intune audit event id; for compliance, the device id and the
snapshot date) and the bounded record content. A receiver that needs to join a Bower row
to the original Microsoft record should use the source record id carried in the labels
above, not recompute the hash.

## What a receiver must not assume

- Values are post-redaction. With `deploy/privacy/microsoft-cloud.yaml`, user principal
  names, user object ids, resource names and email addresses are keyed HMAC pseudonyms;
  the key never leaves the collector.
- Bower delivers at least once. Deduplicate on (`collector.id`, `eventId`), as the
  `BowerSecurityEvents` parser does.
- Bower keeps queue rows only for its delivered retention period. It is not the system of
  record and offers no legal hold.
- Fields can be added in a later pack version; none are renamed or removed within a major
  version.
