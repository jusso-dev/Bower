# Microsoft cloud sources (Intune)

Some Microsoft products hold security-relevant admin and audit data that is hard to get
into Microsoft Sentinel in a stable shape. The Bower collector can pull it directly from the
Microsoft API, keep only what a signed pack selects, redact it and deliver it through the
same durable queue, Data Collection Rule and Logs Ingestion API as every other source. Rows
land in `BowerSecurity_CL` (see [the table reference](../reference/sentinel-table.md)); there
is no new table to create.

The first sources are Microsoft Intune audit events and a daily device compliance snapshot,
mapped by the signed [`microsoft-intune`](../../packs/microsoft-intune) pack.

| Source kind | API | What becomes an event |
|---|---|---|
| `intune-audit` | Graph `GET /v1.0/deviceManagement/auditEvents` | Every Intune admin action: who did what to which resource, the result, the actor's IP address and the **names** of changed properties |
| `intune-device-compliance` | Graph `GET /v1.0/deviceManagement/managedDevices` (once per UTC day) | One event per device that needs attention: noncompliant, in grace period, conflict or error (configurable) |

Not collected, and why:

- **Intune operational logs** (enrolment and policy processing). Microsoft offers no API
  for them; they are only exported by Intune diagnostic settings to Log Analytics
  (`IntuneOperationalLogs`), Event Hub or Storage. Where you can use diagnostic settings,
  use them. Bower does not ship a stub that would only look like coverage.
- **Unified Audit Log, Entra sign-in and Entra audit logs.** Out of scope: Bower is not a
  long-term audit archive.

## Before you start

1. An active Intune licence on the tenant.
2. An app registration (or the collector's managed identity) with these Microsoft Graph
   **application** permissions, and admin consent:

   | Source kind | Permission | Why this one |
   |---|---|---|
   | `intune-audit` | `DeviceManagementApps.Read.All` | Microsoft documents it as the least privileged permission for `auditEvents` |
   | `intune-device-compliance` | `DeviceManagementManagedDevices.Read.All` | Least privileged read of managed devices |

   No `ReadWrite` permission is needed or used.
3. A collector that loads the signed `microsoft-intune` pack (`BOWER_PACKS`, signed by a key
   in `BOWER_PACK_TRUSTED_KEYS`).

## Turn it on

Create `/etc/bower/microsoft.json` (owned by the collector account, mode 0600):

```json
{
  "apiVersion": "bower.security/v1",
  "kind": "MicrosoftCloudSource",
  "pollIntervalSeconds": 300,
  "inputs": [
    {
      "id": "intune-audit",
      "sourceKind": "intune-audit",
      "tenantId": "00000000-0000-0000-0000-000000000000",
      "route": { "pack": "microsoft-intune", "parser": 0 }
    },
    {
      "id": "intune-compliance",
      "sourceKind": "intune-device-compliance",
      "tenantId": "00000000-0000-0000-0000-000000000000",
      "route": { "pack": "microsoft-intune", "parser": 1 }
    }
  ]
}
```

Then set, and restart the collector:

```bash
BOWER_MICROSOFT_CONFIG=/etc/bower/microsoft.json
BOWER_PRIVACY_PROFILE=/etc/bower/privacy/microsoft-cloud.yaml   # deploy/privacy/microsoft-cloud.yaml
BOWER_PRIVACY_HMAC_KEY_FILE=/etc/bower/privacy-hmac.key
```

The privacy profile replaces user principal names, user object ids and resource names with
keyed HMAC pseudonyms. Without it, the default Australian redaction still masks email
addresses, but you lose the ability to follow one person across events.

Check it with `bower status` or `GET /v1/status`: the `microsoftCloud` block lists each
input's state, committed time, page, record and drop counters, retries and failure code.
It never shows record content, URLs or tokens.

### Credentials

By default an input uses the collector's one configured Azure credential
(`BOWER_AZURE_CREDENTIAL`: managed identity, workload identity, environment or Azure CLI).
Grant the Graph permissions above to that identity.

An MSP reading a customer tenant can give the input its own certificate-based app
registration in that tenant instead:

```json
"credential": {
  "clientId": "00000000-0000-0000-0000-000000000000",
  "certificatePath": "/etc/bower/certs/customer-a.pem"
}
```

The PEM holds the certificate and its private key, readable only by the collector account.
Client secrets are not accepted.

### Input settings

| Setting | Default | Range | Meaning |
|---|---|---|---|
| `id` | | 1 to 63 lowercase letters, digits, hyphens | Names the cursor (`mscloud:<id>`) and the source adapter |
| `sourceKind` | | see the table above | The API and record shape |
| `tenantId` | | lowercase GUID | The tenant read |
| `route` | | an active parser of a loaded signed pack | Start-up fails without one |
| `startLookbackHours` | 24 | 1 to 168 | How far back the first poll reads |
| `settleDelaySeconds` | 300 | 0 to 86400 | Windows end this long before now, so late-written records fall in the next one |
| `overlapSeconds` | 600 | 0 to 86400 | Each window starts this long before the last committed time; re-read records deduplicate |
| `maxRecordsPerPoll` | 1000 | 1 to 10000 | Records handed to the parser per poll before it yields |
| `complianceStates` | `noncompliant`, `inGracePeriod`, `conflict`, `error` | Intune states | `intune-device-compliance` only |

## How collection stays correct

- **Checkpoints survive restart.** The cursor lives in the queue database. It records the
  last completed window, the open window and the next page. A page is committed only after
  every record in it was durably queued or definitively dropped.
- **No unbounded re-reads.** Windows are at most 24 hours, and never start more than seven
  days back. A collector stopped longer than that resumes at the seven day floor and counts
  a gap in `gaps`.
- **Duplicates collapse.** Event ids are derived from the input and the record, so the
  overlap and any page re-read after a crash become queue duplicates, not new rows.
- **Throttling and outages.** 429 and 5xx responses are retried with capped exponential
  backoff and jitter, honouring `Retry-After`. After the retries the poll fails with
  `mscloud-throttled` or `mscloud-unavailable` and backs off (30 seconds doubling to 30
  minutes) without moving the cursor.
- **Backpressure.** A full queue stops the poll and keeps the page. Nothing is dropped.
- **Permission problems** show as `mscloud-permission-denied` (403) or
  `mscloud-unauthorised` (401 after one token refresh). Fix the consent; the input retries
  on its own.

## What reaches Sentinel

| `EventType` | `EventCategory` | `EventAction` | Main columns |
|---|---|---|---|
| `intune_audit` | `administrative-activity` | Intune activity, for example `Wipe ManagedDevice` | `ActorUsername` (pseudonymised), `ActorUserId`, `SourceIpAddress`, `Target` (type, id, pseudonymised name), `CorrelationId`, `Labels.intuneCategory`, `Labels.intuneComponent`, `Labels.intuneOperationType`, `Labels.intuneModifiedProperties` |
| `intune_device_compliance` | `application-security` | `device.compliance.<state>` | `ActorUsername` (primary user, pseudonymised), `Target.id` (Entra device id), `Labels.operatingSystem`, `osVersion`, `ownerType`, `isEncrypted`, `jailBroken`, `lastSyncDateTime`, `gracePeriodExpires` |

Each pack parser declares the ASIM and OCSF field each source field corresponds to (for
example `actorIpAddress` to ASIM `SrcIpAddr` and OCSF `src_endpoint.ip`), so ASIM-style
parsers over `BowerSecurity_CL` can be written without guessing. The rows use the Bower
envelope: no third event standard.

Pack detections: device wipe, retire or delete; Intune role or role assignment change;
compliance or configuration policy deletion; jailbroken or rooted device.

## Turn it off

Remove the input from `BOWER_MICROSOFT_CONFIG` (or unset the variable) and restart the
collector. To stop all access immediately, remove the Graph permissions or the app
registration in Entra; the input then reports `mscloud-permission-denied` and reads
nothing. The cursor row (`mscloud:<id>`) stays in the queue database so re-enabling resumes
where it stopped (within the seven day floor).

See [Microsoft cloud sources security](../security/microsoft-cloud-sources.md) for scopes,
tokens, checkpoints and the personal information in each event type.
