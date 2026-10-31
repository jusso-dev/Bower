# 05 — Credential rotation and security failure handling

**Status: tested live for the scoped rollout (WEF/WEC and firewall syslog over mutual
TLS → Bower → Microsoft Sentinel). Release packages remain unsigned; this is not a
production approval.** Evidence: [`docs/evidence/ws5-20261031-074543`](../evidence/ws5-20261031-074543/README.md).

This document is the operator runbook for every credential and trust anchor Bower uses
in the scoped rollout. It covers how each is configured, stored and reloaded, and how to
rotate it on a schedule or revoke it in an emergency on each supported environment. It
also gives the collector behaviour you should expect when a credential fails, the alerts
that catch expiry first, and the security test procedure you can rerun yourself.

Contents:

1. [What changed and what was measured](#1-what-changed-and-what-was-measured)
2. [Credential and trust-anchor inventory](#2-credential-and-trust-anchor-inventory)
3. [Failure modes and expected collector behaviour](#3-failure-modes-and-expected-collector-behaviour)
4. [Detection and alerting before and after expiry](#4-detection-and-alerting-before-and-after-expiry)
5. [Where secrets live on each environment](#5-where-secrets-live-on-each-environment)
6. [Runbooks](#6-runbooks), one per credential
7. [Rejected packs and malicious payloads](#7-rejected-packs-and-malicious-payloads)
8. [Security test procedure you can rerun](#8-security-test-procedure-you-can-rerun)
9. [How we tested this](#9-how-we-tested-this)
10. [Known limits](#10-known-limits)

## 1. What changed and what was measured

Defects found by the live tests and fixed in this change (C# and the Rust port unless
stated):

| Defect | Before | After |
| --- | --- | --- |
| Credential failures looked like network outages | An expired, revoked or disabled Entra credential, or a wrong tenant, was recorded as `destination-azure-unavailable` with **no log line**; operators saw only a growing retry count. | A rejection by the identity service (for example `invalid_client`, `unauthorized_client`), even after a retried network error, or a missing or unusable credential configuration is retryable `destination-azure-credential-failed`. A token service that cannot be reached (DNS, proxy, firewall, TLS, timeout) or answers 5xx/408/429 stays `destination-azure-unavailable`. The delivery worker logs one metadata-only line per failure code (event 1008): `Output adapter azure-logs-ingestion did not deliver 20 events (destination-azure-credential-failed); retrying.` |
| Syslog TLS rotation needed a restart | Certificates, keys and client CAs were read once at start. A collector restart under 10 events/sec lost **1 of 100** frames in the live test. | A background task reads each file once a second and reloads changed material for new handshakes without dropping connections (live: **100/100** frames, **0** sender reconnects). A change that cannot be loaded (any error, including a FIFO or other non-regular file) keeps the last good material, is counted once and retried. Superseded certificates and keys are released once no handshake uses them. |
| Syslog client certificates were never checked for revocation | `RevocationMode.NoCheck`; a stolen sender certificate stayed valid until its CA was removed. | Optional `clientCertificateRevocationListFile`, evaluated identically by C# and Rust: lists are selected by the key of the CA that issued the sender (so a re-keyed CA with the same name works during overlap) and by their critical issuing distribution point. Open sessions are re-validated after a reload and closed when their client is no longer trusted, including a chain that now ends at an expired CA. |
| A bad pack or source file on `reload` stopped collection | The signed `reload` command restarted the collector even when a replaced pack, trusted key, HMAC key, syslog route, syslog TLS file or expectations file no longer loaded, so the restart failed and nothing ran. | `reload` first runs the same loader start-up runs (policies, packs, keys, privacy, source configurations and routes, syslog TLS, expectations, scopes, tokens, relay files); on failure it reports `reload-validation-failed`, keeps its rate-limit slot and the collector keeps its last good configuration. |
| An attacker could hide a failed logon or blur attribution (Windows, C# only) | A control character or unpaired surrogate in an account name made the rendered event XML invalid and the 4625 event was dropped; names differing only in unpaired surrogates would have shared one pseudonym. | Forbidden characters are read as character references; unpaired surrogates are escaped reversibly (U+FFFD plus four hex digits), so every distinct name keeps a distinct pseudonym. |

New status fields (`/v1/status`, metadata only) for alerting: per TLS syslog listener
`tlsReloads`, `tlsReloadFailures`, `tlsRevoked`, `tlsSessionsClosed`,
`serverCertificateNotAfter`, `clientCertificateAuthorityNotAfter` and
`clientRevocationListNextUpdate`. New failure/result codes:
`destination-azure-credential-failed` and `reload-validation-failed`. No Sentinel
schema, Bicep table or DCR change.

Live results (exact counts by independent destination query; details in §9):

| Scenario | Result |
| --- | --- |
| (a) Expired client secret | **Pass.** Entra kept issuing tokens for 4–7 minutes after expiry; then `credential-failed`, events retained, 30-second retries, drained after a new secret and restart. |
| (b) Deleted (revoked) secret | **Pass.** New processes failed within a minute; a running process kept delivering on its cached token for **57 minutes**. |
| (c) Removed role assignment | **Pass.** `destination-azure-http-403` after 11.6–16.7 minutes of RBAC propagation; recovered **without restart** 5 min 40 s after re-assignment. |
| (d) Disabled service principal | **Pass.** As (b) for cached tokens; recovered **without restart** 5–31 s after re-enabling. |
| (e) Wrong tenant / wrong identity | **Pass.** Wrong tenant: `credential-failed`. Reader identity used for ingestion: `http-403`. Audience is fixed to Azure public cloud and cannot be misconfigured. |
| (f) Certificate rotation with overlap | **Pass.** See §9 for the in-place file swap finding: a certificate replaced under a running collector is not used until restart. |
| (g) Secret rotation with / without overlap | **Pass.** With overlap: 80/80 delivered, no failure. Without: 20 events held as `credential-failed`, delivered 25 s after the new secret. |
| Syslog server certificate, client CA, client certificate rotation; expired, revoked, untrusted, wrong-purpose and wrong-name certificates | **Pass** (refusals as expected). Finding: rsyslog loses the frames it writes into a refused session (40/40 while revoked, under TLS 1.2 or 1.3). |
| HMAC key rotation | **Pass.** Pseudonyms change and carry the key ID (`hmac-sha256:k1:…` → `hmac-sha256:k2:…`). |
| Rejected packs (unsigned, untrusted key, tampered, malformed manifest, missing file/key) and trusted-key rotation | **Pass** (unit tested; refusal keeps the running configuration). No version pinning exists. |
| Malicious payloads and privacy sweep | **Pass**: 0 raw secret markers in queue DB/WAL/SHM, logs, status and 28 of 29 accepted Sentinel rows (the 29th, whose ID a detector masked, was checked locally only). Findings: LF-framing CRLF injection, events with very large fields dead-letter at preflight, formula/control text arrives byte-exact. |

## 2. Credential and trust-anchor inventory

"Reload" says what applies a change. "Restart" means restarting the collector process
(Linux `systemctl restart bower`, Windows `Restart-Service Bower`, Kubernetes
`kubectl rollout restart`); events already queued are durable across it.

| # | Credential / trust anchor | Used for | Configured by | Default location | Reload |
| --- | --- | --- | --- | --- | --- |
| 1 | Logs Ingestion identity | Upload to the DCR | `BOWER_AZURE_CREDENTIAL` = `managed-identity` (default, optional `BOWER_AZURE_CLIENT_ID`), `workload-identity` (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_FEDERATED_TOKEN_FILE`), `environment` (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` **or** `AZURE_CLIENT_CERTIFICATE_PATH` [+`AZURE_CLIENT_CERTIFICATE_PASSWORD`]) | Managed identity: none. Certificate: a PEM/PFX file you choose (for example `/etc/bower/secrets/ingest.pem`). Secret: an environment variable only. | **Restart** for a changed secret, certificate file or variable (read at start; the C# SDK caches the loaded certificate). Managed identity and workload identity need no rotation; the federated token file is re-read automatically. **A cached access token keeps working until it expires (measured 58–64 minutes)** even after the credential is revoked. |
| 2 | Syslog listener server certificate and key | TLS 6514 | `BOWER_SYSLOG_CONFIG` → `tls.certificateFile`, `tls.privateKeyFile` | `/etc/bower/syslog/` (Linux), `%ProgramData%\Bower\syslog\` (Windows) | **Hot reload** (a background task checks once a second; new handshakes only). Regular, non-empty files only. |
| 3 | Syslog client CA bundle | Which senders may connect | `tls.clientCertificateAuthorityFile` (PEM, one or more CAs) | as above | **Hot reload**; open sessions from a removed CA are closed before their next frame. |
| 4 | Syslog client revocation lists | Revoking individual sender certificates | `tls.clientCertificateRevocationListFile` (PEM or DER, one list per CA) | as above | **Hot reload**; open sessions of newly listed certificates are closed. Lists must be renewed before `nextUpdate`. |
| 5 | Sender client certificates | Sender (rsyslog, appliance) authenticates to Bower | Sender configuration | Sender host | Sender-side; rsyslog needs a restart (its disk queue survives with `queue.saveOnShutdown`). |
| 6 | WEC transport (Kerberos or HTTPS certificate) | WEF source → WEC `ForwardedEvents` | Windows WinRM/WEF, **not Bower** | WEC and sources | Windows-managed. Bower reads `ForwardedEvents` locally and holds no WEF credential. |
| 7 | HMAC pseudonymisation key | `actor.username` pseudonyms | `BOWER_PRIVACY_HMAC_KEY_FILE` (32+ bytes, base64), `BOWER_PRIVACY_HMAC_KEY_ID` (default `k1`) | `/etc/bower/secrets/privacy-hmac.key`; `/run/secrets/bower-hmac` in containers | **Restart** (or signed `reload`). Pseudonyms change; the key ID is embedded in each (`hmac-sha256:<keyId>:<hex>`). |
| 8 | Pack-signing trusted keys and signed packs | Which packs load | `BOWER_PACK_TRUSTED_KEYS` (one PEM public key **per file**, list with `,`/`;`), `BOWER_PACKS` | `/etc/bower/keys/pack-trusted.pem`, `/etc/bower/packs/`; `%ProgramData%\Bower\keys`, `\packs` | **Restart** or signed `reload` (validated first). |
| 9 | Management credential | Collector ↔ management API | `BOWER_MANAGEMENT_AUTH=enrolment` (one-time `bwe1.` token → collector key pair) or `entra` | `/var/lib/bower/management-credential/credential.json` (0600) | Rotates automatically (30-day credential, renewed with 10 days left) or with the signed `rotate-credential` command. See [collector enrolment](../architecture/collector-enrolment.md). |
| 10 | Management command trusted keys | Which signed commands run | `BOWER_MANAGEMENT_COMMAND_TRUSTED_KEYS` | `/etc/bower/keys/command-trusted.pem` | **Restart.** |
| 11 | Sentinel verifier identity | Independent destination queries (`bower evidence run`, lab query scripts) | `--credential` (`azure-cli`, `managed-identity`, `workload-identity`, `environment`) on the verifier host | Verifier host only, never the collector | Per invocation. Log Analytics Reader on the workspace only. |
| 12 | Local ingest bearer token | Producers posting to `/v1/events` | `BOWER_INGEST_TOKEN_FILE` (restart) or `BOWER_INGEST_TOKENS_FILE` (hot, every 2 s) | `/etc/bower/secrets/ingest-token` | As stated. |

Least privilege: the ingestion identity has only **Monitoring Metrics Publisher on the
DCR**; the verifier has only **Log Analytics Reader on the workspace**. The live tests
confirmed each fails the other's role (`http-403` when the reader identity ingests).

## 3. Failure modes and expected collector behaviour

Every failure below keeps queued events (nothing is deleted before acknowledgement),
retries on a bounded cadence and records metadata only. "Retry" for `destination-*`
codes means the whole queue pauses behind a durable circuit and retries every 30
seconds (or the server's Retry-After, capped at one hour). These codes never consume
the dead-letter budget (`BOWER_MAX_DELIVERY_ATTEMPTS`), so an outage of any length
does not dead-letter healthy events; the queue byte cap (`BOWER_QUEUE_MAX_BYTES`)
eventually applies backpressure (HTTP 503 to producers, TCP flow control to syslog).

| Failure | What Bower records | Measured behaviour | Recovery |
| --- | --- | --- | --- |
| Client secret expired | `destination-azure-credential-failed`; log 1008 | Entra honoured the expired secret for 4–7 min; then held and retried every 30.1 s (median) | New secret, update variable, restart; drained ≤ 41 s after restart |
| Client secret deleted | same | New token requests fail within a minute; **running process keeps working until its cached token expires (57 min)** | As above |
| Certificate credential removed from the app | same (after token expiry) | Running process keeps working on its cached token | Deploy the new certificate file, restart |
| Certificate file replaced in place, no restart | none until token expiry | C# keeps using the certificate loaded at start; failure only appears at the next token refresh | Always restart after replacing the file |
| Role assignment removed | `destination-azure-http-403`; log 1008 | Effective after 11.6–16.7 min (RBAC propagation) | Re-assign; recovers **without restart** (5 min 40 s) |
| Service principal disabled | `destination-azure-credential-failed` | Cached tokens keep working (57 min) | Re-enable; recovers **without restart** (5–31 s) |
| Wrong tenant ID | `destination-azure-credential-failed` | Each attempt ~10 s (instance discovery), then 30 s cadence | Fix variable, restart |
| Wrong identity (no role on DCR) | `destination-azure-http-403` | 30 s cadence | Configure the publisher identity, restart |
| Entra / token endpoint unreachable, or answering 5xx/408/429 | `destination-azure-unavailable` (a network outage, not a credential failure) | Same as any outage | Network fix; no restart |
| Identity service rejects the credential after a retried network error | `destination-azure-credential-failed` (the rejection decides) | 30 s cadence | Fix the credential |
| DCE unreachable | `destination-azure-unavailable` | Same as any outage | Network fix |
| Syslog server certificate expired | `tlsHandshakeFailures` rises (senders refuse); `serverCertificateNotAfter` in the past | Senders queue locally (rsyslog disk queue) | Place a valid certificate and key; picked up within a second, no restart |
| Syslog server certificate file broken, key mismatch, or a TLS path replaced by a FIFO, device or directory | `tlsReloadFailures` +1 (once per distinct content) | Last good certificate stays in use; retried every second | Fix the files |
| Client CA removed while a sender is connected | `tlsSessionsClosed` +1, then `tlsHandshakeFailures` | Open session closed before its next frame; that frame is refused | Overlap CAs during rotation |
| Client certificate revoked (CRL) | `tlsRevoked`, `tlsSessionsClosed` | Open session closed; reconnects refused | Issue a new sender certificate |
| No current CRL signed by the issuing CA's key and covering the sender (expired, missing, signed by another key, or scoped to another distribution point) | `tlsRevoked` for every such client | Those senders refused | Publish a current CRL signed by that CA (hot reload) |
| Sender chain ends at an expired configured CA (a valid leaf) | `tlsHandshakeFailures`; open sessions `tlsSessionsClosed` | Refused at handshake and closed at the next frame | Deploy the re-issued CA certificate |
| CRL with an unsupported scope (reasons, indirect, relative name) or delta list | Start-up or reload refused with a message naming the feature | Running collector keeps its last good lists | Publish a full, direct list |
| Client certificate expired / not yet valid / wrong purpose / untrusted CA | `tlsHandshakeFailures` | Refused at handshake | Re-issue |
| Sender sees wrong server name | Sender error (rsyslog: `peer name not authorized`), no frame reaches Bower | Sender queues; 30/30 delivered after the right certificate returned | Fix certificate SAN |
| HMAC key file missing or shorter than 32 bytes | Start-up fails with a configuration error; `reload` refused | Running collector unaffected by a refused `reload` | Fix the key file |
| Pack unsigned, untrusted, tampered or malformed | Start-up fails (`PackVerificationException` etc.); `reload` refused (`reload-validation-failed`) | Running collector keeps its last good packs | Deploy a valid signed pack |
| Pack trusted key removed while its packs are deployed | As above | As above | Overlap keys (one file each) |

What a sender loses: syslog has no application acknowledgement. When Bower refuses a
sender's certificate, rsyslog 8.2204 (`ossl`) still writes one frame into each refused
session and drops it (40/40 frames in the live revocation test, TLS 1.2 and 1.3
alike). That is correct for a revoked sender but means an **accidental** refusal (CA
removed too early, CRL left to expire) loses data at the sender. Overlap every
rotation and alert before expiry.

## 4. Detection and alerting before and after expiry

Alert **before** expiry (the only way to avoid an outage), and on the failure signals
in case a rotation goes wrong.

### 4.1 Before expiry

| What | How | Alert when |
| --- | --- | --- |
| Entra client secret / certificate | `az ad app credential list --id <appId>` (secrets) and `--cert` (certificates); Microsoft Graph `Get-MgApplication`. Run daily from a scheduler. | Fewer than 30 days remain |
| Key Vault certificates and secrets | Event Grid `Microsoft.KeyVault.CertificateNearExpiry` / `SecretNearExpiry` to an Azure Monitor action group; set Key Vault auto-renewal at 80 % of lifetime | Event received |
| Syslog server certificate | `/v1/status` → `syslog[].serverCertificateNotAfter` | Fewer than 30 days |
| Syslog client CAs | `syslog[].clientCertificateAuthorityNotAfter` | Fewer than 60 days |
| Syslog revocation lists | `syslog[].clientRevocationListNextUpdate` | Fewer than 2 days (lists are short-lived) |
| Sender certificates | Sender-side inventory (`openssl x509 -enddate`) | Fewer than 30 days |
| Management credential | Console collector detail (credential expiry) | Automatic renewal has not happened with 5 days left |
| AWS Secrets Manager | Rotation schedule; CloudWatch alarm on `RotationFailed` (EventBridge) | Event received |

```bash
# Entra application credentials expiring within 30 days (bash, needs az login).
for app in "$INGEST_APP_ID" "$VERIFIER_APP_ID"; do
  az ad app credential list --id "$app" --query "[].{name:displayName,end:endDateTime}" -o tsv
  az ad app credential list --id "$app" --cert --query "[].{name:displayName,end:endDateTime}" -o tsv
done | awk -v limit="$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%S 2>/dev/null || date -u -v+30d +%Y-%m-%dT%H:%M:%S)" '$2 < limit {print "EXPIRING", $0}'
```

```powershell
# The same with Microsoft Graph PowerShell (Application.Read.All).
Connect-MgGraph -Scopes Application.Read.All
$limit = (Get-Date).ToUniversalTime().AddDays(30)
foreach ($appId in $IngestAppId, $VerifierAppId) {
  $app = Get-MgApplication -Filter "appId eq '$appId'"
  @($app.PasswordCredentials) + @($app.KeyCredentials) |
    Where-Object EndDateTime -lt $limit |
    ForEach-Object { "EXPIRING {0} {1} {2}" -f $appId, $_.DisplayName, $_.EndDateTime.ToString('o') }
}
```

```bash
# Collector-local checks (run as root or a member of the bower group).
TOKEN=$(cat /etc/bower/secrets/ingest-token)
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:4319/v1/status |
  python3 -c '
import json, sys, datetime
s = json.load(sys.stdin); now = datetime.datetime.now(datetime.timezone.utc)
for l in s.get("syslog") or []:
    for key, days in (("serverCertificateNotAfter", 30), ("clientCertificateAuthorityNotAfter", 60), ("clientRevocationListNextUpdate", 2)):
        if l.get(key) and datetime.datetime.fromisoformat(l[key]) - now < datetime.timedelta(days=days):
            print("EXPIRING", l["id"], key, l[key])
    for key in ("tlsReloadFailures", "tlsRevoked", "tlsSessionsClosed"):
        if l.get(key):
            print("CHECK", l["id"], key, l[key])
q = s["queue"]
if q["retrying"] or q["deadLettered"]:
    print("DELIVERY", "retrying=%d deadLettered=%d oldest=%s" % (q["retrying"], q["deadLettered"], q["oldestUndelivered"]))
'
```

```powershell
# Windows collector (elevated; the token file is ACL-protected).
$token = Get-Content "$env:ProgramData\Bower\secrets\ingest-token" -Raw
$s = Invoke-RestMethod -Uri http://127.0.0.1:4319/v1/status -Headers @{ Authorization = "Bearer $($token.Trim())" }
$s.queue | Select-Object retrying, deadLettered, oldestUndelivered
$s.syslog | Select-Object id, serverCertificateNotAfter, clientCertificateAuthorityNotAfter, clientRevocationListNextUpdate, tlsReloadFailures, tlsRevoked, tlsSessionsClosed
```

### 4.2 After a failure

- **Collector log event 1008** (`did not deliver … (destination-azure-credential-failed)`
  or `(destination-azure-http-403)`): alert on any occurrence lasting over 10 minutes.
  Linux: `journalctl -u bower --since -15min | grep -c 'credential-failed\|http-40[13]'`.
- **`/v1/status` `queue.retrying` > 0 and `queue.oldestUndelivered` older than 15
  minutes**: the queue is held behind the destination circuit.
- **Sentinel, no new rows from a collector** (catches every cause, including a token that
  silently stops working):

```kusto
BowerSecurity_CL
| where TimeGenerated > ago(1d)
| summarize LastIngested = max(ingestion_time()) by CollectorId
| where LastIngested < ago(30m)
```

- **Dead letters with a preflight code** (`preflight-field-too-large` and similar) mean
  an event was locally rejected before upload; review and use audited replay.

## 5. Where secrets live on each environment

Bower reads every credential from a **file** or an **environment variable**; it does not
read the Windows certificate store, DPAPI blobs or a vault API directly. Protect the
files with operating-system permissions and bring vault material to them.

| Environment | Ingestion identity (preferred → acceptable) | File credentials (TLS, HMAC, keys) | Apply a change |
| --- | --- | --- | --- |
| Linux packages (RPM/DEB, systemd) | Azure Arc or Azure VM managed identity → certificate file `AZURE_CLIENT_CERTIFICATE_PATH` → secret in `/etc/bower/bower.env` | `/etc/bower/secrets` and `/etc/bower/syslog`, `root:bower`, files `0640`, directories `0750`. The unit runs as `bower` with `ProtectSystem=strict` (read-only `/etc`). | Syslog TLS: replace files. Others: `systemctl restart bower`. |
| Windows (MSI, WEC hosts) | Azure Arc managed identity → certificate file → secret in the service environment | `%ProgramData%\Bower\secrets` and `\syslog`; ACL: `NT SERVICE\Bower` read, Administrators and SYSTEM full, inheritance off (the MSI sets this for `%ProgramData%\Bower`). DPAPI is not used: protection is the service-SID ACL. | Syslog TLS: replace files. Others: `Restart-Service Bower`. |
| Docker / containers | Workload identity is Kubernetes-only; use a certificate file from a secret → secret via an env file | Mount secrets as a **directory** (a single-file bind mount pins the old inode and hides an atomic replacement). | `docker compose up -d --force-recreate collector` |
| Kubernetes (`deploy/kubernetes`) | **Workload identity** (default in the manifest; no secret) | Kubernetes Secret or CSI Secrets Store volume mounted as a directory (no `subPath`); kubelet swaps the `..data` link atomically. | Syslog TLS: automatic. Others: `kubectl rollout restart deployment/bower-collector` (Recreate strategy keeps one queue owner). |
| AWS EC2 | Certificate file fetched from Secrets Manager by the instance role → secret | A oneshot unit writes Secrets Manager values to `/etc/bower/secrets` before `bower.service` (§6.1.4) | Re-run the fetch unit, then restart (or nothing for syslog TLS files) |
| Azure VM | **System- or user-assigned managed identity** (no secret) | Key Vault VM extension or `az keyvault secret download` into the directories above | As Linux/Windows |
| On-premises | **Azure Arc** managed identity → certificate file | As Linux/Windows | As Linux/Windows |

The secret variant of the `environment` credential exists only as an environment
variable (`AZURE_CLIENT_SECRET`), which the process owner and root can read
(`/proc/<pid>/environ`). Prefer managed identity, workload identity or a certificate.

## 6. Runbooks

Each runbook gives scheduled rotation (no data loss) and emergency revocation
(contain first, accept a short hold). Commands use these placeholders:

```bash
APP_ID=<ingestion app (client) ID>      TENANT_ID=<tenant ID>
DCR_ID=/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Insights/dataCollectionRules/<dcr>
SP_ID=$(az ad sp show --id "$APP_ID" --query id -o tsv)
```

General acceptance for every rotation: after the change, `/v1/status` shows
`queue.retrying` = 0 and `queue.deadLettered` unchanged, the collector log has no new
event 1008, and an independent query (§8.3) finds the events sent across the change.
General rollback: restore the previous file or variable (keep it until the new one is
proven) and restart if the credential is restart-applied.

### 6.1 Logs Ingestion identity

**Purpose:** keep upload to the DCR authorised without a gap.

**Prerequisites:** Application Administrator (or owner of the app) for app credentials;
User Access Administrator or Owner on the DCR for role changes; access to the collector
host or cluster.

#### 6.1.1 Managed identity or workload identity (recommended)

There is no secret to rotate. Entra manages the managed identity's credential; workload
identity re-reads its projected token file. Keep only the role assignment correct:

```bash
az role assignment list --assignee "$SP_ID" --scope "$DCR_ID" --query "[].roleDefinitionName" -o tsv
# Expected: Monitoring Metrics Publisher (and nothing broader).
```

Emergency revocation: remove the role assignment (effective after RBAC propagation,
measured 11.6–16.7 minutes) **and** detach the identity from the compute or delete the
federated credential:

```bash
az role assignment delete --assignee "$SP_ID" --role "Monitoring Metrics Publisher" --scope "$DCR_ID"
az identity federated-credential delete --identity-name <uami> --resource-group <rg> --name <federation>   # workload identity
az vm identity remove --name <vm> --resource-group <rg> --identities <uami-resource-id>                   # VM managed identity
```

Events queue as `destination-azure-http-403` (or `credential-failed`) and are delivered
once access is restored; no restart is needed for a role change.

#### 6.1.2 Client certificate (`AZURE_CLIENT_CERTIFICATE_PATH`) — scheduled rotation with overlap

1. Create the new certificate (Key Vault, your PKI or, for a lab, OpenSSL) and keep its
   private key on the collector host only:

   ```bash
   openssl req -x509 -newkey rsa:2048 -nodes -keyout ingest-new.key -out ingest-new.crt \
     -days 365 -subj "/CN=bower-ingest-$(hostname)"
   umask 027; cat ingest-new.crt ingest-new.key > /etc/bower/secrets/ingest-new.pem
   chown root:bower /etc/bower/secrets/ingest-new.pem; chmod 0640 /etc/bower/secrets/ingest-new.pem
   shred -u ingest-new.key
   ```

   ```powershell
   # Windows: export the new certificate with its key as PFX, then protect it for the service.
   $pfx = "$env:ProgramData\Bower\secrets\ingest-new.pfx"
   icacls $pfx /inheritance:r /grant:r "NT SERVICE\Bower:R" "BUILTIN\Administrators:F" "NT AUTHORITY\SYSTEM:F"
   ```

2. Add the **public** certificate to the app, keeping the old one (overlap):

   ```bash
   az ad app credential reset --id "$APP_ID" --cert @ingest-new.crt --append
   az ad app credential list --id "$APP_ID" --cert --query "[].{thumbprint:customKeyIdentifier,end:endDateTime}" -o table
   ```

3. Point the collector at the new file and **restart** (the certificate is loaded once
   at start; replacing the file under a running collector has no effect until restart):

   ```bash
   sed -i 's#^AZURE_CLIENT_CERTIFICATE_PATH=.*#AZURE_CLIENT_CERTIFICATE_PATH=/etc/bower/secrets/ingest-new.pem#' /etc/bower/bower.env
   systemctl restart bower
   ```

   ```powershell
   $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower'
   $environment = @((Get-ItemProperty $key).Environment | Where-Object { $_ -notlike 'AZURE_CLIENT_CERTIFICATE_PATH=*' })
   Set-ItemProperty $key -Name Environment -Type MultiString -Value ($environment + "AZURE_CLIENT_CERTIFICATE_PATH=$pfx")
   Restart-Service Bower
   ```

4. Verify (§8.3 query, and no event 1008 for 10 minutes), then remove the old
   certificate from the app and delete its file:

   ```bash
   az ad app credential delete --id "$APP_ID" --cert --key-id <old keyId>
   shred -u /etc/bower/secrets/ingest-old.pem
   ```

Expected output: step 3 restarts with no event 1008; step 4 lists one certificate.
**Acceptance:** every event sent across steps 1–4 is in Sentinel exactly once by
`EventId` (live: 20 + 20 + 20 + 20 events, all delivered, no failure).
**Rollback:** before step 4, set the variable back to the old file and restart.

Kubernetes / Docker: store the PEM in a Secret (`kubectl create secret generic
bower-ingest-cert --from-file=ingest.pem`), mount it as a directory, set
`AZURE_CLIENT_CERTIFICATE_PATH`, update the Secret, then `kubectl rollout restart
deployment/bower-collector` (Docker: `docker compose up -d --force-recreate`).

#### 6.1.3 Client secret — scheduled rotation with overlap

1. Create a new secret with an end date and write it to the protected environment file
   without echoing it, without passing it in any command's arguments (`printf` is a shell
   builtin) and only after checking it was issued:

   ```bash
   set -euo pipefail
   umask 077
   NEW=$(az ad app credential reset --id "$APP_ID" --append --display-name "bower-$(date +%Y%m)" \
     --end-date "$(date -u -d '+180 days' +%Y-%m-%d)" --query password -o tsv)
   [ -n "$NEW" ] || { echo "no secret was issued; nothing changed" >&2; exit 1; }
   { grep -v '^AZURE_CLIENT_SECRET=' /etc/bower/bower.env; printf 'AZURE_CLIENT_SECRET=%s\n' "$NEW"; } \
     > /etc/bower/bower.env.new
   unset NEW
   chown root:bower /etc/bower/bower.env.new && chmod 0640 /etc/bower/bower.env.new
   mv /etc/bower/bower.env.new /etc/bower/bower.env
   systemctl restart bower
   ```

   ```powershell
   $ErrorActionPreference = 'Stop'
   $new = az ad app credential reset --id $AppId --append --display-name "bower-$(Get-Date -Format yyyyMM)" `
     --end-date (Get-Date).AddDays(180).ToString('yyyy-MM-dd') --query password -o tsv
   if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($new)) { throw 'No secret was issued; nothing changed.' }
   $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower'
   $environment = @((Get-ItemProperty $key).Environment | Where-Object { $_ -notlike 'AZURE_CLIENT_SECRET=*' })
   Set-ItemProperty $key -Name Environment -Type MultiString -Value ($environment + "AZURE_CLIENT_SECRET=$new")
   Remove-Variable new; Restart-Service Bower
   ```

2. Verify, then delete the old secret: `az ad app credential delete --id "$APP_ID" --key-id <old keyId>`.

**Acceptance:** live overlap rotation delivered 80/80 events with no failure.
**Without overlap** (old secret deleted first) the collector holds every event as
`credential-failed` until the new secret is configured and the collector restarted
(live: 20 events delivered 25 seconds after the restart). Never delete first.

#### 6.1.4 AWS-hosted collector: secret or certificate from Secrets Manager

Give the instance role read access to exactly one secret. Secrets Manager appends a
random suffix to the ARN, so resolve the full ARN and use it, not a wildcard:

```bash
aws secretsmanager describe-secret --secret-id bower/ingest-cert --query ARN --output text
```

```json
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue",
  "Resource": "arn:aws:secretsmanager:ap-southeast-2:<account>:secret:bower/ingest-cert-AbCdEf"}]}
```

Fetch before the collector starts (`/etc/systemd/system/bower-secrets.service`):

```ini
[Unit]
Description=Fetch Bower secrets from AWS Secrets Manager
Before=bower.service
[Service]
Type=oneshot
UMask=0027
ExecStart=/bin/sh -c 'aws secretsmanager get-secret-value --secret-id bower/ingest-cert --query SecretString --output text > /etc/bower/secrets/ingest.pem.new && chown root:bower /etc/bower/secrets/ingest.pem.new && mv /etc/bower/secrets/ingest.pem.new /etc/bower/secrets/ingest.pem'
[Install]
RequiredBy=bower.service
```

Make `bower.service` depend on it (the package enables `bower.service` only), then
enable it:

```ini
# /etc/systemd/system/bower.service.d/secrets.conf
[Unit]
Requires=bower-secrets.service
After=bower-secrets.service
```

```bash
systemctl daemon-reload
systemctl enable bower-secrets.service
systemctl restart bower-secrets.service bower.service
systemctl is-enabled bower-secrets.service && systemctl is-active bower.service   # enabled, active
```

Rotate: put the new value in Secrets Manager (with the Entra overlap of §6.1.2), then
`systemctl start bower-secrets && systemctl restart bower`. For syslog TLS files
fetched the same way, re-running the fetch is enough (hot reload).

#### 6.1.5 Emergency revocation (secret or certificate leaked)

Revoking the credential does **not** stop a running collector until its cached access
token expires (measured 58–64 minutes after issue). To cut access immediately:

1. Remove the role assignment (`az role assignment delete …`, §6.1.1). Uploads fail with
   `http-403` after RBAC propagation (11.6–16.7 minutes measured).
2. Disable the service principal to stop new tokens: `az ad sp update --id "$SP_ID" --set accountEnabled=false`.
3. Delete the leaked credential: `az ad app credential delete --id "$APP_ID" --key-id <keyId>` (add `--cert` for a certificate).
4. Issue a new credential to the collectors (§6.1.2 or §6.1.3) and restart them;
   re-enable the service principal and re-assign the role. Events held in the meantime
   are delivered without loss (live: 5 to 50 held events per case, all delivered).

Disabling a service principal alone stops new tokens within a minute, but tokens
already issued keep working until expiry (live: 57 minutes). Combine it with role removal.

### 6.2 Syslog listener server certificate

**Purpose:** renew the certificate senders validate, with no restart and no lost frame.

**Prerequisites:** a certificate for the name senders check (`subjectAltName` DNS and,
if used, IP), signed by the CA the senders trust; write access to the TLS directory.

1. Issue the new certificate (the sender-trusted CA can stay the same). Verify the name:

   ```bash
   openssl x509 -in server-new.pem -noout -subject -ext subjectAltName -enddate
   openssl verify -CAfile sender-trusted-ca.pem server-new.pem
   ```

2. Install key first, then certificate, each by atomic rename (same file system):

   ```bash
   install -o root -g bower -m 0640 server-new-key.pem /etc/bower/syslog/server-key.pem.new
   mv /etc/bower/syslog/server-key.pem.new /etc/bower/syslog/server-key.pem
   install -o root -g bower -m 0644 server-new.pem /etc/bower/syslog/server.pem.new
   mv /etc/bower/syslog/server.pem.new /etc/bower/syslog/server.pem
   ```

   ```powershell
   Copy-Item server-new-key.pem "$env:ProgramData\Bower\syslog\server-key.pem.new"
   Move-Item -Force "$env:ProgramData\Bower\syslog\server-key.pem.new" "$env:ProgramData\Bower\syslog\server-key.pem"
   Copy-Item server-new.pem "$env:ProgramData\Bower\syslog\server.pem.new"
   Move-Item -Force "$env:ProgramData\Bower\syslog\server.pem.new" "$env:ProgramData\Bower\syslog\server.pem"
   ```

   Kubernetes: update the Secret holding both files (`kubectl create secret tls
   bower-syslog --cert=server-new.pem --key=server-new-key.pem --dry-run=client -o yaml |
   kubectl apply -f -`); the mounted directory changes within the kubelet sync period.

3. Verify: `tlsReloads` increased by one, `tlsReloadFailures` did not, and a new
   handshake serves the new certificate:

   ```bash
   openssl s_client -connect <collector>:6514 -servername <name> -cert sender.pem -key sender-key.pem </dev/null 2>/dev/null |
     openssl x509 -noout -fingerprint -sha256 -enddate
   ```

**Expected:** existing sender sessions keep running on their already negotiated session
(live: 0 reconnects, 100/100 frames); new sessions get the new certificate.
**Acceptance:** `serverCertificateNotAfter` shows the new date; sender queue drains; no
`tlsHandshakeFailures` increase. **Rollback:** put the previous files back the same way.
**If `tlsReloadFailures` increased:** the key does not match the certificate or a file
is incomplete; the old certificate is still served. Fix and replace again.

Emergency (server key compromised): issue a new certificate as above, and on each sender
restart the forwarding action so it re-handshakes, or wait for its reconnect. Consider
changing the sender-trusted CA if the CA itself is affected.

### 6.3 Syslog client CA bundle (sender CA rotation)

1. **Overlap.** Append the new CA to the bundle (one PEM file with both CAs) and replace
   it atomically. Verify `tlsReloads` +1 and `clientCertificateAuthorityNotAfter`.
2. **Move senders.** Re-issue each sender's certificate from the new CA (§6.5) and
   restart its forwarding (rsyslog keeps its disk queue).
3. **Remove** the old CA from the bundle. Any session still using an old-CA certificate
   is closed before its next frame (`tlsSessionsClosed`) and cannot reconnect.

**Live:** 100/100 frames across overlap, sender move and removal; an old-CA handshake was
refused after removal, a new-CA handshake accepted. **Do not** remove the old CA before
every sender has moved: refused senders lose frames (§3).

**Re-keying a CA that keeps its name.** When the new CA certificate has the same subject
but a new key, put both CA certificates in the bundle and, with revocation enabled, both
CAs' current lists in the CRL file (each signed by its own key). Bower judges each sender
by the lists its own issuer's key signed and ignores same-name lists signed by the other
key, so senders of both keys keep working during the overlap; a sender whose issuing key
has no current list is refused. Remove the old CA certificate and its list together once
every sender has moved. (Unit tested in both collectors.)

**A re-issued CA certificate with the same key** (new validity only) must replace the old
one in the bundle before the old one expires: a sender chain that can only end at an
expired configured CA is refused at handshake and its open session is closed.

Emergency (CA compromised): remove it from the bundle immediately and accept that its
senders stop until re-issued.

### 6.4 Syslog client revocation list (CRL)

Configure once (`clientCertificateRevocationListFile` beside the CA bundle). The file
must contain a current list for **every** CA in the bundle, or that CA's senders are
refused. Lists are PEM (`-----BEGIN X509 CRL-----`, several concatenated) or one DER
list.

```bash
# Revoke and publish with an OpenSSL CA (example).
openssl ca -config ca.cnf -revoke sender-firewall-02.pem
openssl ca -config ca.cnf -gencrl -crldays 7 -out senders-ca.crl.pem
cat senders-ca.crl.pem other-ca.crl.pem > /etc/bower/syslog/client-ca.crl.new
chown root:bower /etc/bower/syslog/client-ca.crl.new; chmod 0644 /etc/bower/syslog/client-ca.crl.new
mv /etc/bower/syslog/client-ca.crl.new /etc/bower/syslog/client-ca.crl
openssl crl -in /etc/bower/syslog/client-ca.crl -noout -nextupdate
```

**Expected:** `tlsReloads` +1; the revoked sender's open session closes at its next frame
(`tlsSessionsClosed`), reconnects are refused (`tlsRevoked`). Live: session closed within
a second, 0 frames accepted while revoked. **Renew lists before `nextUpdate`**
(alert at 2 days); an expired list refuses every sender of that CA.

How Bower applies the lists (C# and Rust identically): for each sender, only lists that
name its issuer, whose signature verifies with the key of the CA that actually issued the
sender, and whose scope covers it apply. The sender is refused when no such list exists,
when one lists its serial number, or when none is current.

- **Issuing distribution point (critical, as AD CS writes it):** supported. A list naming
  distribution points covers only senders whose certificate's CRL distribution points
  name one of them; a list limited to CA or attribute certificates never covers a sender.
  Issue sender certificates with the CDP the list's IDP names.
- **Refused with a message naming the feature** (start-up fails; a reload keeps the last
  good lists and counts a failure): lists limited to some revocation reasons, indirect
  lists, distribution points relative to the issuer, delta lists, other critical
  extensions, and signatures other than RSA PKCS#1 v1.5 or ECDSA with SHA-256/384/512.
  Example: `Syslog listener edge-tls: indirect client revocation lists are not supported.`

### 6.5 Sender (rsyslog) client certificates

1. Issue the new certificate (`extendedKeyUsage = clientAuth`) from a CA in Bower's
   bundle, valid now.
2. Replace the files rsyslog uses and restart rsyslog. Use a disk-assisted action queue
   with `queue.saveOnShutdown="on"` so queued frames survive the restart:

   ```
   action(type="omfwd" target="collector.example" port="6514" protocol="tcp"
          template="RSYSLOG_SyslogProtocol23Format" TCP_Framing="octet-counted"
          StreamDriver="ossl" StreamDriverMode="1" StreamDriverAuthMode="x509/name"
          StreamDriverPermittedPeers="collector.example" RebindInterval="0"
          queue.type="LinkedList" queue.filename="bower" queue.saveOnShutdown="on"
          action.resumeRetryCount="-1")
   ```

   ```bash
   rsyslogd -N1 && systemctl restart rsyslog
   ```

3. Revoke the old certificate (§6.4) once the sender uses the new one.

**Live:** sender moved to a new certificate mid-stream with 100/100 frames delivered.
Keep `x509/name` and `StreamDriverPermittedPeers`: the live test confirmed rsyslog
refuses a server certificate for another name (`peer name not authorized`) and keeps
the frames queued until the right certificate returns (30/30 delivered).

### 6.6 WEC transport (Kerberos or HTTPS)

Bower does not hold or validate the WEF transport credential: it reads
`ForwardedEvents` on the WEC host through the local Windows API (`NT SERVICE\Bower`
needs read access to that channel only). Rotate WinRM HTTPS certificates and Kerberos
keys with Windows tooling (Group Policy subscription manager URL, `winrm` listener
thumbprint, `wecutil`). After a WEC certificate change, verify on the WEC host:

```powershell
wecutil gr <subscription-name>   # every source: RunTimeStatus Active, LastError 0
Get-WinEvent -LogName ForwardedEvents -MaxEvents 1 | Select-Object TimeCreated, Id, MachineName
```

Bower keeps its durable receiving-log bookmark across any WEF outage; events forwarded
after the transport recovers are collected without loss
([WEC evidence](../evidence/aws-native-20261030/README.md)).

### 6.7 HMAC pseudonymisation key

**Effect of rotation:** every pseudonym changes. Pseudonyms carry the key ID
(`hmac-sha256:k1:…` before, `hmac-sha256:k2:…` after; live test), so queries can tell
the key apart, but **joins and detections across the rotation no longer match the same
account**. There is no dual-key period; the new key applies from the restart.

Scheduled rotation (yearly or on staff change with key access):

1. Generate the key and choose a new ID (never reuse an ID):

   ```bash
   umask 027; head -c 32 /dev/urandom | base64 > /etc/bower/secrets/privacy-hmac-k2.key
   chown root:bower /etc/bower/secrets/privacy-hmac-k2.key
   ```

   ```powershell
   $bytes = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
   [Convert]::ToBase64String($bytes) | Set-Content -NoNewline "$env:ProgramData\Bower\secrets\privacy-hmac-k2.key"
   ```

2. Update `BOWER_PRIVACY_HMAC_KEY_FILE` and `BOWER_PRIVACY_HMAC_KEY_ID=k2`, then restart
   the service with its supervisor (`systemctl restart bower`, `Restart-Service Bower`,
   `kubectl rollout restart`). A signed `reload` cannot apply changed environment
   variables: the running process validates only the configuration it started with (§6.8).
3. Move the old key to a vault with restricted access for the investigation retention
   period, then delete it from collectors. With the old key an investigator can compute
   an account's old pseudonym offline: `bower policy test event.json --privacy-profile
   <profile> --hmac-key-file <old-key>`.
4. Update detections that aggregate by account to span both keys, for example:

```kusto
BowerSecurity_CL
| where TimeGenerated > ago(14d) and EventType == "authentication_failure"
| extend HmacKeyId = extract(@"^hmac-sha256:([^:]+):", 1, ActorUsername)
| summarize Failures = count() by ActorUsername, HmacKeyId, bin(TimeGenerated, 1h)
```

Detections with a lookback crossing the rotation (password spray over 24 hours, for
example) under-count for one lookback window; schedule rotations accordingly and record
the time in the detection's runbook. Use one key across all collectors whose events
must correlate; a per-collector key makes the same account look different per host.

**Emergency** (key exposed): rotate as above immediately. Pseudonyms made with the
exposed key can be reversed for guessable account names by anyone holding it; treat
historic `ActorUsername` values as sensitive until they age out.

### 6.8 Pack-signing trusted keys and signed packs

**Trusted-key rotation** (one PEM public key per file):

1. Add the new public key as a **second file** and list both:
   `BOWER_PACK_TRUSTED_KEYS=/etc/bower/keys/pack-trusted.pem;/etc/bower/keys/pack-trusted-2027.pem`.
   This changes the environment, so restart with the supervisor; `reload` cannot see it.
2. Re-sign and deploy packs with the new key; verify each before deploying:

   ```bash
   bower pack verify linux-ssh-gateway-1.1.1.bowerpack --trusted-key /etc/bower/keys/pack-trusted-2027.pem
   install -o root -g root -m 0644 linux-ssh-gateway-1.1.1.bowerpack /etc/bower/packs/
   ```

3. Remove the old key file from the list and restart with the supervisor.

Concatenating two keys in one file fails closed (unit test). A pack signed only by a
removed key no longer loads.

**`reload` versus a supervisor restart.** The signed `reload` re-runs, before restarting,
everything start-up loads from **files named by the running configuration**: policies,
packs and their trusted keys, the privacy profile and HMAC key, the syslog and Windows
Event Log configurations and their routes to the packs, the syslog TLS files, source
expectations, producer scopes, ingest token files and relay files. If any would fail it
reports `reload-validation-failed` (failure type only), does not use its 10-minute rate
limit and the collector keeps running. Environment variables are fixed when the process
starts, so a changed environment file (systemd `EnvironmentFile`, the Windows service
`Environment` value, a Kubernetes manifest) is invisible to the pre-check: apply such
changes with a supervisor restart, and check them first (for example `bower pack verify`
on every listed pack with every listed key).

**Replacing a pack:** keep the previous `.bowerpack` file and replace it in place (same
path), then send `reload`; or change `BOWER_PACKS` and restart with the supervisor. A plain
restart or reboot with a bad pack on disk **stops** the collector (`Restart=on-failure`
retries every 5 s): queued events are kept, nothing is collected until the pack is
fixed. Always `bower pack verify` first.

**Rollback protection:** none. A validly signed older version loads. Control which
versions reach collectors through your deployment pipeline, and retire compromised
signing keys rather than relying on version numbers.

Emergency (signing key compromised): remove its trusted-key file from every collector
and restart; re-sign required packs with a new key first so collectors keep working.

### 6.9 Management credential and command keys

Follow [collector enrolment](../architecture/collector-enrolment.md) and
[fleet and queue integrity](../operations/fleet-and-queue-integrity.md): credentials
rotate automatically; force one with the signed `rotate-credential` command; revoke a
collector in the console (effective at its next heartbeat). Command trusted keys
(`BOWER_MANAGEMENT_COMMAND_TRUSTED_KEYS`) rotate like pack keys (both files, restart,
then remove the old file).

### 6.10 Sentinel verifier identity

Keep it separate from the ingestion identity and off the collectors. Rotate its
certificate or secret the same way as §6.1.2/§6.1.3; a lapse only affects verification,
never delivery. Confirm least privilege after each change:

```bash
az role assignment list --assignee "$(az ad sp show --id "$VERIFIER_APP_ID" --query id -o tsv)" --all \
  --query "[].{role:roleDefinitionName,scope:scope}" -o table   # Log Analytics Reader on the workspace only
```

### 6.11 Environment specifics

**Linux packages (RPM/DEB).** Secrets are files under `/etc/bower/secrets`
(`root:bower 0640`) referenced from `/etc/bower/bower.env`; the unit runs as `bower`
with `ProtectSystem=strict`, so `/etc` is read-only to the service and only root can
change credentials. systemd `LoadCredential=` copies files once at service start, so
use it only for restart-applied credentials (HMAC key, ingestion certificate), not for
syslog TLS files you want hot-reloaded:

```ini
# /etc/systemd/system/bower.service.d/credentials.conf
[Service]
LoadCredential=privacy-hmac:/etc/bower/secrets/privacy-hmac.key
Environment=BOWER_PRIVACY_HMAC_KEY_FILE=%d/privacy-hmac
```

```bash
systemctl daemon-reload && systemctl restart bower && systemctl status bower --no-pager
```

**Windows (MSI, WEC hosts).** The service runs as `NT SERVICE\Bower`; settings live in
the service's `Environment` multi-string (`HKLM\SYSTEM\CurrentControlSet\Services\Bower`).
Bower reads PEM/PFX **files**, not the certificate store: export the certificate (with
key) to `%ProgramData%\Bower\secrets` and restrict it to the service SID:

```powershell
$file = "$env:ProgramData\Bower\secrets\ingest.pfx"
icacls $file /inheritance:r /grant:r "NT SERVICE\Bower:R" "BUILTIN\Administrators:F" "NT AUTHORITY\SYSTEM:F"
icacls $file   # expect exactly those three entries
Restart-Service Bower; Get-Service Bower | Select-Object Status, StartType
```

On a WEC host keep Bower's identity separate from the WEC/WinRM certificate; rotating
one never requires touching the other.

**Docker.** Use file secrets mounted as a directory so an atomic replacement is visible:

```yaml
services:
  collector:
    environment:
      BOWER_SYSLOG_CONFIG: /run/bower/syslog.json
      BOWER_PRIVACY_HMAC_KEY_FILE: /run/secrets/bower/privacy-hmac.key
      AZURE_CLIENT_CERTIFICATE_PATH: /run/secrets/bower/ingest.pem
    volumes:
      - /srv/bower/secrets:/run/secrets/bower:ro   # directory, not single files
      - /srv/bower/syslog:/etc/bower/syslog:ro
```

```bash
docker compose up -d --force-recreate collector && docker compose logs --since 2m collector | grep -c 'did not deliver' || true
```

**Kubernetes.** The manifest uses workload identity (nothing to rotate for ingestion).
For syslog TLS and HMAC material use a Secret or the Secrets Store CSI driver with
rotation enabled, mounted as a directory (no `subPath`):

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata: { name: bower-syslog-tls }
spec:
  provider: azure            # or aws (AWS Secrets Manager / Parameter Store provider)
  parameters:
    clientID: <workload identity client id>
    keyvaultName: <vault>
    tenantId: <tenant>
    objects: |
      array:
        - |
          objectName: bower-syslog-server
          objectType: secret        # PEM bundle (certificate and key) exported by Key Vault
```

```bash
helm upgrade --install csi-secrets-store secrets-store-csi-driver/secrets-store-csi-driver \
  -n kube-system --set enableSecretRotation=true --set rotationPollInterval=2m
kubectl -n bower rollout restart deployment/bower-collector     # restart-applied credentials only
kubectl -n bower rollout status deployment/bower-collector
```

**AWS EC2.** Use the instance role and the fetch unit in §6.1.4. Turn on Secrets
Manager rotation, and on `RotationSucceeded` run the fetch (and a restart for
restart-applied credentials) through SSM Run Command against the tagged instances.
Grant `secretsmanager:GetSecretValue` on the exact secret ARNs and `kms:Decrypt` on
their key only.

**Azure VMs.** Use the VM's managed identity for ingestion. For syslog TLS and other
file credentials, install the Key Vault VM extension (it renews certificates into a
local store) or a timer running `az keyvault secret download` with the VM identity,
then copy into the Bower directories with the ownership above; Bower picks syslog TLS
changes up without a restart:

```bash
az keyvault secret download --vault-name <vault> --name bower-syslog-server \
  --file /etc/bower/syslog/server-bundle.pem.new --encoding utf-8 --overwrite
chown root:bower /etc/bower/syslog/server-bundle.pem.new && chmod 0640 /etc/bower/syslog/server-bundle.pem.new
mv /etc/bower/syslog/server-bundle.pem.new /etc/bower/syslog/server-bundle.pem
```

A single PEM bundle (certificate chain and key in one file) can be named as both
`tls.certificateFile` and `tls.privateKeyFile`; both collectors read the certificates
and the key from it. Replacing one bundle file also avoids a key/certificate mismatch
window.

**On-premises.** Connect the host to Azure Arc and use `BOWER_AZURE_CREDENTIAL=managed-identity`
(the Arc agent provides the token endpoint); otherwise use a certificate from your PKI
with the Linux or Windows steps above.

### 6.12 Troubleshooting

| Symptom | Likely cause | Check | Fix |
| --- | --- | --- | --- |
| Event 1008 `destination-azure-credential-failed` | The identity service rejected the credential (expired, deleted or wrong secret/certificate, disabled service principal, wrong tenant or client ID), or the credential configuration is missing or unusable | `az ad app credential list --id $APP_ID`; `az ad sp show --id $APP_ID --query accountEnabled`; tenant and client ID in the environment | Issue a credential, restart; re-enable the service principal (no restart) |
| Event 1008 `destination-azure-unavailable` | No answer from the DCE or the token service (DNS, proxy, firewall, TLS inspection, timeout) or a 5xx/408/429 from the token service | `curl -sS -o /dev/null -w '%{http_code}' https://login.microsoftonline.com/` and the DCE URL from the collector host; proxy settings | Fix the network path; no restart |
| Event 1008 `destination-azure-http-403` | No Monitoring Metrics Publisher role on this DCR, or the wrong identity configured | `az role assignment list --assignee $SP_ID --scope $DCR_ID` | Assign the role; wait up to 20 minutes |
| Delivery works after revoking a credential | Cached access token | Token issue time | Expected for up to about an hour; remove the role and disable the service principal to contain sooner |
| Certificate replaced but old one still used | The ingestion certificate is loaded at start | Collector start time | Restart |
| `tlsReloadFailures` increases | Torn file, key/certificate mismatch, unreadable CRL | `openssl x509 -noout -modulus` vs `openssl pkey -noout -modulus` (RSA), `openssl crl -noout -text` | Replace both files atomically, key first |
| `tlsRevoked` increases for every sender of one CA | CRL expired, missing for that CA, or signed by another key | `openssl crl -in client-ca.crl -noout -issuer -nextupdate` | Publish a current list for every CA in the bundle |
| `tlsSessionsClosed` increases | A sender's CA was removed or its certificate revoked or expired | Sender certificate issuer and dates | Re-issue the sender certificate; overlap CAs |
| rsyslog `peer name not authorized` | Server certificate SAN does not match `StreamDriverPermittedPeers` | `openssl x509 -ext subjectAltName` | Re-issue with the right name |
| Collector does not start after a pack change | Unsigned, untrusted or tampered pack, or a trusted-key file with two keys | `bower pack verify FILE --trusted-key KEY`; `journalctl -u bower -n 20` | Restore the previous pack or key file |
| `reload` reports `reload-validation-failed` | A pack, key, HMAC key, syslog route or TLS file, Windows route, expectations, scopes, tokens or relay file would not load | Collector log event 1307 (failure type) | Fix the files, then `reload` again (a refused reload does not use the 10-minute rate limit) |
| An environment change has no effect after `reload` | Environment variables are read only at process start | `systemctl show bower -p Environment` vs the file | Restart with the supervisor |
| Detections stop matching an account | HMAC key rotated | `ActorUsername` prefix `hmac-sha256:<keyId>:` | Expected; adjust the detection window (§6.7) |
| Dead letters `preflight-field-too-large` | An event too large for the Sentinel schema | `bower queue dead-letters --database …` | Review; reduce `maximumFieldLength` in the privacy profile; audited replay |

## 7. Rejected packs and malicious payloads

- **Packs:** unsigned, untrusted-key, tampered-content, malformed-manifest, missing-pack,
  missing-trusted-key and short-HMAC-key cases are refused (unit tests in C# and Rust);
  `reload` keeps the last good configuration. Trusted-key overlap rotation works; a key
  removed while its pack is deployed refuses that pack.
- **Syslog listener (live, mutual TLS, 5-second idle timeout, 8 connections, 8 KiB
  frames):** invalid UTF-8 → `malformed`; oversized, octet-count lies and overflow,
  zero/negative counts and garbage close the connection (`oversized`, `framingErrors`,
  `timeouts`); a slow-loris sender (one byte per second) was closed after 6 s; 32 of 40
  flood connections were refused at the limit and legitimate traffic continued; 6
  incomplete handshakes were closed; a 1,000-frame burst was fully queued.
  NUL, control and ANSI characters, injection text and 150-parameter structured data are
  handled as data. **CRLF injection in LF-framed messages produces a second frame**:
  configure senders for octet counting.
- **Windows mapping:** hostile values in every EventData field (secrets, injection text,
  control characters, unpaired surrogates) persist only as the account HMAC, a validated
  address and a fixed reason; a hostile address is not selected (unit tests).
- **HTTP ingest and privacy sweep (live, 40 detector samples from the redaction
  corpus in every free-text field):** 0 raw markers in the queue DB/WAL/SHM, collector
  log, status output and 28 of 29 accepted Sentinel rows. The remaining row's event ID
  was masked by a detector and was checked only in the local queue. Secret-bearing events whose redaction removed
  every actor field were quarantined (default deny). Allowed-by-policy identifiers (ABN,
  ACN, SWIFT/BIC) pass through as configured. Formula (`=HYPERLINK(…)`), KQL-looking and
  control-character text arrives in Sentinel **byte-exact**: treat exported query results
  as untrusted (CSV/Excel formula injection). An event with a 70,000-character value
  repeated across fields was dead-lettered by the schema preflight
  (`preflight-field-too-large`) instead of being truncated by Azure: alert on dead
  letters. Default detectors can mask parts of an event ID that looks like an
  identifier (a `…-licence` ID lost its digits); the row still arrived under the masked ID.

## 8. Security test procedure you can rerun

Use a disposable subscription/resource group and AWS account area you own. Never use
production credentials or data.

### 8.1 Azure credential failures

1. Deploy a workspace and `deploy/bicep/main.bicep` into a new resource group; create one
   publisher app per case with Monitoring Metrics Publisher on the DCR, and one verifier
   app with Log Analytics Reader on the workspace (§9 lists the exact set).
2. For each case run the collector locally against the DCR (`BOWER_AZURE_CREDENTIAL=environment`,
   `BOWER_DELIVERY_LEASE_SECONDS=90`, `BOWER_DELIVERY_TIMEOUT_SECONDS=60`), post 20
   baseline events to `/v1/events`, apply the fault, then start a **fresh** process
   (cached tokens hide the fault in a running one) and post 20 more.
3. Observe for at least 5 minutes: `/v1/status` `queue.retrying`, the collector log
   (event 1008), and the queue (`last_failure_code`). **Pass:** events retained, code
   matches §3, retries every ~30 s, no secret or JWT-shaped string in the queue files,
   log or status (scan them with `grep -c`).
4. Fix the fault (restart where §2 says so) and **pass** when the independent query
   (8.3) finds every accepted event ID exactly once.

`lab/aws/scripts/credential-failure-lab.py` automates steps 2–3 and the scans (set
`DOTNET_ROOT` for a framework-dependent build); its `--help` shows the `lab.json`
layout. `scan` exits non-zero if any configured secret value or JWT-shaped string is
found.

### 8.2 Syslog mutual TLS and adversarial input (Linux host)

On a disposable Amazon Linux 2023 (or any systemd Linux) host with the collector build:

```bash
sudo lab/aws/scripts/syslog-tls-setup.sh <artifact-url> <artifact-sha256> <run-id>   # rsyslog + PKI + collector
sudo python3 /opt/bower-ws5/syslog-tls-rotation.py --run-id <run-id> --phase campaign
sudo python3 /opt/bower-ws5/syslog-tls-rotation.py --run-id <run-id> --phase refusal-tls12
sudo python3 /opt/bower-ws5/syslog-adversarial.py --run-id <run-id>
```

**Pass:** baseline, server-certificate, CA-overlap and wrong-name phases accept every
frame; refused-certificate checks all `true`; `failed-reload` counted with the old
certificate still served; adversarial counters as in §7 and every `markerMatches` count 0.
The revocation and restart phases measure sender loss and are expected to lose frames.

### 8.3 Independent destination query

As the verifier only (isolated CLI cache, never the ingestion identity):

```bash
export AZURE_CONFIG_DIR=$(mktemp -d)
az login --service-principal --username "$VERIFIER_APP_ID" --certificate verifier.pem --tenant "$TENANT_ID" --allow-no-subscriptions
az monitor log-analytics query -w "$WORKSPACE_CUSTOMER_ID" -t P1D --analytics-query "
BowerSecurity_CL
| where EventId startswith '<run-id>-'
| summarize Rows = count(), Ids = dcount(EventId)" -o table
rm -rf "$AZURE_CONFIG_DIR"
```

Compare exact sorted ID lists (not `dcount`, which is approximate) against the IDs the
collector accepted; count duplicate rows separately (at-least-once delivery).

## 9. How we tested this

Full evidence, timings and preserved failures:
[`docs/evidence/ws5-20261031-074543/README.md`](../evidence/ws5-20261031-074543/README.md).

- **Azure** (subscription `945092a0-…`, `australiaeast`, `rg-bower-ws5-20261031-074543`):
  a fresh Log Analytics workspace, the repository Bicep table/DCE/DCR, six publisher
  apps scoped to the DCR and one verifier app. Collectors built from this branch ran
  locally on macOS (arm64) against the real DCR; the baseline binary is the unchanged
  `main` build, the candidate includes the fixes.
- **AWS** (account `959038055523`, `ap-southeast-2`): one private `t4g.small` Amazon
  Linux 2023 host (SSM only, no public address, encrypted disk, IMDSv2, terminate on
  shutdown with an 8-hour timer) running the linux-arm64 candidate collector and rsyslog
  8.2204 (`ossl`) over loopback mutual TLS, with OpenSSL 3.5 `openssl ca` issuing every
  certificate and CRL. No local Docker runtime was available.
- **Unit and integration tests** (C# and Rust): credential failure codes and logging,
  syslog reload/CRL/re-validation, pack reload refusal and trusted-key rotation, hostile
  Windows event data.

## 10. Known limits

- Release packages and the collector binaries used here are **unsigned** development
  builds. Pack signatures remain enforced.
- One Entra tenant and the public cloud only; sovereign clouds, Conditional Access for
  workload identities and continuous access evaluation were not tested.
- Cached access tokens make credential revocation take effect only at token expiry
  (about an hour); role removal takes 10–20 minutes. Bower cannot shorten either.
- Syslog has no application acknowledgement: refused sessions and collector restarts
  lose in-flight frames at the sender (measured). Only rsyslog 8.2204 was tested; other
  appliances need their own qualification.
- No HMAC dual-key period and no pack version pinning or rollback protection.
- Workload identity, managed identity, Key Vault extension, CSI driver and Secrets
  Manager procedures are documented from the code paths and platform behaviour; the live
  tests used client secrets and certificates (the credential types that need rotation).
- Windows hosts were not part of this run; the Windows XML fix is covered by unit and
  in-process collector tests, not a live WEC host.
- The Rust collector has no Windows source; its syslog TLS, revocation and reload
  behaviour matches C# (shared tests on both).
- A signed `reload` cannot validate changed environment variables; use a supervisor
  restart for those.
- Changes made after the live campaign (transport-versus-rejection classification of
  token failures, revocation-list selection by issuing key and IDP scope, expired-anchor
  refusal in Rust, background TLS refresh, the complete reload pre-check) are covered by
  unit and integration tests in both collectors and were not re-run against the cloud.
