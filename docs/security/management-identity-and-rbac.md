# Management identity and RBAC

## Boundary

Bower Management is optional and self-hosted. A collector keeps selecting,
queueing and delivering events when the management API is unavailable.
Management stores metadata only: machine identity, collector configuration and
policy hashes, source/output health, queue depth, approvals and management audit.
It does not store raw security-event payloads or Azure access tokens. For token
enrolment it stores token hashes and collector public keys, never a token or a
private key.

## Entra registrations

Create two single-tenant app registrations:

1. **Bower Management API** — exposes `Bower.Access` and the app roles in
   [`api-app-manifest.json`](../../deploy/entra/api-app-manifest.json).
2. **Bower Management Web** — SPA redirect URI, delegated access to
   `Bower.Access`, using
   [`spa-app-manifest.json`](../../deploy/entra/spa-app-manifest.json).

Replace every `00000000-...` placeholder before importing.

The optional [Azure Functions collector](../deployment/azure-function.md) uses a
third, separate registration, **Bower Ingest API**
([`ingest-api-app-manifest.json`](../../deploy/entra/ingest-api-app-manifest.json)).
It exposes one application-only role, `Bower.Producer`
(`12859e27-8403-42a7-b3e4-66cc808de79f`, a stable contract identifier), and no
delegated scopes. Assign it directly to each producer's managed identity or
service principal. Keeping ingest on its own audience means a management token
can never be replayed against ingest, and the reverse. Grant tenant admin
consent to the SPA's delegated API permission.

## Group-to-role mapping

Assign Entra security groups on the **Bower Management API enterprise
application**:

| App role | Suggested group | Purpose |
|---|---|---|
| `Bower.Viewer` | Bower Readers | Fleet, health, approvals, audit and privacy profile versions read |
| `Bower.Operator` | Bower Operators | Operational response; validate, preview and submit privacy profile versions |
| `Bower.Approver` | Bower Approvers | Collector enrollment decisions; approve or reject privacy profile versions authored by someone else |
| `Bower.Administrator` | Bower Administrators | Suspension, revocation and administration; assign and clear privacy profile versions on collectors |

Collector commands (heartbeat v2): `Bower.Operator` and above may issue `fetch-bundle`
and `run-canary`. Only `Bower.Administrator` may issue `reload` and `rotate-credential`.
Viewers may list commands. No command changes approval state or privacy content, so the
two-person rule below is unaffected. `fetch-bundle` only fetches the version already
approved and assigned. See [fleet controls](../operations/fleet-and-queue-integrity.md#commands).

Token enrolment: only `Bower.Administrator` may create or revoke enrolment tokens and
revoke collector credentials. Viewers and above may list token and credential metadata.
A token never approves anything: the collector still waits in `Pending` for a
`Bower.Approver`. See [token enrolment](#token-enrolment-for-collectors-without-an-azure-identity).

Privacy profile versions follow a two-person rule enforced by the API: the reviewer's
object id must differ from the author's, whatever roles either holds. See [managed
privacy profiles](../privacy/managed-privacy-profiles.md).

Users inherit a compact `roles` access-token claim through group assignment.
Bower deliberately authorizes app roles rather than raw `groups` claims, so
group overage does not weaken or complicate authorization.

Assign `Bower.Collector` directly to each collector managed identity or service
principal. Do not assign it to interactive users in production.

## API configuration

```text
Bower__Entra__TenantId=<tenant-guid>
Bower__Entra__Audience=<api-application-client-id-guid>
Bower__AllowedOrigins__0=https://bower.example.gov.au
AllowedHosts=bower-api.example.gov.au
BOWER_MANAGEMENT_LISTEN_URL=http://127.0.0.1:4320
BOWER_MANAGEMENT_DB_PATH=/var/lib/bower-management/management.db
# Optional: P-256 private key that signs collector commands (issuing returns 503 without it).
BOWER_MANAGEMENT_COMMAND_SIGNING_KEY_FILE=/run/secrets/bower-command-signing.pem
```

Use a key separate from `BOWER_MANAGEMENT_PROFILE_SIGNING_KEY_FILE`, and distribute its
public key to collectors as `BOWER_MANAGEMENT_COMMAND_TRUSTED_KEYS`.

The API validates signature, tenant issuer, audience, lifetime and app roles.
The supplied manifest requests v2 access tokens: their `aud` is the API client-ID
GUID. Keep `api://<api-application-client-id>` in resource/scope identifiers, not
the audience setting. Management API authentication is separate from Azure Monitor
ingestion authentication.
`BOWER_AUTH_MODE=development` is rejected unless
`ASPNETCORE_ENVIRONMENT=Development`.

For a single-container deployment, use
`deploy/docker/Dockerfile.management`. It builds the SPA into the management
API's static root and keeps SQLite on `/var/lib/bower-management`. Terminate TLS
at a trusted reverse proxy and expose only the approved hostname.

`compose.management.preview.yaml` exists only for local or SSH-tunnel UI testing.
It enables development authentication and binds to loopback. Never expose that
profile to a LAN, reverse proxy or production environment.

## Web configuration

Copy `ui/Bower.Management.Web/.env.example` and set the API and SPA application
IDs. Vite variables are public client configuration, never secrets. MSAL uses
popup sign-in, in-memory token caching and silent access-token acquisition with
popup fallback. Tokens are not persisted in local/session storage. Refreshing the
page clears the token cache; sign in again using the existing Entra session.
Allow sign-in popups for the approved console origin. Redirect authentication is
not supported with the in-memory cache.

## Collector enrollment flow

```text
Collector service principal receives Bower.Collector
→ collector registers machine and metadata
→ record remains Pending
→ Bower.Approver checks identity/inventory and records a reason
→ record becomes Approved
→ next identity-bound heartbeat makes it Active
→ operators see sources, queue depth and output health
→ administrators may Suspend or Revoke
```

Set on each collector:

```text
BOWER_MANAGEMENT_ENDPOINT=https://bower-api.example.gov.au/
BOWER_MANAGEMENT_SCOPE=api://<api-application-client-id>/.default
BOWER_ENVIRONMENT=production
# Optional (heartbeat v2): accept signed commands, use an explicit proxy, trust an
# inspection CA. See fleet-and-queue-integrity.md.
BOWER_MANAGEMENT_COMMAND_TRUSTED_KEYS=/etc/bower/command-signing.pub.pem
BOWER_MANAGEMENT_PROXY=http://proxy.corp.example:3128
BOWER_MANAGEMENT_CA_BUNDLE=/etc/bower/tls-inspection-ca.pem
```

The credential selected by `BOWER_AZURE_CREDENTIAL` (managed identity by default)
obtains the machine token. The token is held in memory and attached per request,
never persisted or logged. Remote endpoints must use HTTPS; the collector refuses
to start otherwise. The heartbeat runs as the `management-heartbeat` recurring job
every minute and also reports the collector's background job states. A failed heartbeat is a management health condition; it
does not interrupt the collector's local ingestion or destination delivery.

## Token enrolment for collectors without an Azure identity

On-prem servers without a managed identity or Arc enrol with a one-time token instead
of `Bower.Collector`. The approval flow is unchanged. Design:
[collector enrolment](../architecture/collector-enrolment.md).

```text
Bower.Administrator creates a token in the console (Enrolment)
  environment, optional collector id, lifetime 1-168 hours (default 24), reason
→ console shows the token once; management stores only its SHA-256 hash
→ operator writes it to the collector's token file
→ collector generates a P-256 key and exchanges token + public key
→ token consumed; record Pending; credential active (30 days)
→ Bower.Approver approves as usual → next heartbeat makes it Active
→ collector rotates its key when 10 days remain; Bower.Administrator may revoke
```

Set on the collector:

```text
BOWER_MANAGEMENT_ENDPOINT=https://bower-api.example.gov.au/
BOWER_MANAGEMENT_AUTH=enrolment
BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE=/var/lib/bower/enrolment/enrolment-token
# Delete the token file once management consumed or refused it (the installers set this).
BOWER_MANAGEMENT_ENROLMENT_TOKEN_REMOVE_AFTER_USE=true
BOWER_ENVIRONMENT=production
# Optional: accept signed commands, including rotate-credential.
BOWER_MANAGEMENT_COMMAND_TRUSTED_KEYS=/etc/bower/command-signing.pub.pem
```

`BOWER_MANAGEMENT_SCOPE` is not needed and no Azure credential is created for
management. The collector keeps its key in
`<queue directory>/management-credential/credential.json` (owner-only), with the
hash of the token it used, never the token. Remove the token file after enrolment if
you like; a new token in the file re-enrols the collector, which returns it to
`Pending`.

Controls:

- **Tokens.** 256 random bits, single use (consumed in the enrolment transaction),
  expiring, bound to an environment and optionally a collector id, hashed at rest,
  never logged and never returned after creation. Used, expired, revoked, forged and
  mis-scoped tokens are refused with one generic message and audited as
  `enrolment-token.refused:<code>`. A refusal never consumes the token. The anonymous
  enrolment endpoint allows 10 requests per minute per address
  (`BOWER_MANAGEMENT_ENROLMENT_RATE_PER_MINUTE`).
- **Credentials.** The collector's own P-256 key. Management stores the public key.
  Every request carries a 5-minute assertion signed with the private key; management
  checks it against the stored key on every request, so revocation takes effect on the
  next heartbeat. The principal is `enrolled:<collectorId>` with only `Bower.Collector`,
  and it can act only for its own collector id.
- **No take-over.** A token cannot enrol over a collector id bound to an Entra
  principal, or re-enrol a suspended or revoked collector.
- **Rotation without downtime.** The collector registers a new key under its current
  credential. Management keeps the old one valid until the new one is first used, then
  retires it. Administrators can also send `rotate-credential`
  ([commands](../operations/fleet-and-queue-integrity.md#commands)); Entra collectors
  never advertise it.

Audit actions: `enrolment-token.created`, `enrolment-token.revoked`,
`enrolment-token.used`, `enrolment-token.refused:<code>`, `collector.enrolled`,
`collector.re-enrolled`, `collector.credential-rotated`, `collector.credential-retired`
and `collector.credential-revoked`.

## Approval assurance

Approval records actor object ID, actor display name, reason and UTC time in the
same SQLite transaction as the collector state change and management audit row.
The UI never claims Sentinel delivery. Sentinel query proof remains the job of a
Bower Evidence Bundle.
