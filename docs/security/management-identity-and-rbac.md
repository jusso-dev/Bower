# Management identity and RBAC

## Boundary

Bower Management is optional and self-hosted. A collector keeps selecting,
queueing and delivering events when the management API is unavailable.
Management stores metadata only: machine identity, collector configuration and
policy hashes, source/output health, queue depth, approvals and management audit.
It does not store raw security-event payloads or Azure access tokens.

## Entra registrations

Create two single-tenant app registrations:

1. **Bower Management API** — exposes `Bower.Access` and the app roles in
   [`api-app-manifest.json`](../../deploy/entra/api-app-manifest.json).
2. **Bower Management Web** — SPA redirect URI, delegated access to
   `Bower.Access`, using
   [`spa-app-manifest.json`](../../deploy/entra/spa-app-manifest.json).

Replace every `00000000-...` placeholder before importing. Grant tenant admin
consent to the SPA's delegated API permission.

## Group-to-role mapping

Assign Entra security groups on the **Bower Management API enterprise
application**:

| App role | Suggested group | Purpose |
|---|---|---|
| `Bower.Viewer` | Bower Readers | Fleet, health, approvals and audit read |
| `Bower.Operator` | Bower Operators | Operational response |
| `Bower.Approver` | Bower Approvers | Collector enrollment decisions |
| `Bower.Administrator` | Bower Administrators | Suspension, revocation and administration |

Users inherit a compact `roles` access-token claim through group assignment.
Bower deliberately authorizes app roles rather than raw `groups` claims, so
group overage does not weaken or complicate authorization.

Assign `Bower.Collector` directly to each collector managed identity or service
principal. Do not assign it to interactive users in production.

## API configuration

```text
Bower__Entra__TenantId=<tenant-guid>
Bower__Entra__Audience=api://<api-application-client-id>
Bower__AllowedOrigins__0=https://bower.example.gov.au
AllowedHosts=bower-api.example.gov.au
BOWER_MANAGEMENT_LISTEN_URL=http://127.0.0.1:4320
BOWER_MANAGEMENT_DB_PATH=/var/lib/bower-management/management.db
```

The API validates signature, tenant issuer, audience, lifetime and app roles.
`BOWER_AUTH_MODE=development` is rejected unless
`ASPNETCORE_ENVIRONMENT=Development`.

For a single-container deployment, use
`deploy/docker/Dockerfile.management`. It builds the SPA into the management
API's static root and keeps SQLite on `/var/lib/bower-management`. Terminate TLS
at a trusted reverse proxy and expose only the approved hostname.

## Web configuration

Copy `ui/Bower.Management.Web/.env.example` and set the API and SPA application
IDs. Vite variables are public client configuration, never secrets. MSAL uses
redirect sign-in, session storage and silent access-token acquisition. No token
is written to local storage by Bower code.

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
```

`DefaultAzureCredential` obtains the machine token. The token is held in memory,
not persisted or logged. A failed heartbeat is a management health condition; it
does not interrupt the collector's local ingestion or destination delivery.

## Approval assurance

Approval records actor object ID, actor display name, reason and UTC time in the
same SQLite transaction as the collector state change and management audit row.
The UI never claims Sentinel delivery. Sentinel query proof remains the job of a
Bower Evidence Bundle.
