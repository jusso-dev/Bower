# Producer identity scopes and SEC-01/SEC-05 migration

HTTP authentication identifies a producer; it does not prove the application,
tenant or source named in its payload. Both collectors now default to denying
ingest without a matching identity scope. Authentication and status access remain
unchanged. Denial returns HTTP 403 with a fixed message, before policy evaluation,
privacy-alert generation or persistence; no original event row is written.

Set `BOWER_PRODUCER_SCOPES_FILE` to a local JSON array, for example:

```json
[
  {
    "producer": "portal",
    "application": {
      "name": "customer-portal",
      "environment": "production",
      "tenantId": "customer-a",
      "instance": "portal-01"
    },
    "source": { "hostname": "portal-01", "ipAddress": "192.0.2.10", "port": 443 }
  }
]
```

The producer is the ID in `BOWER_INGEST_TOKENS_FILE`; a shared token uses
`default`, and unauthenticated loopback uses `anonymous`. The
[Azure Functions collector](../deployment/azure-function.md) uses the same file
format and semantics (or the same JSON in `BOWER_PRODUCER_SCOPES_JSON`); there the
producer is the caller's Entra `oid` (service principal object ID, lower-case GUID),
or its `azp` client ID with `BOWER_PRODUCER_CLAIM=azp`. Each array entry is one
complete tuple: application name, environment, tenant ID, instance, source
hostname, IP address and port. All comparisons are exact and case-sensitive.
Missing and null optional values mean **only absent/null**, never wildcard.
An absent source is equivalent to a source with all three fields absent/null.
Application version is not an authorization identity. Multiple entries grant
multiple complete tuples, never independent sets whose cross product is allowed.
Source fields describe reported event origin, not authenticated network peer IP.
For a producer reporting variable client IPs, enumerate approved tuples or place
that producer in a separately isolated collector trust domain; there is no source
wildcard that silently defeats isolation.

The scopes file is loaded at startup, at most 1 MiB / 4096 entries. Unknown
configuration fields, duplicate keys, wrong types and missing required identity
fields fail startup without echoing values. Protect the file like other collector
authorization configuration. Scope edits require restart; token removal retains
its existing two-second reload behavior. Do not reuse producer IDs or credentials
across trust domains. See `schemas/producer-scopes.schema.json` for the format.

For an intentionally single trust domain, explicitly set
`BOWER_SINGLE_TRUST_DOMAIN=true`. This accepts every identity asserted by every
authenticated producer (or by anonymous callers where unauthenticated intake was
already allowed). It provides **no producer, application or tenant isolation**.
It cannot be combined with a scopes file. Keep it limited to isolated development
or collectors whose entire producer population has equal attribution authority.
It does not bypass the existing non-loopback authentication requirement.

## Upgrade and rollback

Before upgrading, inventory producer IDs and exact identity tuples; install scopes
and test legitimate and impersonated events. Otherwise authenticated requests
receive 403 by default. Existing deployment examples require this configuration
or the explicit single-domain setting; older manifests do not imply permission.
The configuration hash now includes the scope path and trust mode; it does not
attest file contents. Scope changes require controlled restart in both runtimes.

No event schema or database migration is required. Existing queued payloads are
not rewritten: pre-upgrade events may still contain secrets or unauthorized
attribution. Quarantine/reconcile those records through a separately authorized
incident process before trusting or replaying them. Rolling back removes these
enforcement controls; do not expose an old collector to isolated producers.

## Semantic privacy behavior

Before/after values in `change` are removed except for reviewed event/field
pairs: `role_membership_changed` with `role`, and `aws_cloudtrail` or
`gcp_cloud_audit` with `permission_direction`. Cloud direction values are limited
to the mapper's grant/revoke/mixed/replacement vocabulary; bounded identity and
permission details use the structured context described in
[cloud permission context](../deployment/cloud-permission-context.md). These
reviewed fields retain investigation context and still pass value detectors.
Unknown fields, passwords, token fields, missing field names and non-scalar values
cannot retain before/after content. Extend the allowlist only with event-specific
regression tests; this does not enable arbitrary attribute forwarding.

URL-like fields (`path`, `url`, `uri`, `href`, `endpoint`, request/redirect URL/URI)
and strings beginning with HTTP(S) lose all query and fragment content, including
encoded query/fragment delimiters. Absolute and network-relative URLs also lose
userinfo. Ambiguous encoded authorities, backslashes and control characters are
replaced entirely. Ordinary origin/path spelling remains; secrets placed in path
segments or unrelated free text still require source-specific avoidance and value
detectors. These structural guards cannot be disabled by detector Allow settings.
Metadata records only `field-name-secret` actions, never removed values.

Tests exercise serialized accepted events, live SQLite/WAL, AMA spool files and
captured/decompressed Azure requests in both runtimes. Azure responses are
simulated; these tests establish no Sentinel query or production delivery claim.
