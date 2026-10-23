# Cloud permission event catalogue and population matrix

AWS CloudTrail and GCP Cloud Audit Logs carry permission investigation context
without raw forwarding. The initiating identity stays in `actor`; it is never
replaced with the identity whose access changed. A denied request describes
**attempted** changes, not effective grants: always query `eventResult` too.

No envelope schema or DCR change is needed. Existing `target`, `change` and
`attributes` objects project to Sentinel `Target`, `Change` and `Attributes`, and
are included in `RawEnvelope` by the default transform.

## Population matrix

All rows use `change.field = permission_direction`. Only literal `grant`, `revoke`,
`mixed`, `replace` and `unknown` survive in `change.newValue` for these cloud event
types. `previousValue` is never populated and remains denied by privacy. Arbitrary
before/after values and policy documents remain prohibited.

| Event type / action | Target | Entry member | Entry permission | Direction / mode |
|---|---|---|---|---|
| `aws_cloudtrail` / `AttachUserPolicy`, `DetachUserPolicy` | `aws-iam-user`, `requestParameters.userName` | Affected user name | Exact `policyArn` | `grant` / `revoke`, `delta` |
| `aws_cloudtrail` / `AttachRolePolicy`, `DetachRolePolicy` | `aws-iam-role`, `roleName` | Affected role name | Exact `policyArn` | `grant` / `revoke`, `delta` |
| `aws_cloudtrail` / `AttachGroupPolicy`, `DetachGroupPolicy` | `aws-iam-group`, `groupName` | Affected group name | Exact `policyArn` | `grant` / `revoke`, `delta` |
| `aws_cloudtrail` / `AddUserToGroup`, `RemoveUserFromGroup` | `aws-iam-group`, `groupName` | Affected `userName` | Group name (membership) | `grant` / `revoke`, `delta` |
| `aws_cloudtrail` / `UpdateAssumeRolePolicy` | `aws-iam-role`, `roleName` | Each submitted `Statement.Principal` | Each submitted `Statement.Action` | Summary `replace`, entries `present`, `replacement` |
| `gcp_cloud_audit` / `SetIamPolicy`, or qualified method ending `.SetIamPolicy` (case insensitive) | Existing resource type and `resourceName` | Each `bindingDeltas.member` | Matching `bindingDeltas.role` | `ADD` = `grant`, `REMOVE` = `revoke`; both = `mixed`, `delta` |
| Same GCP action, no delta but `request.policy.bindings` available | Same resource | Each binding member | That binding's role | Summary `replace`, entries `present`, `replacement` |
| Recognised action with no request/delta context | Available resource or AWS service endpoint fallback | None | None | `unknown`, `unavailable` |

AWS requires `eventSource = iam.amazonaws.com`. Other actions/services retain
existing mapping. GCP deltas come from
`protoPayload.serviceData.policyDelta.bindingDeltas`, or
`protoPayload.metadata.policyDelta.bindingDeltas` when the former is absent.
Deltas take precedence over request policies. An empty delta has `mode = delta`,
`newValue = unknown` and zero entries; it does not assert a grant.

Selection remains separate. AWS pack 1.1.0 and EventBridge identity rules now
include `DetachUserPolicy`, `DetachRolePolicy`, `DetachGroupPolicy` and
`RemoveUserFromGroup` alongside grants. Collector policy tests pin these revoke
operations. Rules remain disabled by default until reviewed deployment. Other
mapper support does not automatically broaden policy or upstream acceptance.

## Compound representation

`attributes["cloud.permissionChanges"]` is a structured object, not a string
containing an unreviewed source document:

```json
{
  "mode": "delta",
  "target": "projects/example",
  "targetNameTruncated": false,
  "entries": [
    {"member": "allUsers", "permission": "roles/viewer", "direction": "grant", "conditionPresent": false},
    {"member": "allAuthenticatedUsers", "permission": "roles/owner", "direction": "revoke", "conditionPresent": true}
  ]
}
```

Member, permission and direction remain associated per entry. Order follows the
source; duplicates are not collapsed. AWS entries also carry a fixed `memberType`:
`user`, `role`, `group`, or trust principal kind (`AWS`, `Service`, `Federated`,
`CanonicalUser`, `wildcard`). Trust entries carry allowlisted `effect` (`Allow` or
`Deny`) and `conditionPresent`.

Trust-policy updates replace the document. Without prior state, removed principals
and effective new grants cannot be inferred. `present` means only that the submitted
replacement contains that entry. The same rule applies to GCP replacement snapshots.
Conditions are represented by presence alone: expressions, descriptions, external
IDs, Sids, etags and other unrestricted values are never copied. Conditional entries
must not be interpreted as unconditional access. Negated AWS `NotPrincipal` and
`NotAction` constructs are rejected rather than misrepresented. AWS trust documents
can be objects, JSON strings or URL-encoded JSON strings, with scalar or array
statements, principals and actions.

## Bounds, privacy and rejection

- At most 64 entries per event, including the AWS principal/action cross product.
  Input binding/member/statement/action arrays are also limited to 64.
- Extracted identifiers must be nonblank, contain no control characters and fit
  2,048 UTF-16 code units. Long policy ARNs and federated principals are preserved
  without squeezing them into labels or 256-character identity fields.
- Complete compact JSON-escaped context is limited to 32,768 UTF-8 bytes, leaving
  room below Azure's 64 KiB field limit for the attributes wrapper and privacy
  processing. Existing input and output preflight limits still apply.
- Full target is in `cloud.permissionChanges.target`. `target.name` retains the
  schema's 256-character display prefix; `targetNameTruncated = true` makes that
  loss explicit. Do not use a flagged display prefix as an exact resource ID.
- Invalid shapes, missing required entry fields, unknown delta actions and excess
  identifiers/entries/bytes reject the **whole** mapping with a metadata-only typed
  error. Lists and identifiers are never silently truncated. The cloud host releases
  malformed messages for retry/dead-letter handling; no partial acknowledgement.
  Missing source context instead produces explicit `unavailable` mode.
- All values still pass secret/PII detectors. Default email masking changes
  email-shaped principals. Tenants explicitly allowing email retention can preserve
  those identities exactly; HMAC profiles can deliberately pseudonymise them.
  Profiles targeting only `actor` do not automatically cover structured members;
  configure relevant detector actions too. Custom privacy field-length limits can
  further shorten identifiers after mapping.
- Both cloud mapper options default raw inclusion **off**. The AWS direct mapper
  previously defaulted it on; the queue agent already defaulted it off. Explicit
  `IncludeRawRecord = true` remains a separate opt-in, can exceed output bounds,
  and is unnecessary for permission context. Keep it disabled in production.

## Verification and limits

`CloudPermissionContextTests` covers attachment/removal, group membership, trust
replacement, both GCP delta locations, multi-binding snapshots, mixed directions,
long identifiers, configured/default email handling, canaries and rejection bounds.
Accepted fixtures traverse redaction, collector validation, SQLite reopen/lease,
ingestion preflight and captured simulated Azure upload. Exact structured context
is asserted at each boundary; database files and captured bodies are checked for
synthetic secrets. C# `SemanticPrivacyTests` and Rust `semantic_privacy` pin the
fixed direction allowlist and matching JSON bytes.

These local tests do not prove live cloud collection, selection, deployment or
query-verified Sentinel delivery.

Source shapes: [AWS IAM API reference](https://docs.aws.amazon.com/IAM/latest/APIReference/Welcome.html),
[GCP policy history](https://cloud.google.com/iam/docs/review-iam-policy-history),
[GCP BindingDelta](https://cloud.google.com/iam/docs/reference/rpc/google.iam.v1#bindingdelta).
