# Token enrolment and credential rotation: design note

Issue #109 (epic #116). Builds on [heartbeat v2](heartbeat-v2.md), whose `rotate-credential`
command this note gives an action.

## Scope

- An administrator creates a one-time enrolment token in the console. It is short-lived
  (default 24 hours, at most 7 days), bound to an environment and optionally to one
  collector id, and stored only as a SHA-256 hash. The console shows it once.
- A collector without an Azure identity exchanges the token for a key-bound credential.
  The record lands in `Pending`, and an approver decides exactly as for Entra collectors.
- Scheduled rotation (the collector rotates when 10 of the credential's 30 days remain),
  the `rotate-credential` command, and console revocation of tokens and credentials.

## Non-goals

- Shared long-lived secrets across collectors. Every credential is a key the collector
  generated; management holds only its public key.
- Inbound connections to collectors and new commands. `rotate-credential` was already in
  the closed set.
- Entra workload identity federation. Collectors that can obtain an Entra token keep using
  `BOWER_MANAGEMENT_AUTH=entra` (`BOWER_AZURE_CREDENTIAL=workload-identity` included).

## Why a key-bound credential, not a TLS client certificate

The issue allows either a client certificate issued by management or a registration
against an Entra app. Bower uses the property a client certificate gives (a private key
that never leaves the host, verified by management) without TLS client authentication:

- Management usually sits behind a TLS-terminating reverse proxy, and heartbeat v2
  supports TLS-inspection proxies on the collector side. Both break mutual TLS.
- A signature over the request credential works through both, and needs no certificate
  authority key on the management host.

So the credential is the collector's P-256 public key, registered at enrolment. Its id is
the key id Bower already uses for signatures (the first 16 hex characters of SHA-256 over
the public key). Each request carries a short-lived assertion signed with the private key:

```text
Authorization: Bearer bwc1.<base64url canonical payload>.<base64url P1363 signature>
payload = {"collectorId","credentialId","expiresAt","issuedAt","kind":"bower.collector-assertion/v1","nonce"}
```

The payload is canonical JSON, so the C# and Rust collectors sign identical bytes.
Management accepts only those exact bytes, a lifetime of at most 10 minutes (collectors
sign 5), 5 minutes of clock skew, and a signature by the stored key of an active,
unexpired credential that belongs to the named collector. The signed `kind` keeps an
assertion from verifying as a command, pack or evidence signature, and the reverse.

An assertion is a bearer value for its 5 minutes, like the Entra token it replaces (which
lasts an hour). TLS protects it in transit, and it is never stored or logged.

## Lifecycle

```text
Administrator creates token (environment, optional collector id, 1-168 h, reason)
→ console shows bwe1.<id>.<secret> once; management stores sha256(token)
→ operator writes it to BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE
→ collector generates a P-256 key, persists it, POST /api/collectors/enrol
→ token consumed in the same transaction; collector record Pending; credential active
→ approver approves (unchanged); next heartbeat makes it Active
→ 20 days later: collector registers a new key under the current credential
→ first use of the new key retires the old one
```

- **Refusals.** A malformed, unknown, forged, used, revoked or expired token, the wrong
  environment or collector id, an Entra-bound collector id, a suspended or revoked
  collector, and a reused key are all refused and audited as
  `enrolment-token.refused:<code>`. A refusal never consumes the token. The response is
  one generic message; the code is in the audit.
- **Lost responses.** The collector persists the new key before sending. Retrying the same
  token with the same collector id and key returns the credential that exchange issued.
  Retrying a rotation with the same key returns the same successor.
- **Re-enrolment.** A new token in the token file re-enrols: management revokes the old
  credentials and returns the record to `Pending`. Suspended and revoked collectors cannot
  re-enrol; an administrator decides first.
- **Revocation.** Every request re-reads the credential, so a revoked credential is
  refused on the collector's next heartbeat. Revoking the collector record works as before.

## Rotation without downtime

Management keeps the current credential valid while a successor exists but is unused.
The collector switches only after management confirms the successor, and the first
request signed with the successor retires the old credential. Every failure path leaves a
working credential:

| Failure | State |
|---|---|
| Rotation request lost | Old credential works; retry sends the same pending key |
| Response lost after management issued the successor | Old works; retry returns the same successor |
| Collector cannot save the new key | Old works; the unused successor is retired by the next rotation |
| Management refuses (suspended, key reused) | Old works; the next attempt uses a fresh key |

## Wire contract

| Endpoint | Caller | Result |
|---|---|---|
| `POST /api/enrolment-tokens` | `Bower.Administrator` | 201 with the token, once |
| `GET /api/enrolment-tokens` | `Bower.Viewer` and above | Metadata, never the token or hash |
| `POST /api/enrolment-tokens/{id}/revoke` | `Bower.Administrator` | Unused tokens only |
| `POST /api/collectors/enrol` | Anonymous (the token is the credential), 10 per minute per address | 202 with the credential metadata, record `Pending` |
| `POST /api/collectors/{id}/credentials/rotate` | The enrolled collector's own credential | 200 with the successor metadata |
| `GET /api/collector-credentials` | `Bower.Viewer` and above | Metadata, never key material |
| `POST /api/collectors/{id}/credentials/{credentialId}/revoke` | `Bower.Administrator` | Refused from the next request |

An enrolled collector authenticates only as `Bower.Collector`, bound to its own collector
id (principal `enrolled:<collectorId>`, never a GUID, so never an Entra object id). It
cannot register, heartbeat, fetch a profile for, or rotate any other collector.

## Collector state

`<queue directory>/management-credential/credential.json`, owner-only (0600 in a 0700
directory on Unix; rely on the directory ACL on Windows). The C# and Rust collectors read
each other's file:

```json
{"schemaVersion":1,"collectorId":"edge-01","credentialId":"…","privateKeyPem":"…",
 "expiresAt":"2026-11-26T00:00:00.0000000Z","pendingPrivateKeyPem":null,
 "consumedTokenSha256":"…","refusedTokenSha256":null}
```

The file holds the private key and the hashes of tokens already exchanged or refused,
never a token. A collector never uses a credential issued to another collector id.

## Test plan

- Management: token lifecycle and authorisation, Pending and approval, every refusal
  audited, idempotent retry, Entra take-over and suspension refused, credential binding,
  forged, expired, early and wrong-key assertions, revocation on the next heartbeat,
  rotation keeping the old credential until the new one is used, and the enrolment rate
  limit.
- Collector, end to end against the in-process management API: enrol, report, rotate by
  command and on schedule, revoke, re-enrol, refused tokens not retried, owner-only file
  without the token.
- Parity: the canonical payload text and the enrolment-mode configuration hash are pinned
  in both runtimes, a Rust-signed assertion verifies in the C# management API, the Rust
  collector reads the C# credential file, and the Rust tests cover the same collector
  behaviour against a fake management API.
- Compose: the CI `docker` job enrols the C# and Rust collector images against the
  management image with a real token, then approves them.
