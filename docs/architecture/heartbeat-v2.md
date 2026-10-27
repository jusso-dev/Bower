# Heartbeat v2: design note

Issue #108 (epic #116). Later fleet work (#109 enrolment, #110 relay, #111 air-gap,
#113 fleet view) builds on this contract.

## Scope

- A versioned heartbeat. v2 adds fields to the v1 body. v1 and v2 collectors and
  management APIs keep working in every combination.
- More metadata in the payload: heartbeat interval, oldest undelivered age, last
  successful delivery, last canary result, the command types the collector supports
  and command results. Version, configuration hash, queue depth and per-source health
  were already sent in v1. Management works out the source health summary from the
  per-source report.
- Outbound-only commands, delivered in the heartbeat response. The set is closed:
  `fetch-bundle`, `run-canary`, `reload` and `rotate-credential`. Each command is
  signed by management and bound to one collector id, a nonce and an expiry. The
  collector reports the result on its next heartbeat.
- Query-time connectivity: `online`, `stale` (no heartbeat for 2 intervals),
  `unhealthy` (delivery failing for 15 minutes) and `offline` (15 minutes). This sits
  apart from the 30-day suspension.
- Proxy support for the management channel: the standard `HTTPS_PROXY`, `HTTP_PROXY`
  and `NO_PROXY` variables, an explicit proxy with a username and a password file, and
  an extra CA bundle for TLS-inspection proxies. TLS verification is never turned off.

## Non-goals

- Inbound connections to collectors, arbitrary remote execution, and a long-poll
  command channel (the issue marks long-poll optional; commands wait for the next
  minute's heartbeat).
- Credential rotation. `rotate-credential` is part of the closed set so the wire
  contract stays stable. #109 gave it an action: a token-enrolled collector advertises
  it and rotates its key-bound credential ([collector enrolment](collector-enrolment.md)).
  Entra collectors have nothing to rotate, never advertise it and refuse it with
  `unsupported-command`.
- Hot reload (#96). `reload` is a supervised graceful restart (exit code 75), the same
  mechanism that applies a managed privacy profile.
- Console views. #113 builds the fleet view on the new fields.

## Wire contract

Request (`POST /api/collectors/{id}/heartbeat`): v1 fields unchanged, plus
`schemaVersion: 2`, `heartbeatIntervalSeconds`, `oldestUndeliveredAgeSeconds`,
`lastSuccessfulDeliveryAt`, `lastCanary`, `commandCapabilities` and `commandResults`.
A body without `schemaVersion` is v1.

Response: a v1 request still gets the collector record. A v2 request gets
`{schemaVersion: 2, collectorId, status, commands: [...], acknowledgedResults: [...]}`.
A v2 collector ignores any response without `schemaVersion: 2`, so an older management
API delivers no commands. It also keeps unacknowledged results and sends them again.

Signed command:

```json
{
  "kind": "bower.collector-command/v1",
  "commandId": "<32 hex>", "collectorId": "edge-01", "command": "run-canary",
  "nonce": "<32 hex>", "issuedAt": "2026-10-26T00:00:00.0000000Z",
  "expiresAt": "2026-10-26T00:15:00.0000000Z",
  "signature": { "algorithm": "ES256", "keyId": "…", "value": "…" }
}
```

The signature is ECDSA P-256 over the canonical JSON of every field except
`signature`. Because the `kind` field is signed, a command signature can never verify
as any other Bower document.

## Invariants touched

- No arbitrary execution. Every command maps to one fixed action. Configuration and
  management cannot supply code, paths or arguments.
- Delivery, acknowledgement and queue state stay out of scheduled jobs. The heartbeat
  job only verifies commands and hands accepted ones to a hosted command worker. The
  worker does the work (the canary enqueue goes through the normal pipeline, with
  redaction and policy first).
- Metadata only. Payloads, logs and audit rows hold ids, codes and times, never event
  content, tokens or proxy credentials.
- Four-eyes rules stay as they are. `fetch-bundle` only fetches the privacy profile
  assignment that management already serves, which needed two-person approval. No
  command changes policy, privacy content or approval state.

## Failure modes and bounds

The collector refuses a command and reports `rejected` with a code. It fails closed in
this order:

1. `malformed-command`
2. `untrusted-signature`
3. `wrong-collector`
4. `unknown-command`
5. `not-yet-valid` (more than 5 minutes of clock skew)
6. `expired`
7. `invalid-lifetime` (over 1 hour)
8. `replayed` (the command id was seen with another nonce, or the nonce was seen with
   another id)
9. `unsupported-command`
10. `commands-not-configured` (no trusted command keys, or any configured key is not a
    readable P-256 public key; keys are parsed at start-up and the collector then
    advertises nothing)
11. `ledger-unavailable` or `ledger-full`

A `malformed-command` or `untrusted-signature` result never carries a command id. Only a
signature-verified document may name a command, so a tampered copy injected on the path
cannot mark the real command rejected.

Redelivering the same command id and nonce is a no-op. The original result is
reported again until management acknowledges it.

Management expires overdue commands in two places: the v2 heartbeat exchange and the
5-minute `collector-staleness` job. The job covers collectors that are offline,
suspended or downgraded to v1, so every expiry is audited once. Reads show overdue
commands as `expired` straight away.

Execution is at most once. The command is written to the durable ledger before it
runs. A command found started but not finished after a restart reports `failed` with
`interrupted`. A reload within 10 minutes of the last one reports `failed` with
`reload-rate-limited`.

Bounds:

| Item | Limit |
|---|---|
| Response body | 64 KiB |
| One heartbeat exchange, request to the end of the body | 15 s |
| Reported heartbeat interval | 15 to 300 s (2 intervals stay inside the 15-minute offline threshold) |
| Commands considered per response | 8 |
| Results per heartbeat | 32 |
| Ledger entries | 128 |
| Outstanding commands per collector (management) | 16 |
| Command lifetime | 1 to 60 minutes, default 15 |

## Test plan

- Compatibility matrix: v1 body to the new API, v2 body to the new API, and a v2
  collector against a v1-style response.
- Command verification: forged, tampered, wrong collector, unknown, expired,
  not-yet-valid, replayed and over-long commands, checked against C# vectors in both
  runtimes.
- Idempotent redelivery, results reported and acknowledged on the next heartbeat,
  interrupted commands, and reload rate limiting.
- Management: issue authorisation by command type, capability gating, delivery,
  result audit, expiry audit and refusal audit.
- Proxy: explicit proxy with credentials, environment proxy, CA bundle merge and
  rejection of invalid settings. In C#, an in-process authenticated CONNECT proxy in
  front of an HTTPS server whose certificate chains to a private CA.
- No secrets: the heartbeat body never contains the bearer token, the proxy password
  or the ingest token.
