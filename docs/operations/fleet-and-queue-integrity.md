# Fleet controls and queue integrity

## Per-producer ingest credentials

Instead of one shared token, give each producer its own revocable credential:

```bash
bower token generate --id sidecar-01      # token on stdout, tokens-file line on stderr
```

```text
# /etc/bower/ingest-tokens  (BOWER_INGEST_TOKENS_FILE)
sidecar-01 sha256:3f1c…
customer-portal sha256:9ab2…
```

The file holds SHA-256 hashes only. Remove a line to revoke that producer; the
collector reloads the file within seconds without a restart. Each accepted event
records its producer in `collector.sourceAdapter` (`local-http:sidecar-01`).
`BOWER_INGEST_TOKEN` still works and is producer `default`. Credentials must also
match [producer identity scopes](../security/producer-scopes.md). Ingest defaults
to deny without scopes; single-trust-domain compatibility requires explicit opt-in.

## Policy assignment and acknowledgement

Every heartbeat reports the collector's **policy bundle hash** (policies, packs,
privacy profile). An administrator sets the expected hash:

```http
POST /api/collectors/{id}/desired-policy
{ "policyHash": "sha256:…", "reason": "Roll out linux-ssh-gateway 1.1.0" }
```

The console shows each collector as *In sync*, *Drift* or *Unassigned*; drifted
collectors appear in fleet exceptions. The action is audited.

## Fleet overview: exceptions and source coverage

`GET /api/overview` is computed at query time from the 15-minute heartbeat
threshold the `collector-staleness` job uses, so its result does not depend on
whether the job has run. A collector is *eligible* when it is `Active` and its
last heartbeat is fresh.

- **Source coverage.** `sourcesReporting` counts `healthy` sources of eligible
  collectors only. `sourcesDegraded` counts every other source, so
  `sourcesReporting + sourcesDegraded` is always every known source and a
  collector that stops reporting cannot improve the score by disappearing.
  `sourcesUnknown` is the part of `sourcesDegraded` with no evidence either way:
  every source of a stale, pending, suspended or revoked collector, and `pending`
  sources (never seen but still inside their first allowance) of eligible
  collectors. `silent`, `never-seen` and any other status stay degraded. The
  console shows unknown as its own *Unknown* row. A fresh heartbeat from an
  authorised, active collector restores its sources.
- **Privacy profile drift.** An eligible collector whose heartbeat reports a
  privacy profile hash other than its assigned version's is a fleet exception and
  counts in `privacyProfileDrift`. `privacyProfileExceptions` lists up to 12 of
  them: the desired assignment (revision, time, version id, profile id, version
  and content hash) against the observed hash and the heartbeat time that
  reported it. `mismatchConfirmed` is true only when that heartbeat arrived at
  least two minutes after the assignment (the collector's heartbeat and
  deployment jobs each run every minute, independently); before that the console
  shows *Awaiting heartbeat* rather than *Not applied*. A collector whose latest
  assignment history row does not assign the version it holds (a concurrent
  change) is counted but not listed, never shown with an invented revision. Rows
  carry hashes and identifiers only, never profile content or key material.
  Unassigned collectors are unaffected; a matching hash clears it. The console
  shows "12 of N shown" when the list is truncated and links each row to the
  assigned version on the privacy profiles page.

## Heartbeat v2

Collectors send `schemaVersion: 2` heartbeats. v2 adds metadata to the v1 body:

- the heartbeat interval (60 s)
- the age of the oldest undelivered event
- the last successful delivery (the last output acknowledgement since start-up;
  management keeps the last time it was told)
- the last canary result
- the command types the collector supports
- command results

Management works out the source health summary (`sourceSummary`) from the per-source
report. Sources that are `pending` (#81) get their own count and are neither healthy
nor degraded.

The design is in [heartbeat v2](../architecture/heartbeat-v2.md). Compatibility:

| Collector | Management | Result |
|---|---|---|
| v1 | v2 | Works as before. The response is the collector record and no commands are sent. |
| v2 | v1 | The extra fields are ignored. The response has no `schemaVersion: 2`, so the collector takes no commands and keeps its results. |
| v2 | v2 | The response holds signed commands and the result ids management recorded. |

### Connectivity

`GET /api/collectors`, `GET /api/collectors/{id}` and the overview exceptions carry a
query-time `connectivity` value:

| Value | Meaning |
|---|---|
| `online` | Heartbeating normally. |
| `stale` | No heartbeat for more than 2 intervals, so it shows within 2 minutes. Reported intervals are limited to 15–300 s, so `stale` always comes before `offline`. |
| `offline` | No heartbeat for 15 minutes (the `collector-staleness` threshold). |
| `unhealthy` | Heartbeating, but every heartbeat for at least 15 minutes reported a failing delivery status. |
| `pending`, `suspended`, `revoked` | The lifecycle state. |

This sits apart from the 30-day inactivity suspension below.

### Commands

Commands travel outbound only, inside the heartbeat response. Nothing connects in to a
collector. The set is closed:

| Command | Collector action | Role to issue |
|---|---|---|
| `fetch-bundle` | Fetches the signed privacy profile assignment now (`managed-privacy-profile` job). Management privacy mode only. | `Bower.Operator` |
| `run-canary` | Queues one synthetic `collector_canary` event through redaction and policy. `queued` means local admission, not Sentinel arrival. Use an evidence bundle for delivery proof. | `Bower.Operator` |
| `reload` | Graceful supervised restart (exit code 75), at most once every 10 minutes. | `Bower.Administrator` |
| `rotate-credential` | Not supported yet (#109). Collectors never advertise it, so it cannot be issued. | `Bower.Administrator` |

```http
POST /api/collectors/{id}/commands
{ "command": "run-canary", "reason": "Check the pipeline after a firewall change", "expiresInMinutes": 15 }

GET /api/collectors/{id}/commands
```

Management signs each command once with `BOWER_MANAGEMENT_COMMAND_SIGNING_KEY_FILE`
(ECDSA P-256). It binds the command to the collector id, a random nonce and an expiry of
1–60 minutes (default 15). Without the key, issuing returns 503 and everything else
keeps working. A command can only be issued to an active collector that advertised it
on its last heartbeat. At most 16 can be outstanding per collector.

Collectors trust the PEM public keys in `BOWER_MANAGEMENT_COMMAND_TRUSTED_KEYS`. Without
them a collector advertises nothing and refuses every command. The collector:

1. Verifies the signature, collector id, closed set and validity window. It allows
   5 minutes of clock skew.
2. Records the command in a durable ledger (`management-commands/ledger.json` next to the
   queue).
3. Runs the command once, from a hosted worker rather than the heartbeat job.
4. Reports the result on the next heartbeat until management acknowledges it.

A replayed, forged, expired, unknown or unsupported command is refused with a code, as
listed in the design note. Only signature-verified documents are reported with their
command id.

Overdue commands are expired by the v2 heartbeat exchange and by the 5-minute
`collector-staleness` job. The job covers offline, suspended and v1 collectors. Reads
show them as `expired` straight away.

Management audits every step:

- `collector.command-issued:<command>`
- `collector.command-refused` (an unknown command at the API)
- `collector.command-forbidden:<command>` (the caller's role may not issue it)
- `collector.command-delivered`
- `collector.command-succeeded`, `-failed` and `-rejected`
- `collector.command-expired`
- `collector.command-result-unknown` (a result for a command management never issued)

### Proxies and TLS inspection

The management channel honours the standard `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`
variables. To use one proxy for management only, or to keep credentials out of the
environment, set:

```text
BOWER_MANAGEMENT_PROXY=http://proxy.corp.example:3128
BOWER_MANAGEMENT_PROXY_USERNAME=bower-collector
BOWER_MANAGEMENT_PROXY_PASSWORD_FILE=/run/secrets/proxy-password
BOWER_MANAGEMENT_CA_BUNDLE=/etc/bower/tls-inspection-ca.pem
```

The proxy URL must not contain credentials. The collector refuses to start if it does,
and the error never repeats the value. The password is read once at start-up and is
never logged, hashed or reported.

`BOWER_MANAGEMENT_CA_BUNDLE` adds roots to the platform roots, for a TLS-inspection
proxy that re-signs traffic. Certificate and host name verification are never turned
off. The configuration hash includes the proxy scheme, host and port, whether
credentials are set, and the CA bundle path.

These settings cover the heartbeat, commands and managed privacy profile requests. The
Entra token and Logs Ingestion clients follow the standard proxy variables.

Note for macOS hosts: Apple's verifier refuses TLS leaf certificates valid for more than
825 days, including ones issued by a CA in the bundle.

## Inactive collectors

The `collector-inactivity` job (daily, 02:00 UTC) suspends approved or active
collectors that have not reported for `BOWER_COLLECTOR_INACTIVE_DAYS` (default 30).
A suspended collector's heartbeats are refused until an administrator reinstates it:

```http
POST /api/collectors/{id}/reinstate
{ "reason": "Host returned from maintenance" }
```

## Holding area and replay

Events that can never be delivered (4xx, preflight failures, attempt limit) are
dead-lettered, never deleted. Inspect and replay them with metadata only:

```bash
bower queue dead-letters --database /var/lib/bower/queue.db
bower queue replay --database /var/lib/bower/queue.db --code preflight-   # or --event <id>
```

Replay resets the attempt count and returns events to the queue. Heartbeats report
the dead-letter count, which the console shows per collector and fleet-wide.

## Tamper-evident queue ledger

Every accepted event gets an entry in an append-only hash chain: each entry commits
to the previous entry, the event id, a SHA-256 of the stored (already redacted)
payload and the receive time. Retention marks entries as purged in the same
transaction. Queue schema v5 folds each contiguous purged run into a hash-bound
checkpoint, including runs behind unresolved events. Verification binds each live
row to its enqueue sequence, so a later replay of the same event ID is a separate
incarnation. See [queue v5 migration and limits](queue-v5-durability.md).

```bash
bower queue verify --database /var/lib/bower/queue.db [--expect-head 902114:<hash>]
```

Verification reports modified payloads, rows deleted outside retention, injected
events, rewritten entries and sequence gaps.

**External witness.** Each heartbeat sends the ledger head to management, which keeps
the last one per collector. A later head with a lower sequence, or the same sequence
with a different hash, marks the collector `ledger-regression` and writes a
`collector.ledger-regression` audit row. Someone with write access to the collector's
database can rewrite its local chain, but cannot rewrite what management already
witnessed. This supports ISM expectations that logs are protected from unauthorised
modification, including by service providers.
