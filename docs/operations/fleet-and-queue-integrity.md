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
`BOWER_INGEST_TOKEN` still works and is producer `default`.

## Policy assignment and acknowledgement

Every heartbeat reports the collector's **policy bundle hash** (policies, packs,
privacy profile). An administrator sets the expected hash:

```http
POST /api/collectors/{id}/desired-policy
{ "policyHash": "sha256:…", "reason": "Roll out linux-ssh-gateway 1.1.0" }
```

The console shows each collector as *In sync*, *Drift* or *Unassigned*; drifted
collectors appear in fleet exceptions. The action is audited.

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
transaction, then folds fully purged prefixes into an anchor.

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
