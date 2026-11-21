# Air-gapped and offline site bundles

Sites with no network path to Azure or the Bower management API can export already-redacted
events and metadata-only site status into signed, hash-chained `.bowerbundle` archives for
sneakernet / media transfer.

## Export on the offline collector

```bash
bower export bundle \
  --database /var/lib/bower/queue.db \
  --out /media/transfer/site-a-001.bowerbundle \
  --signing-key /etc/bower/keys/export-private.pem \
  --collector-id site-a-collector \
  --environment site-a
```

Add `--encrypt-key-file /etc/bower/keys/aes256.key` (32 raw bytes, 64 hex characters, or
32-byte base64) to encrypt `events.ndjson` with AES-256-GCM bound to the signed manifest.
Each export advances a durable cursor in `queue_export_bundles` so consecutive exports
chain cleanly via `bundleSequence` and `previousBundleHash` without gaps or duplicates.

## Verify before import

```bash
bower verify bundle \
  --bundle /media/transfer/site-a-001.bowerbundle \
  --trusted-key /etc/bower/keys/export-public.pem \
  --expect-sequence 1 \
  --expect-previous-hash genesis
```

Verification fails closed (exit code 3) if the ECDSA P-256 signature is missing or
untrusted, the payload digest does not match the signed manifest, the event count differs,
or the chain sequence/hash is broken.

## Import on the connected side

```bash
bower import bundle \
  --bundle /media/transfer/site-a-001.bowerbundle \
  --trusted-key /etc/bower/keys/export-public.pem \
  --collector-url https://collector.connected.example:4319 \
  --management-url https://management.connected.example
```

- Already-redacted events (`events.ndjson`) are sent **only** to the receiving collector
  (`/v1/events`), which deduplicates by fingerprint so re-importing a bundle is idempotent.
- Only the signed metadata-only `status-report.json` (zero event payloads, preserving
  ISM-1985) is posted to `POST /api/fleet/offline-import`. Configure
  `BOWER_OFFLINE_IMPORT_TRUSTED_KEYS` on the management API to trust the offline site's
  public signing key.
- Imported offline collectors appear in the plain-English fleet view (`GET /api/fleet` and
  the console) under **Offline site** (`offline-site`) instead of being flagged as stale or
  offline.
