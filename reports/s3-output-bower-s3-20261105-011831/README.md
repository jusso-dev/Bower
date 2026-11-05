# S3 output live re-qualification: bower-s3-20261105-011831

Short live re-qualification after council round 1, which changed the object key layout.
Amazon S3, ap-southeast-2, 05-11-2026 01:18 to 01:24 UTC. Code: branch `feat/s3-output`
at commit `6ddc7ae` (code; the template and docs commit follows it). The account id is redacted
as `<account>`; no credentials, tokens or event payloads are stored here.

**Result: pass.** Keys now take the form
`<prefix>/<collectorId>/yyyy/MM/dd/HH/<object hash>.jsonl.gz`, where the object hash
covers the length-prefixed ids plus the SHA-256 of the uncompressed body.

- Both collectors delivered every event exactly once into their own namespace.
- The same 20 event ids sent to both collectors landed once in each namespace, with no
  collision between them.
- A forced retry (NoSuchBucket) delivered once.
- The same ids with different content got a separate key, with no false acknowledgement.
- The same content from both runtimes left the objects unchanged.
- The bucket was deleted and the cleanup audit found nothing left.

## Safety

- One resource: bucket `bower-s3-20261105-011831-lab`, tagged `Project=bower-lab` and `RunId=bower-s3-20261105-011831` at
  creation, plus `Expiry=1-day-lifecycle`. Public access blocked, default SSE-S3, and a
  1-day lifecycle expiry as a guard. No IAM, KMS or other resources were created.
  Deletion checked both tags first.
- Credentials: the `homelab-admin` profile was exported into each process's environment
  only (`scripts/with-aws.sh`, the default chain's environment provider). Scans of every
  collector log, live-test log and status snapshot found no access key, secret or ingest
  token value.
- Lab-only setting: the host disk was 97% full, so the C# collector's first attempt
  correctly refused intake (`storage-critical`, see `collector/csharp-failure-log-lines.txt`).
  Both collectors then ran with lower free-space watermarks (critical 1 GiB / 1%,
  warning 2 GiB / 2%; see `scripts/cs.sh` and `scripts/rs.sh`). The empty first queue was
  discarded; no event from that attempt was accepted.
- `BOWER_S3_SSE` was not set. Every object still reports `ServerSideEncryption: AES256`
  from the bucket default (`objects/object-heads.jsonl`). This is the new
  "no header, bucket default applies" behaviour.

## What ran

| Step | Runtime | Outcome |
|---|---|---|
| 30 own plus 20 shared event ids via `POST /v1/events` before the bucket existed | C# collector `bower-s3-20261105-011831-csharp` | Forced retry: 50 held with `destination-s3-no-such-bucket` (`collector/cs-status-before-bucket.json`); after bucket creation, 50 delivered in one object |
| 30 own plus the same 20 shared ids | Rust collector `bower-s3-20261105-011831-rust` | 50 delivered in two objects (two leases). `collector/queue-acks-rust.txt` shows each event's acknowledgement naming its own object (20 and 30) |
| Fixed 5-event batch twice, then the same ids with `"live":false` (`S3OutputTests.Live_SameBatchWritesOneObject`, `bower-output-s3/tests/live.rs`) | C# then Rust, collector segment `live-idem` | Two objects (one per content). The Rust run computed the same two keys, its PUTs got 412, and both objects' ETag and LastModified were unchanged (`objects/live-after-*.json`) |

## Verification

- `objects/reconcile.json` (`scripts/reconcile.py`):
  - 5 objects. Every key equals the layout, recomputed from its own ids and uncompressed
    body.
  - `bower/bower-s3-20261105-011831-csharp` and `bower/bower-s3-20261105-011831-rust`: 50/50 ids exactly once each, so the
    shared ids appear once per collector namespace.
  - `live/idempotent/live-idem`: 5/5 ids exactly twice, once per content version.
  - No missing or unexpected ids.
- `objects/checksums.json`: every SHA-256 checksum matches the downloaded bytes. The two
  live objects hold different content (`live` true and false), so the changed batch was
  stored, not falsely acknowledged by a 412.
- This proves S3 objects only, not Sentinel delivery.

## Cleanup audit

`cleanup-audit.txt`:

- `HeadBucket` returns 404 and `ListObjectsV2` returns `NoSuchBucket`.
- No `bower-s3-` buckets remain.
- The Resource Groups Tagging API returns 0 resources for `RunId=bower-s3-20261105-011831` in
  ap-southeast-2 and us-east-1, and no `Project=bower-lab` bucket for this run.
- No collector process is left running.

Zero billable resources remain.

## Not covered live

- SSE-KMS and an explicit SSE header (fake-endpoint tests only, in both runtimes).
- The template's IAM conditions (`s3:if-none-match`, `s3:ResourceAccount`). The run used
  the admin profile, not a role created from the template; `cfn-lint` and
  `ValidateTemplate` pass.
- Throttling, the mixed partial-failure lease, and credential classification (fake-endpoint
  and queue tests only).

`MANIFEST.sha256` lists the SHA-256 of every file here.
