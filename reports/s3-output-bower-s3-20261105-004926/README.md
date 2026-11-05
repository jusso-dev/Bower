# S3 output live qualification: bower-s3-20261105-004926

Live run of `BOWER_OUTPUT=s3` (C# `Bower.Output.S3` and Rust `bower-output-s3`) against
Amazon S3 in ap-southeast-2, 05-11-2026 00:49 to 00:53 UTC. Code: branch `feat/s3-output`
(working tree on top of `562c3e6`, the commits that follow add this report). The account id
is redacted as `<account>`; no credentials, tokens or event payloads are stored here.

**Result: pass.** 85 of 85 event ids landed exactly once; every forced retry delivered once;
the same batch written four times (C# twice, Rust twice) left one unchanged object; the
bucket was deleted and the cleanup audit found nothing left.

## Safety

- One resource: bucket `bower-s3-20261105-004926-lab`, tagged `Project=bower-lab`, `RunId=bower-s3-20261105-004926` (tags set at
  creation) and `Expiry=1-day-lifecycle`; public access blocked, default SSE-S3, lifecycle
  expiry of 1 day as a guard. No IAM, KMS or other resources were created. Deletion checked
  both tags first.
- Credentials: the `homelab-admin` profile exported into each process's environment
  (`scripts/with-aws.sh`), so both collectors used the AWS default chain's environment
  provider. Nothing was written to disk; a scan of both collector logs and every status
  snapshot found no access key, secret or ingest token value.

## What ran

| Step | Runtime | Forced retry | Outcome |
|---|---|---|---|
| 40 events via `POST /v1/events` (`scripts/produce.py`) before the bucket existed | C# collector (Release build) | `NoSuchBucket` | 40 retrying with `destination-s3-no-such-bucket` (`collector/cs-status-before-bucket.json`); after the bucket was created, 40 delivered in one object (`cs-status-after-bucket.json`) |
| 40 events with a temporary bucket policy denying `s3:PutObject` on `rust/*` (`scripts/forced-retry-deny-policy.json`) | Rust collector (debug build) | `AccessDenied` | 40 retrying with `destination-s3-access-denied` (`rust-failure-log-lines.txt`); after the policy was removed, 40 delivered in one object |
| One fixed 5-event batch, delivered twice per runtime (`S3OutputTests.Live_SameBatchWritesOneObject`, `bower-output-s3/tests/live.rs`) | C# then Rust | Same key, `If-None-Match: *` | All four deliveries acknowledged; one object; ETag, LastModified and checksum identical after the C# and the Rust runs (`objects/live-head-after-*.json`) |

Status snapshots also show `"output": "s3"` (the evidence runner's non-Sentinel signal).
The queue acknowledgements (`collector/queue-acks-*.txt`, state 3 = delivered) name each
object key.

## Verification

- `objects/reconcile.json` (`scripts/reconcile.py`): 3 objects; for `csharp`, `rust` and
  `live/idempotent`, 40, 40 and 5 ids exactly once, none missing, duplicated or unexpected;
  every key equals `<prefix>/yyyy/MM/dd/HH/<sha256 of its ordered event ids>.jsonl.gz`.
- `objects/object-heads.jsonl`: every object has `ServerSideEncryption: AES256`,
  `Content-Encoding: gzip`, `Content-Type: application/x-ndjson`, a SHA-256 checksum and
  `x-amz-meta-bower-events`. `objects/checksums.json`: each checksum equals the SHA-256 of
  the downloaded bytes.
- Not Sentinel delivery: this proves S3 objects only.

## Cleanup audit

`cleanup-audit.txt`: objects and bucket deleted; `HeadBucket` 404 and `ListObjectsV2`
`NoSuchBucket`; Resource Groups Tagging API returned 0 resources for `RunId=bower-s3-20261105-004926` (in
ap-southeast-2 and us-east-1) and no `Project=bower-lab` bucket for this run; no collector
process left running. The first `HeadBucket` straight after deletion still answered
(S3 eventual consistency); the recheck 50 seconds later returned 404. Zero billable
resources remain.

## Not covered live

SSE-KMS (creating or touching a KMS key in the shared account was avoided; covered by
fake-endpoint tests in both runtimes), `ExpectedBucketOwner` mismatch, throttling and
5xx (fake-endpoint tests only), and the C# delivery-deadline cancellation path.

`MANIFEST.sha256` lists the SHA-256 of every file here.
