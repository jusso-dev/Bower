# S3 output live IAM check: bower-s3-iam-20261105-074405

Live check of the IAM policy in `deploy/aws/bower-s3-output.yaml`: `s3:PutObject` on the
prefix, conditioned on `s3:if-none-match` being present and on `s3:ResourceAccount`.
Amazon S3, ap-southeast-2, 05-11-2026 07:44 to 07:48 UTC. Code: branch `feat/s3-output` at
commit `2361457`. The account id and the operator's user name are redacted; no
credentials, tokens or event payloads are stored here.

**Result: pass.** The policy allows Bower's conditional PUTs and nothing else that was tried.

- The C# collector, running only on the template's policy through a lab role, delivered
  10/10 events exactly once.
- Repeat writes of the same batch got 412 and counted as delivered. No extra object
  version was created.
- A PUT without `If-None-Match` was denied, and so was a PUT outside the prefix.
- Everything was deleted, and the cleanup audit found nothing left.

## Safety

- **Stack:** `bower-s3-iam-20261105-074405`, created from the template with `CreateBucket=true`, `KeyPrefix=bower`,
  `ExpirationDays=1` and no `KmsKeyArn` (SSE-S3, so no KMS key in the shared account).
  Stack tags `Project=bower-lab` and `RunId=bower-s3-iam-20261105-074405` propagated to the bucket.
  - The stack created bucket `bower-s3-iam-20261105-074405-lab` (versioned; public access blocked; TLS-only
    bucket policy; SSE-S3 default; 1-day expiry of current and noncurrent versions as a
    guard) and the managed policy `bower-s3-iam-20261105-074405-CollectorWritePolicy-*` (`iam/stack-resources.txt`).
  - CloudFormation cannot tag the managed policy, so its name carries the RunId instead.
- **Lab role:** `bower-s3-iam-20261105-074405-collector`, tagged `Project=bower-lab` and `RunId=bower-s3-iam-20261105-074405`, with the
  stack's policy as its only attachment.
  - Its trust policy allows only the operator's own IAM user, and only until
    `aws:CurrentTime` passes a fixed expiry three hours after creation
    (`iam/trust-redacted.json`, `iam/role-guard.txt`). Maximum session is one hour.
- **Credentials:** `scripts/with-role.sh` assumes the role with the operator's profile and
  exports only the role's temporary credentials into the process environment, so the
  collector uses the AWS default chain's environment provider. Nothing is written to disk.
  A scan of every log and status file found no access key, secret, temporary key id or
  ingest token.
- **Deletion:** every resource's `RunId` tag was checked before it was deleted.

## Checks

| Check | Credentials | Result |
|---|---|---|
| C# collector `bower-s3-iam-20261105-074405-csharp`, 10 events via `POST /v1/events` | role | 10 delivered in one object, 0 failures (`collector/`) |
| `S3OutputTests.Live_SameBatchWritesOneObject` with prefix `bower` (same batch twice, then the same ids with changed content), run twice | role | Both runs passed. The second run's PUTs all got 412 and counted as delivered. Objects, ETags and LastModified were identical after run 1 and run 2 (`objects/live-after-run*.json`) |
| `aws s3api put-object` inside the prefix **without** `--if-none-match` | role | **AccessDenied** ("no identity-based policy allows"); the key does not exist |
| `put-object --if-none-match '*'` **outside** the prefix (`outside/`) | role | **AccessDenied**; the key does not exist |
| `put-object --if-none-match '*'` inside the prefix (positive control) | role | Success |
| The same PUT repeated | role | `PreconditionFailed` (412) |

Command output is in `iam/direct-put-checks.txt` and `iam/denied-keys-absent.txt`.

## Verification

- `objects/reconcile.json`:
  - 3 Bower objects, all keys matching the layout.
  - `bower/bower-s3-iam-20261105-074405-csharp`: 10/10 ids exactly once.
  - `bower/live-idem`: 5/5 ids exactly twice, once per content version.
- `objects/object-versions.json`: 4 versions in the versioned bucket, one per object (3
  Bower objects plus the CLI positive control). The repeat attempts created no versions, so
  nothing was ever overwritten.
- `objects/object-heads.jsonl`: every object is `AES256` from the bucket default (no SSE
  header was sent) and carries a SHA-256 checksum.

## Cleanup audit

`cleanup-audit.txt`:

- The role (policy detached first) is deleted.
- The stack is deleted (`DELETE_COMPLETE`; `DescribeStacks` says it does not exist), which
  removed the managed policy and the bucket policy.
- The retained bucket was emptied of all 4 versions and deleted: `HeadBucket` returns 404,
  and no `bower-s3-iam-` buckets remain.
- No IAM role or customer-managed policy name contains the RunId. `list-roles` printed one
  count per result page, hence two zeros.
- The Resource Groups Tagging API returns 0 resources for `RunId=bower-s3-iam-20261105-074405` in ap-southeast-2
  and us-east-1.
- No collector process is left running.

Zero billable resources remain.

## Not covered

- The template's KMS statement (`kms:GenerateDataKey` with `kms:ViaService`), to avoid
  creating a KMS key in the shared account.
- The `s3:ResourceAccount` condition was present and satisfied, but not tested against a
  bucket in another account.

`MANIFEST.sha256` lists the SHA-256 of every file here.
