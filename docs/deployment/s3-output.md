# Amazon S3 output

`BOWER_OUTPUT=s3` writes queued Bower events to one Amazon S3 bucket as batched
NDJSON objects (`Bower.Output.S3`).

It is an extra sink for events Bower has already selected and redacted, for example a
security data lake or a long-term archive bucket. It is not a generic log forwarder and
it is not Sentinel delivery: an event written to S3 has not reached Microsoft Sentinel,
and evidence bundles say so (see [Evidence](#evidence)).

## What is written

- **Body**: one Bower event envelope per line (NDJSON), exactly as stored in the
  queue after redaction. Gzip is on by default (`.jsonl.gz`, `Content-Encoding: gzip`).
- **Key**: `<prefix>/<collectorId>/<yyyy>/<MM>/<dd>/<HH>/<object hash>.jsonl.gz`.
  - `<collectorId>` is `BOWER_COLLECTOR_ID` (default: the machine name). Collectors that
    share a bucket and prefix never write the same key. With `BOWER_OUTPUT=s3` it must
    be 1 to 128 letters, digits, dots, hyphens and underscores, starting with a letter or
    digit; anything else stops start-up. It is validated, never rewritten, so two
    collectors cannot be mapped to one segment.
  - The hour partition is the first event's **queue receive time** in UTC. It is set
    once when the collector accepts the event and never changes. Delivery time would
    move a retry into a later partition and write a second object.
  - `<object hash>` is the lowercase hex SHA-256 of an unambiguous encoding: the id
    count, then each UTF-8 event id prefixed with its byte length (32-bit big-endian),
    then the SHA-256 of the **uncompressed** NDJSON body. The same batch always gets the
    same key; the same ids with any other content, or a different id split (`a\nb`,`c`
    versus `a`,`b\nc`), get a different key. Gzip bytes are not guaranteed stable across
    compression library versions, so only the uncompressed body is hashed.
- **Batching**: one delivery (up to 500 queued events) is split, in order, into objects
  under `BOWER_S3_MAX_OBJECT_BYTES` (uncompressed, newlines included) and
  `BOWER_S3_MAX_OBJECT_EVENTS`. An event that is not one JSON object on one line, or is
  larger than one object, is dead-lettered alone (`payload-invalid-json`,
  `payload-too-large`).
- **Request**: every `PutObject` sends
  - `If-None-Match: *`: S3 refuses to overwrite an existing key with
    `412 Precondition Failed`. Bower treats 412 as success, because the key binds the
    collector, the exact ids and the uncompressed body: an existing key holds
    byte-identical events. Objects are never overwritten, so versioned or Object Lock
    buckets keep one version per key.
  - `x-amz-checksum-sha256` over the uploaded bytes, so S3 rejects corrupted uploads.
  - server-side encryption **only when `BOWER_S3_SSE` is set**. Unset (the default), no
    encryption header is sent and the bucket's default encryption applies, including a
    bucket KMS key; S3 always encrypts new objects, at least with SSE-S3. An explicit
    `AES256` would override a bucket's KMS default, so leave it unset for KMS buckets or
    set `aws:kms` with the key. A bucket policy that denies uploads without an
    `x-amz-server-side-encryption` header (the common `DenyUnEncryptedObjectUploads`
    statement) refuses every unset-SSE PUT with 403 (`destination-s3-access-denied`):
    for such a bucket set `BOWER_S3_SSE=AES256`, or `aws:kms` with the key, to match it.
  - `ExpectedBucketOwner` when `BOWER_S3_EXPECTED_BUCKET_OWNER` is set, so a bucket
    re-created under another account is refused.
  - `x-amz-meta-bower-events`: the event count.

The shared layout vectors are in `tests/fixtures/s3-output/vectors.json`.

### Delivery semantics

An event is acknowledged only after its object's PUT returned success. S3 stores an
object durably before it answers, so that is the acknowledgement; the queue records
each event's own object, `s3://<bucket>/<key>`. One delivery can write several objects;
each object's events are settled in their own queue transaction.

Delivery is at least once. A retry of the same batch rewrites the same key and gets
412, so it never duplicates. If the queue reassembles a different batch after a crash
between the PUT and the acknowledgement (for example when newer events join it), the
second object holds some of the same events. Event ids are unique only within one
collector's queue (a producer may choose them), so consumers deduplicate on
`(collectorId, eventId)`; the collector id is the key segment after the prefix.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `BOWER_OUTPUT` | `none` | `s3` selects this output. |
| `BOWER_S3_BUCKET` | (required) | Bucket name: 3 to 63 lowercase letters, digits and hyphens. Dotted names are refused (TLS for virtual-hosted requests). |
| `BOWER_S3_REGION` | (required) | Bucket region, for example `ap-southeast-2`. |
| `BOWER_S3_PREFIX` | `bower` | Key prefix: segments of letters, digits and `!-_.'()=`, no leading or trailing slash. `* ? $ { }` are refused: the prefix becomes an IAM resource, where they are wildcards or variables. |
| `BOWER_COLLECTOR_ID` | machine name | Key segment after the prefix (see [What is written](#what-is-written)). |
| `BOWER_S3_SSE` | (unset) | Unset: no header, the bucket default encryption applies. `AES256` (SSE-S3) or `aws:kms`: sent on every PUT. |
| `BOWER_S3_KMS_KEY_ID` | (none) | KMS key id, alias or ARN; only with `aws:kms`. `aws:kms` without it uses the AWS managed `aws/s3` key, **not** the bucket's default key. |
| `BOWER_S3_EXPECTED_BUCKET_OWNER` | (none) | 12-digit account id that must own the bucket. |
| `BOWER_S3_MAX_OBJECT_BYTES` | `8388608` | Uncompressed bytes per object, 1 MiB to 64 MiB. |
| `BOWER_S3_MAX_OBJECT_EVENTS` | `1000` | Events per object, 1 to 100000. |
| `BOWER_S3_GZIP` | `true` | `false` writes plain `.jsonl`. |

`BOWER_S3_*` settings without `BOWER_OUTPUT=s3`, or `BOWER_OUTPUT=s3` without a bucket
and region, stop start-up. The settings (never credentials) are part of the
configuration hash reported to management.

### Credentials

Only the AWS default credential chain is used: environment variables, web identity
(EKS IRSA), the ECS task role or the EC2 instance profile. The collector has no SSO
packages.
Bower has no setting for keys. `BOWER_S3_ACCESS_KEY_ID`, `BOWER_S3_SECRET_ACCESS_KEY`,
`BOWER_S3_SESSION_TOKEN` and the same `BOWER_AWS_*` names stop start-up with a message
that does not echo the value. Credentials are resolved on the first delivery, held by
the SDK in memory and never logged, put in status or hashed.

## Least-privilege IAM

The collector needs `s3:PutObject` on the prefix, and `kms:GenerateDataKey` on the key
when objects are encrypted with a customer managed key (set explicitly, or as the
bucket default). It needs no read, list or delete permission: the conditional PUT
replaces a read-before-write check. The write statement also requires the
`If-None-Match` header (Bower sends it on every PUT, so the role can never overwrite an
object) and a bucket owned by the same account.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BowerS3OutputWrite",
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::<bucket>/<prefix>/*",
      "Condition": {
        "Null": { "s3:if-none-match": "false" },
        "StringEquals": { "s3:ResourceAccount": "<account>" }
      }
    },
    {
      "Sid": "BowerS3OutputKms",
      "Effect": "Allow",
      "Action": "kms:GenerateDataKey",
      "Resource": "arn:aws:kms:<region>:<account>:key/<key-id>",
      "Condition": { "StringEquals": { "kms:ViaService": "s3.<region>.amazonaws.com" } }
    }
  ]
}
```

The collector id segment is a naming convention, not an isolation boundary: the grant
covers the whole prefix, so any collector with this role may write under any collector
segment. `If-None-Match` still stops it overwriting an existing object. To keep each
collector in its own segment, give each collector its own role and scope the resource
to its segment, for example
`"Resource": "arn:aws:s3:::<bucket>/<prefix>/<collectorId>/*"`.

Leave out the second statement for SSE-S3. `deploy/aws/bower-s3-output.yaml` creates
this policy (and, optionally, a bucket with public access blocked, default encryption,
TLS-only access and a lifecycle expiry). Its `CollectorSettings` output lists the
collector settings, including `BOWER_S3_SSE=aws:kms` and `BOWER_S3_KMS_KEY_ID` when
`KmsKeyArn` is given. Validate and review it as a change set before
executing it:

```bash
aws cloudformation validate-template --template-body file://deploy/aws/bower-s3-output.yaml
aws cloudformation create-change-set --change-set-type CREATE \
  --stack-name bower-s3-output --change-set-name plan \
  --template-body file://deploy/aws/bower-s3-output.yaml \
  --parameters ParameterKey=BucketName,ParameterValue=<bucket> \
  --capabilities CAPABILITY_IAM
aws cloudformation describe-change-set --stack-name bower-s3-output --change-set-name plan
```

Attach the managed policy to the collector's role (IRSA role, ECS task role or
instance profile role).

## Failures

Every destination failure keeps the events queued (retryable, `destination-` codes, so
they never spend the poison budget or dead-letter). Objects are uploaded in order; the
first failure holds that object and every later one in the delivery.

| Code | Cause | Action |
|---|---|---|
| `destination-s3-throttled` | `SlowDown`, 503, 429 | None; the queue retries. |
| `destination-s3-http-<status>` | Other 5xx or unclassified 4xx | Retries; investigate if it persists. |
| `destination-s3-unavailable` | Network error or timeout | Check egress, proxy and DNS. |
| `destination-s3-access-denied` | `AccessDenied` | Fix the role policy or bucket policy. If the bucket policy requires an encryption header (`DenyUnEncryptedObjectUploads`), set `BOWER_S3_SSE`. |
| `destination-s3-kms-denied` | KMS key denied, disabled or missing | Grant `kms:GenerateDataKey` or fix the key. |
| `destination-s3-no-such-bucket` | Bucket missing | Create it or fix `BOWER_S3_BUCKET`. |
| `destination-s3-wrong-region` | `PermanentRedirect`, wrong signing region | Fix `BOWER_S3_REGION`. |
| `destination-s3-credential-failed` | No credentials, expired or invalid token | Fix the role or IRSA binding. |
| `destination-s3-cancelled` | C# delivery deadline reached mid-batch | None; finished objects stay acknowledged. |

Both collectors log each code with its event count. The C# collector also reports
credential, access and KMS codes first in status (`deliveryActivity.lastFailureCode`),
and its `collector_health` records raise the high-severity `destination-credential`
problem for them, like Azure credential failures (health records are C#-only). Codes never carry
response bodies, error messages or credentials. The SDKs make at most three attempts
per PUT in memory (standard retry mode); longer outages wait in the durable queue.

## Evidence

S3 delivery is not Sentinel delivery. A collector with `BOWER_OUTPUT=s3` reports
`"output": "s3"` in `/v1/status`. `bower evidence` reads status first and
refuses any `output` outside the Sentinel allowlist (`azure-logs-ingestion`, `ama-spool`,
`ama-syslog`, `relay`; a missing field or unreadable status proceeds to the Sentinel query). For such a
collector it sends no canary or probe: the bundle is `failed` (or `simulated`
without a workspace), with `arrival.queryError` `collector-output-not-sentinel` and a
`NOT SENTINEL` limitation. Proving S3 delivery means downloading the objects and
reconciling event ids, as the live qualification in
`reports/s3-output-*` does.

## Limits

- One bucket per collector; objects are written one at a time per delivery.
- No S3 Express One Zone directory buckets, access points or Object Lambda.
- Gzip bytes are not guaranteed stable across compression library versions; bodies and
  keys are.
- Changing `BOWER_COLLECTOR_ID` starts a new key namespace; events already written stay
  under the old one.
- Every object is one `PutObject`. Adding multipart upload later would conflict with the
  `s3:if-none-match` IAM condition: `CreateMultipartUpload` and `UploadPart` carry no
  `If-None-Match`, so the policy would deny them; only `CompleteMultipartUpload` can.
