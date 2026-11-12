# AWS signal path against AWS Emulator

`tests/e2e/aws-emulator.sh` runs the AWS ingestion path end to end against
[AWS Emulator](https://github.com/aws/aws-emulator), a local emulator of the AWS APIs.
It needs no AWS account, credentials or network route to AWS. CI runs it in the
`docker` job after the compose e2e tests.

## What it runs

| Step | Proves |
|---|---|
| Deploy `deploy/aws/bower-aws-security.yaml` (`RuleState=ENABLED`, `MaxReceiveCount=3`) and `deploy/aws/bower-s3-output.yaml` | The shipped templates create, the Australian region rule passes in `ap-southeast-2`, and the stack outputs match the documented agent and collector settings |
| `TestEventPattern` against each deployed rule | GuardDuty, root console sign-in, StopLogging and an unsupported EC2 event match exactly the rules they should |
| Cloud agent (`bower-cloud:ci`) on the stack's queue, collector (`bower-collector:ci`) with `BOWER_OUTPUT=s3` | Five EventBridge events, two Security Hub findings and one Firehose CloudWatch Logs object reach S3 as one NDJSON line each, plus the privacy engine's `sensitive_data_detected` event |
| A TFN in the Firehose object, a GuardDuty secret in the finding | Redaction runs before the S3 write: the TFN is masked, the secret is dropped, neither reaches S3 or a log |
| Head every output object | `bower/<collectorId>/…/*.jsonl.gz` keys, SSE-S3, a SHA-256 checksum and gzip encoding |
| An unsupported message, a bucket outside `BOWER_AWS_S3_BUCKETS`, a non-JSON body | The first two are deleted as unsupported; the malformed body reaches the dead-letter queue after `MaxReceiveCount` |
| Send the same GuardDuty finding again | The collector deduplicates: no new event, no new object |
| Deny `s3:PutObject` in the bucket policy, then restore it | Events wait in the durable queue as `destination-s3-access-denied` (retryable, never dead-lettered) and deliver once afterwards |
| Stop the collector, send a message, wait, restart | The agent probes before receiving, so no delivery attempt is spent during the outage; the message delivers once on recovery |
| Grep both container logs | No ingest token, emulator key, session token or message content |

Producer scopes are exact identity tuples for the fixture events; the test does not use
`BOWER_SINGLE_TRUST_DOMAIN`.

## Run it locally

```bash
docker build -f deploy/docker/Dockerfile -t bower-collector:ci .
docker build -f deploy/docker/Dockerfile.cloud -t bower-cloud:ci .
docker build -t bower-aws-emulator:ci tests/e2e/aws-emulator
bash tests/e2e/aws-emulator.sh
```

It takes about three minutes; most of it is the deliberate outage waits. Override the
images with `BOWER_COLLECTOR_IMAGE`, `BOWER_CLOUD_IMAGE` and `BOWER_AWS_EMULATOR_IMAGE`.
On a workstation, name the Docker context (`DOCKER_CONTEXT=orbstack bash …`).

## Isolation and credentials

- AWS publishes no emulator image. `tests/e2e/aws-emulator/Dockerfile` installs a pinned
  package version on a digest-pinned Amazon Linux base and verifies the package signature
  against the AWS publishing key fingerprint from the user guide before installing.
  Telemetry is off.
- The emulator listens on `127.0.0.1` inside its own container and publishes no port.
  The AWS CLI, collector and agent containers join its network namespace, so nothing
  else can reach it. Its state lives on a tmpfs and goes when the container is removed.
- Every AWS CLI call runs with the emulator's generated `config` and credentials, and the
  script refuses to continue unless `sts get-caller-identity` returns account
  `000000000000`.
- The agent and collector get temporary credentials from the emulator's STS
  (`GetSessionToken`), like an instance profile or IRSA. No setting weakens Bower's
  refusal of long-lived keys. The .NET SDK reads `AWS_ENDPOINT_URL` and trusts the
  emulator's per-run certificate through `SSL_CERT_FILE`; no Bower code changes.
- Secrets never print, even on failure: failure output filters every token and key.

## What it does not prove

The emulator is not AWS. A pass here is not evidence of tenant behaviour, IAM
enforcement or Sentinel delivery, and does not replace the [AWS lab](lab-and-stress-testing.md).

- **No AWS-sourced events.** EventBridge refuses `PutEvents` for `aws.*` sources, as AWS
  does, so the fixtures go to SQS in the envelope EventBridge delivers. Rule routing is
  checked with `TestEventPattern`, not by EventBridge delivering a GuardDuty finding.
- **Security Hub rule.** The emulator (1.0.322) never matches a pattern field inside an
  array of objects (`detail.findings[].Severity.Label`), which AWS does. The script
  prints a note and accepts no match for that rule only, and fails on any other result.
- **S3 notifications from the template.** With `AppLogBucketName` set, the stack fails:
  the emulator refuses an S3 notification to a queue whose policy also has the
  `aws:SecureTransport` deny statement, which AWS accepts. The test sends the S3
  notification itself. The Firehose stream and log subscription are not exercised.
- **IAM.** The emulator does not enforce scoped session policies or the template's
  consumer and writer policies (see its tracked issues), so least privilege is not tested.
- **Delivery to Sentinel**, KMS-encrypted objects, cross-account bucket ownership and
  VPC endpoints are not covered.

Fixtures are in `tests/fixtures/aws-emulator/`. They are the same events as
`CloudSourceTests`, with the Security Hub `Workflow` and `RecordState` fields the
deployed rule filters on.
