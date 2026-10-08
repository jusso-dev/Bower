# AWS source adapter instructions

Parse AWS security telemetry JSON only. Do not embed AWS credentials, call live
AWS APIs from unit tests, or log raw payloads. Keep parsers pure, bounded and
deterministic.

- `AwsSecurityEventMapper` maps CloudTrail, GuardDuty, Security Hub, CloudWatch,
  VPC flow and Route 53 records. Clip strings to envelope schema limits here, not
  in the collector, so valid findings are never rejected for length.
- `AwsQueueMessageParser` reads SQS bodies: EventBridge events (optionally SNS-wrapped)
  and S3 ObjectCreated notifications. Unknown shapes are `Unsupported` (default deny);
  malformed input throws the typed `AwsTelemetry*Exception`s.
- `FirehoseLogObjectReader` reads Firehose-delivered CloudWatch Logs objects with
  bounded decompression and keeps only Bower envelopes.
- Raw records go into `attributes` only when `IncludeRawRecord` is set.
- Queue access, S3 reads and credentials live in `Bower.Agent.Cloud`.
