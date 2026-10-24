# bower-lambda

AWS Lambda host (`bootstrap`, `provided.al2023`, arm64): `/v1/events` over an IAM
Function URL or direct Invoke, the collector pipeline, delivery to one destination:
CloudWatch Logs (`PutLogEvents`) or CloudTrail Lake (`PutAuditEvents`). Docs:
`docs/deployment/aws-lambda.md`. Template: `deploy/aws/bower-aws-lambda.yaml`.

- Reuse, never fork: bundle loading (`bower_collector::bundle::load_with_key`), producer
  scopes, body parsing, `SecurityEventProcessor`, queue identity rules
  (`bower_persistence::replay_content`), the in-memory `bower_core::capture` store.
  `tests/collector_parity.rs` must keep proving the sent envelope is the collector's
  queued envelope byte for byte, for both destinations.
- Redact before mapping: `audit::map` only sees processor output.
- One destination per deployment, chosen by `BOWER_LAMBDA_DESTINATION`; settings of the
  other destination fail init, and the template grants only the chosen write.
- Acknowledge only after the destination accepted every record of an element; unknown
  CloudTrail error codes and CloudWatch Logs timestamp rejections are retryable.
- IAM only: no bearer tokens, no key files, no static AWS keys. Fail closed at init.
- No payloads, caller ARNs, secrets or CloudTrail error messages in logs or responses.
- Handler logic stays AWS-free and tested through the `AuditSink` fake (both
  `RecordFormat`s); `aws.rs` is the only module that talks to AWS.
- Never deploy from tests; lint the template with `cfn-lint`.
- One ingress per deployment (`function-url` or `invoke`); never reintroduce a mixed
  mode. URL-shaped direct payloads are indistinguishable from URL events, so URL
  functions rely on IAM (resource policy plus `deploy/aws/policies/` Deny).
- An element succeeds only when every required audit record (event and privacy
  alerts) was accepted; duplicates inherit their original's full outcome.
