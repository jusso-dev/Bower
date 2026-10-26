# Bower.Agent.Cloud instructions

Forwarder host that reads AWS (SQS) and GCP (Pub/Sub) security telemetry and posts
candidate events to a Bower collector. Event selection stays in collector policy.

- At-least-once: acknowledge (SQS delete, Pub/Sub ack) only after every event in a
  message was accepted or definitively rejected. On backpressure release the message
  with a delay; never delete it. Malformed messages are released immediately so the
  queue's own dead-letter policy holds them. Unsupported messages are acknowledged
  and dropped (default deny).
- Leases: every received message is leased on receive and renewed by elapsed time
  (half the lease, `TimeProvider`-driven, bounded concurrency) until it is settled.
  Ownership stays in the forwarding loop, never in scheduled jobs. A failed renewal or
  passed deadline cancels that message's work; a lost lease is never acknowledged or
  released. Renewal tasks end with the batch. Lease tests use a fake clock.
- Probe the collector before receiving, so outages do not burn delivery attempts.
- No stored cloud keys: AWS default credential chain (instance profile, ECS task
  role, IRSA) and Google Application Default Credentials (Workload Identity,
  metadata server, Workload Identity Federation). Long-lived AWS keys, Google
  service account key files and gcloud user credentials are refused unless
  explicitly allowed for a lab.
- Native AOT: no reflection-based serializers or libraries. Google ADC lives in
  `Gcp/Auth` (AIP-4110/4117) with source-generated JSON. Keep it to the documented
  flows; never run executable-sourced credentials. Token/IAM endpoints are HTTPS on
  the credential's universe domain; plain HTTP only to metadata or loopback hosts;
  no redirects; bounded response reads; tokens cached in memory only. Error
  messages carry status and OAuth error codes, never bodies, tokens or file contents.
- SigV4 changes must keep the AWS SigV4 test-suite vectors in `GoogleCredentialTests`
  passing.
- S3 reads only from buckets in `BOWER_AWS_S3_BUCKETS`, with `ExpectedBucketOwner`,
  bounded compressed and decompressed size.
- Never log message bodies, attributes, tokens or object contents; ids, counts and
  failure types only.
- Unit tests use fakes for queues, S3 and credential HTTP (`HttpMessageHandler`); no
  live cloud calls.
- Exit with a status code on fatal errors (PID 1 aborts can hang).
- Bower code here must stay trim/AOT safe (it is analysed on every build). The host is
  not published as Native AOT only because Google.Apis.Auth needs Newtonsoft.Json
  reflection; see docs/architecture/dependencies.md.
