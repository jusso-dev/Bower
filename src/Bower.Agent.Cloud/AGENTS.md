# Bower.Agent.Cloud instructions

Forwarder host that reads AWS (SQS) and GCP (Pub/Sub) security telemetry and posts
candidate events to a Bower collector. Event selection stays in collector policy.

- At-least-once: acknowledge (SQS delete, Pub/Sub ack) only after every event in a
  message was accepted or definitively rejected. On backpressure release the message
  with a delay; never delete it. Malformed messages are released immediately so the
  queue's own dead-letter policy holds them. Unsupported messages are acknowledged
  and dropped (default deny).
- Probe the collector before receiving, so outages do not burn delivery attempts.
- No stored cloud keys: AWS default credential chain (instance profile, ECS task
  role, IRSA) and Google Application Default Credentials (Workload Identity,
  metadata server, Workload Identity Federation). Long-lived AWS keys and Google
  service account key files are refused unless explicitly allowed for a lab.
- S3 reads only from buckets in `BOWER_AWS_S3_BUCKETS`, with `ExpectedBucketOwner`,
  bounded compressed and decompressed size.
- Never log message bodies, attributes, tokens or object contents; ids, counts and
  failure types only.
- Unit tests use fakes for queues and S3; no live cloud calls.
- Exit with a status code on fatal errors (PID 1 aborts can hang).
