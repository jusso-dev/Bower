# S3 output instructions

Writes queued, already-redacted Bower events to one Amazon S3 bucket as NDJSON objects
(gzip by default). An additional sink for security-selected events, not a generic log
forwarder, and never Sentinel delivery: evidence must not claim Sentinel arrival.

- Credentials come only from the AWS default chain (web identity/IRSA, ECS and EC2
  roles, environment). Never accept, persist or log static keys; settings that look
  like keys are refused at start-up.
- `S3ObjectLayout` is pure and shared with `rust/crates/bower-output-s3`: object keys,
  NDJSON bodies and splitting must match `tests/fixtures/s3-output/vectors.json` in both
  runtimes. Keys are `<prefix>/<collectorId>/yyyy/MM/dd/HH/<object hash>`; the hash
  length-prefixes every id and binds the SHA-256 of the uncompressed body, so a retried
  batch rewrites the same key and a 412 always means byte-identical content. Never
  weaken that binding (it is what makes 412 safe to acknowledge).
- Every PUT sends `If-None-Match: *`, a SHA-256 checksum, server-side encryption and,
  when set, `ExpectedBucketOwner`. 412 means the object already exists and is success.
- Classification is destination-wide and retryable (`destination-s3-*`): events stay
  queued. Only per-record faults (`payload-too-large`, `payload-invalid-json`) are
  permanent. Never put response bodies, messages or credentials in codes or logs.
- An event is acknowledged only after its object's PUT returned success.
