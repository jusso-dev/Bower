# bower-output-s3 instructions

Rust port of `src/Bower.Output.S3` (the specification). Writes queued, already-redacted
events to one S3 bucket as NDJSON objects (gzip by default). Not Sentinel delivery.

- Credentials come only from the AWS default chain (`aws-config`: environment, web
  identity/IRSA, ECS and EC2 roles). Never accept, persist or log static keys; the
  `BOWER_S3_*`/`BOWER_AWS_*` key settings are refused. The client is built lazily on the
  first delivery, so start-up never touches credentials.
- `layout.rs` must match `tests/fixtures/s3-output/vectors.json` (keys, NDJSON bodies,
  splitting, rejection codes) and `classify`/`acknowledgement` the same file's tables.
- Every PUT sends `If-None-Match: *`, a SHA-256 checksum, server-side encryption and,
  when set, `ExpectedBucketOwner`. 412 means the key already exists and is success.
- Codes are the C# `destination-s3-*` set; never put response bodies, messages or
  credentials in codes or logs. Gzip bytes may differ from .NET; bodies and keys may not.
- Known divergence: the Rust worker has no delivery cancellation token, so
  `destination-s3-cancelled` has no Rust producer (shutdown aborts the task and the
  lease returns the events). A credential provider timeout is `destination-s3-unavailable`;
  any other `CredentialsError` is `destination-s3-credential-failed`.
