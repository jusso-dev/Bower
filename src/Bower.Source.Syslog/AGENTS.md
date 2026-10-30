# Syslog source instructions

This C# source selects narrow security signals from approved senders. It is not a
general log shipper. Rust support is outside this backport and must not be claimed.

- Default deny: require an explicit route to a verified signed pack parser with a
  match filter, then redaction, policy evaluation, and durable queue acceptance.
- Bind loopback by default. Non-loopback listeners require TLS or explicit insecure
  opt-in. Preserve sender allow-lists and certificate validation.
- Bound message size, connections, frame idle time, concurrent submissions, and UDP
  buffers. TCP/TLS must stop reading under backpressure; UDP drops must be counted.
- Never log frame contents, payloads, private keys, or certificate file contents.
- Event IDs derive from listener, sender, and exact bytes for duplicate handling.
- Preserve RFC vectors, malformed-input, TLS, slow-loris, backpressure, and
  cancellation tests. TLS fixture keys are public test-only material, never deployable.
