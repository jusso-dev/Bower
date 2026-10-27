# Bower.Source.Syslog instructions

Narrow syslog intake (RFC 5424 and RFC 3164 over TCP, TLS and UDP) in front of a few
high-value senders. Not a syslog server for the estate; Bower is not a log shipper.
The Rust port (`rust/crates/bower-source-syslog`) must keep the same parsing, failure
codes, record shape, event ids, limits and defaults.

- Default deny: a message reaches the queue only through a route to an active signed
  pack parser whose match filter selects it, then redaction and policy. Unrouted and
  unselected messages are counted and dropped.
- Bind loopback by default. Refuse a non-loopback address unless the protocol is `tls`
  or `allowInsecureNonLoopback` is set. Keep the per-listener sender allow-list.
- Bound everything: message size (64 KiB maximum), connections, the per-frame idle
  timeout (slow loris), concurrent submissions and the UDP datagram buffer.
- TCP/TLS: read the next frame only after the current one is durably enqueued or
  definitively dropped. A full queue stops reading; never drop a TCP frame for
  backpressure. UDP is best effort: drop and count.
- Never log or expose frame content, records, sender payloads, key material or file
  contents. Counters and failure codes only.
- Event ids derive from listener, sender and exact frame bytes so retransmits
  deduplicate; change them only with a migration note.
- Changes need RFC vector, malformed-input, framing, slow-loris, backpressure and
  cancellation tests, mirrored in Rust (`tests/fixtures/syslog-vectors.json` is shared).
