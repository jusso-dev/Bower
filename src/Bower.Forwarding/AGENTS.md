# Bower.Forwarding instructions

Shared client that agents use to post candidate events to a Bower collector.

- At-least-once: callers acknowledge upstream (cursor, SQS delete, Pub/Sub ack) only
  when every event is Accepted or Rejected. Anything else is retried later.
- Never log tokens or event bodies.

Relay output (`RelayOutput`, `RelayProtocol`), downstream side of the relay hop (#110):

- Send each payload exactly as the queue stores it (raw JSON, never re-serialized), so the
  relay ledger hashes the same bytes.
- Acknowledge only `accepted` or `duplicate`. `rejected` is permanent; anything missing,
  malformed or unreachable stays queued. Relay-wide failures use `destination-relay-*`
  codes so the destination circuit holds them without spending attempt budgets.
- Bound everything: 500 events and 4 MiB of payload per request, 1 MiB responses.
