# Bower.Forwarding instructions

Shared client that agents use to post candidate events to a Bower collector.

- At-least-once: callers acknowledge upstream (cursor, SQS delete, Pub/Sub ack) only
  when every event is Accepted or Rejected. Anything else is retried later.
- Never log tokens or event bodies.
