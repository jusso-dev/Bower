# Bower.Core instructions

Source-to-policy-to-queue orchestration.

- Order is fixed: redact, deserialize, validate, evaluate policy, enqueue.
- Any redaction exception or failure quarantines the event without persisting it.
- Generated events (privacy alerts) must be idempotent: derive ids and times from the
  source event so client retries collapse onto one queued alert.
- Never add payload content to `ProcessingResult.Reasons`; reasons are returned to
  producers and may be logged.
