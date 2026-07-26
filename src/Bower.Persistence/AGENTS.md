# Persistence instructions

Queue transitions and cursor updates must be transactional, crash-safe and
idempotent. Use WAL and bound busy timeouts. Never delete accepted data before
destination acknowledgement. Store only redacted payloads. Every migration needs
upgrade, restart and corruption-path tests.
