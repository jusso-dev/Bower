# Queue migration preflight

Offline diagnostics only. Use the C# `EventIdentity` specification. Never initialize,
migrate, repair, checkpoint, or write the inspected database. Bound rows, payload
bytes and output. Report event IDs and summary metadata only, never payloads or
exception details. Unknown schemas and incomplete checks must fail closed.
