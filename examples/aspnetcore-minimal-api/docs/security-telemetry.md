# Security telemetry

Emit semantic Bower events at authoritative transaction boundaries. Keep
actor, action, target, result and correlation context. Never include secrets,
cookies, authorization headers, unrestricted bodies or file contents.

Add `Bower.Sdk` and call `services.AddBower(...)`. Add contract tests for
every catalogue entry.