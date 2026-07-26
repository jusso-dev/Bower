# ASP.NET Core instrumentation

Add `Bower.Sdk`, call `AddBower`, then inject `IBowerTelemetry`. Emit after
authoritative transaction success. Emit meaningful failures when decision is
known. Do not emit duplicate copies from controller, service and repository.

Authentication failures should contain username or user ID, safe failure reason,
correlation ID and source IP where approved. Never attach request body,
authorization header, cookies, submitted password or exception messages that may
contain secrets.

SDK acceptance means bounded local handoff. It does not mean collector, Azure or
Sentinel delivery succeeded.
