# ASP.NET Core instrumentation

Add `Bower.Sdk`, call `AddBower`, then inject `IBowerTelemetry`. Emit after
authoritative transaction success. Emit meaningful failures when decision is
known. Do not emit duplicate copies from controller, service and repository.

`Bower.Sdk` and `Bower.Contracts` target .NET 10 (LTS) and .NET 11, so applications on either can
reference them. The rest of Bower targets .NET 11 only.

Authentication failures should contain username or user ID, safe failure reason,
correlation ID and source IP where approved. Never attach request body,
authorization header, cookies, submitted password or exception messages that may
contain secrets.

SDK acceptance means bounded local handoff. It does not mean collector, Azure or
Sentinel delivery succeeded.

## Event ID scope and conflicts

Event IDs must be globally unique across producers and stable across retries.
Generate a random ID once per event, or use a globally namespaced stable source
ID. HTTP 409 `event-identity-conflict` requires producer repair: preserve the
upstream event without acknowledging or discarding it. See
[event identity conflict recovery](../operations/event-identity-conflicts.md).

## Serilog and the ASVS pack

`Bower.Sdk` has typed helpers for `authentication_failure`, `role_membership_changed` and
`sensitive_data_exported`. For the other [ASVS logging pack](../security/asvs-logging-pack.md)
families (sign-in success, MFA, sessions, authorisation failures, validation, errors), the
[`aspnetcore-serilog`](../../examples/asvs-logging/aspnetcore-serilog) example sends
envelopes over HTTP with a small `BowerEvents` helper, the same one every other
[framework guide](asvs-logging-frameworks.md) uses. Use the SDK where it has a helper: it
buffers and retries.

The example is a standalone project, not in `Bower.sln`, so Serilog isn't a Bower
dependency.

**Serilog.** `UseSerilog` with `RenderedCompactJsonFormatter` writes JSON, which escapes CR
and LF (ASVS 5.0 V16.4.1). A filter drops any log event with a secret-named property
(`BowerEvents.IsSecret`) before a sink sees it (V16.2.5). `UseSerilogRequestLogging` writes
one line per request, and `LogContext` adds the request ID to each line.

**Client IP.** `ForwardedHeadersOptions` clears the default known proxies and adds only the
`TRUSTED_PROXIES` networks, with `ForwardLimit = null` so every trusted hop is skipped. The
example enables `UseForwardedHeaders` only when at least one network is configured: with both
lists cleared and nothing added, ASP.NET Core would accept the header from any peer.
`HttpContext.Connection.RemoteIpAddress` is then the original client address (V15.3.4,
V4.1.3).

**Request ID.** The W3C trace ID of `Activity.Current`, which ASP.NET Core takes from an
incoming `traceparent`, or `TraceIdentifier`. It's returned in `X-Request-Id` and becomes
`request.correlationId`.

**Events.** `Security(context, spec)` adds the client IP, user agent, route pattern
(`RouteEndpoint.RoutePattern.RawText`) and request fields, and `BowerSender` posts in the
background with a typed `HttpClient`. `UseExceptionHandler` sends `application_error` and
returns a generic body (V16.3.4, V16.5.1, V16.5.4). With ASP.NET Core Identity, emit from your
sign-in handler after `PasswordSignInAsync` returns, using `SignInResult.IsLockedOut`,
`RequiresTwoFactor` and `Succeeded` to pick the event type.

**What was run.** The example builds with no warnings on .NET 10 (Serilog.AspNetCore 10.0.0)
and matches the cross-language contract. It was run against a local collector with the ASVS
pack: all four test requests were accepted, a spoofed `X-Forwarded-For` was ignored unless
loopback was listed in `TRUSTED_PROXIES`, and no password reached the collector or the
Serilog output.
