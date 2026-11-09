# Security events from web frameworks

This page covers what every framework guide shares: what to send, how to send it, and the
four things that go wrong most often (client IP, request IDs, secrets in events, log
injection). Then pick your stack:

| Stack | Guide | Example code |
|---|---|---|
| Next.js | [Next.js](frameworks/nextjs.md) | [`examples/asvs-logging/node/nextjs`](../../examples/asvs-logging/node/nextjs) |
| Express, Fastify, NestJS | [Node.js servers](frameworks/node.md) | [`examples/asvs-logging/node`](../../examples/asvs-logging/node) |
| Django, Flask, FastAPI | [Python](frameworks/python.md) | [`examples/asvs-logging/python`](../../examples/asvs-logging/python) |
| Rails | [Rails](frameworks/rails.md) | [`examples/asvs-logging/ruby`](../../examples/asvs-logging/ruby) |
| Laravel | [Laravel](frameworks/laravel.md) | [`examples/asvs-logging/php`](../../examples/asvs-logging/php) |
| Spring Boot | [Spring Boot](frameworks/spring-boot.md) | [`examples/asvs-logging/java`](../../examples/asvs-logging/java) |
| ASP.NET Core | [ASP.NET Core](aspnetcore.md#serilog-and-the-asvs-pack) | [`examples/asvs-logging/aspnetcore-serilog`](../../examples/asvs-logging/aspnetcore-serilog) |
| Go | [Go with log/slog](frameworks/go.md) | [`examples/asvs-logging/go`](../../examples/asvs-logging/go) |

Each example has a small helper with no dependencies (or only the standard library) that
builds a Bower envelope, cleans it and posts it to the collector. All seven helpers produce
byte-identical events from the same inputs; see [how the examples are checked](#how-the-examples-are-checked).

## How it fits together

```text
app ── POST /v1/events (Bearer ingest token) ──▶ Bower collector ──▶ BowerSecurity_CL
        envelope 1.0.0, one event per request       producer scope check
                                                     redaction (pack privacy profile)
                                                     policy (default deny)
                                                     durable queue, delivery
```

The collector loads the [ASVS logging pack](../security/asvs-logging-pack.md) alongside
`policies/default`. Every event type the guides use is in the
[event catalogue](../security/asvs-logging-pack.md#event-catalogue); anything else is
rejected. An HTTP 202 means the collector stored the event for delivery. It doesn't mean
Sentinel has it yet.

Security events and application logs are different things. Keep your normal logger (Pino,
`logging`, Serilog, slog and so on) for debugging and operations, and send security events to
Bower. Don't log the same event twice.

## What to send

Emit once, where the decision is made, after it's final:

| When | Event type | Action |
|---|---|---|
| Sign-in succeeds | `authentication_success` | `authentication.login` |
| Sign-in fails | `authentication_failure` | `authentication.attempt` |
| Account locked | `account_lockout` | `authentication.lockout` |
| MFA challenge, success, failure | `mfa_challenge`, `mfa_success`, `mfa_failure` | `mfa.challenge`, `mfa.verify` |
| Factor added or removed | `mfa_factor_enrolled`, `mfa_factor_removed` | `mfa.enrol`, `mfa.remove` |
| Password reset or change | `password_reset_requested`, `password_reset_completed`, `password_changed` | `password.*` |
| Logout, timeout, revocation | `session_terminated` | `session.logout`, `session.timeout`, `session.revoke_all`, ... |
| Access denied | `authorisation_failure` | `authz.function`, `authz.object`, `authz.field`, `authz.stale_grant` |
| Role or permission change | `role_membership_changed`, `permission_changed` | `role.add`, `role.remove`, ... |
| Admin or security setting change | `admin_action`, `configuration_changed` | your verb, for example `config.update` |
| Sensitive read, change or export | `sensitive_data_accessed`, `sensitive_record_changed`, `sensitive_data_exported` | `data.read`, `data.update`, `data.export`, ... |
| Validation or rate-limit rejection | `input_validation_failure`, `anti_automation_triggered` | `validation.reject`, `ratelimit.exceeded` |
| Unhandled error, control failure | `application_error`, `security_control_failure` | `error.unhandled`, `tls.handshake`, ... |

Every event needs `request.correlationId`. Most need a user (`actor.userId` or
`actor.username`) or a source address. The policies quarantine events without the fields
they require, and `bower tap` shows the reason.

A minimal envelope:

```json
{
  "schemaVersion": "1.0.0",
  "eventId": "6f1c2a8e-4c1b-4f55-9d1f-2b7d8c0e9a31",
  "timeGenerated": "2026-11-09T01:02:03.456Z",
  "eventCategory": "authentication",
  "eventType": "authentication_failure",
  "eventAction": "authentication.attempt",
  "eventResult": "failure",
  "eventSeverity": "low",
  "eventOutcomeReason": "InvalidCredentials",
  "application": { "name": "contoso-portal", "environment": "production", "version": "2.4.1" },
  "actor": { "username": "alice@example.com" },
  "source": { "ipAddress": "203.0.113.24" },
  "request": { "correlationId": "req-002", "method": "POST", "path": "/api/login", "statusCode": 401 },
  "labels": { "route": "/api/login", "userAgent": "Mozilla/5.0 (X11; Linux x86_64)" }
}
```

- `eventId`: a new random UUID per event, kept the same on retries.
- `timeGenerated`: UTC with a `Z` (ASVS 5.0 V16.2.2). Every helper formats it the same way.
- `labels.route`: the route template (`/api/invoices/{id}`), not the concrete path.
- `labels.userAgent`: the raw header. The collector truncates it.
- `eventOutcomeReason`: a short code you choose, never an exception message or user input.

## Client IP from trusted proxies only

`source.ipAddress` must be the original client address (ASVS 5.0 V15.3.4), and a client must
not be able to set it (V4.1.3). `X-Forwarded-For` is just a header: anyone can send one.

Every helper has the same `clientIp(peer, xForwardedFor, trustedProxies)` function:

1. If the direct peer isn't in the trusted list, use the peer address and ignore the header.
2. Otherwise walk `X-Forwarded-For` from right to left, skip trusted hops, and use the first
   untrusted address.
3. If that entry isn't a valid IP address, use the peer address.

Set `TRUSTED_PROXIES` to your load balancer or ingress networks (for example
`10.0.0.0/8`). The default is empty, which trusts nothing. Turn off the framework's own proxy
handling (Express `trust proxy`, Uvicorn `--proxy-headers`, Spring
`server.forward-headers-strategy`, Rails `request.remote_ip`), or point it at the same list,
so the two never disagree.

## Request and trace IDs

Every example sets one ID per request, uses it as `request.correlationId`, returns it in
`X-Request-Id`, and adds it to application log lines. When a W3C `traceparent` header is
present, the ID is its trace ID, so Bower events join OpenTelemetry traces. The Next.js and
ASP.NET Core examples also set `request.traceId` from the active span.

## Keeping secrets and personal data out

The collector is the redaction boundary: the pack profile removes secret-named fields,
pseudonymises usernames and session IDs, replaces CR and LF, and drops query strings before
anything is stored. The helpers repeat the cheap parts so secrets don't cross the network
either:

- Fields named like `password`, `token`, `secret`, `cookie`, `authorization`, `headers`,
  `body`, `otp`, `recoveryCode`, `stackTrace` or `statement` are dropped, at any depth.
- CR, LF, other control characters and Unicode line separators become a space (V16.4.1).
- `request.path` loses its query string and fragment.
- `change.previousValue` and `change.newValue` are dropped for everything except role
  changes, so a configuration or password change records only the field name.
- Strings are cut to 256 characters (1,024 for the reason, 2,048 for the path).

You still choose what to put in. Never pass a request body, a header collection, an
exception message or a submitted credential. Use stable IDs (`actor.userId`) rather than
names or email addresses where you can.

## Sending

`POST {BOWER_COLLECTOR_URL}/v1/events` with `Authorization: Bearer {BOWER_INGEST_TOKEN}` and
the envelope as JSON. Read the token from a secret store or a mounted file, never from
source control.

| Status | Meaning | What to do |
|---|---|---|
| 202, 200 | Stored (200: duplicate of an earlier event) | Nothing |
| 400 | Invalid or quarantined (missing required fields) | Fix the emitter; `bower tap` shows the reason |
| 401, 403 | Bad token, or the token may not send this application's events | Check the token and [producer scopes](../security/producer-scopes.md) |
| 409 | Event ID reused for different content | Generate a new ID per event |
| 422 | Rejected by policy (unknown type or below the value score) | Check the type against the catalogue |
| 503 | Queue full or redaction unavailable | Retry with backoff |

The examples send after the response, in the background, with a two-second timeout, and log a
warning on failure. A slow or unavailable collector never slows down or breaks a sign-in.
That means events can be lost if the process dies. If you need them to survive, put a
local buffer in front, or use the [.NET SDK](aspnetcore.md), which buffers and retries.

For a collector shared by several applications, give each one its own token and a
[producer scope](../security/producer-scopes.md) that pins its `application.name`, so one
app can't send events as another. The local test script uses
`BOWER_SINGLE_TRUST_DOMAIN=true`, which turns that off: use it for development only.

## Try it locally

```bash
dotnet build Bower.sln -c Release
examples/asvs-logging/run-local-collector.sh
```

The script starts a collector with the ASVS pack, an ephemeral signing key, HMAC key and
ingest token, and `BOWER_OUTPUT=none`, so nothing leaves the machine. Export the two values it
prints, start an example, and watch what would be stored:

```bash
bower tap --collector "$BOWER_COLLECTOR_URL" --stage redacted
```

Each example accepts the same four requests: a failed sign-in (`demo` with a wrong password),
a successful one (`demo` / `demo-password`), `GET /admin/users` (always denied) and a
malformed JSON body.

## How the examples are checked

- `contract/cases.json` holds eight inputs that include a CRLF username, a password, a bearer
  token, an OTP code, a stack trace, a query string with a token, and a configuration change
  with before and after values. `contract/expected.jsonl` is the one correct output.
- The main CI (`AsvsExampleContractTests`) checks `expected.jsonl` against the envelope schema,
  runs it through the shipped policies and the pack privacy profile, and checks that none of
  the secrets or line breaks survive.
- `examples/asvs-logging/check.sh` runs every helper against the contract: Python, Node.js,
  Go, Ruby, PHP, Java and C#. The optional `ASVS logging examples` workflow runs it when the
  examples change.

Framework code beyond the helpers (Rails initialisers, Laravel listeners, Spring Security
listeners) is compiled or syntax-checked where noted in each guide, but not every framework
is run in CI.
