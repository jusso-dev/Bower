# Express, Fastify and NestJS

All three use the same helper,
[`node/bower-events.mjs`](../../../examples/asvs-logging/node/bower-events.mjs), which has no
dependencies and works on Node.js 20 and later. Read the
[shared guidance](../asvs-logging-frameworks.md) first.

```js
import { BowerClient, buildEvent, clientIp } from './bower-events.mjs';
const bower = new BowerClient();                       // BOWER_COLLECTOR_URL, BOWER_INGEST_TOKEN
const trusted = (process.env.TRUSTED_PROXIES ?? '').split(',').filter(Boolean);
```

`BowerClient.send()` never throws. It returns the HTTP status, or `null` if the collector is
unreachable.

## Express

[`express-app.mjs`](../../../examples/asvs-logging/node/express-app.mjs), Express 5:

- The first middleware sets `req.id` (from `traceparent` or a new UUID) and `req.clientIp`, and
  returns `x-request-id`. It runs before `express.json()`, so a body parse error still has
  context.
- Leave `app.set('trust proxy')` off: `clientIp()` applies `TRUSTED_PROXIES`.
- `security(req, spec)` adds the route template (`req.route.path`), user agent and request
  fields, and sends without awaiting.
- The final error handler turns body parse errors into `input_validation_failure` and
  everything else into `application_error`, and returns a generic message (ASVS 5.0 V16.5.1).

## Fastify

[`fastify-app.mjs`](../../../examples/asvs-logging/node/fastify-app.mjs), Fastify 5:

- `genReqId` reuses the `traceparent` trace ID; an `onRequest` hook sets `req.clientIp`.
- Keep `trustProxy` false.
- `req.routeOptions.url` is the route template.
- Fastify's built-in Pino logger removes `authorization` and `cookie` headers.
- `setErrorHandler` emits validation and unhandled-error events.

## NestJS

[`nestjs/bower.module.ts`](../../../examples/asvs-logging/node/nestjs/bower.module.ts)
provides `BowerModule`:

- `BowerSecurity.emit(req, spec)` is injectable. Call it from your `AuthService` where the
  credential check happens.
- A global exception filter records `ForbiddenException` from guards as
  `authorisation_failure`, `BadRequestException` (including `ValidationPipe`) as
  `input_validation_failure`, and anything that isn't an `HttpException` as `application_error`.
- Request context is computed on first use, because Nest's body parser runs before module
  middleware.

[`nestjs/main.ts`](../../../examples/asvs-logging/node/nestjs/main.ts) is a runnable app;
`nestjs/check.sh` builds it in a temporary copy.

## Pino

[`logger.mjs`](../../../examples/asvs-logging/node/logger.mjs) uses ISO UTC timestamps and
removes `authorization`, `cookie`, `set-cookie`, passwords, tokens and bodies. Pino writes
JSON, which escapes CR and LF.

## What was run

All three apps were run against a local collector with the ASVS pack. Each produced the four
expected events (failure, success, authorisation failure, validation failure), all accepted.
A spoofed `X-Forwarded-For` was ignored, and no password or CRLF reached the redacted output.
The helper matches the cross-language contract.
