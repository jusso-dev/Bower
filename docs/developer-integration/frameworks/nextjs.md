# Next.js

Send security events from route handlers and server actions, set a request ID in
`proxy.ts`, add OpenTelemetry in `instrumentation.ts`, and keep Pino for application logs.
Read the [shared guidance](../asvs-logging-frameworks.md) first.

Example: [`examples/asvs-logging/node/nextjs`](../../../examples/asvs-logging/node/nextjs)
(Next.js 16, App Router). `check.sh` builds it, with type checking, in a temporary copy.

## Set up

1. Copy [`node/bower-events.mjs`](../../../examples/asvs-logging/node/bower-events.mjs) and
   its type file `bower-events.d.mts` into `lib/`.
2. Add [`lib/bower.ts`](../../../examples/asvs-logging/node/nextjs/lib/bower.ts). Its
   `security()` function reads the request headers, adds the client IP, user agent, request ID
   and active trace ID, and sends the event. It imports `server-only`, so it can't end up in
   a client bundle, where the ingest token would leak.
3. Set `BOWER_COLLECTOR_URL`, `BOWER_INGEST_TOKEN` and `TRUSTED_PROXIES` in the server
   environment. Never prefix them with `NEXT_PUBLIC_`.

## Request ID and client IP: `proxy.ts`

[`proxy.ts`](../../../examples/asvs-logging/node/nextjs/proxy.ts) (called `middleware.ts`
before Next.js 16) gives each request an ID, reusing the `traceparent` trace ID when there is
one, and passes it on in `x-request-id`.

Next.js has no reliable peer address in route handlers. The proxy copies the header named in
`BOWER_PEER_HEADER` (for example `x-real-ip`) into `x-bower-peer`, and **overwrites** any
`x-bower-peer` the client sent. Set `BOWER_PEER_HEADER` only when your load balancer or
platform always sets that header itself and drops client copies of it. Unset, nothing is
trusted and events carry no source IP. `security()` then applies `TRUSTED_PROXIES` to
`X-Forwarded-For` as usual.

## Route handlers

```ts
// app/api/login/route.ts
export const runtime = 'nodejs';

export async function POST(request: Request) {
  // ... check the credential with your identity provider ...
  if (!ok) {
    await security({ eventCategory: 'authentication', eventType: 'authentication_failure',
      eventAction: 'authentication.attempt', eventResult: 'failure', eventSeverity: 'low',
      reason: 'InvalidCredentials', actor: { username }, route: '/api/login' });
    return NextResponse.json({ error: 'invalid credentials' }, { status: 401 });
  }
  await security({ eventCategory: 'authentication', eventType: 'authentication_success',
    eventAction: 'authentication.login', eventResult: 'success',
    actor: { userId: user.id, username }, labels: { authMethod: 'password' }, route: '/api/login' });
  return new NextResponse(null, { status: 204 });
}
```

Pass `route` yourself: Next.js doesn't expose the matched route template to the handler.
Use the file path pattern (`/api/invoices/[id]`). The full file is
[`app/api/login/route.ts`](../../../examples/asvs-logging/node/nextjs/app/api/login/route.ts);
[`app/api/admin/users/route.ts`](../../../examples/asvs-logging/node/nextjs/app/api/admin/users/route.ts)
shows an authorisation failure.

## Server actions

Check permission inside the action, emit the decision, then act.
[`app/admin/actions.ts`](../../../examples/asvs-logging/node/nextjs/app/admin/actions.ts)
emits `authorisation_failure` when a member tries to disable a user, and
`account_status_changed` when an admin does. Use `action:<name>` as the route.

## OpenTelemetry and errors: `instrumentation.ts`

[`instrumentation.ts`](../../../examples/asvs-logging/node/nextjs/instrumentation.ts)
registers `@vercel/otel`, so `security()` can add the active span's trace ID as
`request.traceId`. Its `onRequestError` hook sends one `application_error` event for each
unhandled server error, with the error type and route but no message or stack trace (ASVS
5.0 V16.3.4, V16.5.4).

`@vercel/otel` 2.x needs its OpenTelemetry peers installed explicitly; the example's
`package.json` pins a set that resolves together.

## Pino

[`lib/logger.ts`](../../../examples/asvs-logging/node/nextjs/lib/logger.ts) uses ISO UTC
timestamps and removes authorisation headers, cookies, passwords and tokens. Add `pino` to
`serverExternalPackages` in `next.config.mjs`.

## What was run

`check.sh` (`next build` with type checking) passes. The built app was started and sent all
four test requests to a local collector with the ASVS pack: three were accepted, the
malformed body was accepted as `input_validation_failure`, the client IP came from the
proxy-set header, and no password, CRLF or spoofed header value reached the collector's
redacted output.
