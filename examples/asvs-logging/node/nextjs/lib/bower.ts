// lib/bower.ts: server-only helper for route handlers and server actions.
import 'server-only';
import { headers } from 'next/headers';
import { trace } from '@opentelemetry/api';
// Copy examples/asvs-logging/node/bower-events.mjs into lib/ (it has no dependencies).
import { BowerClient, buildEvent, clientIp } from './bower-events.mjs';

const bower = new BowerClient();
const app = { name: process.env.BOWER_APP_NAME ?? 'nextjs-example', environment: process.env.NODE_ENV ?? 'development', version: '1.0.0' };
const trusted = (process.env.TRUSTED_PROXIES ?? '').split(',').map((s) => s.trim()).filter(Boolean);

type Spec = Record<string, unknown> & { eventType: string; eventCategory: string; eventAction: string; eventResult: string };

/**
 * Emit a Bower security event with request context. proxy.ts sets x-request-id and
 * x-bower-peer, the peer address read from BOWER_PEER_HEADER (empty unless configured).
 */
export async function security(spec: Spec & { route: string }) {
  const h = await headers();
  const span = trace.getActiveSpan()?.spanContext();
  const event = buildEvent(app, {
    ...spec,
    sourceIp: clientIp(h.get('x-bower-peer') ?? '', h.get('x-forwarded-for'), trusted),
    userAgent: h.get('user-agent') ?? undefined,
    request: { correlationId: h.get('x-request-id') ?? span?.traceId, traceId: span?.traceId, ...(spec.request as object) },
  });
  // Route handlers and server actions can await; failures never reach the user.
  const status = await bower.send(event);
  if (!status || status >= 400) console.warn(JSON.stringify({ msg: 'bower event not accepted', status, eventType: spec.eventType }));
}
