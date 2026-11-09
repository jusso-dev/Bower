// Express 5 with request IDs, trusted-proxy client IP, Pino and Bower security events.
//   BOWER_COLLECTOR_URL=... BOWER_INGEST_TOKEN=... TRUSTED_PROXIES=10.0.0.0/8 node express-app.mjs
import { randomUUID, timingSafeEqual } from 'node:crypto';
import express from 'express';
import { BowerClient, buildEvent, clientIp } from './bower-events.mjs';
import { logger } from './logger.mjs';

const app = express();
const bower = new BowerClient();
const appInfo = { name: 'express-example', environment: process.env.NODE_ENV ?? 'development', version: '1.0.0' };
// Trust nothing unless configured. Express's own 'trust proxy' stays off: clientIp decides.
const trustedProxies = (process.env.TRUSTED_PROXIES ?? '').split(',').map((s) => s.trim()).filter(Boolean);

// Request context first, so even body-parser errors carry an id and client IP.
app.use((req, res, next) => {
  const traceparent = req.get('traceparent');
  req.id = traceparent?.length === 55 ? traceparent.slice(3, 35) : randomUUID();
  req.clientIp = clientIp(req.socket.remoteAddress, req.get('x-forwarded-for'), trustedProxies);
  res.set('x-request-id', req.id);
  next();
});
app.use(express.json({ limit: '4kb' }));

function security(req, spec) {
  const event = buildEvent(appInfo, {
    ...spec,
    sourceIp: req.clientIp,
    userAgent: req.get('user-agent'),
    route: req.route?.path ?? spec.route ?? req.path,
    request: { correlationId: req.id, method: req.method, path: req.originalUrl, ...spec.request },
  });
  // Fire and forget: a slow collector never delays the response.
  bower.send(event).then((status) => {
    if (!status || status >= 400) logger.warn({ status, eventType: spec.eventType, requestId: req.id }, 'bower event not accepted');
  });
}

// Compare byte lengths: non-ASCII input has more UTF-8 bytes than UTF-16 code units, and a
// length mismatch would make timingSafeEqual throw.
const safeEqual = (a, b) => {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
};

app.post('/login', (req, res) => {
  const { username = '', password = '' } = req.body ?? {};
  if (!safeEqual(`${username}:${password}`, 'demo:demo-password')) {
    security(req, { eventCategory: 'authentication', eventType: 'authentication_failure', eventAction: 'authentication.attempt',
      eventResult: 'failure', eventSeverity: 'low', reason: 'InvalidCredentials', actor: { username } });
    return res.status(401).json({ error: 'invalid credentials' });
  }
  security(req, { eventCategory: 'authentication', eventType: 'authentication_success', eventAction: 'authentication.login',
    eventResult: 'success', actor: { userId: 'user-demo', username }, labels: { authMethod: 'password' } });
  return res.status(204).end();
});

app.get('/admin/users', (req, res) => {
  security(req, { eventCategory: 'authorisation', eventType: 'authorisation_failure', eventAction: 'authz.function',
    eventResult: 'denied', eventSeverity: 'medium', actor: { userId: 'user-demo', role: 'member' },
    target: { type: 'function', id: 'admin.users.list' }, labels: { requiredPermission: 'users.read' } });
  res.status(403).json({ error: 'forbidden' });
});

// Last-resort handler (ASVS 5.0 V16.5.1, V16.5.4): generic message out, event to Bower.
app.use((err, req, res, _next) => {
  const malformed = err.type === 'entity.parse.failed';
  security(req, malformed
    ? { eventCategory: 'application-security', eventType: 'input_validation_failure', eventAction: 'validation.reject',
        eventResult: 'failure', eventSeverity: 'low', reason: 'MalformedJson' }
    : { eventCategory: 'application-security', eventType: 'application_error', eventAction: 'error.unhandled',
        eventResult: 'failure', eventSeverity: 'medium', reason: 'UnhandledException', labels: { errorType: err.name ?? 'Error' } });
  res.status(malformed ? 400 : 500).json({ error: malformed ? 'bad request' : 'internal error', requestId: req.id });
});

const port = Number(process.env.PORT ?? 3000);
app.listen(port, '127.0.0.1', () => logger.info({ port }, 'express example listening'));
