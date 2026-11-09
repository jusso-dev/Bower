// Fastify 5 with request IDs, trusted-proxy client IP, its built-in Pino logger and Bower events.
//   BOWER_COLLECTOR_URL=... BOWER_INGEST_TOKEN=... TRUSTED_PROXIES=10.0.0.0/8 node fastify-app.mjs
import { randomUUID } from 'node:crypto';
import Fastify from 'fastify';
import { BowerClient, buildEvent, clientIp } from './bower-events.mjs';

const trustedProxies = (process.env.TRUSTED_PROXIES ?? '').split(',').map((s) => s.trim()).filter(Boolean);
const app = Fastify({
  logger: { redact: { paths: ['req.headers.authorization', 'req.headers.cookie'], remove: true } },
  bodyLimit: 4096,
  // Request IDs honour a W3C traceparent, else a random UUID.
  genReqId: (req) => (req.headers.traceparent?.length === 55 ? req.headers.traceparent.slice(3, 35) : randomUUID()),
  // trustProxy stays false: clientIp applies the trusted list itself.
});
const bower = new BowerClient();
const appInfo = { name: 'fastify-example', environment: process.env.NODE_ENV ?? 'development', version: '1.0.0' };

app.decorateRequest('clientIp', '');
app.addHook('onRequest', async (req, reply) => {
  req.clientIp = clientIp(req.socket.remoteAddress, req.headers['x-forwarded-for'], trustedProxies);
  reply.header('x-request-id', req.id);
});

function security(req, spec) {
  const event = buildEvent(appInfo, {
    ...spec,
    sourceIp: req.clientIp,
    userAgent: req.headers['user-agent'],
    route: req.routeOptions?.url,
    request: { correlationId: req.id, method: req.method, path: req.url },
  });
  bower.send(event).then((status) => {
    if (!status || status >= 400) req.log.warn({ status, eventType: spec.eventType }, 'bower event not accepted');
  });
}

app.post('/login', async (req, reply) => {
  const { username = '', password = '' } = req.body ?? {};
  if (`${username}:${password}` !== 'demo:demo-password') {
    security(req, { eventCategory: 'authentication', eventType: 'authentication_failure', eventAction: 'authentication.attempt',
      eventResult: 'failure', eventSeverity: 'low', reason: 'InvalidCredentials', actor: { username } });
    return reply.code(401).send({ error: 'invalid credentials' });
  }
  security(req, { eventCategory: 'authentication', eventType: 'authentication_success', eventAction: 'authentication.login',
    eventResult: 'success', actor: { userId: 'user-demo', username }, labels: { authMethod: 'password' } });
  return reply.code(204).send();
});

app.get('/admin/users', async (req, reply) => {
  security(req, { eventCategory: 'authorisation', eventType: 'authorisation_failure', eventAction: 'authz.function',
    eventResult: 'denied', eventSeverity: 'medium', actor: { userId: 'user-demo', role: 'member' },
    target: { type: 'function', id: 'admin.users.list' } });
  return reply.code(403).send({ error: 'forbidden' });
});

app.setErrorHandler((err, req, reply) => {
  const malformed = err.statusCode === 400;
  security(req, malformed
    ? { eventCategory: 'application-security', eventType: 'input_validation_failure', eventAction: 'validation.reject',
        eventResult: 'failure', eventSeverity: 'low', reason: err.code ?? 'BadRequest' }
    : { eventCategory: 'application-security', eventType: 'application_error', eventAction: 'error.unhandled',
        eventResult: 'failure', eventSeverity: 'medium', reason: 'UnhandledException', labels: { errorType: err.name } });
  reply.code(malformed ? 400 : 500).send({ error: malformed ? 'bad request' : 'internal error', requestId: req.id });
});

await app.listen({ port: Number(process.env.PORT ?? 3001), host: '127.0.0.1' });
