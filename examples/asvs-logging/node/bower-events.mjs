// Bower security events for Node.js (Next.js, Express, Fastify, NestJS). No dependencies.
// Builds Bower envelope 1.0.0 events, sanitises them before they leave the process and posts
// them to a Bower collector. The collector redacts again; this is defence in depth.
import { randomUUID } from 'node:crypto';
import net from 'node:net';

export const SCHEMA_VERSION = '1.0.0';
const CONTROL = /[\u0000-\u001f\u007f\u2028\u2029]+/g;
const SECRET_FRAGMENTS = ['password', 'passwd', 'passphrase', 'secret', 'token', 'apikey', 'cookie',
  'authorization', 'credential', 'privatekey', 'signature'];
const SECRET_NAMES = new Set(['body', 'rawbody', 'requestbody', 'responsebody', 'headers', 'payload', 'otp', 'otpcode',
  'totp', 'mfacode', 'verificationcode', 'recoverycode', 'backupcode', 'stacktrace', 'exceptionmessage', 'statement',
  'querytext', 'sqltext', 'querystring', 'rawquery']);
const LIMITS = { eventOutcomeReason: 1024, path: 2048 };

function isSecret(name) {
  const normal = String(name).toLowerCase().replace(/[^a-z0-9]/g, '');
  return SECRET_NAMES.has(normal) || SECRET_FRAGMENTS.some((fragment) => normal.includes(fragment));
}

function clean(value, key = '') {
  if (typeof value === 'string') return value.replace(CONTROL, ' ').slice(0, LIMITS[key] ?? 256);
  if (Array.isArray(value)) return value.slice(0, 64).map((item) => clean(item));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [name, item] of Object.entries(value)) {
      if (isSecret(name) || item === null || item === undefined) continue;
      const cleaned = clean(item, name);
      if (cleaned && typeof cleaned === 'object' && !Array.isArray(cleaned) && Object.keys(cleaned).length === 0) continue;
      out[String(name).replace(CONTROL, ' ').slice(0, 128)] = cleaned;
    }
    return out;
  }
  return value;
}

/** UTC, millisecond precision, Z suffix (ASVS 5.0 V16.2.2). */
export const formatTime = (date) => date.toISOString();

/**
 * Build a sanitised envelope. spec: eventType, eventCategory, eventAction, eventResult,
 * eventSeverity, reason, actor, target, sourceIp, userAgent, route, tenantId, request,
 * labels, attributes, change.
 */
export function buildEvent(app, spec, { eventId, now } = {}) {
  const application = {};
  for (const key of ['name', 'environment', 'version', 'instance']) if (app[key]) application[key] = app[key];
  if (spec.tenantId) application.tenantId = spec.tenantId;
  const event = {
    schemaVersion: SCHEMA_VERSION,
    eventId: eventId ?? randomUUID(),
    timeGenerated: formatTime(now ?? new Date()),
    eventCategory: spec.eventCategory,
    eventType: spec.eventType,
    eventAction: spec.eventAction,
    eventResult: spec.eventResult,
    eventSeverity: spec.eventSeverity ?? 'informational',
    application,
  };
  if (spec.reason) event.eventOutcomeReason = spec.reason;
  if (spec.actor) event.actor = { ...spec.actor };
  if (spec.target) event.target = { ...spec.target };
  if (spec.sourceIp) event.source = { ipAddress: spec.sourceIp };
  const request = { ...(spec.request ?? {}) };
  if (request.path) request.path = request.path.split(/[?#]/, 1)[0];
  if (Object.keys(request).length) event.request = request;
  const labels = { ...(spec.labels ?? {}) };
  if (spec.userAgent) labels.userAgent = spec.userAgent;
  if (spec.route) labels.route = spec.route;
  if (Object.keys(labels).length) event.labels = Object.fromEntries(Object.entries(labels).map(([k, v]) => [k, String(v)]));
  if (spec.attributes) event.attributes = { ...spec.attributes };
  let change = { ...(spec.change ?? {}) };
  // Before and after values of settings and credentials never leave the process.
  if (Object.keys(change).length && spec.eventType !== 'role_membership_changed') change = 'field' in change ? { field: change.field } : {};
  if (Object.keys(change).length) event.change = change;
  return clean(event);
}

function parseCidr(cidr) {
  const [address, bits] = cidr.split('/');
  const family = net.isIP(address);
  return { address, family, bits: bits === undefined ? (family === 6 ? 128 : 32) : Number(bits) };
}

function toBigInt(address) {
  if (net.isIPv4(address)) return address.split('.').reduce((acc, part) => (acc << 8n) + BigInt(part), 0n);
  const [head, tail = ''] = address.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const parts = address.includes('::') ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h;
  return parts.reduce((acc, part) => (acc << 16n) + BigInt(parseInt(part || '0', 16)), 0n);
}

function inCidr(address, cidr) {
  const family = net.isIP(address);
  if (!family || family !== cidr.family) return false;
  const width = family === 6 ? 128 : 32;
  const shift = BigInt(width - cidr.bits);
  return (toBigInt(address) >> shift) === (toBigInt(cidr.address) >> shift);
}

/**
 * Original client address (ASVS 5.0 V15.3.4, V4.1.3). X-Forwarded-For is read only when the
 * direct peer is a trusted proxy, right to left, skipping trusted hops.
 */
export function clientIp(remoteAddress, forwardedFor, trustedProxies) {
  const networks = trustedProxies.map(parseCidr);
  const trusted = (address) => networks.some((cidr) => inCidr(address, cidr));
  const remote = String(remoteAddress ?? '').replace(/^::ffff:/, '');
  if (!forwardedFor || !trusted(remote)) return remote;
  const hops = forwardedFor.split(',').map((hop) => hop.trim()).filter(Boolean);
  for (const hop of hops.reverse()) {
    if (!trusted(hop)) return net.isIP(hop) ? hop : remote;
  }
  return hops.at(-1) ?? remote;
}

/** Posts events to a Bower collector. Never throws into the request path. */
export class BowerClient {
  constructor({ endpoint = process.env.BOWER_COLLECTOR_URL ?? 'http://127.0.0.1:4319', token = process.env.BOWER_INGEST_TOKEN, timeoutMs = 2000 } = {}) {
    this.endpoint = endpoint.replace(/\/$/, '');
    this.token = token;
    this.timeoutMs = timeoutMs;
  }

  async send(event) {
    try {
      const response = await fetch(`${this.endpoint}/v1/events`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(this.token ? { authorization: `Bearer ${this.token}` } : {}) },
        body: JSON.stringify(event),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      return response.status;
    } catch {
      return null;
    }
  }
}
