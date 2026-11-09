// instrumentation.ts: OpenTelemetry traces, so Bower events carry a W3C trace id that joins
// them to spans (request.traceId). Bower stays the security event path; OTel is for tracing.
export async function register() {
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    const { registerOTel } = await import('@vercel/otel');
    registerOTel({ serviceName: process.env.BOWER_APP_NAME ?? 'nextjs-example' });
  }
}

// Last-resort error hook (Next.js 15+): one application_error event per unhandled server error.
export async function onRequestError(error: unknown, request: { path: string; method: string; headers: Record<string, string> },
  context: { routePath: string; routeType: string }) {
  if (process.env.NEXT_RUNTIME !== 'nodejs') return;
  const { BowerClient, buildEvent } = await import('./lib/bower-events.mjs');
  const event = buildEvent({ name: process.env.BOWER_APP_NAME ?? 'nextjs-example', environment: process.env.NODE_ENV ?? 'development' }, {
    eventCategory: 'application-security', eventType: 'application_error', eventAction: 'error.unhandled', eventResult: 'failure',
    eventSeverity: 'medium', reason: 'UnhandledException', route: context.routePath,
    labels: { errorType: error instanceof Error ? error.name : 'Error', routeType: context.routeType },
    request: { correlationId: request.headers['x-request-id'] ?? 'unknown', method: request.method, path: request.path },
  });
  await new BowerClient().send(event);
}
