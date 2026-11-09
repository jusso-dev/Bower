// app/api/login/route.ts: a route handler that emits authentication events.
import { timingSafeEqual } from 'node:crypto';
import { NextResponse } from 'next/server';
import { security } from '@/lib/bower';

export const runtime = 'nodejs';

export async function POST(request: Request) {
  let body: { username?: string; password?: string };
  try {
    body = await request.json();
  } catch {
    await security({ eventCategory: 'application-security', eventType: 'input_validation_failure', eventAction: 'validation.reject',
      eventResult: 'failure', eventSeverity: 'low', reason: 'MalformedJson', route: '/api/login' });
    return NextResponse.json({ error: 'bad request' }, { status: 400 });
  }
  const supplied = Buffer.from(`${body.username ?? ''}:${body.password ?? ''}`);
  const expected = Buffer.from('demo:demo-password'); // use your identity provider
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    await security({ eventCategory: 'authentication', eventType: 'authentication_failure', eventAction: 'authentication.attempt',
      eventResult: 'failure', eventSeverity: 'low', reason: 'InvalidCredentials', actor: { username: body.username ?? '' }, route: '/api/login' });
    return NextResponse.json({ error: 'invalid credentials' }, { status: 401 });
  }
  await security({ eventCategory: 'authentication', eventType: 'authentication_success', eventAction: 'authentication.login',
    eventResult: 'success', actor: { userId: 'user-demo', username: body.username }, labels: { authMethod: 'password' }, route: '/api/login' });
  return new NextResponse(null, { status: 204 });
}
