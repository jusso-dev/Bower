// app/api/admin/users/route.ts: authorisation failure from a route handler.
import { NextResponse } from 'next/server';
import { security } from '@/lib/bower';

export const runtime = 'nodejs';

export async function GET() {
  await security({ eventCategory: 'authorisation', eventType: 'authorisation_failure', eventAction: 'authz.function',
    eventResult: 'denied', eventSeverity: 'medium', actor: { userId: 'user-demo', role: 'member' },
    target: { type: 'function', id: 'admin.users.list' }, route: '/api/admin/users' });
  return NextResponse.json({ error: 'forbidden' }, { status: 403 });
}
