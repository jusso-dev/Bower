// app/admin/actions.ts: a server action that checks permission and emits the decision.
'use server';
import { security } from '@/lib/bower';

async function currentUser() {
  return { id: 'user-demo', role: 'member' }; // replace with your session lookup
}

export async function disableUser(targetUserId: string) {
  const user = await currentUser();
  if (user.role !== 'admin') {
    await security({ eventCategory: 'authorisation', eventType: 'authorisation_failure', eventAction: 'authz.function',
      eventResult: 'denied', eventSeverity: 'medium', actor: { userId: user.id, role: user.role },
      target: { type: 'function', id: 'users.disable' }, labels: { requiredPermission: 'users.disable' }, route: 'action:disableUser' });
    throw new Error('Forbidden');
  }
  // ... disable the account and revoke its sessions, then:
  await security({ eventCategory: 'identity-management', eventType: 'account_status_changed', eventAction: 'account.disable',
    eventResult: 'success', eventSeverity: 'medium', actor: { userId: user.id, role: user.role },
    target: { type: 'user', id: targetUserId }, route: 'action:disableUser' });
}
