import { disableUser } from './actions';

export default function AdminPage() {
  async function submit() {
    'use server';
    await disableUser('user-2002').catch(() => undefined);
  }
  return (<form action={submit}><button type="submit">Disable user-2002</button></form>);
}
