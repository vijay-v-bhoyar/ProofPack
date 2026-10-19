import { useState } from 'react';
import type { User } from './api';
import { positive, roles, useTasks, uuid } from './workbench';

type Account = { id: string; display_name: string; roles: string[]; enabled: boolean; access_version: number };
type Invitation = { id: string; target_subject: string; roles: string[]; status: string; state_version: number; delivery_status: string; expires_at_ms: number };
type Page<T> = { next_cursor: string | null } & T;
export function AccountsPanel({ user, onSessionEnded, onTransfer }: { user: User; onSessionEnded: () => void; onTransfer: (id: string) => void }) {
  const { busy, message, call, perform, say, fresh } = useTasks('Load accounts to review current grants. Pending invitations also reserve account capacity.');
  const [accounts, setAccounts] = useState<Account[]>([]), [invites, setInvites] = useState<Invitation[]>([]);
  const [userCursor, setUserCursor] = useState<string | null>(null), [inviteCursor, setInviteCursor] = useState<string | null>(null);
  const [selected, setSelected] = useState(''), [grant, setGrant] = useState<string[]>([]), [enabled, setEnabled] = useState(true), [confirmed, setConfirmed] = useState(false);
  const [subject, setSubject] = useState(''), [email, setEmail] = useState(''), [inviteRoles, setInviteRoles] = useState<string[]>(['operator']), [ttl, setTtl] = useState('3600');
  const [created, setCreated] = useState<{ id: string; capability: string } | null>(null), [revealed, setRevealed] = useState(false), [inviteConfirm, setInviteConfirm] = useState(false);
  const account = accounts.find(item => item.id === selected);
  const toggle = (list: string[], role: string) => list.includes(role) ? list.filter(value => value !== role) : [...list, role];
  async function loadAccounts(more = false) {
    await fresh(user, 'owner'); setConfirmed(false);
    const page = await call<Page<{ users: Account[] }>>('/users?limit=5' + (more && userCursor ? '&cursor=' + encodeURIComponent(userCursor) : ''));
    if (!Array.isArray(page.users) || page.users.some(item => !uuid.test(item.id) || !positive(item.access_version) || !Array.isArray(item.roles)
      || item.roles.some(role => !roles.includes(role)) || typeof item.enabled !== 'boolean')) throw new Error('Account list is unavailable.');
    setAccounts(old => more ? [...old.filter(item => !page.users.some(next => next.id === item.id)), ...page.users] : page.users);
    setUserCursor(page.next_cursor); setSelected(''); setGrant([]); say('Current accounts loaded. Review a person before changing access.');
  }
  async function loadInvites(more = false) {
    await fresh(user, 'owner');
    const page = await call<Page<{ invitations: Invitation[] }>>('/invitations?limit=5' + (more && inviteCursor ? '&cursor=' + encodeURIComponent(inviteCursor) : ''));
    if (!Array.isArray(page.invitations) || page.invitations.some(item => !uuid.test(item.id) || !positive(item.state_version) || !Array.isArray(item.roles))) throw new Error('Invitation list is unavailable.');
    setInvites(old => more ? [...old.filter(item => !page.invitations.some(next => next.id === item.id)), ...page.invitations] : page.invitations); setInviteCursor(page.next_cursor);
  }
  async function createInvitation() {
    if (!inviteConfirm || !subject.trim() || !email.trim() || !Number.isInteger(Number(ttl)) || Number(ttl) < 1 || Number(ttl) > 86400) return;
    const live = await fresh(user, 'owner'); setCreated(null); setRevealed(false); setInviteConfirm(false);
    const result = await call<{ id: string; capability: string; delivery_status: string }>('/invitations', { user: live, method: 'POST',
      body: { target_subject: subject.trim(), target_email: email.trim(), roles: inviteRoles, ttl_seconds: Number(ttl) } });
    if (!uuid.test(result.id) || typeof result.capability !== 'string' || result.capability.length > 128 || result.delivery_status !== 'NOT_SENT') throw new Error('Invitation creation returned an unexpected record. Refresh before retrying.');
    setCreated({ id: result.id, capability: result.capability }); setSubject(''); setEmail('');
    say('Invitation created, NOT_SENT. No message was sent. Share privately only through your authorized process; capability is kept in this page memory only.');
  }
  async function changeAccess(operation: 'access' | 'revoke' | 'transfer') {
    if (!account || !confirmed) return;
    const live = await fresh(user, 'owner'); setConfirmed(false);
    if (operation === 'transfer') {
      const result = await call<{ id: string }>('/owner-transfers', { user: live, method: 'POST', version: account.access_version, body: { target_id: account.id } });
      if (!uuid.test(result.id)) throw new Error('Transfer response is unavailable. Refresh before retrying.');
      onTransfer(result.id); say('Handoff started. The successor must review and explicitly accept with recent MFA; ownership has not changed.'); return;
    }
    await call('/users/' + account.id + (operation === 'access' ? '/access' : '/sessions/revoke'), { user: live, method: operation === 'access' ? 'PATCH' : 'POST',
      version: account.access_version, body: operation === 'access' ? { roles: grant, enabled } : undefined });
    if (account.id === user.id) { onSessionEnded(); return; }
    await loadAccounts(); say(operation === 'access' ? 'Access changed. The person must sign in afresh.' : 'App sessions revoked. This does not claim provider-wide sign-out.');
  }
  return <section aria-labelledby="accounts-title"><h3 id="accounts-title">Accounts and invitations</h3><p role="status">{message}</p>
    <fieldset disabled={busy}><legend>Current access</legend><div className="toolbar"><button onClick={() => void perform(() => loadAccounts())}>Load accounts</button>{userCursor && <button onClick={() => void perform(() => loadAccounts(true))}>More accounts</button>}</div>
      <label>Person to review<select value={selected} onChange={event => { const next = accounts.find(item => item.id === event.target.value); setSelected(next?.id ?? ''); setGrant(next?.roles ?? []); setEnabled(next?.enabled ?? true); setConfirmed(false); }}><option value="">Choose person</option>{accounts.map(item => <option key={item.id} value={item.id}>{item.display_name} · {item.enabled ? 'enabled' : 'disabled'}</option>)}</select></label>
      {account && <><p>{account.display_name} · access version {account.access_version}. Roles never imply other roles.</p>
        <fieldset><legend>Granted roles</legend>{roles.map(role => <label className="check" key={role}><input type="checkbox" checked={grant.includes(role)} onChange={() => { setGrant(toggle(grant, role)); setConfirmed(false); }}/>{role}</label>)}</fieldset>
        <label className="check"><input type="checkbox" checked={enabled} onChange={event => { setEnabled(event.target.checked); setConfirmed(false); }}/>Account enabled</label>
        <label className="check"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)}/>I reviewed this person and the intended access or handoff action.</label>
        <div className="toolbar"><button disabled={!confirmed} onClick={() => void perform(() => changeAccess('access'))}>Save access</button><button disabled={!confirmed} onClick={() => void perform(() => changeAccess('revoke'))}>Revoke app sessions</button><button disabled={!confirmed || account.id === user.id || !account.enabled} onClick={() => void perform(() => changeAccess('transfer'))}>Start ownership handoff</button></div>
      </>}
    </fieldset>
    <fieldset disabled={busy}><legend>Create a private invitation</legend><p>The five-account capacity includes pending invitations. You need the intended person's verified provider identity; an email alone is not that identity.</p>
      <div className="form-grid"><label>Provider subject<input value={subject} maxLength={256} onChange={event => { setSubject(event.target.value); setInviteConfirm(false); }}/></label><label>Target email<input type="email" value={email} maxLength={254} onChange={event => { setEmail(event.target.value); setInviteConfirm(false); }}/></label><label>Invitation validity in seconds<input type="number" min={1} max={86400} value={ttl} onChange={event => { setTtl(event.target.value); setInviteConfirm(false); }}/></label></div>
      <fieldset><legend>Requested roles</legend>{roles.map(role => <label className="check" key={role}><input type="checkbox" checked={inviteRoles.includes(role)} onChange={() => { setInviteRoles(toggle(inviteRoles, role)); setInviteConfirm(false); }}/>{role}</label>)}</fieldset>
      <label className="check"><input type="checkbox" checked={inviteConfirm} onChange={event => setInviteConfirm(event.target.checked)}/>I verified the intended identity and requested grant. No delivery is requested.</label>
      <button disabled={!inviteConfirm || !subject.trim() || !email.trim()} onClick={() => void perform(createInvitation)}>Create invitation record</button>
      {created && <div className="private-record"><p>Invitation ID: {created.id} · NOT_SENT</p><label>Private capability<input type={revealed ? 'text' : 'password'} value={created.capability} readOnly autoComplete="off"/></label><div className="toolbar"><button onClick={() => setRevealed(value => !value)}>{revealed ? 'Hide capability' : 'Reveal capability'}</button><button onClick={() => { setCreated(null); setRevealed(false); }}>Forget capability</button></div></div>}
    </fieldset>
    <fieldset disabled={busy}><legend>Pending and historical invitations</legend><button onClick={() => void perform(() => loadInvites())}>Load invitations</button>{inviteCursor && <button onClick={() => void perform(() => loadInvites(true))}>More invitations</button>}
      <ul>{invites.map(item => <li key={item.id}><p>{item.target_subject} · {item.roles.join(', ')} · {item.status} · {item.delivery_status}</p>{item.status === 'pending' && <button onClick={() => void perform(async () => { const live = await fresh(user, 'owner'); await call('/invitations/' + item.id + '/revoke', { user: live, method: 'POST', version: item.state_version }); await loadInvites(); say('Invitation revoked.'); })}>Revoke invitation for {item.target_subject}</button>}</li>)}</ul>
    </fieldset>
  </section>;
}
