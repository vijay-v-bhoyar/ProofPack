import { useEffect, useRef, useState } from 'react';
import { positive, roles, sha, useTasks, uuid } from './workbench';

type Pending = { status: string; invitation_id: string; session_id: string; csrf_token: string };
type Invitation = { id: string; target_subject: string; roles: string[]; status: string; expires_at_ms: number; state_version: number; delivery_status: string };
type Notice = { version: string; text: string; sha256: string; optional_improvement_default: boolean; optional_publicity_default: boolean };

export function InvitationPanel({ onBack }: { onBack: () => void }) {
  const { busy, message, call, perform, say } = useTasks('Loading your invitation…');
  const [session, setSession] = useState<Pending | null>(null), [invitation, setInvitation] = useState<Invitation | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null), [capability, setCapability] = useState(''), [ack, setAck] = useState(false);
  const [finished, setFinished] = useState(false); const heading = useRef<HTMLHeadingElement>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    heading.current?.focus(); let active = true;
    void (async () => {
      const own = await call<Pending>('/auth/session');
      if (own.status !== 'invitation_pending' || !uuid.test(own.invitation_id) || typeof own.csrf_token !== 'string' || typeof own.session_id !== 'string')
        throw new Error('No pending invitation is bound to this session. Return and sign in with the intended account.');
      const details = await call<Invitation>('/invitations/' + own.invitation_id);
      if (details.id !== own.invitation_id || !Array.isArray(details.roles) || details.roles.some(role => !roles.includes(role))
        || !positive(details.state_version) || !Number.isFinite(details.expires_at_ms)) throw new Error('Invitation information is unavailable. Ask the owner.');
      if (active) { setSession(own); setInvitation(details); }
      const terms = await call<Notice>('/auth/notice');
      if (typeof terms.text !== 'string'
        || !terms.version || !sha.test(terms.sha256) || terms.optional_improvement_default !== false || terms.optional_publicity_default !== false)
        throw new Error('Invitation or notice information is unavailable. Ask the owner.');
      if (active) { setSession(own); setInvitation(details); setNotice(terms); say('Review the grant and notice. Acceptance is your choice.'); }
    })().catch(error => { if (active) say(error instanceof Error ? error.message : 'Invitation unavailable.'); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);
  async function decide(accept: boolean) {
    if (!session || !invitation || (accept && (!notice || !ack || !capability))) return;
    const live = await call<Pending>('/auth/session');
    if (live.status !== 'invitation_pending' || live.session_id !== session.session_id || live.invitation_id !== invitation.id)
      throw new Error('Invitation session changed. Sign in again before deciding.');
    if (accept) {
      const current = await call<Notice>('/auth/notice');
      if (current.version !== notice!.version || current.sha256 !== notice!.sha256) {
        setAck(false); setCapability(''); setNotice(null); throw new Error('The notice changed. Return and reopen the invitation to review it.');
      }
    }
    const secret = capability; setCapability(''); setAck(false);
    await call('/invitations/' + invitation.id + (accept ? '/accept' : '/decline'), { method: 'POST', user: live,
      body: accept ? { capability: secret, notice_version: notice!.version, notice_sha256: notice!.sha256 } : undefined });
    setFinished(true); setSession(null); setInvitation(null); setNotice(null);
    say(accept ? 'Invitation accepted. Sign in afresh to use the granted roles.' : 'Invitation declined. No inspection access was granted.');
  }
  return <section className="operator" aria-labelledby="invite-title"><h2 id="invite-title" ref={heading} tabIndex={-1}>Your invitation</h2>
    <p role="status">{message}</p>
    {invitation && !finished && <fieldset disabled={busy || loading}><legend>Review before choosing</legend>
      <p>Requested roles: {invitation.roles.join(', ') || 'No roles'}. Status: {invitation.status}. Expires: {new Date(invitation.expires_at_ms).toLocaleString()}.</p>
      <p>Delivery record: {invitation.delivery_status}. Creating a record does not send an invitation.</p>
      {notice ? <><h3>Processing notice · {notice.version}</h3><p className="notice-text">{notice.text}</p></> : <p>Current processing notice unavailable. Return and reopen to review it before acceptance. You may still decline.</p>}
      <p>Optional improvement-data and publicity use are off. Accepting this invitation does not opt you into either.</p>
      {invitation.status === 'pending' && <><label>Private invitation capability<input type="password" autoComplete="off" maxLength={128} value={capability} onChange={event => setCapability(event.target.value)}/></label>
        <label className="check"><input type="checkbox" checked={ack} disabled={!notice} onChange={event => setAck(event.target.checked)}/>I read the current processing notice and choose to accept these roles.</label>
        <div className="toolbar"><button disabled={!notice || !ack || !capability} onClick={() => void perform(() => decide(true))}>Accept invitation</button><button onClick={() => void perform(() => decide(false))}>Decline invitation</button></div></>}
    </fieldset>}
    {(finished || !session) && <a href="/api/v1/auth/login">Sign in with your invited account</a>}
    <button disabled={busy} onClick={onBack}>Return to workspace</button>
  </section>;
}
