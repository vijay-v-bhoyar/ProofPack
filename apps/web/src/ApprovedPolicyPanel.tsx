import { useState } from 'react';
import type { User } from './api';
import { active, type Active } from './policyLifecycle';
import { sha, useReviewDeadline, useTasks, uuid } from './workbench';

function summary(value: Active): Active {
  const result = active(value);
  const fields = ['policy', 'active_version', 'current', 'current_qualification_verified', 'remaining_ms', 'historical_head', 'inspection_enablement_granted', 'scope'];
  if (Object.keys(result).some(key => !fields.includes(key)) || (!result.current && result.remaining_ms !== 0)
    || (result.policy && (Object.keys(result.policy).some(key => !['id', 'revision', 'revision_sha256', 'behavior_sha256', 'name', 'mode'].includes(key))
      || result.policy.revision > 1000 || !sha.test((result.policy as { behavior_sha256?: string }).behavior_sha256 ?? '')
      || !result.policy.name.trim() || /[\x00-\x1f\x7f]/.test(result.policy.name)))) throw new Error('Approved policy summary is unavailable.');
  return result;
}

export function ApprovedPolicyPanel({ user }: { user: User }) {
  const { busy, message, call, perform, say, fresh } = useTasks('Read the recorded approved policy. This view changes nothing.');
  const [ident, setIdent] = useState(''), [revision, setRevision] = useState(''), [review, setReview] = useState<Active | null>(null);
  const expiry = useReviewDeadline();
  const clear = () => { setReview(null); expiry.clear(); };
  const validRevision = revision === '' || (/^[1-9]\d{0,3}$/.test(revision) && Number(revision) <= 1000);
  async function load(byId: boolean) {
    clear(); const token = expiry.token(), started = performance.now(); await fresh(user);
    const result = summary(await call<Active>(byId ? '/policies/' + ident + '?view=approved' + (revision ? '&revision=' + revision : '') : '/policies/active'));
    if (byId && (!result.policy || result.policy.id.toLowerCase() !== ident.toLowerCase()
      || (revision && result.policy.revision !== Number(revision)))) throw new Error('The response does not match the selected approved policy.');
    if (result.current) expiry.bound(started, result.remaining_ms, 60000, token);
    setReview(result); say(result.policy ? 'Recorded policy loaded. Check its qualification status below.' : 'No approved policy is installed. Ask the owner; use ordinary manual checking.');
  }
  return <section aria-labelledby="approved-policy-title"><h3 id="approved-policy-title">Approved policy</h3>
    <p role="status">{message}</p><p>This minimized record grants no inspection enablement or shipment approval. Drafts and superseded policies are unavailable here.</p>
    <fieldset disabled={busy}><legend>Read approved policy metadata</legend>
      <button onClick={() => void perform(() => load(false))}>Read installed approved policy</button>
      <label>Approved policy ID<input value={ident} maxLength={36} onChange={event => { clear(); setIdent(event.target.value); }}/></label>
      <label>Approved policy revision (optional)<input value={revision} maxLength={4} inputMode="numeric" onChange={event => { clear(); setRevision(event.target.value); }}/></label>
      <button disabled={!uuid.test(ident) || !validRevision} onClick={() => void perform(() => load(true))}>Read exact approved policy</button>
      <button onClick={clear}>Clear approved policy review</button>
    </fieldset>
    {review?.policy && <div><p>{review.policy.name} · {review.policy.id} · revision {review.policy.revision}</p>
      <p>Revision SHA-256: {review.policy.revision_sha256}. Active version: {review.active_version}.</p>
      <p>{review.current && expiry.valid ? 'Qualification current at this bounded read. This does not authorize checking or shipment.' : 'Historical or held record. Qualification is not current in this view. Refresh before relying on it.'}</p>
      <p>After interruption, changed configuration or expired review, ask the owner about fresh qualification and readiness. Continue ordinary manual checking when unavailable.</p>
    </div>}
  </section>;
}
