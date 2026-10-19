import { useState } from 'react';
import { ApiError, type User } from './api';
import { useUnconfirmed, positive, sha, uuid, useTasks } from './workbench';

const actions = ['SEPARATE_REGION', 'PLACE_FLAT', 'RECAPTURE'] as const;
const labels: Record<string, string> = { SEPARATE_REGION: 'Separate overlapping parts', PLACE_FLAT: 'Place a part flat', RECAPTURE: 'Recapture' };
type Spec = { name: string; algorithm: 'reason_priority_v1'; priority: string[] };
type Candidate = { id: string; state_version: number; latest_revision: number; revision: number; revision_sha256: string; previous_sha256: string | null;
  behavior_sha256: string; spec: Spec; status: string; evaluation_status: string; promotion_available: boolean; can_revise: boolean; live_effect: string };
type Intent = { path: string; body: Spec; key: string; version?: number; id?: string; previousRevision: number };
const validSpec = (s: Spec) => s && typeof s.name === 'string' && s.name.trim().length > 0 && s.name.length <= 80 && !/[\x00-\x1f\x7f]/.test(s.name)
  && s.algorithm === 'reason_priority_v1' && Array.isArray(s.priority) && s.priority.length === 3 && new Set(s.priority).size === 3 && s.priority.every(p => actions.some(a => a === p));
function checked(c: Candidate): Candidate {
  if (!c || !uuid.test(c.id) || !positive(c.state_version) || !positive(c.revision) || c.revision > 1000 || !positive(c.latest_revision) || c.latest_revision < c.revision || c.latest_revision > 1000
    || !sha.test(c.revision_sha256) || !sha.test(c.behavior_sha256) || (c.revision === 1 ? c.previous_sha256 !== null : !sha.test(c.previous_sha256 ?? '')) || !validSpec(c.spec)
    || c.status !== 'draft' || c.evaluation_status !== 'NOT_VERIFIED' || c.promotion_available !== false || c.live_effect !== 'none_from_draft_write' || typeof c.can_revise !== 'boolean')
    throw new Error('Policy metadata is incomplete or claims unsupported activation. Read the current record before acting.');
  return c;
}

export function PolicyPanel({ user }: { user: User }) {
  const { busy, message, call, perform, say, fresh } = useTasks('Policy drafts do not change live inspections.');
  const reviewer = user.roles.includes('reviewer');
  const [name, setName] = useState(''), [priority, setPriority] = useState<string[]>([...actions]), [ack, setAck] = useState(false);
  const [view, setView] = useState<Candidate | null>(null), [items, setItems] = useState<Candidate[]>([]), [cursor, setCursor] = useState<string | null>(null);
  const [id, setId] = useState(''), [revision, setRevision] = useState(''), [pending, setPending] = useState<Intent | null>(null), [endAck, setEndAck] = useState(false);
  useUnconfirmed(!!pending);
  const targetMatches = view ? id === view.id && (!revision || Number(revision) === view.revision) : id === '' && revision === '';
  function select(value: Candidate) {
    setView(value); setId(value.id); setRevision(String(value.revision));
    if (!pending) { setName(value.spec.name); setPriority([...value.spec.priority]); setAck(false); }
  }
  async function read(target = id, number = revision) {
    if (!uuid.test(target) || (number && (!positive(Number(number)) || Number(number) > 1000))) throw new Error('Choose a recorded policy and a revision from 1 to 1000, or leave revision empty for latest.');
    const value = checked(await call<Candidate>('/policies/' + target + (number ? '?revision=' + Number(number) : '')));
    if (value.id !== target || (number && value.revision !== Number(number))) throw new Error('Readback does not match the selected policy revision.');
    select(value); say(pending ? 'Metadata read; the original write is still unconfirmed. Retry its unchanged intent.' : 'Historical draft read. No evaluation, promotion or inspection change.');
  }
  async function list(next = false) {
    const page = await call<{ policies: Candidate[]; next_cursor: string | null }>('/policies?limit=20' + (next && cursor ? '&cursor=' + cursor : ''));
    if (!page || !Array.isArray(page.policies) || page.policies.length > 20 || (page.next_cursor !== null && !uuid.test(page.next_cursor))) throw new Error('Policy catalog page is unavailable.');
    setItems(page.policies.map(checked)); setCursor(page.next_cursor); say('Saved drafts loaded. Choose a name to read its exact revision.');
  }
  async function send(intent: Intent) {
    setPending(intent); setEndAck(false);
    try {
      const current = await fresh(user, 'reviewer');
      const value = checked(await call<Candidate>(intent.path, { user: current, method: 'POST', body: intent.body, version: intent.version, idempotencyKey: intent.key }));
      if ((intent.id && value.id !== intent.id) || value.revision !== intent.previousRevision + 1 || value.spec.name !== intent.body.name
          || value.spec.algorithm !== intent.body.algorithm || value.spec.priority.join(',') !== intent.body.priority.join(',')) throw new Error('Committed revision does not match the frozen intent.');
      setPending(null); setView(value); setId(value.id); setRevision(String(value.revision)); setName(value.spec.name); setPriority([...value.spec.priority]); setAck(false);
      say('Policy draft revision recorded. This write does not qualify or activate it. Keep the exact proposal for a future reviewed comparison.');
    } catch (error) {
      if (error instanceof ApiError && [413, 422].includes(error.status)) { setPending(null); setAck(false); say('Draft input was rejected before writing. Review the fields before a new request.'); }
      else say('Write outcome unconfirmed. Retry the unchanged intent. Reading another record does not resolve it.');
    }
  }
  async function save() {
    const body: Spec = { name, algorithm: 'reason_priority_v1', priority: [...priority] };
    if (!reviewer || !ack || !targetMatches || !validSpec(body) || (view && !view.can_revise)) throw new Error('Read the selected revision or start a new draft, then review its valid ordering and limits.');
    await send({ path: view ? '/policies/' + view.id + '/revisions' : '/policies', body, key: crypto.randomUUID(),
      ...(view ? { id: view.id, version: view.state_version } : {}), previousRevision: view?.latest_revision ?? 0 });
  }
  function newDraft() { setView(null); setId(''); setRevision(''); setName(''); setPriority([...actions]); setAck(false); say('New draft. Saving does not affect the active policy.'); }
  function endUnconfirmed() {
    if (!endAck) return;
    setPending(null); setEndAck(false); newDraft();
    say('Retry details forgotten; the server result remains unresolved and may already exist. Review saved drafts with the owner before a separate new intent.');
  }
  return <section aria-labelledby="policy-title"><h3 id="policy-title">Policy candidates</h3><p role="status">{message}</p>
    <p>Draft an ordering of existing corrective actions. Only actions eligible for the measured reason can be selected. REVIEW, manual checks, verifier rules and budgets remain unchanged.</p>
    <p>Open Historical comparisons for a bounded diagnostic of action choices on recorded reasons. Keep the exact proposal ID, revision and hash. This does not measure physical correctness or packing speed. Saving or reading a draft never changes the active inspection policy. Policy qualification provides synthetic-only checks; the owner uses Policy activation for a separate exact-version decision. Physical qualification and beta approval remain unaccepted.</p>
    <div className="toolbar"><button disabled={busy} onClick={() => void perform(() => list())}>Load policy drafts</button>{cursor && <button disabled={busy} onClick={() => void perform(() => list(true))}>Next policy page</button>}</div>
    {items.map(item => <p key={item.id}><button disabled={busy} onClick={() => void perform(() => read(item.id, String(item.revision)))}>Open policy {item.spec.name} revision {item.revision}</button></p>)}
    <label>Policy ID<input disabled={busy} value={id} onChange={e => { setId(e.target.value.trim()); setAck(false); }}/></label><label>Policy revision (empty for latest)<input disabled={busy} value={revision} inputMode="numeric" onChange={e => { setRevision(e.target.value); setAck(false); }}/></label>
    <button disabled={busy || !uuid.test(id)} onClick={() => void perform(() => read())}>Read policy revision</button>
    {view && <><p>Policy {view.id}; revision {view.revision} of {view.latest_revision}; head version {view.state_version}. Draft only; evaluation qualification NOT_VERIFIED.</p><p>Revision hash: {view.revision_sha256}. Behavior hash: {view.behavior_sha256}. {view.can_revise ? 'Current revision can be proposed for editing.' : 'Read latest or start an explicit new draft before editing.'}</p></>}
    {reviewer ? <><button disabled={busy || !!pending} onClick={newDraft}>Start a new policy draft</button><fieldset disabled={busy || !!pending}>
      <legend>Proposed priority among eligible actions</legend><label>Policy name<input maxLength={80} value={name} onChange={e => { setName(e.target.value); setAck(false); }}/></label>
      {priority.map((value, index) => <label key={index}>Policy priority {index + 1}<select value={value} onChange={e => { setPriority(priority.map((p, i) => i === index ? e.target.value : p)); setAck(false); }}>{actions.map(a => <option key={a} value={a}>{labels[a]}</option>)}</select></label>)}
      <label><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)}/>I reviewed this distinct ordering. It is a proposal, not an evaluated improvement or activation.</label>
      <button disabled={!ack || !targetMatches || !validSpec({ name, algorithm: 'reason_priority_v1', priority }) || (!!view && !view.can_revise)} onClick={() => void perform(save)}>{view ? 'Append policy revision' : 'Save policy draft'}</button>
    </fieldset></> : <p>Owner access can review draft metadata. Creating or revising requires a separate reviewer grant.</p>}
    {pending && <><button disabled={busy} onClick={() => void perform(() => send(pending))}>Retry unchanged policy write</button><label><input type="checkbox" disabled={busy} checked={endAck} onChange={e => setEndAck(e.target.checked)}/>I understand forgetting retry details does not undo or determine the server result.</label><button disabled={busy || !endAck} onClick={endUnconfirmed}>Finish without another write</button></>}
    <p>Leaving loses local retry details and does not undo a recorded draft. After interruption, inspect the saved catalog and exact revision before a new reviewed request.</p>
  </section>;
}
