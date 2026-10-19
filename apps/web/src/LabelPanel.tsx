import { useState } from 'react';
import type { User } from './api';
import { useUnconfirmed, positive, sha, useReviewDeadline, useTasks, uuid } from './workbench';

type Tuple = { before_observation_id: string; action_id: string | null; after_observation_id: string | null };
type Context = { tuple: Tuple; inspection_id: string; data_origin: string; artifact_sha256: string; source_context_sha256: string;
  data_epoch: number; remaining_validity_ms: number; max_duration_ms: number; expected_classes: string[];
  observations: { observation_id: string; sequence: number; findings: string[]; reason_codes: string[] }[] };
type Label = { id: string; revision: number; latest_revision: number; state_version: number; tuple: Tuple; source_context_sha256: string;
  source_context: Context; sha256: string; previous_sha256: string | null; outcome: string; method: string; duration_ms: number; note: string;
  independence_declared: boolean; independence_verified: boolean; physical_truth_verified: boolean; machine_pass: boolean;
  ground_truth_counts: { part_class: string; count: number }[]; conflict_codes: string[] };
type Pending = { path: string; body: Record<string, unknown>; version?: number; key: string };
const classes = ['washer', 'nut', 'bolt', 'flat_bracket'], outcomes = ['resolved', 'unresolved', 'incorrect_finding'];
function validTuple(value: Tuple) { return !!value && uuid.test(value.before_observation_id) && ((value.action_id === null && value.after_observation_id === null)
  || (typeof value.action_id === 'string' && uuid.test(value.action_id) && typeof value.after_observation_id === 'string' && uuid.test(value.after_observation_id))); }
function sameTuple(a: Tuple, b: Tuple) { return a.before_observation_id === b.before_observation_id && a.action_id === b.action_id && a.after_observation_id === b.after_observation_id; }
function contextValid(value: Context) { return !!value && validTuple(value.tuple) && uuid.test(value.inspection_id) && sha.test(value.artifact_sha256)
  && sha.test(value.source_context_sha256) && positive(value.data_epoch) && positive(value.max_duration_ms) && value.max_duration_ms <= 3600000
  && ['synthetic', 'printable', 'physical'].includes(value.data_origin) && Array.isArray(value.expected_classes) && value.expected_classes.length > 0
  && value.expected_classes.length <= 4 && value.expected_classes.every(item => classes.includes(item)) && new Set(value.expected_classes).size === value.expected_classes.length
  && Array.isArray(value.observations) && value.observations.length >= 1 && value.observations.length <= 2
  && value.observations.every(item => uuid.test(item.observation_id) && positive(item.sequence) && Array.isArray(item.findings) && item.findings.every(f => ['SATISFIED', 'VIOLATED', 'UNOBSERVABLE'].includes(f)) && Array.isArray(item.reason_codes)); }
function labelValid(value: Label) { return !!value && uuid.test(value.id) && validTuple(value.tuple) && positive(value.revision) && positive(value.state_version)
  && sha.test(value.sha256) && sha.test(value.source_context_sha256) && outcomes.includes(value.outcome) && Array.isArray(value.ground_truth_counts)
  && value.ground_truth_counts.every(item => classes.includes(item.part_class) && Number.isSafeInteger(item.count) && item.count >= 0 && item.count <= 30)
  && value.independence_verified === false && value.physical_truth_verified === false && value.machine_pass === false && Array.isArray(value.conflict_codes); }

export function LabelPanel({ user }: { user: User }) {
  const reviewer = user.roles.includes('reviewer'), { busy, message, call, perform, say } = useTasks('Review permitted historical evidence. Human labels cannot issue a machine pass or grant improvement-data permission.');
  const review = useReviewDeadline();
  const [before, setBefore] = useState(''), [action, setAction] = useState(''), [after, setAfter] = useState('');
  const [context, setContext] = useState<Context | null>(null), [label, setLabel] = useState<Label | null>(null), [labelId, setLabelId] = useState('');
  const [outcome, setOutcome] = useState(''), [method, setMethod] = useState(''), [duration, setDuration] = useState(''), [note, setNote] = useState('');
  const [counts, setCounts] = useState<Record<string, string>>({}), [declared, setDeclared] = useState(false), [ack, setAck] = useState(false);
  const [pending, setPending] = useState<Pending | null>(null), [discard, setDiscard] = useState(false), [items, setItems] = useState<{ id: string; revision: number }[]>([]);
  useUnconfirmed(!!pending);
  function clear() { setContext(null); review.clear(); setAck(false); }
  function sourceEdited(update: () => void) { update(); clear(); setLabel(null); }
  async function preview() {
    clear(); const tuple: Tuple = { before_observation_id: before, action_id: action || null, after_observation_id: after || null };
    if (!validTuple(tuple)) throw new Error('Enter a before observation and either both correction IDs or neither.');
    const query = new URLSearchParams({ before_observation_id: before }); if (action) { query.set('action_id', action); query.set('after_observation_id', after); }
    const started = performance.now(), token = review.token(), value = await call<Context>('/review/context?' + query);
    if (!contextValid(value) || !sameTuple(value.tuple, tuple)) throw new Error('Source review does not match the requested tuple.');
    review.bound(started, value.remaining_validity_ms, 60000, token); setContext(value); say('Current permitted source reviewed. Enter your actual judgment and full review effort.');
  }
  async function load() {
    clear(); setLabel(null); if (!uuid.test(labelId)) throw new Error('Enter a label ID.');
    const value = await call<Label>('/labels/' + labelId); if (!labelValid(value) || value.id !== labelId) throw new Error('Label unavailable or malformed.');
    setLabel(value); setBefore(value.tuple.before_observation_id); setAction(value.tuple.action_id ?? ''); setAfter(value.tuple.after_observation_id ?? '');
    setOutcome(value.outcome); setMethod(value.method); setDuration(String(value.duration_ms)); setNote(value.note); setDeclared(value.independence_declared);
    setCounts(Object.fromEntries(value.ground_truth_counts.map(item => [item.part_class, String(item.count)]))); say('Historical label loaded. Refresh source review before appending a correction.');
  }
  async function list() {
    const value = await call<{ labels: { id: string; revision: number }[] }>('/labels?limit=20');
    if (!Array.isArray(value.labels) || value.labels.length > 20 || value.labels.some(item => !uuid.test(item.id) || !positive(item.revision))) throw new Error('Saved label list unavailable.');
    setItems(value.labels); say('Loaded up to 20 current permitted labels. Missing or withdrawn evidence may hide a record.');
  }
  async function submit(held?: Pending) {
    let operation = held;
    if (!operation) {
      if (!reviewer || !context || !review.valid || !ack || !outcomes.includes(outcome) || !method) throw new Error('Review current sources and acknowledge the label limits.');
      const truth = classes.filter(part => counts[part] !== undefined && counts[part] !== '').map(part => ({ part_class: part, count: Number(counts[part]) }));
      if (truth.some(item => !Number.isSafeInteger(item.count) || item.count < 0 || item.count > 30) || truth.reduce((a, b) => a + b.count, 0) > 30
        || context.expected_classes.some(part => !truth.some(item => item.part_class === part))) throw new Error('Enter explicit counts for every configured class; total cannot exceed 30.');
      if (!positive(Number(duration)) || Number(duration) > context.max_duration_ms || !note.trim() || note.length > 240) throw new Error('Enter bounded full review duration and a review or correction note.');
      operation = { path: label ? '/labels/' + label.id + '/revisions' : '/labels', version: label?.state_version, key: crypto.randomUUID(),
        body: { ...context.tuple, source_context_sha256: context.source_context_sha256, data_epoch: context.data_epoch, outcome,
          ground_truth_counts: truth, method, duration_ms: Number(duration), independence_declared: declared, note } };
      setPending(operation);
    }
    const value = await call<Label>(operation.path, { user, method: 'POST', body: operation.body, version: operation.version, idempotencyKey: operation.key });
    if (!labelValid(value) || value.source_context_sha256 !== operation.body.source_context_sha256 || value.outcome !== operation.body.outcome
      || !sameTuple(value.tuple, { before_observation_id: String(operation.body.before_observation_id), action_id: operation.body.action_id as string | null, after_observation_id: operation.body.after_observation_id as string | null }))
      throw new Error('Write confirmation does not match. Outcome remains uncertain; inspect saved labels.');
    setPending(null); setDiscard(false); setLabel(value); setLabelId(value.id); clear(); say('Operational label saved as immutable revision ' + value.revision + '. Independence is unverified; no machine pass or policy change.');
  }
  return <section aria-labelledby="labels-title"><h3 id="labels-title">Outcome labels</h3><p role="status">{message}</p>
    <p>Record ground truth from a permitted check. Declared independence is not reviewed independence. Labels are historical and do not authorize packing, policy promotion or optional data reuse.</p>
    <div className="toolbar"><button disabled={busy} onClick={() => void perform(list)}>Load saved labels</button><label>Label ID<input disabled={busy || !!pending} value={labelId} onChange={e => setLabelId(e.target.value.trim())}/></label><button disabled={busy || !!pending} onClick={() => void perform(load)}>Read label</button></div>
    {items.map(item => <p key={item.id}>Saved label {item.id} · revision {item.revision}</p>)}
    {label && <p>Label {label.id} · revision {label.revision} · SHA-256 {label.sha256}. Previous revision hash: {label.previous_sha256 ?? 'First revision'}. Conflicts: {label.conflict_codes.join(', ') || 'None recorded'}. Historical; no machine pass.</p>}
    <fieldset disabled={busy || !!pending}><legend>Source tuple</legend>
      <label>Before observation ID<input value={before} onChange={e => sourceEdited(() => setBefore(e.target.value.trim()))}/></label>
      <label>Acknowledged action ID (optional)<input value={action} onChange={e => sourceEdited(() => setAction(e.target.value.trim()))}/></label>
      <label>After observation ID (optional)<input value={after} onChange={e => sourceEdited(() => setAfter(e.target.value.trim()))}/></label>
      <button onClick={() => void perform(preview)}>Review source tuple</button></fieldset>
    {context && <div><p>Inspection {context.inspection_id}; origin {context.data_origin}; software {context.artifact_sha256}. Review {review.valid ? 'current' : 'expired or interrupted'}.</p>
      {context.observations.map(item => <p key={item.observation_id}>Observation {item.sequence}: {item.findings.join(', ')}; reasons {item.reason_codes.join(', ') || 'None recorded'}</p>)}</div>}
    {reviewer ? <fieldset disabled={busy || !!pending}><legend>Human review</legend>
      <label>Outcome<select value={outcome} onChange={e => { setOutcome(e.target.value); setAck(false); }}><option value="">Choose outcome</option><option value="resolved" disabled={!action}>Resolved correction</option><option value="unresolved">Unresolved</option><option value="incorrect_finding">Incorrect finding</option></select></label>
      {classes.map(part => <label key={part}>Ground truth {part}<input type="number" min="0" max="30" value={counts[part] ?? ''} onChange={e => { setCounts({ ...counts, [part]: e.target.value }); setAck(false); }}/></label>)}
      <label>Review method<select value={method} onChange={e => { setMethod(e.target.value); setAck(false); }}><option value="">Choose method</option><option value="synthetic_fixture" disabled={!!context && context.data_origin !== 'synthetic'}>Synthetic fixture check</option><option value="reference_comparison">Reference comparison</option><option value="physical_manual_check" disabled={!!context && context.data_origin !== 'physical'}>Physical manual check</option></select></label>
      <label>Full review duration (milliseconds)<input type="number" min="1" max={context?.max_duration_ms ?? 3600000} value={duration} onChange={e => { setDuration(e.target.value); setAck(false); }}/></label>
      <label>Review or correction note<input maxLength={240} value={note} onChange={e => { setNote(e.target.value); setAck(false); }}/></label>
      <label><input type="checkbox" checked={declared} onChange={e => { setDeclared(e.target.checked); setAck(false); }}/>I declare independence; this declaration remains unverified</label>
      <label><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)}/>I reviewed the exact sources and limits; this human label is not a machine pass</label>
      <button disabled={!context || !review.valid || !ack} onClick={() => void perform(() => submit())}>{label ? 'Append label correction' : 'Save operational label'}</button></fieldset>
      : <p>Your current grant permits metadata review only. An explicit reviewer grant is required to label.</p>}
    {pending && <div role="alert"><p>Write outcome unconfirmed. Inputs are frozen. Retry before leaving; after a reload inspect saved labels before any new write.</p>
      <button disabled={busy} onClick={() => void perform(() => submit(pending))}>Retry unchanged label write</button>
      <label><input type="checkbox" checked={discard} onChange={e => setDiscard(e.target.checked)}/>I will inspect saved labels before another write; discarding does not undo a server commit</label>
      <button disabled={busy || !discard} onClick={() => { setPending(null); setDiscard(false); clear(); say('Local request discarded. Inspect saved labels before another write.'); }}>Discard local retry</button></div>}
  </section>;
}
