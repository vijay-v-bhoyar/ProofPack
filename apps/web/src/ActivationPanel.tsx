import { useState } from 'react';
import type { User } from './api';
import { sha, uuid, useReviewDeadline, useTasks, useUnconfirmed } from './workbench';
import { active, candidate, options, qjob, receipt, sameTarget, type Active, type Candidate, type Options, type QJob, type Receipt, type RollbackTarget } from './policyLifecycle';

type Body = { operation: 'bootstrap' | 'promote' | 'rollback'; policy_id: string; policy_revision: number; policy_state_version: number; policy_revision_sha256: string;
  qualification_id: string; qualification_report_sha256: string; expected_active_version: number; expected_control_version: number; predecessor_activation_id?: string; invalidation_acknowledged: true };
type Preview = { body: Body; policy: Candidate; previousActivation: string | null };
type Intent = Preview & { key: string };

export function ActivationPanel({ user, seedQualification = '' }: { user: User; seedQualification?: string }) {
  const { busy, message, call, perform, say, fresh } = useTasks('Owner decisions require recent MFA and fresh exact evidence.');
  const [operation, setOperation] = useState<Body['operation']>('bootstrap'), [qualificationId, setQualificationId] = useState(seedQualification);
  const [preview, setPreview] = useState<Preview | null>(null), [ack, setAck] = useState(false), [pending, setPending] = useState<Intent | null>(null), [exitAck, setExitAck] = useState(false);
  const [current, setCurrent] = useState<Active | null>(null), [historical, setHistorical] = useState<Receipt | null>(null), [receiptId, setReceiptId] = useState('');
  const [handoff, setHandoff] = useState<{ target: RollbackTarget; policy: Candidate } | null>(null);
  const review = useReviewDeadline(), currentReview = useReviewDeadline(), historyReview = useReviewDeadline(), handoffReview = useReviewDeadline();
  useUnconfirmed(!!pending);
  function clearPreview() { review.clear(); setPreview(null); setAck(false); }
  function clearCurrent() { currentReview.clear(); setCurrent(null); }
  function clearHistory() { historyReview.clear(); setHistorical(null); }
  function clearHandoff() { handoffReview.clear(); setHandoff(null); }
  function edit(run: () => void) { clearPreview(); run(); }
  async function ownerContext() { await fresh(user, 'owner'); return active(await call<Active>('/policies/active?scope=owner'), true); }
  async function readCurrent() {
    clearPreview(); clearCurrent(); clearHandoff(); const started = performance.now(), token = currentReview.token();
    const value = await ownerContext(); currentReview.bound(started, Math.min(value.remaining_ms || 60000, 60000), 60000, token); setCurrent(value);
    say('Current owner context read. A stored activation is not inspection enablement; any uncertain write remains unresolved.');
  }
  async function historicalRead(id = receiptId) {
    clearPreview(); clearHistory(); if (!uuid.test(id)) throw new Error('Enter a transition receipt ID.');
    const started = performance.now(), token = historyReview.token(); await fresh(user, 'owner');
    const value = receipt(await call<Receipt>('/policy-activations/' + id)); if (value.transition_id !== id) throw new Error('Transition receipt target changed.');
    historyReview.bound(started, 60000, 60000, token); setHistorical(value); setReceiptId(id); say('Historical transition only. This read neither settles an uncertain write nor restores current qualification or inspection authority.');
  }
  async function readHandoff() {
    clearPreview(); clearHandoff(); const started = performance.now(), token = handoffReview.token(); const head = await ownerContext();
    if (!head.policy || !head.activation_id || !head.predecessor_activation_id) throw new Error('There is no recorded exact predecessor for this active head.');
    const previous = receipt(await call<Receipt>('/policy-activations/' + head.predecessor_activation_id));
    if (previous.transition_id !== head.predecessor_activation_id) throw new Error('Predecessor receipt changed.');
    const selected = candidate(await call<Candidate>('/policies/' + previous.policy_id + '?revision=' + previous.policy_revision));
    if (selected.id !== previous.policy_id || selected.revision !== previous.policy_revision || selected.revision_sha256 !== previous.policy_revision_sha256) throw new Error('Predecessor candidate digest changed.');
    handoffReview.bound(started, Math.min(head.remaining_ms || 60000, 60000), 60000, token);
    setHandoff({ target: { active_version: head.active_version, activation_id: head.activation_id, predecessor_activation_id: head.predecessor_activation_id }, policy: selected });
    say('Exact predecessor selectors read for the authorized reviewer handoff. They are not qualification or permission to activate.');
  }
  async function readPreview() {
    clearPreview(); clearHistory(); clearCurrent(); if (pending || !uuid.test(qualificationId)) throw new Error('Select a qualification job before reviewing an activation.');
    const started = performance.now(), token = review.token(); await fresh(user, 'owner');
    const limits = options(await call<Options>('/policy-qualifications/options'));
    const report = qjob(await call<QJob>('/policy-qualifications/' + qualificationId), limits);
    if (report.id !== qualificationId || !report.report_current || !report.current || report.qualification_status !== 'qualified' || !report.report_sha256 || !report.remaining_ms) throw new Error('A complete current synthetic qualification with zero failed or unknown cases is required.');
    const head = await ownerContext();
    if ((head.policy === null) !== (operation === 'bootstrap')) throw new Error('Bootstrap requires an empty active head; promotion or rollback requires an existing head.');
    const selected = candidate(await call<Candidate>('/policies/' + report.policy_id + '?revision=' + report.policy_revision));
    if (selected.id !== report.policy_id || selected.revision !== report.policy_revision || selected.state_version !== report.policy_state_version || selected.revision_sha256 !== report.policy_revision_sha256) throw new Error('Qualification no longer matches the exact candidate state and digest.');
    if (operation === 'rollback') {
      const expected: RollbackTarget | null = head.activation_id && head.predecessor_activation_id ? { active_version: head.active_version, activation_id: head.activation_id, predecessor_activation_id: head.predecessor_activation_id } : null;
      if (!expected || !sameTarget(report.rollback_target, expected)) throw new Error('Qualification does not name this exact current rollback predecessor.');
      const previous = receipt(await call<Receipt>('/policy-activations/' + expected.predecessor_activation_id));
      if (previous.transition_id !== expected.predecessor_activation_id || previous.policy_id !== selected.id || previous.policy_revision !== selected.revision || previous.policy_revision_sha256 !== selected.revision_sha256) throw new Error('Selected candidate differs from the immutable predecessor.');
    } else if (report.rollback_target !== null || selected.revision !== selected.latest_revision) throw new Error('Ordinary activation requires the latest revision and ordinary qualification purpose.');
    if (operation === 'bootstrap' && selected.spec.priority.join(',') !== 'SEPARATE_REGION,PLACE_FLAT,RECAPTURE') throw new Error('Bootstrap requires the installed default priority.');
    const body: Body = { operation, policy_id: selected.id, policy_revision: selected.revision, policy_state_version: selected.state_version, policy_revision_sha256: selected.revision_sha256,
      qualification_id: report.id, qualification_report_sha256: report.report_sha256, expected_active_version: head.active_version, expected_control_version: head.control_version!, invalidation_acknowledged: true,
      ...(operation === 'rollback' ? { predecessor_activation_id: head.predecessor_activation_id! } : {}) };
    review.bound(started, Math.min(report.remaining_ms, head.remaining_ms || 60000, 60000), 60000, token); setPreview({ body, policy: selected, previousActivation: head.activation_id ?? null });
    say('Exact owner decision preview read. A separate acknowledgment is required; activation disables inspections and grants no enablement.');
  }
  async function send(intent: Intent) {
    setPending(intent); setExitAck(false); clearPreview(); clearCurrent(); clearHistory(); clearHandoff();
    try {
      const live = await fresh(user, 'owner'), b = intent.body;
      const result = await call<{ transition_id: string; operation: string; policy_id: string; policy_revision: number; active_version: number; control_version: number; activation_sha256: string; historical_receipt: boolean; inspection_enablement_granted: boolean }>('/policies/' + b.policy_id + '/' + b.operation,
        { user: live, method: 'POST', body: b, version: b.policy_state_version, idempotencyKey: intent.key });
      if (!result || !uuid.test(result.transition_id) || result.operation !== b.operation || result.policy_id !== b.policy_id || result.policy_revision !== b.policy_revision
        || result.active_version !== b.expected_active_version + 1 || result.control_version !== b.expected_control_version + 1 || !sha.test(result.activation_sha256)
        || result.historical_receipt !== true || result.inspection_enablement_granted !== false) throw new Error('Transition acknowledgment does not match the frozen request.');
      // Confirmation checks immutable provenance. It does not reuse fresh authority or make a second write.
      await fresh(user, 'owner'); const started = performance.now(), token = historyReview.token();
      const saved = receipt(await call<Receipt>('/policy-activations/' + result.transition_id));
      if (saved.transition_id !== result.transition_id || saved.activation_sha256 !== result.activation_sha256 || saved.operation !== b.operation || saved.policy_id !== b.policy_id
        || saved.policy_revision !== b.policy_revision || saved.policy_revision_sha256 !== b.policy_revision_sha256 || saved.policy_state_version !== b.policy_state_version
        || saved.qualification_id !== b.qualification_id || saved.qualification_report_sha256 !== b.qualification_report_sha256 || saved.previous_active_version !== b.expected_active_version
        || saved.previous_control_version !== b.expected_control_version || saved.predecessor_activation_id !== intent.previousActivation) throw new Error('Stored transition provenance differs from the original decision.');
      historyReview.bound(started, 60000, 60000, token); setHistorical(saved); setReceiptId(saved.transition_id); setPending(null);
      say('Exact transition recorded and inspected. Inspections were disabled by the transition; read current context and establish fresh readiness before separate enablement.');
    } catch (error) { say('Activation outcome is unconfirmed. Keep the exact retry or investigate the original records; no new intent was submitted.'); throw error; }
  }
  return <section aria-labelledby="activation-title"><h3 id="activation-title">Policy activation</h3><p role="status">{message}</p>
    <p>Owner only, with recent MFA. Synthetic qualification cannot establish physical correctness, independent truth, saved labor or beta approval. Every transition disables inspections; readiness and explicit enablement remain separate.</p>
    <fieldset disabled={busy || !!pending}><legend>Review an owner decision</legend><label htmlFor="policy-transition-operation">Policy transition</label><select id="policy-transition-operation" value={operation} onChange={e => edit(() => setOperation(e.target.value as Body['operation']))}><option value="bootstrap">Bootstrap installed default</option><option value="promote">Promote latest candidate</option><option value="rollback">Roll back exact predecessor</option></select>
      <label>Activation qualification job ID<input value={qualificationId} onChange={e => edit(() => setQualificationId(e.target.value))}/></label><button disabled={!uuid.test(qualificationId)} onClick={() => void perform(readPreview)}>Review exact activation</button>
      {preview && <><p>Operation {preview.body.operation}; candidate {preview.policy.spec.name}, {preview.body.policy_id}, revision {preview.body.policy_revision}, state {preview.body.policy_state_version}, hash {preview.body.policy_revision_sha256}.</p>
        <p>Qualification {preview.body.qualification_id}; report {preview.body.qualification_report_sha256}. Expected active version {preview.body.expected_active_version}; runtime control {preview.body.expected_control_version}.</p>
        {preview.body.predecessor_activation_id && <p>Exact predecessor {preview.body.predecessor_activation_id}.</p>}
        <label><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)}/>I reviewed this exact decision and understand all current inspection approvals are invalidated; this does not enable inspections or approve beta.</label></>}
      <button disabled={!preview || !review.valid || !ack} onClick={() => preview && void perform(() => send({ ...preview, key: crypto.randomUUID() }))}>Confirm exact policy transition</button>
    </fieldset>
    <fieldset disabled={busy}><legend>Inspect current or historical state</legend><button onClick={() => void perform(readCurrent)}>Read current owner policy context</button><button onClick={() => void perform(readHandoff)}>Read exact predecessor handoff</button>
      {current && currentReview.valid && <><p>Active version {current.active_version}; control version {current.control_version}. Current qualification {String(current.current)}; inspections enabled {String(current.inspection_enabled)}.</p><p>Activation {current.activation_id ?? 'none'}; predecessor {current.predecessor_activation_id ?? 'none'}.</p>
        {current.activation_id && <button onClick={() => void perform(() => historicalRead(current.activation_id!))}>Read current transition receipt</button>}</>}
      {handoff && handoffReview.valid && <div aria-label="Exact rollback handoff"><p>Reviewer handoff only, not authority: active version {handoff.target.active_version}; current activation {handoff.target.activation_id}; predecessor activation {handoff.target.predecessor_activation_id}.</p>
        <p>Predecessor candidate ID {handoff.policy.id}; revision {handoff.policy.revision}; current candidate state {handoff.policy.state_version}; hash {handoff.policy.revision_sha256}. Use the agreed authorized handoff channel; no message has been sent.</p></div>}
      <label>Policy transition receipt ID<input value={receiptId} onChange={e => { setReceiptId(e.target.value); clearHistory(); clearPreview(); }}/></label><button disabled={!uuid.test(receiptId)} onClick={() => void perform(() => historicalRead())}>Read historical policy transition</button>
    </fieldset>
    {historical && historyReview.valid && <div aria-label="Historical policy transition"><p>Historical {historical.operation} receipt {historical.transition_id}; candidate {historical.policy_id} revision {historical.policy_revision}, hash {historical.policy_revision_sha256}; original candidate state {historical.policy_state_version ?? 'not recorded in this older event'}.</p>
      <p>Qualification {historical.qualification_id}; report {historical.qualification_report_sha256}; resulting active version {historical.active_version}, control {historical.control_version}. Historical receipt only; current qualification is not established and inspection enablement is not granted.</p></div>}
    {pending && <fieldset disabled={busy}><legend>Unconfirmed policy transition</legend><p>The server may already have committed. Current or historical reads do not automatically settle this intent. Exact retry retains the original body, candidate version and key.</p>
      <button onClick={() => void perform(() => send(pending))}>Retry unchanged policy transition</button><label><input type="checkbox" checked={exitAck} onChange={e => setExitAck(e.target.checked)}/>I understand only local retry details are discarded; the server transition must still be investigated.</label>
      <button disabled={!exitAck} onClick={() => { setPending(null); clearPreview(); say('Local retry details forgotten. Investigate the original activation before a separate intent; no server transition was undone.'); }}>Finish without another policy transition</button></fieldset>}
  </section>;
}
