import { useEffect, useState } from 'react';
import type { User } from './api';
import { positive, sha, useReviewDeadline, useTasks, uuid } from './workbench';

type Transfer = { id: string; source_id: string; target_id: string; source_name: string; target_name: string; source_version: number; target_version: number;
  status: string; remaining_validity_ms: number; eligible_for_accept: boolean; requires_recent_mfa: boolean };
export function TransferPanel({ user, transferId, onSessionEnded }: { user: User; transferId: string; onSessionEnded: () => void }) {
  const { busy, message, call, perform, say, fresh } = useTasks('Only the bound source and successor can review an ownership handoff.');
  const [ident, setIdent] = useState(transferId), [review, setReview] = useState<Transfer | null>(null), [confirmed, setConfirmed] = useState(false);
  const expiry = useReviewDeadline();
  useEffect(() => { setIdent(transferId); setReview(null); setConfirmed(false); expiry.clear(); }, [transferId]);
  async function load() {
    setReview(null); setConfirmed(false); expiry.clear(); await fresh(user);
    const token = expiry.token(), started = performance.now(), result = await call<Transfer>('/owner-transfers/' + ident);
    if (result.id !== ident || !uuid.test(result.source_id) || !uuid.test(result.target_id) || !positive(result.source_version)
      || !positive(result.target_version) || typeof result.eligible_for_accept !== 'boolean' || typeof result.requires_recent_mfa !== 'boolean') throw new Error('Handoff information is unavailable.');
    if (result.status === 'pending' && positive(result.remaining_validity_ms)) expiry.bound(started, result.remaining_validity_ms, Number.MAX_SAFE_INTEGER, token);
    setReview(result); say('Review the named people and versions. A preview does not transfer ownership.');
  }
  async function accept() {
    if (!review || !confirmed || !expiry.valid || !review.eligible_for_accept || review.target_id !== user.id) return;
    setConfirmed(false); expiry.clear();
    const live = await fresh(user), current = await call<Transfer>('/owner-transfers/' + review.id);
    if (!current.eligible_for_accept || current.source_version !== review.source_version || current.target_version !== review.target_version
      || current.target_id !== user.id || current.status !== 'pending') { setReview(null); throw new Error('Handoff changed or recent MFA is required. Review it again after signing in.'); }
    await call('/owner-transfers/' + review.id + '/accept', { user: live, method: 'POST' });
    setReview(null); onSessionEnded();
  }
  return <section aria-labelledby="transfer-title"><h3 id="transfer-title">Ownership handoff</h3><p role="status">{message}</p>
    <fieldset disabled={busy}><legend>Review a handoff</legend><label>Handoff ID<input value={ident} maxLength={36} onChange={event => { setIdent(event.target.value); setReview(null); setConfirmed(false); expiry.clear(); }}/></label>
      <button disabled={!uuid.test(ident)} onClick={() => void perform(load)}>Review ownership handoff</button>
      {review && <><p>From {review.source_name} ({review.source_id}) to {review.target_name} ({review.target_id}). Status: {review.status}. Access versions: {review.source_version} / {review.target_version}.</p>
        <p>{expiry.valid ? 'Review validity is bounded; acceptance checks current authority again.' : 'Review expired or unavailable. Refresh before accepting.'}</p>
        {review.requires_recent_mfa && <p>Recent verified MFA is required. Sign in with MFA, then review this handoff again.</p>}
        <label className="check"><input type="checkbox" checked={confirmed} disabled={!expiry.valid || !review.eligible_for_accept || review.target_id !== user.id} onChange={event => setConfirmed(event.target.checked)}/>I am the intended successor and explicitly accept ownership responsibilities.</label>
        <button disabled={!confirmed || !expiry.valid || !review.eligible_for_accept || review.target_id !== user.id} onClick={() => void perform(accept)}>Accept ownership handoff</button>
      </>}
    </fieldset>
  </section>;
}

type Runtime = { control_version: number; runtime_epoch: number; inspection_enabled: boolean; local_instance_current: boolean; environment: string; artifact_sha256: string; controls_sha256: string; reason: string };
type Readiness = { id: string; eligible_for_enable: boolean; control_version: number; runtime_epoch: number; environment: string;
  artifact_sha256: string; controls_sha256: string; receipt_sha256: string; checks: Record<string, boolean>; remaining_validity_ms: number };
const requiredChecks = ['opencv5', 'storage', 'dependencies', 'authorization', 'worker', 'recovery', 'release_gates'];
export function RuntimePanel({ user }: { user: User }) {
  const { busy, message, call, perform, say, fresh } = useTasks('Read the current runtime before changing inspection admission.');
  const [runtime, setRuntime] = useState<Runtime | null>(null), [receipt, setReceipt] = useState(''), [reason, setReason] = useState('');
  type Maintenance = { enabled: boolean; state: string; local_instance_current: boolean; thread_alive: boolean; active_step: boolean; drain_failed: boolean;
    counts: { polls: number; attempts: number; succeeded: number; held: number; errors: number }; last_reason: string | null;
    poll_ms: number; page_size: number; steps_per_minute: number; drain_ms: number };
  const [maintenance, setMaintenance] = useState<Maintenance | null>(null);
  const [review, setReview] = useState<Readiness | null>(null), [confirmed, setConfirmed] = useState(false); const expiry = useReviewDeadline();
  const clear = () => { setReview(null); setConfirmed(false); expiry.clear(); };
  async function loadMaintenance() {
    setMaintenance(null); await fresh(user, 'owner'); const value = await call<Maintenance>('/admin/maintenance');
    if (!['constructed', 'disabled', 'running', 'stopping', 'stopped', 'superseded', 'drain_failed', 'failed'].includes(value.state)
      || [value.enabled, value.local_instance_current, value.thread_alive, value.active_step, value.drain_failed].some(v => typeof v !== 'boolean')
      || !value.counts || ['polls', 'attempts', 'succeeded', 'held', 'errors'].some(k => !Number.isSafeInteger(value.counts[k as keyof Maintenance['counts']]) || value.counts[k as keyof Maintenance['counts']] < 0)
      || !Number.isSafeInteger(value.poll_ms) || value.poll_ms < 250 || value.poll_ms > 60000
      || !Number.isSafeInteger(value.page_size) || value.page_size < 1 || value.page_size > 25
      || !Number.isSafeInteger(value.steps_per_minute) || value.steps_per_minute < 1 || value.steps_per_minute > 120
      || !Number.isSafeInteger(value.drain_ms) || value.drain_ms < 1000 || value.drain_ms > 60000
      || (value.last_reason !== null && !['STEP_FINISHED', 'RUNTIME_SUPERSEDED', 'STOPPED', 'STEP_ALLOWANCE', 'EXECUTOR_ALLOWANCE', 'AUTHORITY_HELD', 'STATE_CHANGED', 'DEPENDENCY_UNAVAILABLE', 'INTERNAL_ERROR'].includes(value.last_reason))) throw new Error('Maintenance information is unavailable.');
    setMaintenance(value); say('Maintenance snapshot loaded. A finished step does not establish full request fulfillment.');
  }
  async function load() {
    clear(); await fresh(user, 'owner'); const result = await call<Runtime>('/admin/runtime');
    if (!positive(result.control_version) || !positive(result.runtime_epoch) || typeof result.inspection_enabled !== 'boolean'
      || typeof result.local_instance_current !== 'boolean' || !sha.test(result.artifact_sha256) || !sha.test(result.controls_sha256)) throw new Error('Runtime information is unavailable.');
    setRuntime(result); say('Runtime loaded. Inspection admission is separate from beta release approval.');
  }
  async function inspect() {
    clear(); if (!runtime) return; await fresh(user, 'owner'); const token = expiry.token(), started = performance.now();
    const result = await call<Readiness>('/admin/readiness/' + receipt);
    if (result.id !== receipt || result.eligible_for_enable !== true || result.control_version !== runtime.control_version
      || result.runtime_epoch !== runtime.runtime_epoch || result.environment !== runtime.environment || result.artifact_sha256 !== runtime.artifact_sha256
      || result.controls_sha256 !== runtime.controls_sha256 || !sha.test(result.receipt_sha256) || !result.checks
      || requiredChecks.some(name => result.checks[name] !== true)) throw new Error('The existing receipt does not support this runtime. Refresh status and ask the operations owner.');
    expiry.bound(started, result.remaining_validity_ms, 60000, token); setReview(result); say('Existing reviewed readiness receipt loaded. It creates no new evidence and enables nothing.');
  }
  async function change(enable: boolean) {
    if (!runtime || (enable && (!review || !confirmed || !expiry.valid))) return;
    const selected = review; clear(); const live = await fresh(user, 'owner');
    const current = await call<Runtime>('/admin/runtime');
    if (current.control_version !== runtime.control_version || current.runtime_epoch !== runtime.runtime_epoch) { setRuntime(null); throw new Error('Runtime changed. Load and review current status again.'); }
    await call('/admin/' + (enable ? 'enable-inspection' : 'disable-inspection'), { user: live, method: 'POST', version: runtime.control_version,
      body: enable ? { receipt_id: selected!.id } : { reason: reason.trim() } });
    await load(); say(enable ? 'Inspection admission updated. This is not beta GO or shipment authorization.' : 'Inspection admission disabled. Treat prior observations as historical.');
  }
  return <section aria-labelledby="runtime-title"><h3 id="runtime-title">Runtime and safe stop</h3><p><strong>Beta NO_GO.</strong> Enabling a configured runtime does not approve external beta use.</p><p role="status">{message}</p>
    <fieldset disabled={busy}><legend>Maintenance processing</legend><button onClick={() => void perform(loadMaintenance)}>Load maintenance status</button>
      {maintenance && <><p>Snapshot: {maintenance.state}. Current instance: {maintenance.local_instance_current ? 'yes' : 'no'}. Processing configured: {maintenance.enabled ? 'yes' : 'no'}. Worker active: {maintenance.thread_alive ? 'yes' : 'no'}. Step in progress: {maintenance.active_step ? 'yes' : 'no'}. Drain failed: {maintenance.drain_failed ? 'yes' : 'no'}.</p>
        <p>Attempts: {maintenance.counts.attempts}; finished steps: {maintenance.counts.succeeded}; held: {maintenance.counts.held}; errors: {maintenance.counts.errors}. Last reason: {maintenance.last_reason ?? 'none'}.</p>
        <p>Poll interval {maintenance.poll_ms} ms; discovery page {maintenance.page_size}; attempted steps per minute {maintenance.steps_per_minute}; shutdown drain {maintenance.drain_ms} ms. Jobs may wait for current authority or dependencies. This screen cannot start or stop the worker.</p></>}
    </fieldset>
    <fieldset disabled={busy}><legend>Inspection admission</legend><button onClick={() => void perform(load)}>Load runtime status</button>
      {runtime && <><p>Environment: {runtime.environment}. Epoch {runtime.runtime_epoch} · control version {runtime.control_version}. Admission: {runtime.inspection_enabled ? 'enabled' : 'disabled'}. This instance: {runtime.local_instance_current ? 'current' : 'superseded'}.</p>
        <label>Stop reason<input value={reason} maxLength={120} onChange={event => setReason(event.target.value)} placeholder="Brief reason, no personal data"/></label>
        <button disabled={!/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,119}$/.test(reason.trim())} onClick={() => void perform(() => change(false))}>Disable inspection admission</button>
        <h4>Review existing assurance</h4><p>No browser control creates a readiness receipt. Missing qualified storage, authorization, worker, recovery or release evidence keeps admission closed.</p>
        <label>Existing readiness receipt ID<input value={receipt} maxLength={36} onChange={event => { setReceipt(event.target.value); clear(); }}/></label>
        <button disabled={!uuid.test(receipt) || !runtime.local_instance_current || runtime.inspection_enabled} onClick={() => void perform(inspect)}>Review readiness receipt</button>
        {review && <><p>Receipt digest: {review.receipt_sha256}. Checks verified: {requiredChecks.join(', ')}.</p><p>{expiry.valid ? 'Review is within its original validity.' : 'Review expired or was cleared. Review a current receipt again.'}</p>
          <label className="check"><input type="checkbox" disabled={!expiry.valid} checked={confirmed} onChange={event => setConfirmed(event.target.checked)}/>I reviewed the existing assurance for this exact runtime and intend to enable inspection admission.</label></>}
        <button disabled={!review || !confirmed || !expiry.valid || !runtime.local_instance_current || runtime.inspection_enabled} onClick={() => void perform(() => change(true))}>Enable inspection admission</button>
      </>}
    </fieldset>
  </section>;
}
