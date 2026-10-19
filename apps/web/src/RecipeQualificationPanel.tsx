import { useEffect, useRef, useState } from 'react';
import { ApiError } from './api';
import type { User } from './api';
import { positive, sha, useReviewDeadline, useTasks, uuid } from './workbench';

type Draft = { id: string; revision: number; state_version: number; last_qualification_job_id?: string | null;
  content: { data_origin: string; constraints: { part_class_id: string; expected_count: number }[] } };
type Case = { asset_id: string; kind: string; expected_findings: string[]; expected_counts: number[] };
type Job = { id: string; recipe_id: string; status: string; report_id: string | null; remaining_ms: number };
type Report = { id: string; recipe_id: string; recipe_revision: number; passed: boolean; eligible_for_approval: boolean; diagnostic_passed: boolean;
  physical_truth_verified: false; independence_verified: false; sha256: string; remaining_validity_ms: number;
  results: { asset_id: string; kind: string; matched: boolean; findings: string[]; measured_counts: number[]; quality_ok: boolean }[] };

export function RecipeQualificationPanel({ user, draft, disabled, onBusy, onReview, onInvalidateReview, readOnly = false }: {
  user: User; draft: Draft; disabled: boolean; readOnly?: boolean; onBusy: (value: boolean) => void; onInvalidateReview: () => void; onReview: (id: string) => Promise<void>;
}) {
  const { busy, message, call, perform, fresh, say } = useTasks('Measure stored comparison cases. These declarations are not independent physical truth.');
  const initial = (kind: string): Case => ({ asset_id: '', kind,
    expected_findings: draft.content.constraints.map((_, i) => kind === 'challenge' ? 'UNOBSERVABLE' : kind === 'incorrect' && i === 0 ? 'VIOLATED' : 'SATISFIED'),
    expected_counts: draft.content.constraints.map((c, i) => kind === 'challenge' ? 0 : kind === 'incorrect' && i === 0 ? c.expected_count === 0 ? 1 : c.expected_count - 1 : c.expected_count) });
  const [cases, setCases] = useState<Case[]>(() => ['complete', 'incorrect', 'challenge'].map(initial));
  const [jobId, setJobId] = useState(draft.last_qualification_job_id ?? ''), [job, setJob] = useState<Job | null>(null), [report, setReport] = useState<Report | null>(null);
  const [uncertain, setUncertain] = useState(false), [confirmed, setConfirmed] = useState(false);
  const intent = useRef<{ body: { cases: Case[] }; version: number; key: string } | null>(null), expiry = useReviewDeadline();
  useEffect(() => { onBusy(busy || uncertain); return () => onBusy(false); }, [busy, uncertain, onBusy]);
  const clear = () => { onInvalidateReview(); setReport(null); expiry.clear(); setConfirmed(false); };
  function edit(index: number, value: Partial<Case>) { clear(); setCases(old => old.map((c, i) => i === index ? { ...c, ...value } : c)); }
  function checkedJob(value: Job): Job {
    if (!value || !uuid.test(value.id) || value.recipe_id !== draft.id || !['processing', 'completed', 'failed', 'expired'].includes(value.status)
      || !Number.isFinite(value.remaining_ms) || value.remaining_ms < 0 || value.remaining_ms > 60000
      || (value.report_id !== null && value.report_id !== value.id) || (value.status === 'completed' && value.report_id !== value.id)) throw new Error('Qualification job response is unrecognized. Keep the original intent and ask the owner.');
    return value;
  }
  const valid = cases.length >= 3 && cases.length <= 8 && new Set(cases.map(c => c.asset_id)).size === cases.length
    && ['complete', 'incorrect', 'challenge'].every(kind => cases.some(c => c.kind === kind)) && cases.every(c => uuid.test(c.asset_id)
      && c.expected_counts.every(n => Number.isSafeInteger(n) && n >= 0 && n <= 30)
      && (c.kind !== 'complete' || c.expected_counts.every((n, i) => n === draft.content.constraints[i].expected_count))
      && (c.kind !== 'complete' || c.expected_findings.every(f => f === 'SATISFIED'))
      && (c.kind !== 'incorrect' || c.expected_findings.includes('VIOLATED')) && (c.kind !== 'challenge' || c.expected_findings.includes('UNOBSERVABLE')));
  async function submit() {
    if (readOnly) return;
    const live = await fresh(user, 'owner');
    if (!intent.current) {
      if (!valid || !confirmed) throw new Error('Provide distinct complete, incorrect and challenge cases and confirm the comparison inputs.');
      intent.current = { body: { cases: structuredClone(cases) }, version: draft.state_version, key: crypto.randomUUID() };
    }
    const chosen = intent.current; onInvalidateReview(); setUncertain(true); setReport(null); expiry.clear();
    try {
      const result = checkedJob(await call<Job>('/recipes/' + draft.id + '/qualify', { user: live, method: 'POST', version: chosen.version, idempotencyKey: chosen.key, body: chosen.body }));
      setJob(result); setJobId(result.id); setUncertain(false); intent.current = null;
      say('Qualification job recorded. Read its status/report, then reload the draft for a separate approval review. No configuration was activated.');
    } catch (error) {
      if (error instanceof ApiError && error.status < 500) { intent.current = null; setUncertain(false); }
      throw error;
    }
  }
  async function readJob() {
    clear(); const result = checkedJob(await call<Job>('/recipe-qualification-jobs/' + jobId));
    if (result.id !== jobId) throw new Error('Different qualification job returned.'); setJob(result);
  }
  async function readReport() {
    if (!job?.report_id) return;
    clear(); const started = performance.now(), token = expiry.token();
    const value = await call<Report>('/recipes/' + draft.id + '/qualification-reports/' + job.report_id);
    if (!value || value.id !== job.report_id || value.recipe_id !== draft.id || value.recipe_revision !== draft.revision
      || typeof value.passed !== 'boolean' || typeof value.eligible_for_approval !== 'boolean' || (value.eligible_for_approval && !value.passed) || typeof value.diagnostic_passed !== 'boolean' || (value.passed && (!value.diagnostic_passed || draft.content.data_origin === 'physical'))
      || value.physical_truth_verified !== false || value.independence_verified !== false || !sha.test(value.sha256)
      || !Array.isArray(value.results) || value.results.length < 3 || value.results.length > 8
      || value.results.some(r => !uuid.test(r.asset_id) || typeof r.matched !== 'boolean' || typeof r.quality_ok !== 'boolean'
        || !Array.isArray(r.findings) || r.findings.length !== draft.content.constraints.length || r.findings.some(f => !['SATISFIED', 'VIOLATED', 'UNOBSERVABLE'].includes(f))
        || !Array.isArray(r.measured_counts) || r.measured_counts.length !== draft.content.constraints.length || r.measured_counts.some(n => !Number.isSafeInteger(n) || n < 0 || n > 30))) throw new Error('Qualification report does not match this draft. Reload the current candidate.');
    if (!Number.isFinite(value.remaining_validity_ms) || value.remaining_validity_ms <= 0) throw new Error('Qualification report expired.');
    expiry.bound(started, Math.min(60000, value.remaining_validity_ms), 60000, token); setReport(value);
  }
  return <section aria-label="Recipe case qualification"><h4>Measure recipe qualification cases</h4><p role="status" aria-label="Recipe qualification message">{message}</p>
    <p>Use permitted stored images from complete, incorrect and challenging scenes. Declared expectations and matching diagnostics do not certify physical truth or enable inspections.</p>
    {!readOnly && <><fieldset disabled={disabled || busy || uncertain || job !== null}><legend>Declared comparison cases</legend>
      {cases.map((c, index) => <fieldset key={index}><legend>Case {index + 1}: {c.kind}</legend>
        <label>Case {index + 1} reference asset ID<input value={c.asset_id} maxLength={36} onChange={e => edit(index, { asset_id: e.target.value })}/></label>
        <label>Case {index + 1} kind<select value={c.kind} onChange={e => edit(index, { kind: e.target.value })}>{['complete', 'incorrect', 'challenge'].map(k => <option key={k}>{k}</option>)}</select></label>
        {draft.content.constraints.map((constraint, i) => <div className="form-grid" key={constraint.part_class_id}>
          <label>Case {index + 1} {constraint.part_class_id} expected finding<select value={c.expected_findings[i]} onChange={e => edit(index, { expected_findings: c.expected_findings.map((f, n) => n === i ? e.target.value : f) })}>{['SATISFIED', 'VIOLATED', 'UNOBSERVABLE'].map(f => <option key={f}>{f}</option>)}</select></label>
          <label>Case {index + 1} {constraint.part_class_id} declared count<input type="number" min={0} max={30} value={Number.isFinite(c.expected_counts[i]) ? c.expected_counts[i] : ''} onChange={e => edit(index, { expected_counts: c.expected_counts.map((n, j) => j === i ? e.target.value === '' ? Number.NaN : Number(e.target.value) : n) })}/></label></div>)}
        <button disabled={cases.length <= 3} onClick={() => { clear(); setCases(old => old.filter((_, i) => i !== index)); }}>Remove qualification case {index + 1}</button>
      </fieldset>)}
      <button disabled={cases.length >= 8} onClick={() => { clear(); setCases(old => [...old, initial('challenge')]); }}>Add qualification case</button>
      <label className="check"><input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)}/>I reviewed these comparison inputs and their permitted use. They do not establish independent physical truth.</label>
    </fieldset>
    <button disabled={disabled || busy || (!uncertain && (!valid || !confirmed || job !== null)) || !positive(draft.state_version)} onClick={() => void perform(submit)}>{uncertain ? 'Retry unchanged recipe qualification' : 'Run recipe qualification cases'}</button>
    {uncertain && <p>Outcome unconfirmed. Retry the same frozen request. Leaving loses the local request; reload this draft to find its recorded job before another run.</p>}
    </>}
    <fieldset disabled={disabled || busy}><legend>Recorded job and report</legend><label>Recipe qualification job ID<input value={jobId} maxLength={36} disabled={uncertain} onChange={e => { clear(); setJob(null); setJobId(e.target.value); }}/></label>
      <button disabled={!uuid.test(jobId)} onClick={() => void perform(readJob)}>Read recipe qualification job</button>
      {job && <><p>Recorded job: {job.status}. Completion never activates the recipe.</p><button disabled={!job.report_id} onClick={() => void perform(readReport)}>Read measured recipe report</button></>}
      {report && expiry.valid && <><p>Diagnostic comparison: {report.diagnostic_passed ? 'matched' : 'failed'}. Qualification: {report.eligible_for_approval ? 'eligible for separate review' : 'held or failed'}.</p>
        <p>Physical truth verified: no. Independent review verified: no.</p><ul>{report.results.map(r => <li key={r.asset_id}>{r.kind}: {r.matched ? 'matched' : 'mismatch'}; {r.findings.join(', ')}; measured counts {r.measured_counts.join(', ')}; quality {r.quality_ok ? 'supported' : 'unsupported'}.</li>)}</ul>
        <button onClick={() => void perform(() => onReview(report.id))}>Reload draft to review this qualification</button></>}
    </fieldset>
  </section>;
}
