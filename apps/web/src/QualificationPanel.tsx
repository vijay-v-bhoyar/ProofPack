import { useRef, useState } from 'react';
import type { User } from './api';
import { identifier, positive, sha, uuid, useReviewDeadline, useTasks, useUnconfirmed } from './workbench';
import { active, candidate, decision, flags, integer, options, qjob, sameTarget, target, type Active, type Candidate, type Decision, type Options, type QJob, type RollbackTarget } from './policyLifecycle';

type Body = { mode: 'installed_default' | 'candidate'; policy_id: string; policy_revision: number; policy_state_version: number; policy_revision_sha256: string;
  preparation_id?: string; preparation_state_version?: number; preparation_report_sha256?: string; rollback_target?: RollbackTarget; synthetic_demo_acknowledged: true };
type Intent = { kind: string; path: string; body: Body | Record<string, unknown>; key: string; registry: string; version?: number; id?: string; before?: QJob };
type Catalog = Decision & { id: string; kind: string; state_version: number; status: string; steps_prepared: number; planned_steps: number; steps_reserved: number; current: null; report_current: null; currency_not_checked: true };
type Phase = { index: number; phase: string; cases?: number; passed: boolean | number; failed?: number; unknown?: boolean; case_id?: string; source_index?: number;
  source_entry_sha256?: string; new_pixel_measurement?: boolean; physical_truth_verified?: boolean; expected?: unknown; actual?: unknown; software_report_sha256?: string; entries?: { index: number; sha256: string }[]; start?: number };
type Software = { id: string; status: string; expected: unknown; actual: unknown; reason: string | null };
const base = '/policy-qualifications';
const defaultPriority = ['SEPARATE_REGION', 'PLACE_FLAT', 'RECAPTURE'];

export function QualificationPanel({ user, seedPreparation = '', onActivate }: { user: User; seedPreparation?: string; onActivate?: (id: string) => void }) {
  const { busy, message, call, perform, say, fresh } = useTasks('Read exact inputs before requesting synthetic qualification.');
  const reviewer = user.roles.includes('reviewer'), owner = user.roles.includes('owner');
  const [mode, setMode] = useState<'installed_default' | 'candidate'>(seedPreparation ? 'candidate' : 'installed_default'), [policyId, setPolicyId] = useState(''), [revision, setRevision] = useState('');
  const [preparationId, setPreparationId] = useState(seedPreparation), [rollback, setRollback] = useState(false), [activeVersion, setActiveVersion] = useState(''), [activationId, setActivationId] = useState(''), [predecessor, setPredecessor] = useState('');
  const [context, setContext] = useState<{ body: Body; policy: Candidate; installed: Options; sourceCount: number } | null>(null), [ack, setAck] = useState(false);
  const [jobId, setJobId] = useState(''), [job, setJob] = useState<QJob | null>(null), [installed, setInstalled] = useState<Options | null>(null);
  const [catalog, setCatalog] = useState<Catalog[]>([]), [cursor, setCursor] = useState<string | null>(null), [ownerView, setOwnerView] = useState(owner && !reviewer);
  const [pending, setPending] = useState<Intent | null>(null), [exitAck, setExitAck] = useState(false), [endAck, setEndAck] = useState(false), [reason, setReason] = useState('qualification-ended');
  const [entries, setEntries] = useState<Phase[]>([]), [software, setSoftware] = useState<Software[]>([]), [next, setNext] = useState<number | null>(null), [pageKind, setPageKind] = useState<'entries' | 'software-cases'>('entries');
  const inputReview = useReviewDeadline(), resultReview = useReviewDeadline(), deadline = useRef(0);
  const softwareSeen = useRef(new Map<number, string>());
  useUnconfirmed(!!pending);
  function clearInputs() { inputReview.clear(); setContext(null); setAck(false); }
  function clearResult() { resultReview.clear(); setJob(null); setInstalled(null); setEntries([]); setSoftware([]); softwareSeen.current.clear(); setNext(null); setEndAck(false); }
  function edit(run: () => void) { clearInputs(); run(); }
  async function bounds() { return options(await call<Options>(base + '/options')); }
  async function readInputs() {
    clearInputs(); clearResult(); const started = performance.now(), token = inputReview.token(); await fresh(user, 'reviewer');
    const limits = await bounds(); let body: Body, selected: Candidate, count = 0, remaining = limits.lifetime_ms;
    if (mode === 'candidate') {
      if (!uuid.test(preparationId)) throw new Error('Enter the completed preparation ID.');
      const prep = await call<{ id: string; policy_id: string; state_version: number; source_evaluation_id: string; source_report_sha256: string; report_sha256: string; report_current: boolean; source_current: boolean; status: string; qualification_status: string; source_examples: number; remaining_ms: number; physical_truth_verified: false; independent_benchmark_qualified: false; promotion_eligible: false; qualification_eligible: false }>('/qualification-preparations/' + preparationId);
      if (!prep || prep.id !== preparationId || !uuid.test(prep.policy_id) || !positive(prep.state_version) || !uuid.test(prep.source_evaluation_id) || !sha.test(prep.source_report_sha256) || !sha.test(prep.report_sha256)
        || prep.status !== 'completed' || prep.source_current !== true || prep.report_current !== true || prep.qualification_status !== 'not_qualified' || !positive(prep.source_examples) || prep.source_examples > 1000
        || !positive(prep.remaining_ms) || prep.remaining_ms > 3600000 || prep.physical_truth_verified !== false || prep.independent_benchmark_qualified !== false || prep.promotion_eligible !== false || prep.qualification_eligible !== false) throw new Error('A complete current preparation is required; preparation alone is not qualification.');
      const source = await call<{ policy_id: string; policy_revision: number; policy_state_version: number; policy_revision_sha256: string; runner: string; rollback_target?: RollbackTarget }>('/evaluations/' + prep.source_evaluation_id + '/request');
      if (!source || source.runner !== 'vision_replay_v1' || source.policy_id !== prep.policy_id || !positive(source.policy_revision) || source.policy_revision > 1000 || !positive(source.policy_state_version)
        || !sha.test(source.policy_revision_sha256) || (source.rollback_target !== undefined && !target(source.rollback_target))) throw new Error('The original image-evaluation candidate or purpose is unavailable.');
      selected = candidate(await call<Candidate>('/policies/' + source.policy_id + '?revision=' + source.policy_revision));
      if (selected.id !== source.policy_id || selected.revision !== source.policy_revision || selected.state_version !== source.policy_state_version || selected.revision_sha256 !== source.policy_revision_sha256) throw new Error('Preparation no longer matches the exact candidate head.');
      body = { mode, policy_id: selected.id, policy_revision: selected.revision, policy_state_version: selected.state_version, policy_revision_sha256: selected.revision_sha256,
        preparation_id: prep.id, preparation_state_version: prep.state_version, preparation_report_sha256: prep.report_sha256, synthetic_demo_acknowledged: true,
        ...(source.rollback_target ? { rollback_target: source.rollback_target } : {}) };
      count = prep.source_examples; remaining = Math.min(remaining, prep.remaining_ms);
    } else {
      if (!uuid.test(policyId) || (revision && (!positive(Number(revision)) || Number(revision) > 1000))) throw new Error('Enter a candidate ID and optional exact revision.');
      selected = candidate(await call<Candidate>('/policies/' + policyId + (revision ? '?revision=' + revision : '')));
      if (selected.id !== policyId || (revision && selected.revision !== Number(revision)) || selected.spec.priority.some((v, i) => v !== defaultPriority[i])) throw new Error('Installed-default qualification requires the installed default priority.');
      let selectedTarget: RollbackTarget | null = null;
      if (rollback) {
        selectedTarget = { active_version: Number(activeVersion), activation_id: activationId, predecessor_activation_id: predecessor };
        if (!target(selectedTarget) || !revision) throw new Error('Review the owner handoff and enter its exact active version, activation, predecessor and candidate revision.');
      } else if (selected.revision !== selected.latest_revision) throw new Error('Ordinary qualification requires the latest candidate revision.');
      body = { mode, policy_id: selected.id, policy_revision: selected.revision, policy_state_version: selected.state_version, policy_revision_sha256: selected.revision_sha256,
        synthetic_demo_acknowledged: true, ...(selectedTarget ? { rollback_target: selectedTarget } : {}) };
    }
    if (body.rollback_target) {
      const head = active(await call<Active>('/policies/active'));
      if (head.active_version !== body.rollback_target.active_version) throw new Error('The rollback handoff no longer names the current active version.');
    }
    const required = limits.software_cases + limits.golden_cases + count;
    const steps = (mode === 'installed_default' ? 1 : Math.ceil((limits.software_cases + count) / 20) + count) + limits.golden_cases;
    if (required > limits.max_reserved_cases || steps > limits.max_steps) throw new Error('The complete qualification plan exceeds the installed budget; no cases will be truncated.');
    inputReview.bound(started, Math.min(remaining, 60000), 60000, token); setContext({ body, policy: selected, installed: limits, sourceCount: count });
    say('Exact candidate, purpose and complete plan read. Acknowledge the synthetic-only scope before creating work.');
  }
  async function read(id = jobId) {
    clearInputs(); clearResult(); if (!uuid.test(id)) throw new Error('Enter a qualification ID.');
    const started = performance.now(), token = resultReview.token(); await fresh(user); const limits = await bounds();
    const value = qjob(await call<QJob>(base + '/' + id), limits); if (value.id !== id) throw new Error('Qualification target changed.');
    const window = Math.min(value.remaining_ms || 60000, 60000); resultReview.bound(started, window, 60000, token); deadline.current = started + window;
    setJob(value); setJobId(id); setInstalled(limits); say(value.report_current ? 'Current synthetic report read. Independent physical evidence and owner activation remain separate.' : 'Control metadata read. There is no current complete qualification report.');
  }
  async function list(more = false) {
    clearInputs(); clearResult(); setCatalog([]); await fresh(user, ownerView ? 'owner' : 'reviewer'); const scope = ownerView ? 'owner' : 'own';
    const value = await call<{ qualifications: Catalog[]; scope: string; next_cursor: string | null }>(base + '?limit=20&scope=' + scope + (more && cursor ? '&cursor=' + cursor : ''));
    if (!value || value.scope !== scope || !Array.isArray(value.qualifications) || value.qualifications.length > 20 || (value.next_cursor !== null && !uuid.test(value.next_cursor))) throw new Error('Qualification catalog is unavailable.');
    value.qualifications.forEach(v => { decision(v); if (!uuid.test(v.id) || v.kind !== 'policy_qualification' || !positive(v.state_version) || !['queued', 'processing', 'completed', 'failed', 'cancelled', 'retired'].includes(v.status)
      || !positive(v.planned_steps) || v.planned_steps > 1256 || !integer(v.steps_prepared) || v.steps_prepared > v.planned_steps || !integer(v.steps_reserved) || v.steps_reserved < v.steps_prepared || v.steps_reserved > 10000
      || v.current !== null || v.report_current !== null || v.currency_not_checked !== true || !flags(v)) throw new Error('Catalog currency or identity is unsupported.'); });
    setCatalog(value.qualifications); setCursor(value.next_cursor); say('Historical discovery only. Open a record for current status; a read does not settle an uncertain write.');
  }
  async function send(intent: Intent) {
    setPending(intent); setExitAck(false); clearInputs(); clearResult();
    try {
      const live = await fresh(user, ['create', 'advance'].includes(intent.kind) ? 'reviewer' : undefined);
      const value = qjob(await call<QJob>(intent.path, { user: live, method: 'POST', body: intent.body, version: intent.version, idempotencyKey: intent.key }));
      if (value.registry_sha256 !== intent.registry || (intent.id && value.id !== intent.id)) throw new Error('Qualification write identity changed.');
      if (intent.before) {
        const b = intent.before, keys = ['policy_id', 'policy_revision', 'policy_state_version', 'policy_revision_sha256', 'mode', 'preparation_id', 'preparation_state_version', 'preparation_report_sha256', 'registry_sha256', 'source_examples', 'planned_steps', 'required_cases'] as const;
        if (keys.some(k => value[k] !== b[k]) || !sameTarget(value.rollback_target, b.rollback_target) || value.state_version < b.state_version
          || value.steps_prepared < b.steps_prepared || value.steps_reserved < b.steps_reserved || value.cases_reserved < b.cases_reserved) throw new Error('Qualification reply changed its request or refunded observed work and reservations.');
      }
      if (intent.kind === 'create') {
        const b = intent.body as Body;
        if (value.policy_id !== b.policy_id || value.policy_revision !== b.policy_revision || value.policy_state_version !== b.policy_state_version || value.policy_revision_sha256 !== b.policy_revision_sha256
          || value.mode !== b.mode || value.preparation_id !== (b.preparation_id ?? null) || value.preparation_state_version !== (b.preparation_state_version ?? null)
          || value.preparation_report_sha256 !== (b.preparation_report_sha256 ?? null) || !sameTarget(value.rollback_target, b.rollback_target ?? null)) throw new Error('Qualification differs from the frozen source and purpose.');
      }
      setPending(null); setJob(value); setJobId(value.id); say('Qualification operation recorded. Read current status before another action; no policy was activated.');
    } catch (error) { say('Qualification outcome is unconfirmed. Keep the exact retry or investigate the original records before another intent.'); throw error; }
  }
  async function write(kind: 'create' | 'advance' | 'cancel' | 'retire') {
    if (pending) return;
    if (kind === 'create') {
      if (!reviewer || !context || !inputReview.valid || !ack) return;
      return send({ kind, path: base, key: crypto.randomUUID(), body: context.body, registry: context.installed.registry_sha256 });
    }
    if (!job || !resultReview.valid || (kind === 'advance' ? !reviewer || !job.can_advance : !endAck || (kind === 'cancel' ? !job.can_cancel : !job.can_retire || !identifier.test(reason)))) return;
    return send({ kind, path: kind === 'retire' ? base + '/' + job.id + '/retire' : '/jobs/' + job.id + '/' + kind, id: job.id, key: crypto.randomUUID(), version: job.state_version,
      body: kind === 'retire' ? { acknowledged: true, reason } : {}, registry: job.registry_sha256, before: job });
  }
  async function original() {
    if (!job || !reviewer || !job.can_read_request) return; const id = job.id; clearInputs(); clearResult(); await fresh(user, 'reviewer');
    const value = await call<Body>(base + '/' + id + '/request');
    if (!value || !uuid.test(value.policy_id) || !positive(value.policy_revision) || value.policy_revision > 1000 || !positive(value.policy_state_version) || !sha.test(value.policy_revision_sha256) || !['candidate', 'installed_default'].includes(value.mode)
      || value.synthetic_demo_acknowledged !== true || (value.rollback_target !== undefined && !target(value.rollback_target))
      || (value.mode === 'candidate' ? !uuid.test(value.preparation_id ?? '') || !positive(value.preparation_state_version) || !sha.test(value.preparation_report_sha256 ?? '')
        : value.preparation_id != null || value.preparation_state_version != null || value.preparation_report_sha256 != null)) throw new Error('Original qualification request is unavailable.');
    setMode(value.mode); setPolicyId(value.policy_id); setRevision(String(value.policy_revision)); setPreparationId(value.preparation_id ?? ''); setRollback(!!value.rollback_target);
    setActiveVersion(value.rollback_target ? String(value.rollback_target.active_version) : ''); setActivationId(value.rollback_target?.activation_id ?? ''); setPredecessor(value.rollback_target?.predecessor_activation_id ?? '');
    say('Original selectors recovered without submitting. Existing uncertainty remains; read current inputs before a new intent.');
  }
  async function page(kind: 'entries' | 'software-cases', start = 0) {
    if (!job || !installed || !reviewer || !resultReview.valid || !job.can_read_details) return;
    const selected = job, limits = installed, token = resultReview.token(), expires = deadline.current; setEntries([]); setSoftware([]); setNext(null); setPageKind(kind);
    try {
      await fresh(user, 'reviewer');
      const value = await call<{ id: string; entries?: Phase[]; cases?: Software[]; next_index: number | null }>(base + '/' + selected.id + '/' + kind + '?start=' + start + '&limit=20');
      const count = kind === 'entries' ? selected.planned_steps : limits.software_cases, end = Math.min(start + 20, count);
      if (!value || value.id !== selected.id || !flags(value) || value.next_index !== (end === count ? null : end)) throw new Error('Qualification page identity changed.');
      if (kind === 'entries') {
        if (!Array.isArray(value.entries) || value.entries.length !== end - start) throw new Error('Qualification phases are incomplete.');
        const prepPages = selected.mode === 'candidate' ? Math.ceil((limits.software_cases + selected.source_examples) / 20) : 1;
        value.entries.forEach((v, i) => {
          const position = start + i, phase = position < prepPages ? selected.mode === 'candidate' ? 'verified_preparation_page' : 'executed_installed_default_contracts' : position < prepPages + selected.source_examples ? 'source_regression' : 'installed_golden';
          if (!v || v.index !== position || v.phase !== phase || JSON.stringify(v).length > 32768) throw new Error('Qualification phase order changed.');
          if (phase === 'installed_golden' && (typeof v.passed !== 'boolean' || typeof v.case_id !== 'string' || !v.case_id || v.case_id.length > 128 || v.new_pixel_measurement !== true || v.physical_truth_verified !== false)) throw new Error('Golden image evidence is unsupported.');
          if (phase === 'source_regression' && (v.source_index !== position - prepPages || !sha.test(v.source_entry_sha256 ?? '') || typeof v.passed !== 'boolean' || typeof v.unknown !== 'boolean' || (v.passed && v.unknown) || v.physical_truth_verified !== false)) throw new Error('Source outcome is unsupported.');
          if (phase === 'executed_installed_default_contracts' && (v.cases !== limits.software_cases || !integer(v.passed) || !integer(v.failed) || v.passed + v.failed !== v.cases || !sha.test(v.software_report_sha256 ?? ''))) throw new Error('Software denominator changed.');
          if (phase === 'verified_preparation_page' && (v.start !== position * 20 || !Array.isArray(v.entries) || v.entries.length !== Math.min(20, limits.software_cases + selected.source_examples - position * 20)
            || v.entries.some((e, n) => e.index !== position * 20 + n || !sha.test(e.sha256)) || !integer(v.passed) || !integer(v.failed) || v.passed + v.failed > 20)) throw new Error('Prepared page binding changed.');
        }); setEntries(value.entries);
      } else {
        if (!Array.isArray(value.cases) || value.cases.length !== end - start || new Set(value.cases.map(v => v.id)).size !== value.cases.length || value.cases.some(v => !v || typeof v.id !== 'string' || !v.id || v.id.length > 128
          || !['PASS', 'FAIL'].includes(v.status) || !Object.prototype.hasOwnProperty.call(v, 'expected') || !Object.prototype.hasOwnProperty.call(v, 'actual') || JSON.stringify(v).length > 8192
          || (v.status === 'PASS' && (JSON.stringify(v.expected) !== JSON.stringify(v.actual) || v.reason !== null)) || (v.reason !== null && (typeof v.reason !== 'string' || v.reason.length > 2000)))) throw new Error('Software cases are incomplete or unsupported.');
        value.cases.forEach((v, i) => {
          const position = start + i, previous = softwareSeen.current.get(position);
          if ((previous !== undefined && previous !== v.id) || [...softwareSeen.current].some(([index, id]) => index !== position && id === v.id)) throw new Error('Software page repeated or changed a previously inspected case.');
          softwareSeen.current.set(position, v.id);
        }); setSoftware(value.cases);
      }
      resultReview.bound(performance.now(), Math.floor(expires - performance.now()), 60000, token); setNext(value.next_index);
    } catch (error) { clearResult(); throw error; }
  }
  return <section aria-labelledby="qualification-title"><h3 id="qualification-title">Policy qualification</h3><p role="status">{message}</p>
    <p>Runs installed software checks, analytic golden images and, for candidates, permitted source regressions. Results are synthetic-demo only. Declared counts are not independent physical truth, operator effort, beta approval or activation.</p>
    {reviewer && <fieldset disabled={busy || !!pending}><legend>Prepare a qualification request</legend>
      <label htmlFor="qualification-mode">Qualification mode</label><select id="qualification-mode" value={mode} onChange={e => edit(() => setMode(e.target.value as typeof mode))}><option value="installed_default">Installed default</option><option value="candidate">Prepared candidate</option></select>
      {mode === 'candidate' ? <label>Completed preparation ID<input value={preparationId} onChange={e => edit(() => setPreparationId(e.target.value))}/></label> : <>
        <label>Qualification candidate ID<input value={policyId} onChange={e => edit(() => setPolicyId(e.target.value))}/></label><label>Qualification candidate revision (blank for latest)<input value={revision} onChange={e => edit(() => setRevision(e.target.value))}/></label>
        <label><input type="checkbox" checked={rollback} onChange={e => edit(() => setRollback(e.target.checked))}/>Qualify the exact predecessor from an owner rollback handoff</label>
        {rollback && <><label>Rollback active version<input value={activeVersion} onChange={e => edit(() => setActiveVersion(e.target.value))}/></label><label>Rollback current activation ID<input value={activationId} onChange={e => edit(() => setActivationId(e.target.value))}/></label><label>Rollback predecessor activation ID<input value={predecessor} onChange={e => edit(() => setPredecessor(e.target.value))}/></label></>}
      </>}
      <button onClick={() => void perform(readInputs)}>Read qualification inputs</button>
      {context && <><p>Candidate {context.policy.spec.name}; {context.body.policy_id}; revision {context.body.policy_revision}; state {context.body.policy_state_version}; hash {context.body.policy_revision_sha256}.</p>
        <p>Purpose: {context.body.rollback_target ? 'exact predecessor rollback only' : 'ordinary proposal'}. Complete cases: {context.installed.software_cases} software + {context.installed.golden_cases} golden + {context.sourceCount} source. Attempts are not refunded or renewed.</p>
        {context.body.rollback_target && <p>Active version {context.body.rollback_target.active_version}; activation {context.body.rollback_target.activation_id}; predecessor {context.body.rollback_target.predecessor_activation_id}.</p>}
        <label><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)}/>I reviewed this exact complete plan and its synthetic-only limits; completion does not authorize activation, physical use or beta.</label></>}
      <button disabled={!inputReview.valid || !context || !ack} onClick={() => void perform(() => write('create'))}>Create synthetic qualification</button>
    </fieldset>}
    <fieldset disabled={busy}><legend>Discover or read qualification</legend>{owner && reviewer && <label><input type="checkbox" checked={ownerView} onChange={e => { setOwnerView(e.target.checked); setCatalog([]); setCursor(null); clearInputs(); clearResult(); }}/>Owner aggregate catalog (recent MFA)</label>}
      <button onClick={() => void perform(() => list())}>Find qualification jobs</button><button disabled={!cursor} onClick={() => void perform(() => list(true))}>Next qualification catalog page</button>
      <ul>{catalog.map(v => <li key={v.id}><button onClick={() => void perform(() => read(v.id))}>Read qualification {v.id} · {v.status}</button> Candidate {v.policy_id} revision {v.policy_revision}; {v.rollback_target ? 'rollback-only' : 'ordinary'}; currency unchecked.</li>)}</ul>
      <label>Qualification job ID<input value={jobId} onChange={e => { setJobId(e.target.value); clearInputs(); clearResult(); }}/></label><button disabled={!uuid.test(jobId)} onClick={() => void perform(() => read())}>Read qualification job</button>
    </fieldset>
    {job && <><p>Qualification {job.id}: {job.status}; {resultReview.valid ? job.qualification_status : 'historical metadata — refresh required'}. Candidate {job.policy_id} revision {job.policy_revision}; purpose {job.rollback_target ? 'rollback only' : 'ordinary proposal'}.</p>
      <p>Candidate state {job.policy_state_version}; hash {job.policy_revision_sha256}. Report {job.report_sha256 ?? 'no current report'}.</p>
      {job.rollback_target && <p>Recorded rollback target: active version {job.rollback_target.active_version}; activation {job.rollback_target.activation_id}; predecessor {job.rollback_target.predecessor_activation_id}. This is not a fresh authority grant.</p>}
      <p>Steps {job.steps_prepared}/{job.planned_steps}; reserved attempts {job.steps_reserved}; reserved cases {job.cases_reserved}; required cases {job.required_cases}; lease remaining at read {resultReview.valid ? job.lease_remaining_ms : 'unknown'} ms.</p>
      {job.counts && <p>Recorded outcomes: {job.counts.passed} passed, {job.counts.failed} failed, {job.counts.unknown} unknown. {job.report_current && resultReview.valid ? 'Current synthetic report.' : 'Historical only.'}</p>}
      {job.failure_reason && <p>Failure: {job.failure_reason}</p>}
      {owner && onActivate && <button disabled={busy || !resultReview.valid || !job.report_current || job.qualification_status !== 'qualified'} onClick={() => onActivate(job.id)}>Review owner activation for this qualification</button>}
      {reviewer && <fieldset disabled={busy || !resultReview.valid}><legend>Original reviewer evidence</legend><button disabled={!job.can_read_request} onClick={() => void perform(original)}>Read original qualification selectors</button>
        <button disabled={!job.can_read_details} onClick={() => void perform(() => page('entries'))}>Read qualification phases</button><button disabled={!job.can_read_details} onClick={() => void perform(() => page('software-cases'))}>Read qualification software cases</button></fieldset>}
      <fieldset disabled={busy || !!pending || !resultReview.valid}><legend>Qualification controls</legend>
        {reviewer && <button disabled={!job.can_advance} onClick={() => void perform(() => write('advance'))}>Advance one qualification step</button>}
        <label><input type="checkbox" checked={endAck} onChange={e => setEndAck(e.target.checked)}/>I understand stopping preserves history and consumed attempts; retirement advances the data epoch and invalidates all dependent comparisons, qualifications and live approvals, requiring fresh evidence.</label>
        <button disabled={!job.can_cancel || !endAck} onClick={() => void perform(() => write('cancel'))}>Cancel qualification work</button>
        <label>Qualification retirement reason<input value={reason} onChange={e => { setReason(e.target.value); setEndAck(false); }}/></label><button disabled={!job.can_retire || !endAck || !identifier.test(reason)} onClick={() => void perform(() => write('retire'))}>Retire qualification report</button>
      </fieldset>
    </>}
    {resultReview.valid && <><ol>{entries.map(v => <li key={v.index}>Step {v.index + 1}: {v.phase.replaceAll('_', ' ')}; passed {String(v.passed)}{v.failed !== undefined ? '; failed ' + v.failed : ''}{v.unknown !== undefined ? '; unknown ' + v.unknown : ''}{v.case_id ? '; case ' + v.case_id : ''}
      {(v.expected !== undefined || v.actual !== undefined) && <details><summary>Expected and measured values</summary><pre>{JSON.stringify({ expected: v.expected, measured: v.actual }, null, 2)}</pre></details>}</li>)}</ol>
      <ol>{software.map(v => <li key={v.id}>{v.id}: {v.status}; expected {JSON.stringify(v.expected)}, actual {JSON.stringify(v.actual)}; {v.reason ?? 'no reported error'}</li>)}</ol>
      <button disabled={busy || next === null} onClick={() => void perform(() => page(pageKind, next!))}>Next qualification evidence page</button></>}
    {pending && <fieldset disabled={busy}><legend>Unconfirmed qualification operation</legend><p>The server may already have committed. A read does not settle this write; retry keeps the original body, target, version and key.</p>
      <button onClick={() => void perform(() => send(pending))}>Retry unchanged qualification request</button><label><input type="checkbox" checked={exitAck} onChange={e => setExitAck(e.target.checked)}/>I understand only local retry details are discarded; the server outcome must still be investigated.</label>
      <button disabled={!exitAck} onClick={() => { setPending(null); clearInputs(); clearResult(); say('Local retry details forgotten. Investigate the original qualification before a separate intent; nothing was cancelled or undone.'); }}>Finish without another qualification write</button></fieldset>}
  </section>;
}
