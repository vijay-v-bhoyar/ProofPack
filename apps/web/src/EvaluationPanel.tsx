import { useRef, useState } from 'react';
import type { User } from './api';
import { useUnconfirmed, identifier, positive, sha, uuid, useReviewDeadline, useTasks } from './workbench';
import { active, sameTarget, target as validRollbackTarget, type Active, type RollbackTarget } from './policyLifecycle';

const categories = ['observed_match', 'counterfactual_unknown', 'no_recorded_outcome', 'not_actionable', 'incorrect_finding'] as const;
const actions = ['SEPARATE_REGION', 'PLACE_FLAT', 'RECAPTURE', 'REVIEW'];
type Counts = Record<string, number>;
type Runner = 'decision_replay_v1' | 'vision_replay_v1';
type RecipeBinding = { candidate_recipe_id?: string; candidate_recipe_revision?: number; candidate_recipe_state_version?: number; candidate_recipe_sha256?: string; vision_measurement_acknowledged?: boolean };
type RequestBody = RecipeBinding & { runner: Runner; policy_id: string; policy_revision: number; policy_state_version: number; policy_revision_sha256: string;
  manifest_id: string; manifest_sha256: string; historical_diagnostic_acknowledged: boolean; frozen_holdout_acknowledged: boolean; rollback_target?: RollbackTarget };
type Job = RecipeBinding & { id: string; kind: string; state_version: number; status: string; policy_id: string; policy_revision: number; policy_revision_sha256: string;
  manifest_id: string; manifest_sha256: string; candidate_name: string; example_count: number; prepared_count: number; steps_reserved: number;
  remaining_ms: number; lease_remaining_ms: number; report_sha256: string | null; failure_reason: string | null; runner: string;
  diagnostic_only: boolean; independent_benchmark_qualified: boolean; promotion_eligible: boolean; operator_effort_measured: boolean;
  can_advance: boolean; can_cancel: boolean; can_retire: boolean; result_header_current?: boolean; counts?: { baseline: Counts; candidate: Counts } | null;
  pixel_measurement_performed?: boolean; physical_truth_verified?: boolean; policy_state_version?: number; rollback_target?: RollbackTarget; can_read_request?: boolean };
type Context = Omit<RequestBody, 'historical_diagnostic_acknowledged' | 'frozen_holdout_acknowledged'> & { name: string; count: number; frozen: number };
type Measurement = { observation_id: string; original_asset_id: string; source_sha256: string; calibration_sha256: string; findings: string[];
  class_counts: Counts; declared_truth_counts: Counts; count_comparison_observable: boolean; counts_match_declared_truth: boolean | null;
  physical_truth_verified: boolean; dimension_truth_accuracy_measured: boolean };
type Side = { action: string | null; classification: string; declared_resolved: boolean | null; recipe_sha256?: string; measurements?: Measurement[] };
type Example = { index: number; label_id: string; label_revision: number; content_sha256: string; policy_revision_sha256: string; split: string; data_origin: string;
  diagnostic_only: boolean; independent_benchmark_qualified: boolean; promotion_eligible: boolean; operator_effort_measured: boolean; baseline: Side; candidate: Side;
  runner?: string; original_frames?: number; measurement_count?: number; calibration_sha256?: string; pixel_measurement_performed?: boolean; physical_truth_verified?: boolean };
type Intent = { kind: 'create' | 'advance' | 'cancel' | 'retire'; path: string; body: RequestBody | object; key: string; version?: number; id?: string };
const nonnegative = (n: unknown): n is number => Number.isSafeInteger(n) && Number(n) >= 0;
const flags = (v: { diagnostic_only: boolean; independent_benchmark_qualified: boolean; promotion_eligible: boolean; operator_effort_measured: boolean }) =>
  v.diagnostic_only === true && v.independent_benchmark_qualified === false && v.promotion_eligible === false && v.operator_effort_measured === false;
function recipeBinding(value: RecipeBinding) { return uuid.test(value.candidate_recipe_id ?? '') && positive(value.candidate_recipe_revision)
  && positive(value.candidate_recipe_state_version) && sha.test(value.candidate_recipe_sha256 ?? ''); }
function checked(value: Job): Job {
  if (value && ((value.policy_state_version !== undefined && !positive(value.policy_state_version)) || (value.rollback_target !== undefined && (!validRollbackTarget(value.rollback_target) || !positive(value.policy_state_version)))
    || (value.can_read_request !== undefined && (typeof value.can_read_request !== 'boolean' || (value.can_advance && !value.can_read_request))))) throw new Error('Recorded comparison state or rollback purpose is unavailable.');
  if (!value || !uuid.test(value.id) || value.kind !== 'policy_evaluation' || !positive(value.state_version)
    || !uuid.test(value.policy_id) || !positive(value.policy_revision) || value.policy_revision > 1000 || !sha.test(value.policy_revision_sha256)
    || !uuid.test(value.manifest_id) || !sha.test(value.manifest_sha256) || typeof value.candidate_name !== 'string' || value.candidate_name.length > 80
    || !positive(value.example_count) || value.example_count > 1000 || !nonnegative(value.prepared_count) || value.prepared_count > value.example_count
    || !nonnegative(value.steps_reserved) || value.steps_reserved > 10000 || !nonnegative(value.remaining_ms) || value.remaining_ms > 3600000
    || !nonnegative(value.lease_remaining_ms) || value.lease_remaining_ms > 60000 || (value.report_sha256 !== null && !sha.test(value.report_sha256))
    || !['queued', 'processing', 'completed', 'failed', 'cancelled', 'retired'].includes(value.status) || !['decision_replay_v1','vision_replay_v1'].includes(value.runner) || !flags(value)
    || (value.runner === 'vision_replay_v1' && !recipeBinding(value))
    || [value.can_advance, value.can_cancel, value.can_retire].some(v => typeof v !== 'boolean')) throw new Error('Evaluation metadata is unavailable or claims unsupported qualification.');
  return value;
}
function counts(value: Counts, total: number, vision = false) {
  return value && [...categories, 'declared_resolved', 'declared_unresolved'].every(k => nonnegative(value[k]))
    && Object.keys(value).length === (vision ? 12 : 7) && categories.reduce((sum, key) => sum + value[key], 0) === total
    && value.declared_resolved + value.declared_unresolved === value.observed_match
    && (!vision || (['measurements','observable_frames','count_matches','count_mismatches','unobservable_frames'].every(k => nonnegative(value[k]))
      && value.measurements >= total && value.measurements <= total * 2 && value.observable_frames + value.unobservable_frames === value.measurements
      && value.count_matches + value.count_mismatches === value.observable_frames));
}
function side(value: Side) {
  return value && categories.some(k => k === value.classification) && (value.action === null || actions.includes(value.action))
    && (value.classification === 'observed_match' ? typeof value.declared_resolved === 'boolean' : value.declared_resolved === null);
}
function measured(value: Example, target: Job) {
  if (value.runner !== 'vision_replay_v1' || value.pixel_measurement_performed !== true || value.physical_truth_verified !== false
    || !positive(value.original_frames) || value.original_frames! > 2 || value.measurement_count !== value.original_frames! * 2 || !sha.test(value.calibration_sha256 ?? '')
    || value.candidate.recipe_sha256 !== target.candidate_recipe_sha256 || !sha.test(value.baseline.recipe_sha256 ?? '')) return false;
  return [value.baseline, value.candidate].every(s => Array.isArray(s.measurements) && s.measurements.length === value.original_frames
    && new Set(s.measurements.map(m => m.observation_id)).size === s.measurements.length
    && s.measurements.every(m => uuid.test(m.observation_id) && uuid.test(m.original_asset_id) && sha.test(m.source_sha256)
      && m.calibration_sha256 === value.calibration_sha256 && Array.isArray(m.findings) && m.findings.length >= 1 && m.findings.length <= 4
      && m.findings.every(f => ['SATISFIED','VIOLATED','UNOBSERVABLE'].includes(f)) && typeof m.count_comparison_observable === 'boolean'
      && (m.count_comparison_observable ? typeof m.counts_match_declared_truth === 'boolean' : m.counts_match_declared_truth === null)
      && m.physical_truth_verified === false && m.dimension_truth_accuracy_measured === false
      && !!m.class_counts && !!m.declared_truth_counts && Object.keys(m.class_counts).length >= 1 && Object.keys(m.class_counts).length <= 4
      && Object.keys(m.class_counts).every(c => ['washer','nut','bolt','flat_bracket'].includes(c) && nonnegative(m.class_counts[c]) && m.class_counts[c] <= 30
        && nonnegative(m.declared_truth_counts[c]) && m.declared_truth_counts[c] <= 30)
      && Object.keys(m.declared_truth_counts).length === Object.keys(m.class_counts).length
      && (!m.count_comparison_observable || m.counts_match_declared_truth === Object.keys(m.class_counts).every(c => m.class_counts[c] === m.declared_truth_counts[c]))))
    && value.baseline.measurements!.every((m, i) => { const candidate = value.candidate.measurements![i]; return m.observation_id === candidate.observation_id
      && m.original_asset_id === candidate.original_asset_id && m.source_sha256 === candidate.source_sha256; });
}

export function EvaluationPanel({ user, onPrepare }: { user: User; onPrepare?: (id: string) => void }) {
  const reviewer = user.roles.includes('reviewer');
  const { busy, message, call, perform, fresh, say } = useTasks('Historical action diagnostics do not measure physical correctness or packing speed.');
  const inputReview = useReviewDeadline(), resultReview = useReviewDeadline();
  const resultExpires = useRef(0);
  const [policyId, setPolicyId] = useState(''), [manifestId, setManifestId] = useState(''), [context, setContext] = useState<Context | null>(null);
  const [mode, setMode] = useState<Runner>('decision_replay_v1'), [recipeId, setRecipeId] = useState(''), [visionAck, setVisionAck] = useState(false);
  const [rollback, setRollback] = useState(false), [policyRevision, setPolicyRevision] = useState(''), [activeVersion, setActiveVersion] = useState(''), [activationId, setActivationId] = useState(''), [predecessorId, setPredecessorId] = useState('');
  const [ack, setAck] = useState(false), [frozenAck, setFrozenAck] = useState(false), [id, setId] = useState(''), [current, setCurrent] = useState<Job | null>(null);
  const [catalog, setCatalog] = useState<Job[]>([]), [cursor, setCursor] = useState<string | null>(null), [examples, setExamples] = useState<Example[]>([]), [next, setNext] = useState<number | null>(null);
  const [pending, setPending] = useState<Intent | null>(null), [exitAck, setExitAck] = useState(false), [retireAck, setRetireAck] = useState(false), [reason, setReason] = useState('');
  useUnconfirmed(!!pending);
  function clearInputs() { inputReview.clear(); setContext(null); setAck(false); setFrozenAck(false); setVisionAck(false); }
  function clearResult() { resultReview.clear(); resultExpires.current = 0; setCurrent(null); setExamples([]); setNext(null); setRetireAck(false); setExitAck(false); }
  async function inputs() {
    clearInputs(); clearResult(); const token = inputReview.token(), started = performance.now(); await fresh(user, 'reviewer');
    if (mode === 'vision_replay_v1') {
      const capabilities = await call<{ runners: string[]; promotion_available: boolean; physical_truth_verified: boolean }>('/evaluations/options');
      if (!Array.isArray(capabilities.runners) || !capabilities.runners.includes(mode) || capabilities.promotion_available !== false || capabilities.physical_truth_verified !== false)
        throw new Error('Original-image comparisons are unavailable here. Use recorded-action review or ask the owner.');
    }
    let rollbackTarget: RollbackTarget | undefined;
    if (rollback) {
      rollbackTarget = { active_version: Number(activeVersion), activation_id: activationId, predecessor_activation_id: predecessorId };
      if (!validRollbackTarget(rollbackTarget) || !positive(Number(policyRevision)) || Number(policyRevision) > 1000) throw new Error('Enter the exact predecessor revision and current owner handoff.');
      const head = active(await call<Active>('/policies/active')); if (head.active_version !== rollbackTarget.active_version) throw new Error('The rollback handoff no longer names the current active version.');
    }
    const p = await call<{ id: string; revision: number; latest_revision: number; state_version: number; revision_sha256: string; binding_current: boolean; spec: { name: string }; evaluation_status: string; promotion_available: boolean }>('/policies/' + policyId + (rollback ? '?revision=' + Number(policyRevision) : ''));
    const d = await call<{ id: string; kind: string; status: string; receipt_usable: boolean; example_count: number; manifest_sha256: string; remaining_ms: number; splits: Record<string, number>; independent_benchmark_qualified: boolean }>('/jobs/' + manifestId);
    if (p.id !== policyId || !positive(p.revision) || p.revision > 1000 || !positive(p.latest_revision) || p.latest_revision > 1000 || p.latest_revision < p.revision || (rollback ? p.revision !== Number(policyRevision) : p.latest_revision !== p.revision) || !positive(p.state_version) || !sha.test(p.revision_sha256)
      || p.binding_current !== true || p.evaluation_status !== 'NOT_VERIFIED' || p.promotion_available !== false || typeof p.spec?.name !== 'string'
      || d.id !== manifestId || d.kind !== 'dataset_manifest' || d.status !== 'completed' || d.receipt_usable !== true || !sha.test(d.manifest_sha256)
      || !positive(d.example_count) || d.example_count > 1000 || !positive(d.remaining_ms) || d.remaining_ms > 3600000 || d.independent_benchmark_qualified !== false
      || !d.splits || ['DEVELOPMENT', 'VALIDATION', 'FROZEN_TEST'].some(k => !nonnegative(d.splits[k])) || Object.values(d.splits).reduce((n, v) => n + v, 0) !== d.example_count)
      throw new Error('Read an exact currently bound candidate and complete permitted dataset; ordinary comparisons require the latest revision. Held inputs cannot be reused.');
    let recipe: RecipeBinding = {};
    if (mode === 'vision_replay_v1') {
      const r = await call<{ id: string; revision: number; state_version: number; recipe_sha256: string; retired: boolean }>('/recipes/' + recipeId + '/draft');
      if (r.id !== recipeId || !positive(r.revision) || !positive(r.state_version) || !sha.test(r.recipe_sha256) || r.retired !== false) throw new Error('Read a current non-retired candidate recipe.');
      recipe = { candidate_recipe_id: r.id, candidate_recipe_revision: r.revision, candidate_recipe_state_version: r.state_version, candidate_recipe_sha256: r.recipe_sha256 };
    }
    inputReview.bound(started, Math.min(d.remaining_ms, 60000), 60000, token);
    setContext({ runner: mode, ...recipe, policy_id: p.id, policy_revision: p.revision, policy_state_version: p.state_version,
      policy_revision_sha256: p.revision_sha256, manifest_id: d.id, manifest_sha256: d.manifest_sha256, name: p.spec.name, count: d.example_count, frozen: d.splits.FROZEN_TEST, ...(rollbackTarget ? { rollback_target: rollbackTarget } : {}) });
    say('Exact inputs read. Review historical scope and any frozen-data limitations before a separate submission.');
  }
  async function read(target = id) {
    clearInputs(); clearResult(); const token = resultReview.token(), started = performance.now(); await fresh(user);
    const value = checked(await call<Job>('/evaluations/' + target));
    if (value.id !== target || typeof value.result_header_current !== 'boolean' || (value.result_header_current
      ? value.status !== 'completed' || !value.report_sha256 || !value.counts || !counts(value.counts.baseline, value.example_count, value.runner === 'vision_replay_v1') || !counts(value.counts.candidate, value.example_count, value.runner === 'vision_replay_v1') || value.remaining_ms === 0
        || (value.runner === 'vision_replay_v1' && (value.pixel_measurement_performed !== true || value.physical_truth_verified !== false || value.counts.baseline.measurements !== value.counts.candidate.measurements))
      : value.counts !== null)) throw new Error('Evaluation summary is incomplete or its counts do not reconcile.');
    const window = Math.min(value.remaining_ms || 60000, 60000);
    resultReview.bound(started, window, 60000, token); resultExpires.current = started + window; setCurrent(value); setId(value.id);
    say(value.result_header_current ? 'Current historical diagnostics read. Unknown outcomes remain unknown; this is not an activation qualification.' : 'Control status read. No current complete comparison is available.');
  }
  async function list(nextPage = false) {
    clearInputs(); clearResult(); await fresh(user);
    const value = await call<{ evaluations: Job[]; next_cursor: string | null }>('/evaluations?limit=20' + (nextPage && cursor ? '&cursor=' + cursor : ''));
    if (!value || !Array.isArray(value.evaluations) || value.evaluations.length > 20 || (value.next_cursor !== null && !uuid.test(value.next_cursor))) throw new Error('Evaluation catalog is unavailable.');
    setCatalog(value.evaluations.map(checked)); setCursor(value.next_cursor); say('Recorded evaluations loaded. Open the original ID to inspect current status; no write was resolved by this catalog read.');
  }
  async function send(intent: Intent) {
    setPending(intent); clearInputs(); clearResult();
    try {
      const live = await fresh(user, ['create', 'advance'].includes(intent.kind) ? 'reviewer' : undefined);
      const value = checked(await call<Job>(intent.path, { user: live, method: 'POST', body: intent.body, version: intent.version, idempotencyKey: intent.key }));
      if (intent.id && value.id !== intent.id) throw new Error('Evaluation write target changed.');
      if (intent.kind === 'create') { const body = intent.body as RequestBody;
        if (value.policy_id !== body.policy_id || value.policy_revision !== body.policy_revision || value.policy_revision_sha256 !== body.policy_revision_sha256
          || value.manifest_id !== body.manifest_id || value.manifest_sha256 !== body.manifest_sha256 || value.runner !== body.runner
          || !sameTarget(value.rollback_target ?? null, body.rollback_target ?? null) || (value.policy_state_version !== undefined && value.policy_state_version !== body.policy_state_version)
          || (body.runner === 'vision_replay_v1' && (value.candidate_recipe_id !== body.candidate_recipe_id || value.candidate_recipe_revision !== body.candidate_recipe_revision
            || value.candidate_recipe_state_version !== body.candidate_recipe_state_version || value.candidate_recipe_sha256 !== body.candidate_recipe_sha256))) throw new Error('Evaluation scope differs from the frozen request.'); }
      setId(value.id); setPending(null); setCurrent(value); say('Evaluation operation recorded. Read its current summary before another action; no policy was activated.');
    } catch { say('Evaluation outcome unconfirmed. Retry only the unchanged request, or explicitly exit and investigate the original recorded job before another intent.'); }
  }
  async function write(kind: Intent['kind']) {
    if (pending) return;
    if (kind === 'create') {
      if (!reviewer || !context || !inputReview.valid || !ack || (context.frozen > 0 && !frozenAck) || (context.runner === 'vision_replay_v1' && !visionAck)) return;
      const { name: _name, count: _count, frozen: _frozen, ...scope } = context;
      return send({ kind, path: '/evaluations', key: crypto.randomUUID(), body: { ...scope, historical_diagnostic_acknowledged: true, frozen_holdout_acknowledged: frozenAck,
        ...(context.runner === 'vision_replay_v1' ? { vision_measurement_acknowledged: true } : {}) } });
    }
    if (!current || !resultReview.valid || (kind === 'advance' && (!reviewer || !current.can_advance)) || (kind === 'cancel' && !current.can_cancel)
      || (kind === 'retire' && (!current.can_retire || !retireAck || !identifier.test(reason)))) return;
    return send({ kind, id: current.id, path: kind === 'retire' ? '/evaluations/' + current.id + '/retire' : '/jobs/' + current.id + '/' + kind,
      version: current.state_version, key: crypto.randomUUID(), body: kind === 'retire' ? { acknowledged: true, reason } : {} });
  }
  async function requestRead() {
    if (!current) return; const target = current.id; clearInputs(); clearResult(); await fresh(user, 'reviewer');
    const value = await call<RequestBody>('/evaluations/' + target + '/request');
    if (!value || !['decision_replay_v1','vision_replay_v1'].includes(value.runner) || !uuid.test(value.policy_id) || !positive(value.policy_revision) || !positive(value.policy_state_version)
      || !sha.test(value.policy_revision_sha256) || !uuid.test(value.manifest_id) || !sha.test(value.manifest_sha256) || value.historical_diagnostic_acknowledged !== true
      || typeof value.frozen_holdout_acknowledged !== 'boolean' || (value.rollback_target !== undefined && !validRollbackTarget(value.rollback_target)) || (value.runner === 'vision_replay_v1' && (!recipeBinding(value) || value.vision_measurement_acknowledged !== true))) throw new Error('Recorded evaluation request is unavailable.');
    setRollback(!!value.rollback_target); setPolicyRevision(value.rollback_target ? String(value.policy_revision) : ''); setActiveVersion(value.rollback_target ? String(value.rollback_target.active_version) : ''); setActivationId(value.rollback_target?.activation_id ?? ''); setPredecessorId(value.rollback_target?.predecessor_activation_id ?? '');
    setMode(value.runner); setRecipeId(value.candidate_recipe_id ?? ''); setPolicyId(value.policy_id); setManifestId(value.manifest_id); say('Original request IDs read; any unconfirmed write remains unresolved. Read current inputs and review afresh before a separate new evaluation.');
  }
  async function page(start = 0) {
    if (!current || !resultReview.valid || !current.result_header_current) return;
    const target = current; setExamples([]); setNext(null); const token = resultReview.token(), started = performance.now(); await fresh(user, 'reviewer');
    const value = await call<{ id: string; report_sha256: string; diagnostic_only: boolean; promotion_eligible: boolean; examples: Example[]; next_index: number | null }>('/evaluations/' + target.id + '/examples?start=' + start);
    if (!value || value.id !== target.id || value.report_sha256 !== target.report_sha256 || value.diagnostic_only !== true || value.promotion_eligible !== false
      || !Array.isArray(value.examples) || value.examples.length !== Math.min(20, target.example_count - start)
      || value.examples.some((e, i) => e.index !== start + i || !uuid.test(e.label_id) || !positive(e.label_revision) || !sha.test(e.content_sha256)
        || e.policy_revision_sha256 !== target.policy_revision_sha256 || !['DEVELOPMENT', 'VALIDATION', 'FROZEN_TEST'].includes(e.split) || !['physical', 'synthetic','printable'].includes(e.data_origin)
        || !flags(e) || !side(e.baseline) || !side(e.candidate) || (target.runner === 'vision_replay_v1' && !measured(e, target))) || value.next_index !== (start + value.examples.length === target.example_count ? null : start + value.examples.length))
      throw new Error('Evaluation page is incomplete or does not match this report.');
    resultReview.bound(started, Math.floor(resultExpires.current - started), 60000, token); setExamples(value.examples); setNext(value.next_index);
    say('Historical example delivery was audited. Admission does not prove delivery, prior exposure or independent physical truth.');
  }
  const vision = current?.runner === 'vision_replay_v1' || mode === 'vision_replay_v1';
  return <section aria-labelledby="evaluation-title"><h3 id="evaluation-title">{vision ? 'Original-image comparisons' : 'Historical decision comparisons'}</h3><p role="status">{message}</p>
    <p>{vision ? 'Measure the same permitted original images under the recorded and candidate recipes using their original capture geometry. Counts are compared only with declared review labels; unknown frames remain unknown. This is not independent physical or dimension-truth qualification, packing-speed measurement or activation.' : 'Compare action choices on recorded reasons. An observed match retains only the declared historical outcome. A different action has an unknown counterfactual outcome. Review duration is not operator effort. No vision reprocessing, physical qualification, packing-speed measurement or activation occurs.'}</p>
    {reviewer && <fieldset disabled={busy || !!pending}><legend>Review exact comparison inputs</legend>
      <label htmlFor="evaluation-method">Comparison method</label><select id="evaluation-method" value={mode} onChange={e => { setMode(e.target.value as Runner); clearInputs(); clearResult(); }}><option value="decision_replay_v1">Recorded action choices</option><option value="vision_replay_v1">Original-image measurements</option></select>
      <label>Evaluation candidate ID<input maxLength={36} value={policyId} onChange={e => { setPolicyId(e.target.value.trim()); clearInputs(); }}/></label>
      <label>Evaluation dataset ID<input maxLength={36} value={manifestId} onChange={e => { setManifestId(e.target.value.trim()); clearInputs(); }}/></label>
      <label><input type="checkbox" checked={rollback} onChange={e => { setRollback(e.target.checked); clearInputs(); }}/>Compare the exact predecessor from an owner rollback handoff</label>
      {rollback && <><p>Use the owner handoff for this exact active head. Only original-image comparisons can feed qualification preparation; recorded action choices remain diagnostic.</p>
        <label>Evaluation predecessor revision<input value={policyRevision} onChange={e => { setPolicyRevision(e.target.value); clearInputs(); }}/></label><label>Evaluation rollback active version<input value={activeVersion} onChange={e => { setActiveVersion(e.target.value); clearInputs(); }}/></label>
        <label>Evaluation current activation ID<input value={activationId} onChange={e => { setActivationId(e.target.value.trim()); clearInputs(); }}/></label><label>Evaluation predecessor activation ID<input value={predecessorId} onChange={e => { setPredecessorId(e.target.value.trim()); clearInputs(); }}/></label></>}
      {mode === 'vision_replay_v1' && <label>Candidate recipe ID for image comparison<input maxLength={36} value={recipeId} onChange={e => { setRecipeId(e.target.value.trim()); clearInputs(); }}/></label>}
      <button disabled={!uuid.test(policyId) || !uuid.test(manifestId) || (mode === 'vision_replay_v1' && !uuid.test(recipeId))} onClick={() => void perform(inputs)}>Read comparison inputs</button>
      {context && inputReview.valid && <><p>{context.name}; policy revision {context.policy_revision}; revision hash {context.policy_revision_sha256}. Dataset hash {context.manifest_sha256}; examples {context.count}; frozen examples {context.frozen}.</p>
        {context.rollback_target && <p>Exact rollback purpose: active version {context.rollback_target.active_version}; activation {context.rollback_target.activation_id}; predecessor {context.rollback_target.predecessor_activation_id}. No live policy changes during this comparison.</p>}
        <label><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)}/>I reviewed these exact inputs for historical diagnostics only.</label>
        {context.runner === 'vision_replay_v1' && <><p>Candidate recipe {context.candidate_recipe_id}; revision {context.candidate_recipe_revision}; hash {context.candidate_recipe_sha256}. Both sides use the exact original geometry and equal measurement limits.</p>
          <label><input type="checkbox" checked={visionAck} onChange={e => setVisionAck(e.target.checked)}/>I separately authorize fresh measurement of the permitted originals. Declared counts are not independent physical truth and completion cannot activate changes.</label></>}
        {context.frozen > 0 && <label><input type="checkbox" checked={frozenAck} onChange={e => setFrozenAck(e.target.checked)}/>Frozen data access is recorded and does not establish untouched or independent qualification.</label>}</>}
      <button disabled={!inputReview.valid || !context || !ack || (context.frozen > 0 && !frozenAck) || (context.runner === 'vision_replay_v1' && !visionAck)} onClick={() => void perform(() => write('create'))}>{mode === 'vision_replay_v1' ? 'Create original-image comparison' : 'Create historical comparison'}</button>
    </fieldset>}
    <div className="toolbar"><button disabled={busy} onClick={() => void perform(() => list())}>Find recorded evaluations</button>{cursor && <button disabled={busy} onClick={() => void perform(() => list(true))}>Next evaluation catalog page</button>}</div>
    {catalog.map(item => <p key={item.id}><button disabled={busy} onClick={() => void perform(() => read(item.id))}>Open comparison {item.candidate_name} {item.id}</button> · {item.status} · historical metadata</p>)}
    <label>Evaluation ID<input disabled={busy} maxLength={36} value={id} onChange={e => { setId(e.target.value.trim()); clearResult(); clearInputs(); }}/></label>
    <button disabled={busy || !uuid.test(id)} onClick={() => void perform(() => read())}>Read evaluation summary</button>
    {current && <><p>Evaluation {current.id}: {current.status}; {current.prepared_count} of {current.example_count} prepared; {current.steps_reserved} attempts reserved. {current.failure_reason || ''}</p>
      {!resultReview.valid && <p>Read the current summary before relying on counts or taking another action.</p>}
      {resultReview.valid && current.result_header_current && current.counts && <><p>Historical diagnostic counts only. Promotion eligible: no. Independent benchmark qualified: no.</p><table><caption>All completed examples, including unknowns</caption><thead><tr><th>Category</th><th>Baseline</th><th>Candidate</th></tr></thead><tbody>{[...categories, 'declared_resolved', 'declared_unresolved'].map(key => <tr key={key}><th scope="row">{key}</th><td>{current.counts!.baseline[key]}</td><td>{current.counts!.candidate[key]}</td></tr>)}</tbody></table></>}
      {resultReview.valid && current.result_header_current && current.runner === 'vision_replay_v1' && current.counts && <table><caption>Pixel measurements against declared counts; unknown frames remain unknown</caption><thead><tr><th>Measure</th><th>Baseline</th><th>Candidate</th></tr></thead><tbody>{['measurements','observable_frames','count_matches','count_mismatches','unobservable_frames'].map(k => <tr key={k}><th scope="row">{k}</th><td>{current.counts!.baseline[k]}</td><td>{current.counts!.candidate[k]}</td></tr>)}</tbody></table>}
      {resultReview.valid && !current.result_header_current && <p>No current complete comparison result. Preserve unresolved work and original budgets.</p>}
      {reviewer && onPrepare && current.runner === 'vision_replay_v1' && current.can_read_request !== false && <button disabled={busy || !resultReview.valid || !current.result_header_current || current.pixel_measurement_performed !== true} onClick={() => onPrepare(current.id)}>Review preparation for this image comparison</button>}
      <div className="toolbar">{reviewer && <><button disabled={busy || !!pending || !resultReview.valid || !current.can_advance} onClick={() => void perform(() => write('advance'))}>Advance one comparison step</button><button disabled={busy || !resultReview.valid || current.can_read_request === false} onClick={() => void perform(requestRead)}>Read original comparison request</button></>}
        {current.can_cancel && <button disabled={busy || !!pending || !resultReview.valid} onClick={() => void perform(() => write('cancel'))}>Cancel unfinished comparison</button>}
        {reviewer && current.result_header_current && <button disabled={busy || !resultReview.valid} onClick={() => void perform(() => page())}>Read comparison examples</button>}</div>
      {current.can_retire && <fieldset disabled={busy || !!pending || !resultReview.valid}><legend>Retire completed comparison</legend><label>Comparison retirement reason code<input maxLength={64} value={reason} onChange={e => { setReason(e.target.value); setRetireAck(false); }}/></label><p>Use 1–64 letters, digits, underscores or hyphens, starting with a letter or digit.</p>
        <label><input type="checkbox" checked={retireAck} onChange={e => setRetireAck(e.target.checked)}/>Retirement preserves history, advances DATA and invalidates dependent current use.</label><button disabled={!retireAck || !identifier.test(reason)} onClick={() => void perform(() => write('retire'))}>Retire comparison</button></fieldset>}
    </>}
    {resultReview.valid && examples.map(item => <p key={item.index}>Example {item.index + 1}; {item.split}; {item.data_origin}. Baseline: {item.baseline.action || 'none'}, {item.baseline.classification}; candidate: {item.candidate.action || 'none'}, {item.candidate.classification}. Declared resolution: {item.candidate.declared_resolved === null ? 'unknown' : String(item.candidate.declared_resolved)}. Content hash {item.content_sha256}.</p>)}
    {resultReview.valid && examples.filter(e => e.runner === 'vision_replay_v1').map(e => <div key={'pixels-' + e.index}><p>Example {e.index + 1}: {e.measurement_count} fresh measurements; exact geometry hash {e.calibration_sha256}. Physical truth and dimension-truth accuracy remain unverified.</p>
      {(['baseline','candidate'] as const).map(s => <ul key={s}>{e[s].measurements!.map(m => <li key={m.observation_id}>{s}: {m.findings.join(', ')}; counts {JSON.stringify(m.class_counts)}; declared counts {JSON.stringify(m.declared_truth_counts)}; count agreement {m.counts_match_declared_truth === null ? 'unknown' : String(m.counts_match_declared_truth)}. Original {m.original_asset_id}; source hash {m.source_sha256}.</li>)}</ul>)}</div>)}
    {resultReview.valid && next !== null && <button disabled={busy} onClick={() => void perform(() => page(next))}>Next comparison example page</button>}
    {pending && <><button disabled={busy} onClick={() => void perform(() => send(pending))}>Retry unchanged evaluation request</button><label><input type="checkbox" checked={exitAck} onChange={e => setExitAck(e.target.checked)}/>I understand the server outcome stays unresolved and may already exist; exiting only forgets local retry details.</label>
      <button disabled={busy || !exitAck} onClick={() => { setPending(null); clearInputs(); clearResult(); setPolicyId(''); setManifestId(''); say('Local retry details forgotten. Investigate the original recorded evaluation before a separate new intent; no server work was undone.'); }}>Finish without another evaluation write</button></>}
  </section>;
}
