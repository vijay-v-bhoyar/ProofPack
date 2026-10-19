import { useRef, useState } from 'react';
import type { User } from './api';
import { useUnconfirmed, identifier, positive, sha, uuid, useReviewDeadline, useTasks } from './workbench';

type Flags = { qualification_eligible: false; promotion_eligible: false; physical_truth_verified: false; independent_benchmark_qualified: false };
type RequestBody = { policy_id: string; source_evaluation_id: string; source_evaluation_state_version: number; source_report_sha256: string; preparation_only_acknowledged: true };
type Options = Flags & { software_cases: number; max_source_examples: number; max_steps: number; lifetime_ms: number; lease_ms: number; page_size: number; image_evaluation_required: boolean; preparation_only: boolean; registry_sha256: string; implementation_sha256: string };
type Catalog = Flags & { id: string; kind: string; state_version: number; status: string; policy_id: string; source_evaluation_id: string; source_report_sha256: string; planned_count: number; prepared_count: number; steps_reserved: number; qualification_status: string };
type Job = Catalog & { software_cases: number; source_examples: number; remaining_ms: number; lease_remaining_ms: number; source_current: boolean; report_current: boolean; report_sha256: string | null; counts: { software_pass: number; software_fail: number; source_entries_verified: number } | null; can_advance: boolean; failure_reason: string | null; blocking_reasons: string[] };
type Context = { body: RequestBody; options: Options; sourceExamples: number };
type Intent = { kind: 'create' | 'advance' | 'cancel' | 'retire'; path: string; key: string; body: RequestBody | Record<string, unknown>; id?: string; version?: number };
type Entry = { phase: string; case?: { id: string }; passed?: boolean; source_index?: number; source_entry_sha256?: string; source_report_sha256?: string; physical_truth_verified?: boolean; new_pixel_measurement?: boolean };
const base = '/qualification-preparations';
const integer = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) >= 0;
const flags = (v: Flags) => v && v.qualification_eligible === false && v.promotion_eligible === false && v.physical_truth_verified === false && v.independent_benchmark_qualified === false;
const statuses = ['queued', 'processing', 'completed', 'failed', 'cancelled', 'retired'];
function metadata(v: Catalog): Catalog {
  if (!v || !uuid.test(v.id) || v.kind !== 'policy_qualification_preparation' || !positive(v.state_version) || !statuses.includes(v.status)
    || !uuid.test(v.policy_id) || !uuid.test(v.source_evaluation_id) || !sha.test(v.source_report_sha256) || !positive(v.planned_count) || v.planned_count > 1256
    || !integer(v.prepared_count) || v.prepared_count > v.planned_count || !integer(v.steps_reserved) || v.steps_reserved > 10000
    || v.steps_reserved < v.prepared_count || v.qualification_status !== 'not_qualified' || !flags(v)) throw new Error('Preparation metadata is unavailable or claims unsupported qualification.');
  return v;
}
function checked(v: Job): Job {
  metadata(v);
  if (!positive(v.software_cases) || v.software_cases > 256 || !positive(v.source_examples) || v.source_examples > 1000 || v.software_cases + v.source_examples !== v.planned_count
    || !integer(v.remaining_ms) || v.remaining_ms > 3600000 || !integer(v.lease_remaining_ms) || v.lease_remaining_ms > 60000
    || [v.source_current, v.report_current, v.can_advance].some(x => typeof x !== 'boolean') || (v.report_sha256 !== null && !sha.test(v.report_sha256))
    || !Array.isArray(v.blocking_reasons) || v.blocking_reasons.length > 20 || v.blocking_reasons.some(x => typeof x !== 'string' || x.length > 128)
    || (v.report_current ? v.status !== 'completed' || !v.source_current || !v.remaining_ms || !v.report_sha256 || v.prepared_count !== v.planned_count
      || !v.counts || !integer(v.counts.software_pass) || !integer(v.counts.software_fail) || v.counts.software_pass + v.counts.software_fail !== v.software_cases
      || v.counts.source_entries_verified !== v.source_examples : v.counts !== null)) throw new Error('Preparation summary is incomplete or its counts do not reconcile.');
  return v;
}

export function PreparationPanel({ user, seedEvaluation = '', onQualify }: { user: User; seedEvaluation?: string; onQualify?: (id: string) => void }) {
  const reviewer = user.roles.includes('reviewer'), owner = user.roles.includes('owner');
  const { busy, message, call, perform, fresh, say } = useTasks('Preparation checks software contracts and prior report integrity. It never qualifies or activates a policy.');
  const inputs = useReviewDeadline(), results = useReviewDeadline(), expires = useRef(0);
  const [source, setSource] = useState(seedEvaluation), [context, setContext] = useState<Context | null>(null), [ack, setAck] = useState(false);
  const [id, setId] = useState(''), [job, setJob] = useState<Job | null>(null), [catalog, setCatalog] = useState<Catalog[]>([]), [cursor, setCursor] = useState<string | null>(null);
  const [ownerView, setOwnerView] = useState(!reviewer), [pending, setPending] = useState<Intent | null>(null), [exitAck, setExitAck] = useState(false);
  const [entries, setEntries] = useState<Entry[]>([]), [next, setNext] = useState<number | null>(null), [reason, setReason] = useState(''), [retireAck, setRetireAck] = useState(false);
  useUnconfirmed(!!pending);
  function clearInputs() { inputs.clear(); setContext(null); setAck(false); }
  function clearResult() { results.clear(); expires.current = 0; setJob(null); setEntries([]); setNext(null); setReason(''); setRetireAck(false); }
  async function review() {
    clearInputs(); clearResult(); const token = inputs.token(), started = performance.now(); await fresh(user, 'reviewer');
    const options = await call<Options>(base + '/options');
    if (!flags(options) || !positive(options.software_cases) || options.software_cases > 256 || !positive(options.max_source_examples) || options.max_source_examples > 1000
      || !positive(options.max_steps) || options.max_steps > 10000 || options.max_steps < options.software_cases + 1 || !positive(options.lifetime_ms) || options.lifetime_ms > 3600000
      || !positive(options.lease_ms) || options.lease_ms > 60000 || options.page_size !== 20 || options.image_evaluation_required !== true || options.preparation_only !== true
      || !sha.test(options.registry_sha256) || !sha.test(options.implementation_sha256)) throw new Error('Installed preparation bounds are unavailable.');
    const value = await call<{ id: string; policy_id: string; state_version: number; runner: string; status: string; result_header_current: boolean; remaining_ms: number; report_sha256: string; example_count: number; promotion_eligible: boolean; independent_benchmark_qualified: boolean; physical_truth_verified: boolean; pixel_measurement_performed: boolean }>('/evaluations/' + source);
    if (!value || value.id !== source || !uuid.test(value.policy_id) || !positive(value.state_version) || value.runner !== 'vision_replay_v1' || value.status !== 'completed'
      || value.result_header_current !== true || !sha.test(value.report_sha256) || !positive(value.remaining_ms) || value.remaining_ms > 3600000 || !positive(value.example_count)
      || value.example_count > options.max_source_examples || value.example_count + options.software_cases > options.max_steps || value.promotion_eligible !== false
      || value.independent_benchmark_qualified !== false || value.physical_truth_verified !== false || value.pixel_measurement_performed !== true) throw new Error('Read a complete current original-image comparison within the installed preparation budget.');
    inputs.bound(started, Math.min(value.remaining_ms, options.lifetime_ms, 60000), 60000, token);
    setContext({ body: { policy_id: value.policy_id, source_evaluation_id: value.id, source_evaluation_state_version: value.state_version, source_report_sha256: value.report_sha256, preparation_only_acknowledged: true }, options, sourceExamples: value.example_count });
    say('Exact source and installed bounds read. Review and acknowledge preparation-only scope before submitting.');
  }
  async function read(target = id) {
    clearInputs(); clearResult(); const token = results.token(), started = performance.now(); await fresh(user);
    const value = checked(await call<Job>(base + '/' + target));
    if (value.id !== target) throw new Error('Preparation target changed.');
    const window = Math.min(value.remaining_ms || 60000, 60000); results.bound(started, window, 60000, token); expires.current = started + window;
    setJob(value); setId(value.id); say(value.report_current ? 'Complete preparation read. Independent qualification is still required; no policy was activated.' : 'Control status read. No current complete preparation report is available.');
  }
  async function list(nextPage = false) {
    clearInputs(); clearResult(); setCatalog([]); const mode = ownerView ? 'owner' : 'own'; await fresh(user, ownerView ? 'owner' : 'reviewer');
    const value = await call<{ preparations: (Catalog & { source_current: null; report_current: null; currency_not_checked: true })[]; scope: string; next_cursor: string | null }>(base + '?limit=20&scope=' + mode + (nextPage && cursor ? '&cursor=' + cursor : ''));
    if (!value || value.scope !== mode || !Array.isArray(value.preparations) || value.preparations.length > 20 || (value.next_cursor !== null && !uuid.test(value.next_cursor))
      || value.preparations.some(x => x.source_current !== null || x.report_current !== null || x.currency_not_checked !== true)) throw new Error('Preparation catalog is unavailable.');
    setCatalog(value.preparations.map(metadata)); setCursor(value.next_cursor); say('Historical metadata loaded. Open a record for current status; discovery does not resolve an uncertain write.');
  }
  async function send(intent: Intent) {
    setPending(intent); setExitAck(false); clearInputs(); clearResult();
    try {
      const live = await fresh(user, ['create', 'advance'].includes(intent.kind) ? 'reviewer' : undefined);
      const value = checked(await call<Job>(intent.path, { user: live, method: 'POST', body: intent.body, version: intent.version, idempotencyKey: intent.key }));
      if (intent.id && value.id !== intent.id) throw new Error('Preparation write target changed.');
      if (intent.kind === 'create') { const body = intent.body as RequestBody;
        if (value.policy_id !== body.policy_id || value.source_evaluation_id !== body.source_evaluation_id || value.source_report_sha256 !== body.source_report_sha256) throw new Error('Preparation differs from the frozen source request.'); }
      setId(value.id); setPending(null); setJob(value); say('Preparation operation recorded. Read current status before another action. No qualification or activation occurred.');
    } catch { say('Preparation outcome unconfirmed. Retry only the unchanged request, or explicitly exit and investigate the original job.'); }
  }
  async function write(kind: Intent['kind']) {
    if (pending) return;
    if (kind === 'create') { if (reviewer && context && inputs.valid && ack) await send({ kind, path: base, key: crypto.randomUUID(), body: context.body }); return; }
    if (!job || !results.valid || (kind === 'advance' && (!reviewer || !job.can_advance))
      || (kind === 'cancel' && !['queued', 'processing', 'failed'].includes(job.status)) || (kind === 'retire' && (job.status !== 'completed' || !retireAck || !identifier.test(reason)))) return;
    await send({ kind, id: job.id, path: kind === 'retire' ? base + '/' + job.id + '/retire' : '/jobs/' + job.id + '/' + kind,
      key: crypto.randomUUID(), version: job.state_version, body: kind === 'retire' ? { acknowledged: true, reason } : {} });
  }
  async function requestRead() {
    if (!job) return; const target = job.id; clearInputs(); clearResult(); await fresh(user, 'reviewer');
    const value = await call<RequestBody>(base + '/' + target + '/request');
    if (!value || !uuid.test(value.policy_id) || !uuid.test(value.source_evaluation_id) || !positive(value.source_evaluation_state_version) || !sha.test(value.source_report_sha256) || value.preparation_only_acknowledged !== true) throw new Error('Original preparation request is unavailable.');
    setSource(value.source_evaluation_id); say('Original source ID recovered. Any uncertain write remains unresolved; review current source before a new intent.');
  }
  async function page(start = 0) {
    if (!job || !results.valid || !job.report_current || !reviewer) return;
    try {
    const target = job, token = results.token(), deadline = expires.current; setEntries([]); setNext(null); await fresh(user, 'reviewer');
    const value = await call<Flags & { id: string; entries: Entry[]; next_index: number | null }>(base + '/' + target.id + '/entries?start=' + start + '&limit=20');
    const end = Math.min(start + 20, target.planned_count);
    if (!value || value.id !== target.id || !flags(value) || !Array.isArray(value.entries) || value.entries.length !== end - start || value.next_index !== (end === target.planned_count ? null : end)
      || value.entries.some((e, i) => JSON.stringify(e).length > 8192 || (start + i < target.software_cases
        ? e.phase !== 'software_contract' || !e.case || typeof e.case.id !== 'string' || e.case.id.length > 128 || typeof e.passed !== 'boolean'
        : e.phase !== 'source_evaluation_integrity' || e.source_index !== start + i - target.software_cases || !sha.test(e.source_entry_sha256 ?? '') || e.source_report_sha256 !== target.source_report_sha256 || e.physical_truth_verified !== false || e.new_pixel_measurement !== false))) throw new Error('Preparation page does not match its complete report.');
    const now = performance.now(); results.bound(now, Math.floor(deadline - now), 60000, token); setEntries(value.entries); setNext(value.next_index);
    } catch (error) { clearResult(); throw error; }
  }
  return <section aria-labelledby="preparation-title"><h3 id="preparation-title">Qualification preparation</h3><p role="status">{message}</p>
    <p>Software preparation is not physical qualification, independent benchmarking, promotion or activation. Existing live policy is unchanged. Automatic progress requires enabled same-host maintenance; otherwise advance manually and refresh.</p>
    {reviewer && <fieldset disabled={busy || !!pending}><legend>Prepare from a completed image comparison</legend>
      <label>Source evaluation ID<input maxLength={36} value={source} onChange={e => { setSource(e.target.value.trim()); clearInputs(); clearResult(); }}/></label>
      <button disabled={!uuid.test(source)} onClick={() => void perform(review)}>Review preparation inputs</button>
      {context && inputs.valid && <><p>Candidate {context.body.policy_id}; source report {context.body.source_report_sha256}. {context.options.software_cases} software cases plus {context.sourceExamples} source entries. Maximum original lifetime {context.options.lifetime_ms / 1000} seconds, limited further by original source and session.</p>
        <label><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)}/>I understand preparation does not qualify or activate the policy.</label>
        <button disabled={!ack} onClick={() => void perform(() => write('create'))}>Create qualification preparation</button></>}
    </fieldset>}
    {owner && reviewer && <label><input type="checkbox" disabled={busy || !!pending} checked={ownerView} onChange={e => { setOwnerView(e.target.checked); setCatalog([]); setCursor(null); clearInputs(); clearResult(); }}/>Use owner metadata catalog with recent MFA</label>}
    <div className="toolbar"><button disabled={busy} onClick={() => void perform(() => list())}>Find recorded preparations</button>{cursor && <button disabled={busy} onClick={() => void perform(() => list(true))}>Next preparation catalog page</button>}</div>
    {catalog.map(item => <p key={item.id}><button disabled={busy} onClick={() => void perform(() => read(item.id))}>Open preparation {item.id}</button> · {item.status}; historical metadata, currency unchecked.</p>)}
    <label>Preparation ID<input disabled={busy} maxLength={36} value={id} onChange={e => { setId(e.target.value.trim()); clearInputs(); clearResult(); }}/></label><button disabled={busy || !uuid.test(id)} onClick={() => void perform(() => read())}>Read preparation summary</button>
    {job && <><p>Preparation {job.id}: {job.status}; {job.prepared_count} of {job.planned_count} prepared; {job.steps_reserved} attempts reserved. {job.failure_reason || ''}</p>
      {reviewer && onQualify && <button disabled={busy || !results.valid || !job.report_current || !job.source_current} onClick={() => onQualify(job.id)}>Review synthetic qualification for this preparation</button>}
      {!results.valid && <p>Refresh the current summary before relying on counts or taking another action.</p>}
      {results.valid && <><p>Remaining original lifetime: {Math.ceil(job.remaining_ms / 1000)} seconds at read. Source current: {String(job.source_current)}. Qualification: not qualified.</p>
        {job.report_current && job.counts ? <p>Software passed: {job.counts.software_pass}; software failed: {job.counts.software_fail}; source entries verified: {job.counts.source_entries_verified}. Independent qualification evidence is still required.</p> : <p>No current complete preparation report. Preserve unresolved work and original budgets.</p>}
        <p>Blocking reasons: {job.blocking_reasons.join(', ')}</p>
        <div className="toolbar">{reviewer && <><button disabled={busy || !!pending || !job.can_advance} onClick={() => void perform(() => write('advance'))}>Advance one preparation step</button><button disabled={busy} onClick={() => void perform(requestRead)}>Read original preparation request</button>{job.report_current && <button disabled={busy} onClick={() => void perform(() => page())}>Read preparation entries</button>}</>}
          {['queued', 'processing', 'failed'].includes(job.status) && <button disabled={busy || !!pending} onClick={() => void perform(() => write('cancel'))}>Cancel unfinished preparation</button>}</div>
        {job.status === 'completed' && <fieldset disabled={busy || !!pending}><legend>Retire completed preparation</legend><label>Preparation retirement reason code<input maxLength={64} value={reason} onChange={e => { setReason(e.target.value); setRetireAck(false); }}/></label>
          <p>Use 1–64 letters, digits, underscores or hyphens, starting with a letter or digit.</p><label><input type="checkbox" checked={retireAck} onChange={e => setRetireAck(e.target.checked)}/>Retirement preserves history, advances DATA and invalidates dependent use.</label><button disabled={!retireAck || !identifier.test(reason)} onClick={() => void perform(() => write('retire'))}>Retire preparation</button></fieldset>}
      </>}
    </>}
    {results.valid && entries.map((e, i) => <p key={i}>{e.phase === 'software_contract' ? `Software case ${e.case!.id}: ${e.passed ? 'passed' : 'failed'}` : `Source entry ${e.source_index! + 1}: prior report integrity verified; no new pixels or physical truth measured. Hash ${e.source_entry_sha256}`}</p>)}
    {results.valid && next !== null && <button disabled={busy} onClick={() => void perform(() => page(next))}>Next preparation entry page</button>}
    {pending && <><button disabled={busy} onClick={() => void perform(() => send(pending))}>Retry unchanged preparation request</button><label><input type="checkbox" checked={exitAck} onChange={e => setExitAck(e.target.checked)}/>The server outcome remains unresolved and may already exist; exiting forgets only local retry details.</label><button disabled={busy || !exitAck} onClick={() => { setPending(null); clearInputs(); clearResult(); setSource(''); say('Local retry details forgotten. Investigate the original job before another intent; no server work was undone.'); }}>Finish without another preparation write</button></>}
  </section>;
}
