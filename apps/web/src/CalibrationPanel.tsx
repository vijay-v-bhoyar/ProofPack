import { useRef, useState } from 'react';
import type { User } from './api';
import { identifier, positive, sha, useReviewDeadline, useTasks, uuid } from './workbench';

type Settings = { max_displacement_px: number; max_reprojection_error_px: number; measurement_error_mm: number; min_area_px: number; min_blur_variance: number; threshold_gray: number };
type Enrollment = { name: string; camera_id: string; mat_version: string; reference_asset_id: string; data_origin: string; settings: Settings };
type Draft = { id: string; name: string; latest_revision: number; state_version: number; status: string; retired: boolean; report_id: string | null; last_job_id: string;
  request: Enrollment; profile_sha256: string | null; profile: { frame_width: number; frame_height: number; output_width: number; output_height: number } | null;
  enrollment: { accepted: boolean; reason_codes: string[]; physical_truth_verified: boolean }; current: { effective_approved: boolean; active_revision: number | null } };
type Job = { id: string; calibration_id: string; status: string; kind: string; report_id?: string | null; reason?: string | null };
type Report = { id: string; calibration_id: string; revision: number; state_version: number; profile_sha256: string; passed: boolean; eligible_for_approval: boolean;
  requires_physical_assurance: boolean; physical_truth_verified: boolean; independence_verified: boolean; remaining_validity_ms: number;
  results: { asset_id: string; expected: string; matched: boolean; diagnostic: { accepted: boolean; reason_codes: string[]; blur_variance: number | null; max_reprojection_error_px: number | null } }[] };
type Action = { kind: 'enroll' | 'qualify' | 'approve' | 'retire'; path: string; method: string; body: object; version?: number };
const labels: Record<keyof Settings, string> = { max_displacement_px: 'Maximum marker movement in pixels', max_reprojection_error_px: 'Maximum planar residual in pixels',
  measurement_error_mm: 'Chosen uncertainty bound in millimetres', min_area_px: 'Minimum region area in pixels', min_blur_variance: 'Minimum focus variance', threshold_gray: 'Foreground gray threshold' };
const blank = (): Record<keyof Settings, string> => ({ max_displacement_px: '', max_reprojection_error_px: '', measurement_error_mm: '', min_area_px: '', min_blur_variance: '', threshold_gray: '' });
function settingsValue(value: Record<keyof Settings, string>): Settings | null {
  if (Object.values(value).some(text => !text.trim() || !Number.isFinite(Number(text)))) return null;
  const result = Object.fromEntries(Object.entries(value).map(([key, text]) => [key, Number(text)])) as Settings;
  return result.max_displacement_px > 0 && result.max_displacement_px <= 20 && result.max_reprojection_error_px > 0 && result.max_reprojection_error_px <= 5
    && result.measurement_error_mm >= 0 && result.min_area_px > 0 && result.min_blur_variance >= 0 && Number.isInteger(result.threshold_gray)
    && result.threshold_gray >= 1 && result.threshold_gray <= 254 ? result : null;
}
export function CalibrationPanel({ user, seedReference }: { user: User; seedReference: string }) {
  const owner = user.roles.includes('owner'), { busy, message, call, perform, say, fresh } = useTasks('Enroll a versioned camera setup, then test both supported and rejected scenes. No diagnostic is a live kit pass.');
  const [catalog, setCatalog] = useState<{ id: string; name: string }[]>([]), [cursor, setCursor] = useState<string | null>(null), [selected, setSelected] = useState('');
  const [draft, setDraft] = useState<Draft | null>(null), [name, setName] = useState(''), [camera, setCamera] = useState(''), [referenceId, setReferenceId] = useState(seedReference);
  const [source, setSource] = useState<{ id: string; data_origin: string; sha256: string } | null>(null), [settings, setSettings] = useState(blank), [dirty, setDirty] = useState(false);
  const [cases, setCases] = useState([{ asset_id: '', expected: 'supported' }, { asset_id: '', expected: 'rejected' }]), [caseAck, setCaseAck] = useState(false);
  const [job, setJob] = useState<Job | null>(null), [report, setReport] = useState<Report | null>(null), [approveAck, setApproveAck] = useState(false), [reason, setReason] = useState('');
  const [uncertain, setUncertain] = useState(false), [discardAck, setDiscardAck] = useState(false); const pending = useRef<Action | null>(null); const expiry = useReviewDeadline();
  const running = !!job && ['processing', 'expired'].includes(job.status), frozen = busy || uncertain;
  const clearReview = () => { setReport(null); setApproveAck(false); expiry.clear(); };
  const edit = () => { setDirty(true); clearReview(); };
  async function list(more = false) {
    await fresh(user, owner ? 'owner' : 'reviewer');
    const result = await call<{ calibrations: { id: string; name: string }[]; next_cursor: string | null }>('/calibrations?view=candidates&limit=20' + (more && cursor ? '&cursor=' + encodeURIComponent(cursor) : ''));
    if (!Array.isArray(result.calibrations) || result.calibrations.some(item => !uuid.test(item.id) || typeof item.name !== 'string')) throw new Error('Calibration catalog is unavailable.');
    setCatalog(old => more ? [...old.filter(item => !result.calibrations.some(next => next.id === item.id)), ...result.calibrations] : result.calibrations); setCursor(result.next_cursor);
  }
  function adopt(value: Draft) {
    if (!value || !uuid.test(value.id) || !positive(value.state_version) || !positive(value.latest_revision) || !value.request
      || !settingsValue(Object.fromEntries(Object.entries(value.request.settings).map(([key, number]) => [key, String(number)])) as Record<keyof Settings, string>)
      || typeof value.enrollment?.accepted !== 'boolean' || value.enrollment.physical_truth_verified !== false || typeof value.current?.effective_approved !== 'boolean'
      || !Array.isArray(value.enrollment.reason_codes) || value.enrollment.reason_codes.some(code => typeof code !== 'string')
      || (value.enrollment.accepted && (!value.profile || !sha.test(value.profile_sha256 ?? '')))
      || (value.current.effective_approved && !positive(value.current.active_revision))) throw new Error('Calibration draft information is unavailable.');
    clearReview(); setDraft(value); setSelected(value.id); setName(value.request.name); setCamera(value.request.camera_id); setReferenceId(value.request.reference_asset_id);
    setSource(null); setSettings(Object.fromEntries(Object.entries(value.request.settings).map(([key, number]) => [key, String(number)])) as Record<keyof Settings, string>);
    setDirty(false); setCases([{ asset_id: value.request.reference_asset_id, expected: 'supported' }, { asset_id: '', expected: 'rejected' }]); setCaseAck(false);
  }
  async function load(id = selected) {
    await fresh(user, owner ? 'owner' : 'reviewer'); const value = await call<Draft>('/calibrations/' + id + '/draft');
    if (value.id !== id) throw new Error('Calibration selection changed.'); adopt(value);
  }
  async function readSource() {
    await fresh(user, owner ? 'owner' : 'reviewer'); setSource(null);
    const value = await call<{ id: string; data_origin: string; sha256: string; physical_truth_verified: boolean }>('/reference-assets/' + referenceId);
    if (value.id !== referenceId || !['synthetic','printable','physical'].includes(value.data_origin) || !sha.test(value.sha256) || value.physical_truth_verified !== false) throw new Error('Current scoped reference information is unavailable.');
    setSource(value);
  }
  async function complete(value: Job) {
    if (!value || !uuid.test(value.id) || !uuid.test(value.calibration_id) || !['processing','expired','completed','failed'].includes(value.status)) throw new Error('Calibration job information is unavailable.');
    setJob(value); setSelected(value.calibration_id);
    if (value.status === 'completed') { await load(value.calibration_id); say('Diagnostic work completed. Read the draft/report before any separate owner approval.'); }
    else say('Original job: ' + value.status + '. Refresh it; a retry does not start another diagnostic. ' + (value.reason ?? ''));
  }
  async function execute(action: Action) {
    pending.current = action; setUncertain(true); setDiscardAck(false); clearReview();
    const live = await fresh(user, 'owner');
    if (action.kind === 'enroll' || action.kind === 'qualify') {
      const result = await call<Job>(action.path, { user: live, method: action.method, version: action.version, body: action.body });
      pending.current = null; setUncertain(false); await complete(result);
    } else {
      const value = await call<Draft>(action.path, { user: live, method: action.method, version: action.version, body: action.body });
      pending.current = null; setUncertain(false); adopt(value);
      say(action.kind === 'retire' ? 'Calibration retired. Historical geometry cannot be reused as current.' : value.current.effective_approved
        ? 'Calibration approval recorded for the qualified scope. This is not beta GO or shipment approval.' : 'Approval recorded, but current dependencies are unavailable. Requalify before use.');
    }
  }
  async function enroll() {
    const values = settingsValue(settings);
    if (!source || source.id !== referenceId || !values || !name.trim() || !identifier.test(camera)) return;
    await execute({ kind: 'enroll', path: draft ? '/calibrations/' + draft.id + '/draft' : '/calibrations', method: draft ? 'PUT' : 'POST', version: draft?.state_version,
      body: { name: name.trim(), camera_id: camera, mat_version: 'desktop-v1', reference_asset_id: source.id, data_origin: source.data_origin, settings: values } });
  }
  async function review() {
    clearReview(); if (!draft?.report_id) return; await fresh(user, owner ? 'owner' : 'reviewer'); const token = expiry.token(), started = performance.now();
    const value = await call<Report>('/calibrations/' + draft.id + '/reports/' + draft.report_id);
    if (value.id !== draft.report_id || value.calibration_id !== draft.id || value.revision !== draft.latest_revision || value.state_version !== draft.state_version
      || value.profile_sha256 !== draft.profile_sha256 || typeof value.passed !== 'boolean' || typeof value.eligible_for_approval !== 'boolean'
      || value.physical_truth_verified !== false || value.independence_verified !== false || typeof value.requires_physical_assurance !== 'boolean'
      || !Array.isArray(value.results) || value.results.length < 2 || value.results.length > 8 || value.passed !== value.results.every(item => item.matched === true)
      || value.results.some(item => !uuid.test(item.asset_id) || !['supported','rejected'].includes(item.expected) || typeof item.matched !== 'boolean'
        || typeof item.diagnostic?.accepted !== 'boolean' || !Array.isArray(item.diagnostic.reason_codes) || item.diagnostic.reason_codes.some(code => typeof code !== 'string'))
      || (value.eligible_for_approval && (!value.passed || value.requires_physical_assurance))) throw new Error('Calibration report does not support this draft. Reload current state.');
    expiry.bound(started, value.remaining_validity_ms, Number.MAX_SAFE_INTEGER, token); setReport(value);
    setCases(value.results.map(item => ({ asset_id: item.asset_id, expected: item.expected }))); setCaseAck(false);
  }
  const casesValid = cases.length >= 2 && cases.length <= 8 && cases.every(item => uuid.test(item.asset_id)) && new Set(cases.map(item => item.asset_id)).size === cases.length
    && cases.some(item => item.expected === 'supported') && cases.some(item => item.expected === 'rejected');
  return <section aria-labelledby="calibration-title"><h3 id="calibration-title">Camera calibration</h3><p role="status">{message}</p>
    <p><a href="/api/v1/calibrations/mat" download>Download desktop-v1 printable mat</a>. Print actual size, measure the 100 mm ruler and keep the full mat visible. A template or screen does not prove physical scale or lens accuracy.</p>
    {uncertain && <fieldset disabled={busy}><legend>Unconfirmed action</legend><p>Keep this action unchanged to recover its original job/outcome. No automatic retry occurs.</p><button onClick={() => pending.current && void perform(() => execute(pending.current!))}>Retry original calibration request</button>
      <label className="check"><input type="checkbox" checked={discardAck} onChange={event => setDiscardAck(event.target.checked)}/>I will inspect current server jobs/catalog before starting a different action; discarding this local retry context cannot undo server work.</label><button disabled={!discardAck} onClick={() => { pending.current = null; setUncertain(false); }}>Discard local retry context</button></fieldset>}
    <fieldset disabled={busy}><legend>Existing camera setups</legend><div className="toolbar"><button onClick={() => void perform(() => list())}>Load calibration candidates</button>{cursor && <button onClick={() => void perform(() => list(true))}>More calibration candidates</button>}</div>
      <label>Calibration candidate<select value={selected} disabled={uncertain || dirty} onChange={event => { setSelected(event.target.value); setDraft(null); setJob(null); clearReview(); }}><option value="">Choose camera setup</option>{catalog.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label><button disabled={!selected || uncertain || dirty} onClick={() => void perform(() => load())}>Read calibration draft</button>
      {owner && <button disabled={uncertain || running || dirty} onClick={() => { setDraft(null); setSelected(''); setJob(null); setName(''); setCamera(''); setReferenceId(seedReference); setSource(null); setSettings(blank()); clearReview(); }}>New camera setup</button>}
      {dirty && <button disabled={uncertain} onClick={() => { setDirty(false); clearReview(); if (draft) void perform(() => load(draft.id)); }}>Discard calibration edits</button>}
    </fieldset>
    <fieldset disabled={frozen || !owner || running}><legend>Enrollment settings{!owner ? ' · owner writes required' : ''}</legend>
      <div className="form-grid"><label>Setup name<input value={name} maxLength={80} onChange={event => { setName(event.target.value); edit(); }}/></label><label>Camera identifier<input value={camera} maxLength={64} onChange={event => { setCamera(event.target.value); edit(); }}/></label><label>Enrollment reference ID<input value={referenceId} maxLength={36} onChange={event => { setReferenceId(event.target.value); setSource(null); edit(); }}/></label></div>
      <button disabled={!uuid.test(referenceId)} onClick={() => void perform(readSource)}>Read enrollment reference</button>
      {source && <><p>Declared origin: {source.data_origin}. Stored source hash: {source.sha256}. Physical truth remains unverified.</p>{source.data_origin !== 'physical' && <button onClick={() => { setSettings({ max_displacement_px: '2', max_reprojection_error_px: '1', measurement_error_mm: '0.5', min_area_px: '30', min_blur_variance: '1', threshold_gray: '127' }); edit(); }}>Use synthetic practice settings</button>}</>}
      <p>Settings are proposed limits to test, not validated accuracy guarantees. Physical scope needs measured ruler/lens/source evidence and a separate reviewed assurance record.</p>
      <div className="form-grid">{(Object.keys(labels) as (keyof Settings)[]).map(key => <label key={key}>{labels[key]}<input type="number" step={key === 'threshold_gray' ? 1 : 'any'} value={settings[key]} onChange={event => { setSettings(old => ({ ...old, [key]: event.target.value })); edit(); }}/></label>)}</div>
      <button disabled={!source || !name.trim() || !identifier.test(camera) || !settingsValue(settings) || (!!draft && !dirty)} onClick={() => void perform(enroll)}>{draft ? 'Save new calibration revision' : 'Enroll camera draft'}</button>
    </fieldset>
    {draft && <><p>Stored status: {draft.status}. Revision {draft.latest_revision} · state version {draft.state_version}. Effective approved revision: {draft.current.effective_approved ? draft.current.active_revision : 'none'}.</p>
      <p>{draft.enrollment.accepted ? 'Enrollment geometry was derived by the server.' : 'Enrollment rejected: ' + draft.enrollment.reason_codes.join(', ')} {draft.profile && `Frame ${draft.profile.frame_width} × ${draft.profile.frame_height}; retained plane ${draft.profile.output_width} × ${draft.profile.output_height}.`}</p>
      <fieldset disabled={frozen || !owner || running || dirty || !draft.profile || draft.retired}><legend>Qualification cases</legend><p>Include distinct supported and deliberately rejected scenes from permitted references. These labels declare expected tests; the server computes the actual outcomes. They do not certify physical truth.</p>
        {cases.map((item, index) => <div className="form-grid" key={index}><label>Case {index + 1} reference ID<input value={item.asset_id} maxLength={36} onChange={event => { setCases(old => old.map((entry, i) => i === index ? { ...entry, asset_id: event.target.value } : entry)); setCaseAck(false); clearReview(); }}/></label><label>Case {index + 1} expected outcome<select value={item.expected} onChange={event => { setCases(old => old.map((entry, i) => i === index ? { ...entry, expected: event.target.value } : entry)); setCaseAck(false); clearReview(); }}><option value="supported">Supported geometry</option><option value="rejected">Must reject</option></select></label>{cases.length > 2 && <button onClick={() => { setCases(old => old.filter((_, i) => i !== index)); setCaseAck(false); clearReview(); }}>Remove case {index + 1}</button>}</div>)}
        <button disabled={cases.length >= 8} onClick={() => { setCases(old => [...old, { asset_id: '', expected: 'rejected' }]); setCaseAck(false); clearReview(); }}>Add diagnostic case</button>
        <label className="check"><input type="checkbox" checked={caseAck} onChange={event => setCaseAck(event.target.checked)}/>I reviewed these expected cases and will preserve failed outcomes and source limitations.</label>
        <button disabled={!casesValid || !caseAck} onClick={() => void perform(() => execute({ kind: 'qualify', path: '/calibrations/' + draft.id + '/qualify', method: 'POST', version: draft.state_version, body: { cases } }))}>Run calibration diagnostics</button>
      </fieldset>
    </>}
    {job && <fieldset disabled={busy}><legend>Original diagnostic job</legend><p>Job {job.id}: {job.status}. {job.reason}</p><button onClick={() => void perform(async () => { await fresh(user, owner ? 'owner' : 'reviewer'); await complete(await call<Job>('/calibration-jobs/' + job.id)); })}>Refresh calibration job</button></fieldset>}
    {draft?.report_id && <fieldset disabled={busy || uncertain || dirty}><legend>Recorded qualification report</legend><button onClick={() => void perform(review)}>Review calibration report</button>
      {report && <><p>Diagnostic report: {report.passed ? 'passed expected cases' : 'FAILED expected cases'}. Physical truth and reviewer independence remain unverified.</p>
        <ul>{report.results.map(item => <li key={item.asset_id}>{item.expected}: actual {item.diagnostic.accepted ? 'supported' : 'rejected'} · {item.matched ? 'matched' : 'FAILED'} · {item.diagnostic.reason_codes.join(', ')}</li>)}</ul>
        <p>{expiry.valid ? 'Report review is within its original validity.' : 'Review expired or was interrupted. Read current report again.'}</p>{report.requires_physical_assurance && <p>Physical approval held: matching reviewed ruler, lens and source assurance is required. No browser checkbox can supply it.</p>}
        {owner && <><label className="check"><input type="checkbox" checked={approveAck} disabled={!expiry.valid || !report.eligible_for_approval} onChange={event => setApproveAck(event.target.checked)}/>I reviewed this exact diagnostic scope and intend to approve this calibration revision.</label><button disabled={!approveAck || !expiry.valid || !report.eligible_for_approval} onClick={() => void perform(() => execute({ kind: 'approve', path: '/calibrations/' + draft.id + '/approve', method: 'POST', version: draft.state_version, body: { report_id: report.id } }))}>Approve qualified calibration</button></>}
      </>}
    </fieldset>}
    {owner && draft && <fieldset disabled={frozen || dirty}><legend>Retire setup</legend><label>Calibration retirement reason<input value={reason} maxLength={120} onChange={event => setReason(event.target.value)}/></label><button disabled={!reason.trim()} onClick={() => void perform(() => execute({ kind: 'retire', path: '/calibrations/' + draft.id + '/retire', method: 'POST', version: draft.state_version, body: { reason: reason.trim() } }))}>Retire calibration</button></fieldset>}
    <p>Diagnostic scope does not establish a real webcam, qualified lens, physical kit accuracy, beta readiness or shipment authorization. Physical evidence import, full station setup and target qualification still require completion.</p>
  </section>;
}
