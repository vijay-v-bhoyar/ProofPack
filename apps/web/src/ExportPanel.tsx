import { useEffect, useRef, useState } from 'react';
import { ApiError } from './api';
import type { User } from './api';
import { useUnconfirmed, positive, sha, useTasks, uuid } from './workbench';

type Context = { inspection_id: string; state_version: number; state_as_recorded: string; latest_asset_id: string | null;
  max_assets: number; historical: true; current_approval: false; can_create: boolean };
type Job = { id: string; kind: string; state_version: number; status: string; inspection_id: string; inspection_revision: number;
  historical: true; current_approval: false; remaining_ms: number; lease_remaining_ms: number; scanned_rows: number; record_count: number;
  selected_asset_ids: string[]; manifest_sha256: string | null; can_advance: boolean; can_issue_ticket: boolean; can_cancel: boolean; failure_reason: string | null };
type Ticket = { id: string; job_id: string; ticket: string; remaining_ms: number; usable: boolean; historical: true; current_approval: false };
type Intent = { kind: 'create' | 'advance' | 'ticket' | 'cancel'; path: string; version: number; key: string; body: object; inspection: string; jobId?: string; ids?: string[] };
const states = ['queued', 'processing', 'completed', 'failed', 'cancelled'];
const nonnegative = (n: unknown) => Number.isSafeInteger(n) && Number(n) >= 0;
function checkedJob(value: Job, id?: string, inspection?: string, ids?: string[]) {
  if (!value || !uuid.test(value.id) || (id && value.id !== id) || value.kind !== 'inspection_export' || !positive(value.state_version)
    || !uuid.test(value.inspection_id) || (inspection && value.inspection_id !== inspection) || !positive(value.inspection_revision)
    || !states.includes(value.status) || value.historical !== true || value.current_approval !== false
    || !nonnegative(value.remaining_ms) || value.remaining_ms > 3600000 || !nonnegative(value.lease_remaining_ms) || value.lease_remaining_ms > 60000
    || !nonnegative(value.scanned_rows) || !nonnegative(value.record_count) || !Array.isArray(value.selected_asset_ids)
    || value.scanned_rows > 5000 || value.record_count > 512 || ![null, 'EXPORT_LIMIT_EXCEEDED', 'SOURCE_NOT_TERMINAL'].includes(value.failure_reason)
    || value.selected_asset_ids.length > 3 || new Set(value.selected_asset_ids).size !== value.selected_asset_ids.length || value.selected_asset_ids.some(id => !uuid.test(id))
    || (ids && [...ids].sort().join(',') !== [...value.selected_asset_ids].sort().join(','))
    || [value.can_advance, value.can_issue_ticket, value.can_cancel].some(v => typeof v !== 'boolean')
    || (value.manifest_sha256 !== null && !sha.test(value.manifest_sha256)) || (value.status === 'completed' && !value.manifest_sha256)
    || (value.can_issue_ticket && (value.status !== 'completed' || value.remaining_ms === 0))
    || (value.can_advance && (!['queued', 'processing'].includes(value.status) || value.remaining_ms === 0 || (value.status === 'processing' && value.lease_remaining_ms > 0)))
    || (value.status === 'cancelled' && (value.can_cancel || value.can_issue_ticket || value.can_advance))) throw new Error('Export job does not match the requested historical scope. Read server state before continuing.');
  return value;
}

export function ExportPanel({ user }: { user: User }) {
  const { busy, message, call, perform, fresh, say } = useTasks('Prepare a historical inspection archive. It never authorizes shipment or public reuse.');
  const [inspection, setInspection] = useState(''), [selected, setSelected] = useState(''), [context, setContext] = useState<Context | null>(null);
  const [jobId, setJobId] = useState(''), [job, setJob] = useState<Job | null>(null), [ack, setAck] = useState(false), [cancelAck, setCancelAck] = useState(false);
  const [uncertain, setUncertain] = useState(false), [ticket, setTicket] = useState<Ticket | null>(null), [copy, setCopy] = useState<string | null>(null);
  const [needsRead, setNeedsRead] = useState(false);
  const [listed, setListed] = useState<{ id: string; status: string }[]>([]), [cursor, setCursor] = useState<string | null>(null);
  const intent = useRef<Intent | null>(null), active = useRef(true), generation = useRef(0), until = useRef(0), url = useRef<string | null>(null), controller = useRef<AbortController | null>(null);
  const ids = selected.trim().split(/[\s,]+/).filter(Boolean), validIds = ids.length <= (context?.max_assets ?? 3) && ids.every(id => uuid.test(id)) && new Set(ids).size === ids.length;
  const role = user.roles.includes('reviewer') ? 'reviewer' : 'operator';
  useUnconfirmed(!!uncertain);
  function clearCopies() {
    generation.current++; until.current = 0; controller.current?.abort(); controller.current = null;
    if (url.current) URL.revokeObjectURL(url.current); url.current = null;
    if (active.current) { setCopy(null); setTicket(null); }
  }
  useEffect(() => {
    active.current = true;
    const interrupt = () => { clearCopies(); setAck(false); setCancelAck(false); setContext(null); }, hidden = () => { if (document.visibilityState !== 'visible') interrupt(); };
    const timer = window.setInterval(() => { if (until.current && performance.now() >= until.current) clearCopies(); }, 100);
    document.addEventListener('visibilitychange', hidden); window.addEventListener('offline', interrupt);
    return () => { active.current = false; clearCopies(); window.clearInterval(timer); document.removeEventListener('visibilitychange', hidden); window.removeEventListener('offline', interrupt); };
  }, []);
  async function readContext() {
    clearCopies(); setContext(null); setJob(null); setAck(false); setCancelAck(false); await fresh(user, role);
    const value = await call<Context>('/inspections/' + inspection + '/export-context');
    if (!value || value.inspection_id !== inspection || !positive(value.state_version) || value.historical !== true || value.current_approval !== false
      || !['CREATED', 'OBSERVING', 'ACTION_REQUIRED', 'REVIEW_REQUIRED', 'PASSED_CURRENT', 'INVALIDATED', 'CLOSED'].includes(value.state_as_recorded)
      || !positive(value.max_assets) || value.max_assets > 3 || typeof value.can_create !== 'boolean' || (value.latest_asset_id !== null && !uuid.test(value.latest_asset_id))) throw new Error('Inspection export context is unavailable.');
    setContext(value);
  }
  async function readJob(id = jobId) {
    clearCopies(); setNeedsRead(true); setAck(false); setCancelAck(false); setContext(null); await fresh(user, role); const value = checkedJob(await call<Job>('/jobs/' + id), id);
    setJob(value); setJobId(value.id); setInspection(value.inspection_id); setContext(null); setAck(false); setCancelAck(false);
    setNeedsRead(false);
  }
  async function listJobs(next = false) {
    clearCopies(); await fresh(user, role);
    const value = await call<{ inspection_id: string; jobs: { id: string; status: string; state_version: number }[]; next_cursor: string | null; historical: true; current_approval: false }>(
      '/inspections/' + inspection + '/exports' + (next && cursor ? '?cursor=' + encodeURIComponent(cursor) : ''));
    if (value.inspection_id !== inspection || value.historical !== true || value.current_approval !== false || !Array.isArray(value.jobs) || value.jobs.length > 20
      || value.jobs.some(v => !uuid.test(v.id) || !positive(v.state_version) || !states.includes(v.status))
      || (value.next_cursor !== null && (typeof value.next_cursor !== 'string' || value.next_cursor.length > 1024))) throw new Error('Recorded export list is unrecognized.');
    setListed(value.jobs); setCursor(value.next_cursor);
  }
  async function write(kind: Intent['kind']) {
    const live = await fresh(user, role);
    if (!intent.current) {
      if (kind === 'create') {
        if (!context?.can_create || !ack || !validIds) throw new Error('Read the current inspection, select permitted assets and acknowledge historical export.');
        intent.current = { kind, path: '/inspections/' + context.inspection_id + '/exports', version: context.state_version, key: crypto.randomUUID(), inspection: context.inspection_id,
          ids: [...ids], body: { selected_asset_ids: [...ids], historical_export_acknowledged: true } };
      } else {
        if (!job || (kind === 'advance' && !job.can_advance) || (kind === 'ticket' && (!job.can_issue_ticket || !ack || needsRead)) || (kind === 'cancel' && (!job.can_cancel || !cancelAck))) throw new Error('Read an eligible current job and acknowledge the requested action.');
        intent.current = { kind, path: '/jobs/' + job.id + '/' + (kind === 'ticket' ? 'download-tickets' : kind), version: job.state_version,
          key: crypto.randomUUID(), inspection: job.inspection_id, jobId: job.id, body: kind === 'ticket' ? { historical_export_acknowledged: true } : {} };
      }
    }
    const chosen = intent.current; clearCopies(); setUncertain(true); const started = performance.now(), token = generation.current;
    try {
      if (chosen.kind === 'ticket') {
        const value = await call<Ticket>(chosen.path, { user: live, method: 'POST', version: chosen.version, idempotencyKey: chosen.key, body: chosen.body });
        if (!value || !uuid.test(value.id) || value.job_id !== chosen.jobId || value.historical !== true || value.current_approval !== false || typeof value.usable !== 'boolean'
          || typeof value.ticket !== 'string' || !new RegExp('^' + value.id + '\\.[A-Za-z0-9_-]{43}$').test(value.ticket) || !nonnegative(value.remaining_ms) || value.remaining_ms > 60000) throw new Error('Export ticket response is unrecognized. Keep the original request.');
        if (token !== generation.current || document.visibilityState !== 'visible' || !navigator.onLine) throw new Error('Ticket review interrupted. Read current state before another action.');
        until.current = started + value.remaining_ms;
        if (value.usable && performance.now() < until.current) setTicket(value);
        say(value.usable ? 'Session-bound ticket issued. Fetch the archive once before expiry.' : 'Original ticket is expired or consumed. Read the job before explicitly requesting another.');
      } else {
        const value = checkedJob(await call<Job>(chosen.path, { user: live, method: 'POST', version: chosen.version, idempotencyKey: chosen.key, body: chosen.body }), chosen.jobId, chosen.inspection, chosen.ids);
        setJob(value); setJobId(value.id); setContext(null); setCancelAck(false); setAck(false);
        setNeedsRead(false);
        say(value.status === 'completed' ? 'Historical manifest prepared. Reauthorize a one-use download ticket; no bytes have been delivered.' : 'Export progress recorded. Read status or explicitly advance/cancel.');
      }
      intent.current = null; setUncertain(false);
    } catch (error) {
      if (error instanceof ApiError && error.status < 500) { intent.current = null; setUncertain(false); setContext(null); setJob(null); setAck(false); setCancelAck(false); }
      throw error;
    }
  }
  async function fetchArchive() {
    if (!job || !ticket || performance.now() >= until.current) throw new Error('Request a fresh session-bound ticket.');
    await fresh(user, role);
    if (performance.now() >= until.current || document.visibilityState !== 'visible' || !navigator.onLine) throw new Error('Ticket expired or delivery was interrupted.');
    const chosen = ticket, chosenJob = job, token = generation.current, started = performance.now(); setTicket(null); setNeedsRead(true);
    const abort = new AbortController(); controller.current = abort; const timer = window.setTimeout(() => abort.abort(), Math.min(30000, Math.max(1, until.current - started)));
    try {
      const response = await fetch('/api/v1/jobs/' + chosenJob.id + '/download', { credentials: 'same-origin', cache: 'no-store', signal: abort.signal, headers: { 'X-Export-Ticket': chosen.ticket } });
      if (!response.ok) throw new ApiError(response.status);
      const length = Number(response.headers.get('content-length')), hash = response.headers.get('x-content-sha256') ?? '', remaining = Number(response.headers.get('x-remaining-validity-ms'));
      if (response.headers.get('content-type') !== 'application/zip' || response.headers.get('x-export-job-id') !== chosenJob.id
        || response.headers.get('x-manifest-sha256') !== chosenJob.manifest_sha256 || response.headers.get('x-export-historical') !== 'true'
        || !positive(length) || length > 8388608 || !sha.test(hash) || !positive(remaining) || remaining > 60000 || !response.body) throw new Error('Archive response is unrecognized. Do not save it.');
      const reader = response.body.getReader(), chunks: Uint8Array[] = []; let size = 0;
      for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.length; if (size > length || size > 8388608) { await reader.cancel(); throw new Error('Archive exceeds its declared bounds.'); } chunks.push(part.value); }
      if (size !== length) throw new Error('Archive is incomplete.');
      const bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
      const actual = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(b => b.toString(16).padStart(2, '0')).join('');
      if (actual !== hash || bytes[0] !== 80 || bytes[1] !== 75 || bytes[2] !== 3 || bytes[3] !== 4) throw new Error('Archive integrity failed. Do not save it.');
      await fresh(user, role); until.current = Math.min(until.current, started + remaining);
      if (!active.current || token !== generation.current || document.visibilityState !== 'visible' || !navigator.onLine || performance.now() >= until.current) throw new Error('Archive delivery expired or was interrupted.');
      url.current = URL.createObjectURL(new Blob([bytes], { type: 'application/zip' })); setCopy(url.current); say('Archive bytes verified locally. Saving is your choice; already delivered copies cannot be recalled.');
    } catch (error) { throw new Error((error instanceof Error ? error.message + ' ' : '') + 'Delivery is unconfirmed or rejected. Read the job before explicitly requesting another ticket; already delivered copies cannot be recalled.'); }
    finally { window.clearTimeout(timer); abort.abort(); if (controller.current === abort) controller.current = null; }
  }
  return <section aria-label="Inspection exports"><h3>Historical inspection exports</h3><p role="status" aria-label="Export message">{message}</p>
    <p>Archive a permitted historical record and up to three selected cropped images. Unselected or unavailable media are omitted. This is not current approval, capture authentication or permission for public reuse.</p>
    <fieldset disabled={busy || uncertain}><legend>Inspection and recorded exports</legend>
      <label>Export inspection ID<input value={inspection} maxLength={36} onChange={e => { clearCopies(); setInspection(e.target.value); setContext(null); setJob(null); setSelected(''); setListed([]); setCursor(null); setAck(false); }}/></label>
      <button disabled={!uuid.test(inspection)} onClick={() => void perform(readContext)}>Read inspection export scope</button>
      <button disabled={!uuid.test(inspection)} onClick={() => void perform(() => listJobs())}>Find recorded exports</button>
      {listed.map(v => <button key={v.id} onClick={() => void perform(() => readJob(v.id))}>Read export {v.id} · {v.status}</button>)}
      {cursor && <button onClick={() => void perform(() => listJobs(true))}>Next export page</button>}
      {context && <><p>Inspection revision {context.state_version}; recorded state {context.state_as_recorded}. Latest retained asset: {context.latest_asset_id ?? 'none'}. Availability is checked separately.</p>
        <label>Selected frame asset IDs, or empty for metadata only<textarea maxLength={120} value={selected} onChange={e => { clearCopies(); setAck(false); setSelected(e.target.value); }}/></label>
        <label className="check"><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)}/>I reviewed this historical inspection and selected media. Export does not grant shipping approval or optional reuse.</label>
        <button disabled={!context.can_create || !ack || !validIds} onClick={() => void perform(() => write('create'))}>Create historical export</button></>}
      <label>Export job ID<input value={jobId} maxLength={36} onChange={e => { clearCopies(); setJob(null); setAck(false); setCancelAck(false); setJobId(e.target.value); }}/></label>
      <button disabled={!uuid.test(jobId)} onClick={() => void perform(() => readJob())}>Read export job</button>
    </fieldset>
    {job && <fieldset disabled={busy || uncertain}><legend>Recorded export progress</legend><p>Job {job.id}: {job.status}. Historical only; current approval: no.</p>
      <p>The configured maintenance worker may prepare this job automatically. Read current status before another manual step; changed versions require a new review.</p>
      <p>Scanned rows: {job.scanned_rows}; records: {job.record_count}; failure: {job.failure_reason ?? 'none'}. Selected media: {job.selected_asset_ids.join(', ') || 'none'}. Manifest SHA-256: {job.manifest_sha256 ?? 'not prepared'}.</p>
      <button disabled={!job.can_advance} onClick={() => void perform(() => write('advance'))}>Advance one export page</button>
      <label className="check"><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)}/>I request my permitted historical copy and understand downloaded copies cannot be recalled.</label>
      <button disabled={!job.can_issue_ticket || !ack || needsRead} onClick={() => void perform(() => write('ticket'))}>Request one-use export ticket</button>
      {needsRead && <p>Read current export job status before requesting another ticket.</p>}
      <button disabled={!ticket} onClick={() => void perform(fetchArchive)}>Fetch historical archive once</button>
      <label className="check"><input type="checkbox" checked={cancelAck} onChange={e => setCancelAck(e.target.checked)}/>Cancel future export delivery; this cannot recall copies already received.</label>
      <button disabled={!job.can_cancel || !cancelAck} onClick={() => void perform(() => write('cancel'))}>Cancel export delivery</button>
    </fieldset>}
    {uncertain && <><p>Outcome unconfirmed. Retry the unchanged request. Leaving loses local intent; use the inspection ID and Find recorded exports before creating another job.</p><button disabled={busy} onClick={() => void perform(() => write(intent.current!.kind))}>Retry unchanged export request</button></>}
    {copy && <p><a href={copy} download={'proofpack-' + job!.id + '.zip'}>Save prepared historical archive</a> <button disabled={busy} onClick={clearCopies}>Forget prepared archive</button></p>}
  </section>;
}
