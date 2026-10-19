import { useEffect, useRef, useState } from 'react';
import { ApiError } from './api';
import type { User } from './api';
import { useUnconfirmed, positive, sha, useReviewDeadline, useTasks, uuid } from './workbench';

type Selected = { id: string; kind: string; sha256: string; asset_revision: number; receipt_sha256: string };
type Scope = { schema_version: number; kind: string; assets: Selected[]; storage_binding_sha256: string };
type Preview = { id: string; state_version: number; scope: Scope; scope_sha256: string; remaining_ms: number;
  status: string; job_id: string | null; can_confirm: boolean; erasure_complete: false; remaining_duties: string[] };
type Progress = { id: string; kind: string; live_versions_removed: boolean; delete_acknowledgments: number; checked_at_ms: number | null };
type Job = { id: string; kind: string; state_version: number; status: string; scope_sha256: string; assets: Progress[];
  lease_remaining_ms: number; last_error: string | null; target_matches_current_config: boolean; can_advance: boolean;
  erasure_complete: false; dependent_metadata_erased: false; backups_erased: false; downloaded_copies_recalled: false };
type Intent = { kind: 'preview' | 'confirm' | 'advance'; path: string; body: object; key: string; version?: number;
  ids?: string[]; preview?: Preview; job?: Job };
const duties = ['backups', 'dependent_metadata', 'orphans_and_restore', 'recipient_copies'];
const nonnegative = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) >= 0;
const kind = (value: string) => value === 'frame' || value === 'reference';

async function checkedPreview(value: Preview, expectedId?: string, ids?: string[]): Promise<Preview> {
  const scope = value?.scope;
  if (!value || !uuid.test(value.id) || (expectedId && value.id !== expectedId) || !positive(value.state_version)
    || value.erasure_complete !== false || typeof value.can_confirm !== 'boolean' || !sha.test(value.scope_sha256)
    || !nonnegative(value.remaining_ms) || value.remaining_ms > 60000 || !['preview', 'committed'].includes(value.status)
    || (value.status === 'preview' ? value.job_id !== null : !value.job_id || !uuid.test(value.job_id) || value.can_confirm)
    || !Array.isArray(value.remaining_duties) || [...value.remaining_duties].sort().join(',') !== duties.join(',')
    || !scope || scope.schema_version !== 1 || scope.kind !== 'selected_live_asset_versions' || !sha.test(scope.storage_binding_sha256)
    || !Array.isArray(scope.assets) || scope.assets.length < 1 || scope.assets.length > 16
    || new Set(scope.assets.map(a => a.id)).size !== scope.assets.length
    || scope.assets.some(a => !uuid.test(a.id) || !kind(a.kind) || !sha.test(a.sha256) || !sha.test(a.receipt_sha256) || !positive(a.asset_revision))
    || (ids && [...ids].sort().join(',') !== scope.assets.map(a => a.id).sort().join(','))) throw new Error('Deletion review does not match the selected scope. No new approval is available.');
  // These validated fields contain ASCII only; order matches the service canonical JSON.
  const canonical = { assets: scope.assets.map(a => ({ asset_revision: a.asset_revision, id: a.id, kind: a.kind,
    receipt_sha256: a.receipt_sha256, sha256: a.sha256 })), kind: scope.kind, schema_version: scope.schema_version, storage_binding_sha256: scope.storage_binding_sha256 };
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(canonical)));
  const hash = [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
  if (hash !== value.scope_sha256) throw new Error('Deletion scope digest does not match its contents. Do not confirm.');
  return value;
}

function checkedJob(value: Job, expectedId?: string, preview?: Preview, prior?: Job): Job {
  if (!value || !uuid.test(value.id) || (expectedId && value.id !== expectedId) || value.kind !== 'asset_erasure'
    || !positive(value.state_version) || !sha.test(value.scope_sha256) || !['queued', 'processing', 'metadata_pending'].includes(value.status)
    || value.erasure_complete !== false || value.dependent_metadata_erased !== false || value.backups_erased !== false || value.downloaded_copies_recalled !== false
    || typeof value.can_advance !== 'boolean' || typeof value.target_matches_current_config !== 'boolean'
    || !nonnegative(value.lease_remaining_ms) || value.lease_remaining_ms > 60000
    || ![null, 'VERSION_DELETE_PARTIAL', 'STORAGE_OUTCOME_UNCONFIRMED'].includes(value.last_error)
    || !Array.isArray(value.assets) || value.assets.length < 1 || value.assets.length > 16
    || new Set(value.assets.map(a => a.id)).size !== value.assets.length
    || value.assets.some(a => !uuid.test(a.id) || !kind(a.kind) || typeof a.live_versions_removed !== 'boolean'
      || !nonnegative(a.delete_acknowledgments) || (a.live_versions_removed ? !positive(a.checked_at_ms) : a.checked_at_ms !== null))
    || (value.status === 'metadata_pending' && (value.can_advance || value.lease_remaining_ms !== 0 || value.assets.some(a => !a.live_versions_removed)))
    || (value.status === 'processing' && value.lease_remaining_ms > 0 && value.can_advance)
    || (preview && value.scope_sha256 !== preview.scope_sha256) || (prior && value.scope_sha256 !== prior.scope_sha256)
    || (preview && value.assets.map(a => a.id + ':' + a.kind).sort().join(',') !== preview.scope.assets.map(a => a.id + ':' + a.kind).sort().join(','))
    || (prior && value.assets.map(a => a.id + ':' + a.kind).sort().join(',') !== prior.assets.map(a => a.id + ':' + a.kind).sort().join(','))) throw new Error('Cleanup progress is unrecognized or belongs to a different scope. Keep the original request and read server state.');
  return value;
}

export function ErasurePanel({ user }: { user: User }) {
  const { busy, message, call, perform, fresh, say } = useTasks('Review selected assets before irreversible read denial and version cleanup.');
  const [selection, setSelection] = useState(''), [previewId, setPreviewId] = useState(''), [jobId, setJobId] = useState('');
  const [preview, setPreview] = useState<Preview | null>(null), [job, setJob] = useState<Job | null>(null);
  const [denyAck, setDenyAck] = useState(false), [limitsAck, setLimitsAck] = useState(false), [uncertain, setUncertain] = useState(false);
  const intent = useRef<Intent | null>(null), expiry = useReviewDeadline();
  const ids = selection.trim().split(/[\s,]+/).filter(Boolean), valid = ids.length > 0 && ids.length <= 16 && ids.every(id => uuid.test(id)) && new Set(ids).size === ids.length;
  useUnconfirmed(uncertain);
  const clearReview = () => { expiry.clear(); setDenyAck(false); setLimitsAck(false); };
  useEffect(() => { if (!expiry.valid) { setDenyAck(false); setLimitsAck(false); } }, [expiry.valid]);
  const adoptPreview = (value: Preview, started: number, token: number) => {
    setPreview(value); setPreviewId(value.id);
    if (value.job_id) { setJobId(value.job_id); say('Read denial was committed. Read the recorded job; do not create another deletion intent.'); }
    if (value.status === 'preview' && value.can_confirm && value.remaining_ms > 0) expiry.bound(started, value.remaining_ms, 60000, token);
  };
  async function write(operation: Intent['kind']) {
    const live = await fresh(user, 'owner');
    if (!intent.current) {
      if (operation === 'preview') {
        if (!valid) throw new Error('Select 1–16 distinct asset UUIDs.');
        intent.current = { kind: operation, path: '/privacy/deletion-previews', body: { asset_ids: [...ids] }, ids: [...ids], key: crypto.randomUUID() };
      } else if (operation === 'confirm') {
        if (!preview?.can_confirm || !expiry.valid || !denyAck || !limitsAck) throw new Error('Read a current preview and acknowledge both consequences.');
        intent.current = { kind: operation, path: '/privacy/deletions', version: preview.state_version, key: crypto.randomUUID(), preview,
          body: { preview_id: preview.id, confirmed_digest: preview.scope_sha256, erase_asset_versions_acknowledged: true, understands_remaining_metadata_and_backups: true } };
      } else {
        if (!job?.can_advance || !job.target_matches_current_config) throw new Error('Read a current eligible cleanup job.');
        intent.current = { kind: operation, path: '/jobs/' + job.id + '/advance', body: {}, version: job.state_version, job, key: crypto.randomUUID() };
      }
    }
    const chosen = intent.current, started = performance.now(), token = expiry.token(); setUncertain(true);
    try {
      if (chosen.kind === 'preview') {
        const value = await checkedPreview(await call<Preview>(chosen.path, { user: live, method: 'POST', body: chosen.body, idempotencyKey: chosen.key }), undefined, chosen.ids);
        // Approval never survives the original request's interruption or network delay.
        adoptPreview(value, started, token);
      } else {
        clearReview();
        const value = checkedJob(await call<Job>(chosen.path, { user: live, method: 'POST', body: chosen.body, version: chosen.version, idempotencyKey: chosen.key }), chosen.job?.id, chosen.preview, chosen.job);
        setJob(value); setJobId(value.id);
        say(value.status === 'metadata_pending' ? 'Selected live versions checked absent. Full erasure remains incomplete; metadata and backup duties remain.' : 'Cleanup progress recorded. Read status before another explicit bounded step.');
      }
      intent.current = null; setUncertain(false);
    } catch (error) {
      clearReview();
      if (error instanceof ApiError && error.status < 500) { intent.current = null; setUncertain(false); }
      throw error;
    }
  }
  async function readPreview() {
    clearReview(); setPreview(null); const started = performance.now(), token = expiry.token();
    await fresh(user, 'owner');
    const value = await checkedPreview(await call<Preview>('/privacy/deletion-previews/' + previewId), previewId);
    adoptPreview(value, started, token);
  }
  async function readJob() {
    await fresh(user, 'owner');
    const value = checkedJob(await call<Job>('/jobs/' + jobId), jobId, preview?.job_id === jobId ? preview : undefined, job?.id === jobId ? job : undefined);
    setJob(value);
  }
  return <section aria-label="Selected asset cleanup"><h3>Selected asset cleanup</h3><p role="status" aria-label="Cleanup message">{message}</p>
    <p>Owner-only, irreversible read denial and selected live-object version cleanup. This does not discover all records about a person or certify full erasure. No cancellation can undo a committed denial.</p>
    <fieldset disabled={busy || uncertain}><legend>Select or recover a review</legend>
      <label>Asset UUIDs, separated by spaces or commas<textarea value={selection} maxLength={600} onChange={e => { clearReview(); setPreview(null); setJob(null); setSelection(e.target.value); }}/></label>
      <button disabled={!valid} onClick={() => { clearReview(); setPreview(null); setJob(null); void perform(() => write('preview')); }}>Preview selected asset cleanup</button>
      <label>Deletion preview ID<input maxLength={36} value={previewId} onChange={e => { clearReview(); setPreview(null); setJob(null); setPreviewId(e.target.value); }}/></label>
      <button disabled={!uuid.test(previewId)} onClick={() => void perform(readPreview)}>Read deletion preview</button>
    </fieldset>
    {preview && <div><p>Preview ID: {preview.id}. Status: {preview.status}. Scope SHA-256: {preview.scope_sha256}.</p>
      <ul>{preview.scope.assets.map(a => <li key={a.id}>{a.kind} asset {a.id}; SHA-256 {a.sha256}; source revision {a.asset_revision}.</li>)}</ul>
      <p>Remaining duties: dependent metadata, orphan/restore reconciliation, backups and recipient copies.</p>
      <fieldset disabled={busy || uncertain || !expiry.valid || !preview.can_confirm}><legend>Confirm exact reviewed scope</legend>
        <label className="check"><input type="checkbox" checked={denyAck} onChange={e => setDenyAck(e.target.checked)}/>I authorize irreversible read denial and version removal for these exact assets.</label>
        <label className="check"><input type="checkbox" checked={limitsAck} onChange={e => setLimitsAck(e.target.checked)}/>I understand metadata, backups and downloaded copies remain unresolved.</label>
        <button disabled={!denyAck || !limitsAck} onClick={() => void perform(() => write('confirm'))}>Commit reviewed asset denial</button>
      </fieldset>
      {preview.status === 'preview' && (!expiry.valid || !preview.can_confirm) && <p>Review expired, interrupted or ineligible. Read the current preview before another approval.</p>}
    </div>}
    <fieldset disabled={busy || uncertain}><legend>Recorded cleanup job</legend>
      <label>Cleanup job ID<input maxLength={36} value={jobId} onChange={e => { clearReview(); setJob(null); setJobId(e.target.value); }}/></label>
      <button disabled={!uuid.test(jobId)} onClick={() => void perform(readJob)}>Read cleanup job</button>
      {job && <><p>Job {job.id}: {job.status}. Full erasure: incomplete. Metadata erased: no. Backups erased: no. Downloaded copies recalled: no.</p>
        <p>The configured maintenance worker may advance cleanup automatically. Read current status before another manual step; an acknowledgment does not complete the remaining privacy duties.</p>
        <p>Storage target matches: {job.target_matches_current_config ? 'yes' : 'no'}. Lease remaining at read: {job.lease_remaining_ms} ms. Error: {job.last_error ?? 'none'}.</p>
        <ul>{job.assets.map(a => <li key={a.id}>{a.kind} {a.id}: live versions {a.live_versions_removed ? 'checked absent at ' + a.checked_at_ms + ' ms UTC' : 'not yet verified absent'}; delete acknowledgments {a.delete_acknowledgments} (not a distinct-object count).</li>)}</ul>
        <button disabled={!job.can_advance || !job.target_matches_current_config} onClick={() => void perform(() => write('advance'))}>Advance one cleanup page</button>
      </>}
    </fieldset>
    {uncertain && <><p>Outcome unconfirmed. Retry only the unchanged request. Leaving loses the local request; keep the preview/job IDs and read server state before another action. Sign-out cannot undo committed denial.</p>
      <button disabled={busy} onClick={() => void perform(() => write(intent.current!.kind))}>Retry unchanged cleanup request</button></>}
  </section>;
}
