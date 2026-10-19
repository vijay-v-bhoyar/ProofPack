import { useRef, useState } from 'react';
import type { User } from './api';
import { useUnconfirmed, positive, sha, uuid, useTasks, useReviewDeadline } from './workbench';

type Notice = { version: string; sha256: string; text: string };
type Asset = { id: string; kind: string; sha256: string; data_origin: string; purpose_id: string; source_permission_reference: string; expires_at_ms: number };
type Preview = { id: string; state_version: number; status: string; scope_sha256: string; assets: Asset[]; remaining_review_ms: number;
  server_time_ms: number; source_expires_at_ms: number; max_lifetime_ms: number; can_confirm: boolean; permission_id: string | null; notice: Notice };
type Permission = { id: string; state_version: number; scope_sha256: string; grant_sha256: string; withdrawn: boolean; usable: boolean;
  optional_improvement: boolean; optional_publicity: boolean; rights_independently_verified: boolean; physical_truth_verified: boolean;
  independence_verified: boolean; derived_review_metadata_allowed: boolean; authority_basis: string; notice: Notice; documented_permission_reference: string; expires_at_ms: number; held_reason: string | null; assets: Asset[] };
type Intent = { kind: 'preview' | 'confirm' | 'withdraw'; path: string; body?: object; version?: number; key: string };
const assetList = (items: Asset[]) => Array.isArray(items) && items.length > 0 && items.length <= 16 && new Set(items.map(a => a.id)).size === items.length
  && items.every(a => uuid.test(a.id) && uuid.test(a.purpose_id) && sha.test(a.sha256) && ['frame', 'reference'].includes(a.kind)
    && ['synthetic', 'printable', 'physical'].includes(a.data_origin) && positive(a.expires_at_ms) && typeof a.source_permission_reference === 'string');
function permission(value: Permission) {
  if (!value || !uuid.test(value.id) || !positive(value.state_version) || !sha.test(value.scope_sha256) || !sha.test(value.grant_sha256)
    || !assetList(value.assets) || !positive(value.expires_at_ms) || typeof value.usable !== 'boolean' || typeof value.withdrawn !== 'boolean'
    || value.optional_improvement !== true || [value.optional_publicity, value.rights_independently_verified, value.physical_truth_verified, value.independence_verified].some(v => v !== false)
    || typeof value.derived_review_metadata_allowed !== 'boolean' || value.authority_basis !== 'owner_attestation' || !value.notice || !sha.test(value.notice.sha256) || !value.notice.version || typeof value.notice.text !== 'string'
    || typeof value.documented_permission_reference !== 'string') throw new Error('Optional permission information is unavailable.');
  return value;
}

export function ImprovementPanel({ user }: { user: User }) {
  const owner = user.roles.includes('owner'), { busy, message, call, perform, fresh, say } = useTasks('Optional improvement use is separate from normal operation and stays off without a recorded grant.');
  const [notice, setNotice] = useState<Notice | null>(null), [idsText, setIdsText] = useState(''), [reference, setReference] = useState(''), [duration, setDuration] = useState('60');
  const [preview, setPreview] = useState<Preview | null>(null), [previewId, setPreviewId] = useState(''), [reviewStarted, setReviewStarted] = useState(0);
  const [selected, setSelected] = useState<Permission | null>(null), [permissionId, setPermissionId] = useState(''), [items, setItems] = useState<Permission[]>([]), [cursor, setCursor] = useState<string | null>(null);
  const [ack, setAck] = useState(false), [limitsAck, setLimitsAck] = useState(false), [withdrawAck, setWithdrawAck] = useState(false), [uncertain, setUncertain] = useState(false);
  const [derivedAck, setDerivedAck] = useState(false);
  const intent = useRef<Intent | null>(null), expiry = useReviewDeadline();
  const ids = idsText.split(/[\s,]+/).filter(Boolean), validIds = ids.length > 0 && ids.length <= 16 && new Set(ids).size === ids.length && ids.every(id => uuid.test(id));
  const durationMs = /^\d+(\.\d{1,3})?$/.test(duration) ? Math.round(Number(duration) * 1000) : 0;
  const grantExpiry = preview ? Math.min(preview.source_expires_at_ms, preview.server_time_ms + durationMs) : 0;
  const clearReview = () => { setPreview(null); setAck(false); setLimitsAck(false); setDerivedAck(false); expiry.clear(); };
  useUnconfirmed(!!uncertain);
  const clearIntent = () => { intent.current = null; setUncertain(false); };
  function acceptPreview(value: Preview, started: number, token: number) {
    if (!value || !uuid.test(value.id) || !positive(value.state_version) || !sha.test(value.scope_sha256) || !assetList(value.assets)
      || !positive(value.server_time_ms) || !positive(value.source_expires_at_ms) || !positive(value.max_lifetime_ms) || value.max_lifetime_ms > 31536000000
      || typeof value.can_confirm !== 'boolean' || !value.notice || !sha.test(value.notice.sha256) || typeof value.notice.text !== 'string'
      || (value.permission_id !== null && !uuid.test(value.permission_id))) throw new Error('Improvement scope information is unavailable.');
    setPreviewId(value.id); setPreview(value); setReviewStarted(started); setNotice(value.notice); setAck(false); setLimitsAck(false); setDerivedAck(false);
    if (value.can_confirm) expiry.bound(started, value.remaining_review_ms, 60000, token);
  }
  async function loadNotice() {
    clearReview(); setNotice(null); await fresh(user, 'owner');
    const result = await call<{ notice: Notice }>('/privacy/improvement-options');
    if (!result.notice || !sha.test(result.notice.sha256) || !result.notice.text || !result.notice.version) throw new Error('Separate improvement notice is unavailable.');
    setNotice(result.notice); say('Read the separate optional-use notice. Normal operation does not require this grant.');
  }
  async function readPermission(id = permissionId) {
    setSelected(null); setWithdrawAck(false); await fresh(user); const value = permission(await call<Permission>('/privacy/improvement-permissions/' + id));
    if (value.id !== id) throw new Error('Permission identity changed.'); setPermissionId(id); setSelected(value);
    if (intent.current?.kind === 'withdraw' && intent.current.path === '/privacy/improvement-permissions/' + value.id + '/withdraw' && value.withdrawn) clearIntent();
  }
  async function readPreview() {
    clearReview(); await fresh(user, 'owner'); const started = performance.now(), token = expiry.token();
    const value = await call<Preview>('/privacy/improvement-previews/' + previewId);
    if (value.id !== previewId) throw new Error('Preview identity changed.'); acceptPreview(value, started, token);
    if (value.permission_id) {
      await readPermission(value.permission_id);
      if (intent.current?.kind === 'confirm' && (intent.current.body as { preview_id?: string })?.preview_id === value.id) clearIntent();
    }
  }
  async function send(value: Intent) {
    intent.current = value; setUncertain(false); setAck(false); setLimitsAck(false); setWithdrawAck(false);
    const started = performance.now(), token = expiry.token();
    try {
      const live = await fresh(user, 'owner');
      const result = await call<Preview | Permission>(value.path, { user: live, method: 'POST', body: value.body, version: value.version, idempotencyKey: value.key });
      if (value.kind === 'preview') {
        const review = result as Preview;
        if (!assetList(review.assets) || JSON.stringify(review.assets.map(a => a.id).sort()) !== JSON.stringify((value.body as { asset_ids: string[] }).asset_ids.slice().sort())) throw new Error('Reviewed scope changed.');
        acceptPreview(review, started, token);
      } else {
        const current = permission(result as Permission);
        if ((value.kind === 'confirm' && (current.scope_sha256 !== (value.body as { confirmed_scope_sha256: string }).confirmed_scope_sha256 || current.derived_review_metadata_allowed !== (value.body as { derived_review_metadata_acknowledged: boolean }).derived_review_metadata_acknowledged))
          || (value.kind === 'withdraw' && value.path !== '/privacy/improvement-permissions/' + current.id + '/withdraw')) throw new Error('Permission scope changed.');
        setPermissionId(current.id); setSelected(current); clearReview();
      }
      clearIntent(); say(value.kind === 'withdraw' ? 'Withdrawal recorded. Future dependent uses must stop; received copies cannot be recalled.' : value.kind === 'confirm' ? 'Separate owner attestation recorded. No data was trained on or published.' : 'Review the exact assets, notice and expiry before confirming.');
    } catch { setUncertain(true); say('Outcome unconfirmed. Retry the unchanged request or recover through the recorded preview/permission ID before another intent.'); }
  }
  async function write(kind: Intent['kind']) {
    if (intent.current) return;
    if (kind === 'preview' && notice && validIds) await send({ kind, path: '/privacy/improvement-previews', body: { asset_ids: ids }, key: crypto.randomUUID() });
    if (kind === 'confirm' && preview && ack && limitsAck && expiry.valid) {
      expiry.clear(); await send({ kind, path: '/privacy/improvement-permissions', version: preview.state_version, key: crypto.randomUUID(), body: {
        preview_id: preview.id, confirmed_scope_sha256: preview.scope_sha256, documented_permission_reference: reference,
        notice_version: preview.notice.version, notice_sha256: preview.notice.sha256, optional_improvement_acknowledged: true, limitations_acknowledged: true, derived_review_metadata_acknowledged: derivedAck, expires_at_ms: grantExpiry } });
    }
    if (kind === 'withdraw' && selected && withdrawAck) await send({ kind, path: '/privacy/improvement-permissions/' + selected.id + '/withdraw', version: selected.state_version, key: crypto.randomUUID() });
  }
  async function list(next = false) {
    await fresh(user); const result = await call<{ permissions: Permission[]; next_cursor: string | null }>('/privacy/improvement-permissions' + (next && cursor ? '?cursor=' + cursor : ''));
    if (!Array.isArray(result.permissions) || result.permissions.length > 20 || (result.next_cursor !== null && !uuid.test(result.next_cursor))) throw new Error('Permission page is unavailable.');
    setItems(result.permissions.map(permission)); setCursor(result.next_cursor);
  }
  const canConfirm = !!preview?.can_confirm && expiry.valid && ack && limitsAck && /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(reference)
    && Number.isSafeInteger(durationMs) && durationMs > 0 && durationMs <= preview.max_lifetime_ms && performance.now() < reviewStarted + grantExpiry - preview.server_time_ms;
  return <section aria-labelledby="improvement-title"><h3 id="improvement-title">Optional improvement permissions</h3><p role="status">{message}</p>
    <p>Refusing optional use leaves normal authorized operation available. This records a scoped owner attestation; it does not certify consent, independent truth, publicity or a learning benefit.</p>
    <p>Recording or withdrawing a grant changes data authority. Affected inspections need fresh verification; no current result is renewed.</p>
    {owner && <><fieldset disabled={busy || uncertain}><legend>Review separate optional use</legend>
      <button onClick={() => void perform(loadNotice)}>Load improvement notice</button>
      {notice && <p>Separate notice {notice.version}: {notice.text} Notice SHA-256: {notice.sha256}.</p>}
      <label>Selected improvement asset IDs<textarea value={idsText} onChange={e => { setIdsText(e.target.value); clearReview(); }} maxLength={600}/></label>
      <button disabled={!notice || !validIds} onClick={() => void perform(() => write('preview'))}>Preview optional improvement scope</button>
    </fieldset>
    <fieldset disabled={busy}><legend>Recover a reviewed scope</legend><label>Improvement preview ID<input value={previewId} maxLength={36} onChange={e => { setPreviewId(e.target.value); clearReview(); }}/></label>
      <button disabled={!uuid.test(previewId)} onClick={() => void perform(readPreview)}>Read improvement preview</button></fieldset>
    {preview && <fieldset disabled={busy || uncertain}><legend>Confirm reviewed optional use</legend><p>Scope SHA-256: {preview.scope_sha256}. Status: {preview.status}.</p>
      <ul>{preview.assets.map(a => <li key={a.id}>{a.kind} {a.id}; origin {a.data_origin}; SHA-256 {a.sha256}; original permission {a.source_permission_reference}.</li>)}</ul>
      <label>Documented optional permission reference<input value={reference} maxLength={64} onChange={e => { setReference(e.target.value); setAck(false); setLimitsAck(false); setDerivedAck(false); }}/></label>
      <label>Permission duration in seconds<input inputMode="decimal" value={duration} maxLength={16} onChange={e => { setDuration(e.target.value); setAck(false); setLimitsAck(false); setDerivedAck(false); }}/></label>
      <p>Duration starts at the reviewed server time and is capped by source expiry. Chosen expiry: {Number.isSafeInteger(grantExpiry) && grantExpiry > 0 && grantExpiry <= 8640000000000000 ? new Date(grantExpiry).toISOString() : 'unavailable'}. Review: {expiry.valid ? 'within original validity' : 'expired or interrupted'}.</p>
      <label className="check"><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)}/>I hold documented authorization for optional improvement use of these exact assets.</label>
      <label className="check"><input type="checkbox" checked={limitsAck} onChange={e => setLimitsAck(e.target.checked)}/>This use is optional and revocable; it does not authorize publicity or certify truth or independence.</label>
      <label className="check"><input type="checkbox" checked={derivedAck} onChange={e => { setDerivedAck(e.target.checked); setAck(false); setLimitsAck(false); }}/>I also hold documented optional-use authorization for associated outcome counts, review method and duration metadata. This is needed for labelled datasets.</label>
      <button disabled={!canConfirm} onClick={() => void perform(() => write('confirm'))}>Confirm optional improvement permission</button>
    </fieldset>}</>}
    <fieldset disabled={busy}><legend>Recorded optional permissions</legend><button onClick={() => void perform(() => list())}>List improvement permissions</button>
      <button disabled={!cursor} onClick={() => void perform(() => list(true))}>Next improvement permission page</button>
      <ul>{items.map(item => <li key={item.id}><button onClick={() => void perform(() => readPermission(item.id))}>Read improvement permission {item.id}</button></li>)}</ul>
      <label>Improvement permission ID<input value={permissionId} maxLength={36} onChange={e => { setPermissionId(e.target.value); setSelected(null); setWithdrawAck(false); }}/></label>
      <button disabled={!uuid.test(permissionId)} onClick={() => void perform(() => readPermission())}>Read improvement permission</button>
      {selected && <><p>Permission {selected.id}; version {selected.state_version}. Withdrawn: {selected.withdrawn ? 'yes' : 'no'}. Usable: {selected.usable ? 'yes' : 'no'}. Held reason: {selected.held_reason ?? 'none'}. Truth, independence and publicity: not authorized or certified.</p>
        <p>Grant SHA-256: {selected.grant_sha256}. Documented reference: {selected.documented_permission_reference}.</p>
        <p>Associated review metadata allowed: {selected.derived_review_metadata_allowed ? 'yes' : 'no'}.</p>
        <p>Recorded notice {selected.notice.version}: {selected.notice.text} Notice SHA-256: {selected.notice.sha256}. Expires: {selected.expires_at_ms <= 8640000000000000 ? new Date(selected.expires_at_ms).toISOString() : 'unavailable'}.</p>
        <ul>{selected.assets.map(a => <li key={a.id}>{a.kind} {a.id}; origin {a.data_origin}; SHA-256 {a.sha256}; original permission {a.source_permission_reference}.</li>)}</ul>
        {owner && <><label className="check"><input type="checkbox" checked={withdrawAck} disabled={uncertain || selected.withdrawn} onChange={e => setWithdrawAck(e.target.checked)}/>Stop future improvement use; already received copies cannot be recalled.</label>
          <button disabled={uncertain || !withdrawAck || selected.withdrawn} onClick={() => void perform(() => write('withdraw'))}>Withdraw optional improvement permission</button></>}
      </>}
    </fieldset>
    {uncertain && <><p>Keep the preview and permission IDs. Leaving loses this local request, and cannot undo a committed grant or withdrawal.</p><button disabled={busy} onClick={() => void perform(() => intent.current ? send(intent.current) : Promise.resolve())}>Retry unchanged improvement request</button></>}
  </section>;
}
