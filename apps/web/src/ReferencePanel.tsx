import { useEffect, useRef, useState } from 'react';
import type { User } from './api';
import { blobSha256, identifier, positive, sha, useTasks, uuid } from './workbench';

type Notice = { version: string; text: string; sha256: string; optional_improvement_default: boolean; optional_publicity_default: boolean };
type Options = { max_lifetime_ms: number; server_time_ms: number; notice: Notice; original_capture_notice?: { version: string; sha256: string; text: string } };
type Purpose = { id: string; state_version: number; withdrawn: boolean; expires_at_ms: number; source_permission_reference: string;
  notice_version: string; notice_sha256: string; allowed_uses: string[]; rights_independently_verified: boolean; optional_improvement: boolean; optional_publicity: boolean;
  original_capture_retention_allowed?: boolean; original_capture_notice_sha256?: string | null };
type Reference = { id: string; purpose_id: string; status: string; data_origin: string; origin_basis: string; physical_truth_verified: boolean;
  sha256: string; source_sha256: string; width: number; height: number; byte_length: number; expires_at_ms: number; operation_status?: string; requires_reconciliation?: boolean };
function purposeValue(value: Purpose): Purpose {
  if (!value || !uuid.test(value.id) || !positive(value.state_version) || !positive(value.expires_at_ms) || !identifier.test(value.source_permission_reference)
    || typeof value.withdrawn !== 'boolean' || !Array.isArray(value.allowed_uses) || value.allowed_uses.join(',') !== 'operation'
    || value.rights_independently_verified !== false || value.optional_improvement !== false || value.optional_publicity !== false
    || !sha.test(value.notice_sha256) || !value.notice_version
    || (value.original_capture_retention_allowed !== undefined && typeof value.original_capture_retention_allowed !== 'boolean')
    || (value.original_capture_retention_allowed === true && !sha.test(value.original_capture_notice_sha256 ?? ''))) throw new Error('Operational purpose information is unavailable.');
  return value;
}
export function ReferencePanel({ user, onEnroll }: { user: User; onEnroll: (id: string) => void }) {
  const owner = user.roles.includes('owner'), { busy, message, call, perform, say, fresh } = useTasks('Reference photos need a current recorded operational purpose. Declared origin is not verified physical truth.');
  const [options, setOptions] = useState<Options | null>(null), [permission, setPermission] = useState(''), [seconds, setSeconds] = useState(''), [ack, setAck] = useState(false);
  const [originalAck, setOriginalAck] = useState(false);
  const [purpose, setPurpose] = useState<Purpose | null>(null), [purposeId, setPurposeId] = useState(''), [withdraw, setWithdraw] = useState(false);
  const [file, setFile] = useState<File | null>(null), [preview, setPreview] = useState(''), [previewReady, setPreviewReady] = useState(false), [origin, setOrigin] = useState('synthetic'), [uploadAck, setUploadAck] = useState(false);
  const [assetId, setAssetId] = useState(''), [reference, setReference] = useState<Reference | null>(null), [fileKey, setFileKey] = useState(0);
  const [purposes, setPurposes] = useState<Purpose[]>([]), [cursor, setCursor] = useState<string | null>(null);
  const pendingPurpose = useRef<{ signature: string; body: object } | null>(null);
  useEffect(() => {
    if (!file) { setPreview(''); return; }
    const url = URL.createObjectURL(file); setPreview(url);
    return () => URL.revokeObjectURL(url);
  }, [file]);
  function resetFile() { setFile(null); setPreviewReady(false); setUploadAck(false); setFileKey(value => value + 1); }
  async function policy() {
    await fresh(user, 'owner'); const value = await call<Options>('/purposes/options');
    if (!positive(value.max_lifetime_ms) || !positive(value.server_time_ms) || !value.notice || !sha.test(value.notice.sha256)
      || typeof value.notice.text !== 'string' || !value.notice.version || value.notice.optional_improvement_default !== false || value.notice.optional_publicity_default !== false
      || (value.original_capture_notice !== undefined && (!value.original_capture_notice || !value.original_capture_notice.version
        || !sha.test(value.original_capture_notice.sha256) || typeof value.original_capture_notice.text !== 'string' || !value.original_capture_notice.text.trim())))
      throw new Error('Finalized operational notice and explicit lifetime configuration are required.');
    return value;
  }
  async function create() {
    if (!options || !ack || !identifier.test(permission) || !Number.isSafeInteger(Number(seconds)) || Number(seconds) < 1 || Number(seconds) * 1000 > options.max_lifetime_ms) return;
    const retainOriginal = originalAck;
    if (retainOriginal && !options.original_capture_notice) throw new Error('Read the separate original-image notice.');
    setAck(false); setOriginalAck(false); const current = await policy();
    if (current.notice.sha256 !== options.notice.sha256 || current.notice.version !== options.notice.version || current.max_lifetime_ms !== options.max_lifetime_ms
      || (retainOriginal && (current.original_capture_notice?.sha256 !== options.original_capture_notice?.sha256 || current.original_capture_notice?.version !== options.original_capture_notice?.version))) {
      setOptions(current); throw new Error('Notice or lifetime limits changed. Review them and acknowledge again.');
    }
    const live = await fresh(user, 'owner'), signature = JSON.stringify([options.notice.version, options.notice.sha256, permission, seconds, retainOriginal, retainOriginal ? options.original_capture_notice?.sha256 : null]);
    if (pendingPurpose.current?.signature !== signature) pendingPurpose.current = { signature, body: { notice_version: options.notice.version,
      notice_sha256: options.notice.sha256, source_permission_reference: permission, operational_use_acknowledged: true, expires_at_ms: current.server_time_ms + Number(seconds) * 1000,
      ...(retainOriginal ? { original_capture_retention_acknowledged: true, original_capture_notice_sha256: options.original_capture_notice!.sha256 } : {}) } };
    const value = purposeValue(await call<Purpose>('/purposes', { user: live, method: 'POST', body: pendingPurpose.current.body }));
    if ((value.original_capture_retention_allowed === true) !== retainOriginal || (retainOriginal && value.original_capture_notice_sha256 !== options.original_capture_notice?.sha256))
      throw new Error('Original-image attestation response is mismatched. Inspect the recorded purpose before a new request.');
    pendingPurpose.current = null;
    setPurpose(value); setPurposeId(value.id); setWithdraw(false); setUploadAck(false);
    say('Operational purpose recorded as your attestation. Optional reuse remains off; this does not certify rights or physical truth.');
  }
  async function readPurpose() {
    await fresh(user, owner ? 'owner' : 'reviewer'); setPurpose(null); setUploadAck(false); setWithdraw(false);
    setPurpose(purposeValue(await call<Purpose>('/purposes/' + purposeId)));
  }
  async function list(more = false) {
    await fresh(user, owner ? 'owner' : 'reviewer');
    const page = await call<{ purposes: Purpose[]; next_cursor: string | null }>('/purposes?limit=20' + (more && cursor ? '&cursor=' + encodeURIComponent(cursor) : ''));
    if (!Array.isArray(page.purposes)) throw new Error('Purpose list is unavailable.');
    const records = page.purposes.map(purposeValue);
    setPurposes(old => more ? [...old.filter(item => !records.some(next => next.id === item.id)), ...records] : records); setCursor(page.next_cursor);
  }
  function show(value: Reference) {
    if (!value || !uuid.test(value.id) || !uuid.test(value.purpose_id) || value.status !== 'committed' || !sha.test(value.sha256) || !sha.test(value.source_sha256)
      || !positive(value.width) || !positive(value.height) || value.width > 2000 || value.height > 2000 || value.width * value.height > 2000000
      || !positive(value.byte_length) || value.byte_length > 2097152 || value.physical_truth_verified !== false || value.origin_basis !== 'owner_declaration') throw new Error('Stored reference metadata is unavailable. Refresh before another upload.');
    setReference(value); setAssetId(value.id);
  }
  async function upload() {
    if (!purpose || !file || !previewReady || !uploadAck || purpose.withdrawn) return;
    setUploadAck(false); setReference(null); const live = await fresh(user, 'owner');
    const current = purposeValue(await call<Purpose>('/purposes/' + purpose.id));
    if (current.withdrawn || current.state_version !== purpose.state_version || current.expires_at_ms !== purpose.expires_at_ms) {
      setPurpose(current); throw new Error('Operational purpose changed. Review current permissions before uploading.');
    }
    const form = new FormData(); form.append('image', file, 'reference'); form.append('metadata', JSON.stringify({ purpose_id: purpose.id,
      source_permission_reference: purpose.source_permission_reference, data_origin: origin, expires_at_ms: purpose.expires_at_ms }));
    const sourceHash = await blobSha256(file);
    const result = await call<Reference>('/reference-assets', { user: live, method: 'POST', body: form });
    if (result.operation_status !== 'committed') {
      say('Original reference operation is ' + (result.operation_status ?? 'unconfirmed') + '. Ask the owner to reconcile it; this retry did not process or store another image.'); return;
    }
    if (result.purpose_id !== purpose.id || result.data_origin !== origin || result.expires_at_ms !== purpose.expires_at_ms || result.source_sha256 !== sourceHash)
      throw new Error('Reference acknowledgment does not match this image or purpose. Review current server records before another upload.');
    show(result); resetFile(); say('Verified reference stored privately. Saving a reference does not approve calibration, a recipe, beta use or physical truth.');
  }
  return <section aria-labelledby="references-title"><h3 id="references-title">Reference media and purposes</h3><p role="status">{message}</p>
    {owner && <fieldset disabled={busy}><legend>Record operational use</legend><button onClick={() => void perform(async () => { setAck(false); setOriginalAck(false); setOptions(await policy()); })}>Read reference-use notice</button>
      {options && <><h4>Notice · {options.notice.version}</h4><p className="notice-text">{options.notice.text}</p><p>Maximum configured lifetime: {Math.floor(options.max_lifetime_ms / 1000)} seconds. Improvement and publicity permissions remain off.</p>
        <div className="form-grid"><label>Source permission reference<input maxLength={64} value={permission} onChange={event => { setPermission(event.target.value); setAck(false); setOriginalAck(false); }}/></label><label>Operational-use duration in seconds<input type="number" min={1} max={Math.floor(options.max_lifetime_ms / 1000)} value={seconds} onChange={event => { setSeconds(event.target.value); setAck(false); setOriginalAck(false); }}/></label></div>
        {options.original_capture_notice && <><h4>Selected original images · {options.original_capture_notice.version}</h4><p>{options.original_capture_notice.text}</p>
          <label className="check"><input type="checkbox" checked={originalAck} onChange={event => setOriginalAck(event.target.checked)}/>I separately attest permission for operators to select original transmitted images under this notice. Leave off for ordinary checking.</label>
          <p>This records a new purpose only. The administrator must explicitly configure its use; no inspection is enabled and improvement/publicity stay off.</p></>}
        <label className="check"><input type="checkbox" checked={ack} onChange={event => setAck(event.target.checked)}/>I have authority for this operational use and reviewed the current notice and retention deadline. This is my attestation, not independent certification.</label>
        <button disabled={!ack || !identifier.test(permission) || !positive(Number(seconds)) || Number(seconds) * 1000 > options.max_lifetime_ms} onClick={() => void perform(create)}>Record operational purpose</button>
      </>}
    </fieldset>}
    <fieldset disabled={busy}><legend>Review an existing purpose</legend><div className="toolbar"><button onClick={() => void perform(() => list())}>Load operational purposes</button>{cursor && <button onClick={() => void perform(() => list(true))}>More operational purposes</button>}</div>
      {purposes.length > 0 && <label>Recorded purpose<select value={purposes.some(item => item.id === purposeId) ? purposeId : ''} onChange={event => { setPurposeId(event.target.value); setPurpose(null); setUploadAck(false); setWithdraw(false); }}><option value="">Choose purpose</option>{purposes.map(item => <option key={item.id} value={item.id}>{item.source_permission_reference} · {item.withdrawn ? 'withdrawn' : 'recorded'} · {item.id}</option>)}</select></label>}
      <label>Operational purpose ID<input value={purposeId} maxLength={36} onChange={event => { setPurposeId(event.target.value); setPurpose(null); setUploadAck(false); setWithdraw(false); }}/></label><button disabled={!uuid.test(purposeId)} onClick={() => void perform(readPurpose)}>Read operational purpose</button>
      {purpose && <><p>Purpose: {purpose.id}. Permission reference: {purpose.source_permission_reference}. Version {purpose.state_version} · {purpose.withdrawn ? 'withdrawn' : 'recorded'} · expires {new Date(purpose.expires_at_ms).toISOString()}.</p><p>Operational use only. Independent rights verification: absent. No permission to publish or improve models is granted.</p>
        <p>Selected original-image retention attestation: {purpose.original_capture_retention_allowed === true ? 'recorded; each operator selection is separate' : 'off'}. Runtime configuration and release approval are separate.</p>
        {owner && !purpose.withdrawn && <><label className="check"><input type="checkbox" checked={withdraw} onChange={event => setWithdraw(event.target.checked)}/>Withdraw this purpose and invalidate future dependent use; this does not erase downloaded copies.</label><button disabled={!withdraw} onClick={() => void perform(async () => { setWithdraw(false); setUploadAck(false); setReference(null); const live = await fresh(user, 'owner'); setPurpose(purposeValue(await call<Purpose>('/purposes/' + purpose.id + '/withdraw', { user: live, method: 'POST', version: purpose.state_version }))); say('Purpose withdrawn. Future dependent use is denied; cleanup remains a separate obligation.'); })}>Withdraw operational purpose</button></>}
      </>}
    </fieldset>
    {owner && <fieldset disabled={busy}><legend>Upload a reference photo</legend><p>The entire selected image is uploaded. Keep faces, paperwork and third-party confidential material out. Only single-frame orientation-normalized JPEG/PNG up to 2 MiB, 2000 pixels per side and two million pixels total are supported. The server strips metadata and stores a canonical JPEG.</p>
      <label>Reference image<input key={fileKey} type="file" accept="image/jpeg,image/png" onChange={event => { setPreviewReady(false); setUploadAck(false); setReference(null); const selected = event.target.files?.[0]; if (selected && selected.size > 0 && selected.size <= 2097152 && ['image/jpeg','image/png'].includes(selected.type)) setFile(selected); else { resetFile(); say('Choose a JPEG or PNG no larger than 2 MiB.'); } }}/></label>
      {preview && <><p>Local selected-source preview; this is not a stored-image or physical-qualification result.</p><img className="reference-preview" src={preview} alt="Selected local reference photo" onLoad={() => setPreviewReady(true)} onError={() => { setPreviewReady(false); say('Local preview failed. Choose another supported file.'); }}/></>}
      <label>Declared reference origin<select value={origin} onChange={event => { setOrigin(event.target.value); setUploadAck(false); }}><option value="synthetic">Synthetic</option><option value="printable">Printable stand-in</option><option value="physical">Physical, owner declaration only</option></select></label>
      <label className="check"><input type="checkbox" checked={uploadAck} disabled={!purpose || purpose.withdrawn || !previewReady} onChange={event => setUploadAck(event.target.checked)}/>I reviewed the entire selected image and its recorded operational purpose. Declared origin cannot certify physical truth.</label>
      <div className="toolbar"><button disabled={!purpose || purpose.withdrawn || !previewReady || !uploadAck} onClick={() => void perform(upload)}>Store private reference</button><button onClick={resetFile}>Forget selected image</button></div>
    </fieldset>}
    <fieldset disabled={busy}><legend>Stored reference metadata</legend><label>Reference asset ID<input value={assetId} maxLength={36} onChange={event => { setAssetId(event.target.value); setReference(null); }}/></label><button disabled={!uuid.test(assetId)} onClick={() => void perform(async () => { setReference(null); await fresh(user, owner ? 'owner' : 'reviewer'); show(await call<Reference>('/reference-assets/' + assetId)); })}>Read reference metadata</button>
      {reference && <><p>Reference: {reference.id}. {reference.width} × {reference.height} pixels; {reference.byte_length} stored bytes. Declared origin: {reference.data_origin}. Physical truth: unverified.</p><p>Stored hash: {reference.sha256}. Input hash: {reference.source_sha256}.</p></>}
      {owner && reference && <button onClick={() => onEnroll(reference.id)}>Enroll camera from this reference</button>}
      <p>No object key, public link or stored image is exposed here. Image retrieval, cleanup/reconciliation and genuine physical calibration/recipe qualification remain incomplete.</p>
    </fieldset>
  </section>;
}
