import { useEffect, useRef, useState } from 'react';
import type { User } from './api';
import { ApiError } from './api';
import { positive, sha, useTasks, uuid } from './workbench';
import { correctionValue, regionText, selectedRegions, type CorrectionReference, type CorrectionRequest } from './correctionReference';

type Asset = { id: string; state_version: number; kind: string; sha256: string; binding_sha256: string; byte_length: number; content_type: string;
  data_origin: string; remaining_validity_ms: number; can_download: boolean; historical: boolean; machine_pass: boolean; storage_verified: boolean; derivation?: string | null;
  observation_id?: string | null; inspection_id?: string | null; correction_reference?: CorrectionReference };
function valid(value: Asset) { return !!value && uuid.test(value.id) && positive(value.state_version) && sha.test(value.sha256) && sha.test(value.binding_sha256)
  && positive(value.byte_length) && value.byte_length <= 2097152 && ['image/jpeg', 'image/png'].includes(value.content_type)
  && ['reference', 'inspection_evidence'].includes(value.kind) && ['synthetic', 'printable', 'physical'].includes(value.data_origin)
  && typeof value.can_download === 'boolean' && value.historical === true && value.machine_pass === false && value.storage_verified === false
  && positive(value.remaining_validity_ms) && value.remaining_validity_ms <= 60000
  && (value.derivation == null || ['rectified_roi_jpeg','original_transmitted_frame'].includes(value.derivation)); }

export function EvidencePanel({ user, seedInspection = '', correction }: { user: User; seedInspection?: string; correction?: CorrectionRequest }) {
  const { busy, message, call, perform, say } = useTasks('Inspect permitted historical evidence. Metadata alone does not prove storage or physical truth.');
  const [id, setId] = useState(''), [inspection, setInspection] = useState(seedInspection), [asset, setAsset] = useState<Asset | null>(null), [image, setImage] = useState<string | null>(null);
  const [originals, setOriginals] = useState<Asset[] | null>(null);
  const generation = useRef(0), until = useRef(0), blobURL = useRef<string | null>(null), active = useRef(true), controller = useRef<AbortController | null>(null);
  function clear() {
    generation.current++; until.current = 0; controller.current?.abort(); controller.current = null;
    if (blobURL.current) URL.revokeObjectURL(blobURL.current); blobURL.current = null;
    if (active.current) { setImage(null); setAsset(null); setOriginals(null); }
  }
  useEffect(() => {
    active.current = true;
    const hide = () => { if (document.visibilityState !== 'visible') clear(); }, offline = () => clear();
    const timer = window.setInterval(() => { if (until.current && performance.now() >= until.current) { clear(); say('Historical preview expired. Refresh permitted metadata before viewing again.'); } }, 100);
    document.addEventListener('visibilitychange', hide); window.addEventListener('offline', offline);
    return () => { active.current = false; clear(); window.clearInterval(timer); document.removeEventListener('visibilitychange', hide); window.removeEventListener('offline', offline); };
  }, []);
  function current(token: number) { return active.current && token === generation.current && document.visibilityState === 'visible' && navigator.onLine; }
  async function load(latest: boolean, selectedId = id) {
    clear(); if (!uuid.test(latest ? inspection : selectedId)) throw new Error('Enter a valid inspection or asset ID.');
    const token = generation.current, started = performance.now();
    const value = await call<Asset>(latest ? '/inspections/' + inspection + '/evidence' : '/assets/' + selectedId);
    if (!current(token) || !valid(value) || (!latest && value.id !== selectedId)) throw new Error('Evidence metadata is mismatched or review was interrupted.');
    if (value.correction_reference) correctionValue(value.correction_reference, value);
    if (correction && (value.inspection_id !== correction.inspection_id || value.observation_id !== correction.observation_id
      || !value.correction_reference || !selectedRegions(value.correction_reference, correction).length)) throw new Error('This retained frame does not match the pending measured correction. Refresh the inspection or use manual review.');
    until.current = started + value.remaining_validity_ms;
    if (until.current <= performance.now()) throw new Error('Evidence review expired. Refresh metadata.');
    setAsset(value); setId(value.id); say(value.can_download ? 'Permitted historical metadata loaded. Viewing bytes is a separate authenticated request.' : 'Metadata only. Your current grant does not permit these image bytes.');
  }
  async function discoverOriginals() {
    clear(); if (!uuid.test(inspection)) throw new Error('Enter a valid inspection ID.');
    const token = generation.current, started = performance.now();
    const value = await call<{ inspection_id: string; originals: Asset[]; remaining_validity_ms: number; historical: boolean; machine_pass: boolean }>('/inspections/' + inspection + '/evidence/originals');
    if (!current(token) || value.inspection_id !== inspection || value.historical !== true || value.machine_pass !== false
      || !positive(value.remaining_validity_ms) || value.remaining_validity_ms > 60000 || !Array.isArray(value.originals) || value.originals.length > 3
      || value.originals.some(item => !valid(item) || item.kind !== 'inspection_evidence' || item.derivation !== 'original_transmitted_frame')
      || new Set(value.originals.map(item => item.id)).size !== value.originals.length)
      throw new Error('Original-image discovery is mismatched or unavailable. Refresh current permitted metadata.');
    until.current = Math.min(started + value.remaining_validity_ms, ...value.originals.map(item => started + item.remaining_validity_ms));
    if (until.current <= performance.now()) throw new Error('Original-image metadata expired. Refresh before review.');
    setOriginals(value.originals); say(value.originals.length ? 'Selected original metadata loaded. Open one for a fresh permission check; no image has been downloaded.' : 'No retained originals are linked. Crop-only history is not full-frame replay input.');
  }
  async function view() {
    if (!asset || !asset.can_download || !until.current || performance.now() >= until.current) throw new Error('Refresh permitted evidence metadata.');
    if (blobURL.current) URL.revokeObjectURL(blobURL.current); blobURL.current = null; setImage(null);
    const token = generation.current, started = performance.now(), abort = new AbortController(); controller.current = abort;
    const timer = window.setTimeout(() => abort.abort(), 7000);
    try {
      const response = await fetch('/api/v1/assets/' + asset.id + '/download', { credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: abort.signal });
      if (!response.ok) throw new ApiError(response.status);
      const remaining = Number(response.headers.get('x-remaining-validity-ms')), length = Number(response.headers.get('content-length'));
      if (response.headers.get('x-asset-id') !== asset.id || Number(response.headers.get('x-asset-state-version')) !== asset.state_version
        || response.headers.get('x-content-sha256') !== asset.sha256 || response.headers.get('x-evidence-binding-sha256') !== asset.binding_sha256
        || response.headers.get('x-evidence-historical') !== 'true' || response.headers.get('content-type')?.split(';')[0] !== asset.content_type
        || !positive(remaining) || remaining > 60000 || length !== asset.byte_length || !response.body) throw new Error('Evidence response does not match the reviewed metadata.');
      const deadline = Math.min(until.current, started + remaining), reader = response.body.getReader(), chunks: ArrayBuffer[] = []; let size = 0;
      try {
        while (true) {
          const item = await reader.read(); if (item.done) break;
          size += item.value.byteLength;
          if (size > length || size > 2097152 || performance.now() >= deadline || !current(token)) throw new Error('Evidence bytes exceeded their permitted size, time or context.');
          chunks.push(new Uint8Array(item.value).buffer);
        }
      } finally { await reader.cancel(); reader.releaseLock(); }
      const blob = new Blob(chunks, { type: asset.content_type });
      const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', await blob.arrayBuffer()))].map(value => value.toString(16).padStart(2, '0')).join('');
      if (size !== length || hash !== asset.sha256 || !current(token) || performance.now() >= deadline) throw new Error('Evidence integrity or current read permission could not be confirmed.');
      if (asset.correction_reference) {
        const decoded = await createImageBitmap(blob);
        try { if (decoded.width !== asset.correction_reference.width || decoded.height !== asset.correction_reference.height) throw new Error('Correction geometry does not match the verified image dimensions.'); }
        finally { decoded.close(); }
        if (!current(token) || performance.now() >= deadline) throw new Error('Correction reference review expired or was interrupted.');
      }
      until.current = deadline; blobURL.current = URL.createObjectURL(blob); setImage(blobURL.current);
      say('Retained historical image verified against its receipt. This is not a current result or independent physical truth.');
    } catch (error) { clear(); throw error; }
    finally { window.clearTimeout(timer); controller.current = null; }
  }
  return <section aria-labelledby="evidence-title"><h3 id="evidence-title">Retained evidence</h3><p role="status">{message}</p>
    <p>Signed in as {user.display_name}. Historical images do not authorize packing or shipment. Each new read checks your current grant and data purpose. Delivered bytes, screenshots and copies cannot be recalled.</p>
    {correction ? <><p>Correction reference for the captured observation {correction.observation_id}. The camera is stopped. This image is historical and cannot restore current approval.</p>
      <button disabled={busy} onClick={() => void perform(() => load(true))}>Load measured correction reference</button></> : <>
    <label>Inspection ID for latest evidence<input disabled={busy} value={inspection} onChange={event => { clear(); setInspection(event.target.value.trim()); }}/></label>
    <button disabled={busy} onClick={() => void perform(() => load(true))}>Load latest inspection evidence</button>
    <button disabled={busy} onClick={() => void perform(discoverOriginals)}>Find selected original images</button>
    {originals && originals.length > 0 && <ul>{originals.map(item => <li key={item.id}>Original transmitted image · {item.byte_length} bytes · origin {item.data_origin}. <button disabled={busy} onClick={() => void perform(() => load(false, item.id))}>Review original {item.id}</button></li>)}</ul>}
    <label>Retained asset ID<input disabled={busy} value={id} onChange={event => { clear(); setId(event.target.value.trim()); }}/></label>
    <button disabled={busy} onClick={() => void perform(() => load(false))}>Load evidence metadata</button>
    </>}
    {asset && <div><p>{asset.derivation === 'original_transmitted_frame' ? 'Original transmitted image' : asset.derivation === 'rectified_roi_jpeg' ? 'Rectified work-area crop' : asset.kind} · origin {asset.data_origin} · {asset.byte_length} bytes · SHA-256 {asset.sha256}. Historical; no machine pass.</p>
      <button disabled={busy || !asset.can_download} onClick={() => void perform(view)}>View retained image</button>{!asset.can_download && <p>An explicit scoped media grant is required. Owner status alone does not grant other people’s image access.</p>}</div>}
    {image && <figure><div className="measured-reference" style={asset?.correction_reference ? { width: asset.correction_reference.width, maxWidth: '100%' } : undefined}>
      <img src={image} alt="Retained historical evidence; not a current inspection result" style={asset?.correction_reference ? { width: '100%', display: 'block' } : { maxWidth: '100%', maxHeight: '32rem' }}/>
      {asset?.correction_reference && <><svg viewBox={`0 0 ${asset.correction_reference.width} ${asset.correction_reference.height}`} preserveAspectRatio="none" aria-hidden="true">
        {selectedRegions(asset.correction_reference, correction).map(region => <g key={region.candidate_index}><rect className="region-outline" x={region.box[0]} y={region.box[1]} width={region.box[2]} height={region.box[3]}/><rect className="region-line" x={region.box[0]} y={region.box[1]} width={region.box[2]} height={region.box[3]}/></g>)}
      </svg>{selectedRegions(asset.correction_reference, correction).map(region => <span className="region-number" aria-hidden="true" key={region.candidate_index} style={{ left: `${100 * region.box[0] / asset.correction_reference!.width}%`, top: `${100 * region.box[1] / asset.correction_reference!.height}%` }}>{region.candidate_index + 1}</span>)}</>}
      </div><figcaption>Retained historical image. Review its origin and limitations; perform a separate current manual check.</figcaption>
      {asset?.correction_reference && <><p>Numbered regions refer only to this verified crop, not the moving scene or current approval.</p><ul>{selectedRegions(asset.correction_reference, correction).map(region => <li key={region.candidate_index}>Region {region.candidate_index + 1}: {regionText(region)}</li>)}</ul></>}
    </figure>}
    <button onClick={() => { clear(); say('Historical image cleared. Refresh metadata for another view.'); }}>Clear retained image or cancel read</button>
  </section>;
}
