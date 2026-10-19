import { useState } from 'react';
import type { User } from './api';
import { RecipeQualificationPanel } from './RecipeQualificationPanel';
import { identifier, positive, sha, useReviewDeadline, useTasks, uuid } from './workbench';

type Constraint = { constraint_id: string; part_class_id: string; expected_count: number; dimension_mm: { minimum: number; maximum: number } | null;
  flat_reference_aspect_ratio?: { minimum: number; maximum: number } | null;
  permitted_variant_ids: string[]; required_visibility: string; unsupported_properties: string[] };
type Content = { name: string; kit_sku: string; calibration_profile_id: string; reference_asset_ids: string[]; data_origin: string; constraints: Constraint[] };
type Draft = { last_qualification_job_id?: string | null; id: string; revision: number; state_version: number; content: Content; retired: boolean; current: { effective_approved: boolean; active_revision: number | null } };
type Qualification = { id: string; recipe_id: string; recipe_revision: number; state_version: number; data_origin: string; passed: boolean;
  artifact_sha256: string; recipe_sha256: string; reviewer_id: string; environment: string; eligible_for_approval: boolean; reason_codes: string[]; remaining_qualification_ms: number };
const classes = ['washer', 'nut', 'bolt', 'flat_bracket'], origins = ['synthetic', 'printable', 'physical'];
const part = (name = 'washer'): Constraint => ({ constraint_id: crypto.randomUUID(), part_class_id: name, expected_count: 1,
  dimension_mm: null, permitted_variant_ids: [], required_visibility: 'Entire part visible, flat and separated', unsupported_properties: ['material', 'thread specification', 'hidden contents'] });
const blank = (): Content => ({ name: '', kit_sku: '', calibration_profile_id: '', reference_asset_ids: [], data_origin: 'synthetic', constraints: [part()] });
function validContent(value: Content) {
  return !!value && typeof value.name === 'string' && value.name.trim().length > 0 && value.name.length <= 100 && identifier.test(value.kit_sku)
    && identifier.test(value.calibration_profile_id) && origins.includes(value.data_origin) && Array.isArray(value.reference_asset_ids)
    && value.reference_asset_ids.length > 0 && value.reference_asset_ids.length <= 16 && value.reference_asset_ids.every(item => identifier.test(item))
    && new Set(value.reference_asset_ids).size === value.reference_asset_ids.length && Array.isArray(value.constraints) && value.constraints.length > 0 && value.constraints.length <= 4
    && new Set(value.constraints.map(item => item.part_class_id)).size === value.constraints.length
    && value.constraints.reduce((total, item) => total + item.expected_count, 0) <= 30
    && value.constraints.every(item => identifier.test(item.constraint_id) && classes.includes(item.part_class_id) && Number.isInteger(item.expected_count)
      && item.expected_count >= 0 && item.expected_count <= 20 && typeof item.required_visibility === 'string' && item.required_visibility.trim().length > 0
      && item.required_visibility.length <= 300 && Array.isArray(item.permitted_variant_ids) && item.permitted_variant_ids.every(variant => identifier.test(variant))
      && Array.isArray(item.unsupported_properties) && item.unsupported_properties.every(property => typeof property === 'string')
      && (!item.flat_reference_aspect_ratio || (Number.isFinite(item.flat_reference_aspect_ratio.minimum) && item.flat_reference_aspect_ratio.minimum >= 1
        && Number.isFinite(item.flat_reference_aspect_ratio.maximum) && item.flat_reference_aspect_ratio.maximum >= item.flat_reference_aspect_ratio.minimum && item.flat_reference_aspect_ratio.maximum <= 2000))
      && (item.dimension_mm === null || (Number.isFinite(item.dimension_mm.minimum) && item.dimension_mm.minimum >= 0
        && Number.isFinite(item.dimension_mm.maximum) && item.dimension_mm.maximum >= item.dimension_mm.minimum)));
}
export function RecipePanel({ user }: { user: User }) {
  const owner = user.roles.includes('owner'), { busy: taskBusy, message, call, perform, say, fresh } = useTasks('Review immutable recipe drafts and their existing qualification. A valid form is not qualification evidence.');
  const [candidates, setCandidates] = useState<{ id: string; name: string }[]>([]), [cursor, setCursor] = useState<string | null>(null), [selected, setSelected] = useState('');
  const [draft, setDraft] = useState<Draft | null>(null), [content, setContent] = useState<Content>(blank), [dirty, setDirty] = useState(false), [editing, setEditing] = useState(false);
  const [qualificationId, setQualificationId] = useState(''), [review, setReview] = useState<Qualification | null>(null), [confirmed, setConfirmed] = useState(false), [reason, setReason] = useState('');
  const [qualificationBusy, setQualificationBusy] = useState(false);
  const busy = taskBusy || qualificationBusy;
  const expiry = useReviewDeadline();
  const clear = () => { setReview(null); setConfirmed(false); expiry.clear(); };
  const edit = (value: Content) => { setContent(value); setDirty(true); clear(); };
  const constraint = (index: number, value: Partial<Constraint>) => edit({ ...content, constraints: content.constraints.map((item, i) => i === index ? { ...item, ...value } : item) });
  async function list(more = false) {
    await fresh(user, owner ? 'owner' : 'reviewer');
    const result = await call<{ recipes: { id: string; name: string }[]; next_cursor: string | null }>('/recipes?view=candidates&limit=20' + (more && cursor ? '&cursor=' + encodeURIComponent(cursor) : ''));
    if (!Array.isArray(result.recipes) || result.recipes.some(item => !uuid.test(item.id) || typeof item.name !== 'string')) throw new Error('Recipe catalog is unavailable.');
    setCandidates(old => more ? [...old.filter(item => !result.recipes.some(next => next.id === item.id)), ...result.recipes] : result.recipes); setCursor(result.next_cursor);
  }
  async function load(id = selected) {
    clear(); setDraft(null); setEditing(false); await fresh(user, owner ? 'owner' : 'reviewer');
    const result = await call<Draft>('/recipes/' + id + '/draft');
    if (result.id !== id || !positive(result.state_version) || !positive(result.revision) || !validContent(result.content)
      || typeof result.retired !== 'boolean' || !result.current || typeof result.current.effective_approved !== 'boolean') throw new Error('Recipe draft is unavailable.');
    setDraft(result); setContent(result.content); setSelected(id); setDirty(false); setEditing(true); setQualificationId('');
    say('Immutable draft loaded. Saving a revision does not approve it or replace an active recipe.');
  }
  async function save() {
    if (!validContent(content)) throw new Error('Check recipe fields: up to four distinct classes, 20 per class and 30 total; valid references, visibility and ordered dimensions are required.');
    clear(); const live = await fresh(user, 'owner');
    const result = await call<{ id: string; state_version: number }>(draft ? '/recipes/' + draft.id + '/draft' : '/recipes', {
      user: live, method: draft ? 'PUT' : 'POST', version: draft?.state_version, body: { content } });
    if (!uuid.test(result.id) || !positive(result.state_version)) throw new Error('Save outcome is unconfirmed. Refresh the catalog before another create.');
    setDirty(false); await load(result.id); await list(); say('Draft revision saved. It stays inactive until matching qualification and explicit owner approval.');
  }
  async function inspect() {
    clear(); if (!draft || dirty) return; await fresh(user, owner ? 'owner' : 'reviewer');
    const token = expiry.token(), started = performance.now(), result = await call<Qualification>('/recipes/' + draft.id + '/qualifications/' + qualificationId);
    if (result.id !== qualificationId || result.recipe_id !== draft.id || result.recipe_revision !== draft.revision || result.state_version !== draft.state_version
      || result.data_origin !== draft.content.data_origin || typeof result.passed !== 'boolean' || typeof result.eligible_for_approval !== 'boolean'
      || (result.eligible_for_approval && !result.passed) || !sha.test(result.artifact_sha256) || !sha.test(result.recipe_sha256)
      || !Array.isArray(result.reason_codes)) throw new Error('Qualification does not match this draft. Reload and review the current candidate.');
    expiry.bound(started, result.remaining_qualification_ms, Number.MAX_SAFE_INTEGER, token); setReview(result);
    say(result.eligible_for_approval ? 'Matching existing qualification loaded. Review origin, failures and provenance before approval.' : 'This qualification is not eligible for approval. Read the current job/report and keep this draft inactive.');
  }
  async function approve() {
    if (!draft || dirty || !confirmed || !review?.eligible_for_approval || !expiry.valid) return;
    const chosen = review; clear(); const live = await fresh(user, 'owner');
    await call('/recipes/' + draft.id + '/approve', { user: live, method: 'POST', version: draft.state_version, body: { qualification_id: chosen.id } });
    await load(draft.id); await list(); say('Owner approval recorded for the matching qualified revision. This is not beta launch approval.');
  }
  return <section aria-labelledby="recipes-title"><h3 id="recipes-title">Recipe drafts and qualification</h3><p role="status">{message}</p>
    <fieldset disabled={busy}><legend>Choose a candidate</legend><div className="toolbar"><button onClick={() => void perform(() => list())}>Load recipe candidates</button>{cursor && <button onClick={() => void perform(() => list(true))}>More recipe candidates</button>}
      {owner && <button disabled={dirty} onClick={() => { setDraft(null); setContent(blank()); setSelected(''); setEditing(true); setDirty(false); setQualificationId(''); clear(); }}>New recipe draft</button>}</div>
      <label>Recipe candidate<select value={selected} disabled={dirty} onChange={event => { setSelected(event.target.value); setDraft(null); setEditing(false); setQualificationId(''); clear(); }}><option value="">Choose recipe</option>{candidates.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
      <button disabled={!selected || dirty} onClick={() => void perform(() => load())}>Read recipe draft</button>
      {dirty && <><p>Unsaved edits. Previous qualification review has been cleared.</p><button onClick={() => { setContent(draft?.content ?? blank()); setDirty(false); clear(); }}>Discard unsaved edits</button></>}
    </fieldset>
    {editing && <><p>{draft ? 'Revision ' + draft.revision + ' · state version ' + draft.state_version + (draft.retired ? ' · retired' : '') : 'New inactive draft'}.</p>
      {draft && <p>Effective approved revision: {draft.current.effective_approved ? draft.current.active_revision : 'none'}. A draft does not replace this active binding.</p>}
      <fieldset disabled={busy || !owner}><legend>Recipe contents{!owner ? ' · read only for reviewer' : ''}</legend>
        <div className="form-grid"><label>Recipe name<input value={content.name} maxLength={100} onChange={event => edit({ ...content, name: event.target.value })}/></label><label>Kit SKU<input value={content.kit_sku} maxLength={64} onChange={event => edit({ ...content, kit_sku: event.target.value })}/></label><label>Calibration profile ID<input value={content.calibration_profile_id} maxLength={64} onChange={event => edit({ ...content, calibration_profile_id: event.target.value })}/></label>
          <label>Data origin<select value={content.data_origin} onChange={event => edit({ ...content, data_origin: event.target.value })}>{origins.map(origin => <option key={origin}>{origin}</option>)}</select></label></div>
        <label>Permitted reference asset IDs, comma separated<textarea value={content.reference_asset_ids.join(', ')} maxLength={1100} onChange={event => edit({ ...content, reference_asset_ids: event.target.value.split(',').map(value => value.trim()) })}/></label>
        <p>IDs must refer to genuine permitted records. Typing an ID does not upload, calibrate or qualify evidence. Physical recipes require physical qualification; synthetic demonstrations cannot qualify beta.</p>
        {content.constraints.map((item, index) => <fieldset key={item.constraint_id}><legend>Visible constraint {index + 1}</legend><div className="form-grid">
          <label>Part class {index + 1}<select value={item.part_class_id} onChange={event => constraint(index, { part_class_id: event.target.value })}>{classes.map(name => <option key={name} value={name}>{name.replaceAll('_', ' ')}</option>)}</select></label>
          <label>Expected count {index + 1}<input type="number" min={0} max={20} value={Number.isFinite(item.expected_count) ? item.expected_count : ''} onChange={event => constraint(index, { expected_count: event.target.value === '' ? Number.NaN : Number(event.target.value) })}/></label>
          <label>Required visibility {index + 1}<input value={item.required_visibility} maxLength={300} onChange={event => constraint(index, { required_visibility: event.target.value })}/></label></div>
          <label className="check"><input type="checkbox" checked={!!item.dimension_mm} onChange={event => constraint(index, { dimension_mm: event.target.checked ? { minimum: 0, maximum: 0 } : null })}/>Constrain measured dimension for part {index + 1}</label>
          {item.dimension_mm && <div className="form-grid"><label>Minimum millimetres {index + 1}<input type="number" min={0} step="any" value={Number.isFinite(item.dimension_mm.minimum) ? item.dimension_mm.minimum : ''} onChange={event => constraint(index, { dimension_mm: { ...item.dimension_mm!, minimum: event.target.value === '' ? Number.NaN : Number(event.target.value) } })}/></label><label>Maximum millimetres {index + 1}<input type="number" min={0} step="any" value={Number.isFinite(item.dimension_mm.maximum) ? item.dimension_mm.maximum : ''} onChange={event => constraint(index, { dimension_mm: { ...item.dimension_mm!, maximum: event.target.value === '' ? Number.NaN : Number(event.target.value) } })}/></label></div>}
          <p>Excluded properties: {item.unsupported_properties.join(', ')}.</p>
          <label className="check"><input type="checkbox" checked={!!item.flat_reference_aspect_ratio} onChange={event => constraint(index, { flat_reference_aspect_ratio: event.target.checked ? { minimum: Number.NaN, maximum: Number.NaN } : undefined })}/>Enroll a measured flat-reference aspect interval for part {index + 1}</label>
          {item.flat_reference_aspect_ratio && <><p>This compares the visible planar projection. It does not measure 3D flatness or height. Supply independently qualified reference bounds; saving is not approval.</p><div className="form-grid">
            <label>Minimum flat-reference aspect {index + 1}<input type="number" min={1} max={2000} step="any" value={Number.isFinite(item.flat_reference_aspect_ratio.minimum) ? item.flat_reference_aspect_ratio.minimum : ''} onChange={event => constraint(index, { flat_reference_aspect_ratio: { ...item.flat_reference_aspect_ratio!, minimum: event.target.value === '' ? Number.NaN : Number(event.target.value) } })}/></label>
            <label>Maximum flat-reference aspect {index + 1}<input type="number" min={1} max={2000} step="any" value={Number.isFinite(item.flat_reference_aspect_ratio.maximum) ? item.flat_reference_aspect_ratio.maximum : ''} onChange={event => constraint(index, { flat_reference_aspect_ratio: { ...item.flat_reference_aspect_ratio!, maximum: event.target.value === '' ? Number.NaN : Number(event.target.value) } })}/></label>
          </div></>}
          <label>Permitted variant IDs {index + 1}, comma separated<input value={item.permitted_variant_ids.join(', ')} maxLength={1100} onChange={event => constraint(index, { permitted_variant_ids: event.target.value.trim() ? event.target.value.split(',').map(value => value.trim()) : [] })}/></label>
          <button disabled={content.constraints.length <= 1} onClick={() => edit({ ...content, constraints: content.constraints.filter((_, i) => i !== index) })}>Remove constraint {index + 1}</button>
        </fieldset>)}
        <div className="toolbar"><button disabled={content.constraints.length >= 4} onClick={() => edit({ ...content, constraints: [...content.constraints, part(classes.find(name => !content.constraints.some(item => item.part_class_id === name)))] })}>Add visible constraint</button>
          <button disabled={!validContent(content) || (!!draft && !dirty)} onClick={() => void perform(save)}>Save inactive draft revision</button></div>
      </fieldset>
      {draft && !draft.retired && <RecipeQualificationPanel key={draft.id + ':' + draft.state_version} user={user} draft={draft} readOnly={!owner} disabled={taskBusy || dirty}
        onBusy={setQualificationBusy} onInvalidateReview={clear} onReview={async id => { await perform(async () => { clear(); await load(draft.id); setQualificationId(id); say('Draft reloaded. Review this qualification explicitly before any approval.'); }); }}/>}
      {draft && <fieldset disabled={busy || dirty}><legend>Existing qualification review</legend><label>Qualification run ID<input value={qualificationId} maxLength={36} onChange={event => { setQualificationId(event.target.value); clear(); }}/></label><button disabled={!uuid.test(qualificationId)} onClick={() => void perform(inspect)}>Review qualification</button>
        {review && <><p>{review.passed ? 'Recorded check passed' : 'Recorded check FAILED'} · {review.data_origin} · {review.environment}. Reviewer reference: {review.reviewer_id}; independence is not established by this identifier.</p><p>Recipe digest: {review.recipe_sha256}. {review.reason_codes.join(', ')}</p><p>{expiry.valid ? 'Review is within its original validity.' : 'Review expired or was cleared.'}</p>
          {owner && <><label className="check"><input type="checkbox" checked={confirmed} disabled={!review.eligible_for_approval || !expiry.valid} onChange={event => setConfirmed(event.target.checked)}/>I reviewed the qualification and intend to approve this exact draft.</label><button disabled={!confirmed || !review.eligible_for_approval || !expiry.valid} onClick={() => void perform(approve)}>Approve qualified revision</button></>}
        </>}
      </fieldset>}
      {owner && draft && <fieldset disabled={busy || dirty}><legend>Retire recipe</legend><label>Retirement reason<input value={reason} maxLength={120} onChange={event => setReason(event.target.value)}/></label><button disabled={!reason.trim()} onClick={() => void perform(async () => { clear(); const live = await fresh(user, 'owner'); await call('/recipes/' + draft.id + '/retire', { user: live, method: 'POST', version: draft.state_version, body: { reason: reason.trim() } }); await load(draft.id); await list(); say('Recipe retired. Prior live approvals cannot be reused.'); })}>Retire this recipe</button></fieldset>}
    </>}
    <p>Physical qualification and complete replay/privacy workflows remain unavailable. Reviewers prepare findings; owner permission is required for configuration writes.</p>
  </section>;
}
