import { test, expect, type Page } from '@playwright/test';
import { createHash } from 'node:crypto';

test('unconfirmed policy navigation requires an informed exit and can preserve exact retry', async ({ page }) => {
  const state = await policyFixture(page, { lostOnce: true }); await newPolicy(page);
  await page.getByRole('button', { name: 'Save policy draft', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry unchanged policy write', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Historical comparisons', exact: true }).click();
  const dialog = page.getByRole('alertdialog', { name: 'Leave unconfirmed work?' });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('button', { name: 'Leave and investigate', exact: true })).toBeDisabled();
  await dialog.getByRole('button', { name: 'Keep working here', exact: true }).click();
  await page.getByRole('button', { name: 'Retry unchanged policy write', exact: true }).click();
  await expect(page.getByText('Policy draft revision recorded.', { exact: false })).toBeVisible();
  expect(state.writes).toHaveLength(2); expect(state.writes[1]).toEqual(state.writes[0]);
});

const browserErrors = new WeakMap<Page, string[]>();
test.beforeEach(async ({ page }) => { const errors: string[] = []; browserErrors.set(page, errors); page.on('pageerror', error => errors.push(error.message)); });
test.afterEach(async ({ page }) => { expect(browserErrors.get(page)).toEqual([]); });

const ownerId = '10000000-0000-4000-8000-000000000001', targetId = '10000000-0000-4000-8000-000000000002';
const inviteId = '20000000-0000-4000-8000-000000000001', transferId = '30000000-0000-4000-8000-000000000001';
const recipeId = '40000000-0000-4000-8000-000000000001', qualificationId = '50000000-0000-4000-8000-000000000001', receiptId = '60000000-0000-4000-8000-000000000001';
const purposeId = '70000000-0000-4000-8000-000000000001', referenceId = '80000000-0000-4000-8000-000000000001';
const calibrationId = '90000000-0000-4000-8000-000000000001', enrollmentJob = '91000000-0000-4000-8000-000000000001', calibrationReport = '92000000-0000-4000-8000-000000000001', rejectedReference = '80000000-0000-4000-8000-000000000002';
const csrf = 'c'.repeat(43), capability = 'private-synthetic-capability', checks = { opencv5: true, storage: true, dependencies: true, authorization: true, worker: true, recovery: true, release_gates: true };
const labelBefore = '93000000-0000-4000-8000-000000000001', labelAfter = '93000000-0000-4000-8000-000000000002', labelAction = '94000000-0000-4000-8000-000000000001', labelId = '95000000-0000-4000-8000-000000000001';
async function fixture(page: Page, options: { role?: string; restricted?: boolean; failed?: boolean; ttl?: number; delay?: number; logoutFail?: boolean; denied?: boolean; noticeFail?: boolean; failedReadiness?: boolean; mismatchQualification?: boolean; ambiguousInvite?: boolean; ambiguousPurpose?: boolean; ambiguousReference?: boolean; physicalCalibration?: boolean; failedCalibration?: boolean; ambiguousEnrollment?: boolean; pendingCalibration?: boolean; ambiguousLabel?: boolean; mismatchedLabelContext?: boolean; ambiguousRecipeQualification?: boolean; failedRecipeCase?: boolean; physicalRecipeCase?: boolean; mismatchRecipeReport?: boolean; pendingRecipeQualification?: boolean; supersededRecipeQualification?: boolean } = {}) {
  const writes: { path: string; method: string; body: any; version?: string; key: string }[] = [];
  let restricted = options.restricted ?? false, signedOut = false, noticeChanged = false;
  let policyReads = 0;
  let originalNotice = false;
  let savedLabel: any = null, labelEpoch = 1;
  const sourceContext = (tuple: any) => ({ tuple, inspection_id: '96000000-0000-4000-8000-000000000001', data_origin: 'synthetic', artifact_sha256: 'a'.repeat(64),
    source_context_sha256: 'b'.repeat(64), data_epoch: labelEpoch, remaining_validity_ms: options.ttl ?? 30000, max_duration_ms: 60000,
    expected_classes: ['washer', 'nut', 'bolt', 'flat_bracket'], observations: [{ observation_id: tuple.before_observation_id, sequence: 1, findings: ['VIOLATED'], reason_codes: ['missing_part'] }] });
  const purpose = { id: purposeId, state_version: 1, withdrawn: false, expires_at_ms: Date.now() + 60000, source_permission_reference: 'owned-photo-1',
    notice_version: 'notice-v1', notice_sha256: 'd'.repeat(64), allowed_uses: ['operation'], rights_independently_verified: false, optional_improvement: false, optional_publicity: false };
  const reference = { id: referenceId, purpose_id: purposeId, status: 'committed', data_origin: 'synthetic', origin_basis: 'owner_declaration', physical_truth_verified: false,
    sha256: 'e'.repeat(64), source_sha256: 'f'.repeat(64), width: 64, height: 64, byte_length: 800, expires_at_ms: purpose.expires_at_ms, operation_status: 'committed' };
  if (options.physicalCalibration) reference.data_origin = 'physical';
  let calVersion = 1, calRevision = 1, calActive = false, calRetired = false, calStatus = 'draft', calReport: string | null = null, calLastJob = enrollmentJob;
  let calRequest = { name: 'Synthetic camera setup', camera_id: 'synthetic-camera', mat_version: 'desktop-v1', reference_asset_id: referenceId, data_origin: reference.data_origin,
    settings: { max_displacement_px: 2, max_reprojection_error_px: 1, measurement_error_mm: 0.5, min_area_px: 30, min_blur_variance: 1, threshold_gray: 127 } };
  const calDraft = () => ({ id: calibrationId, name: calRequest.name, camera_id: calRequest.camera_id, latest_revision: calRevision, state_version: calVersion,
    request: calRequest, profile_sha256: 'a'.repeat(64), profile: { frame_width: 800, frame_height: 500, output_width: 600, output_height: 300 },
    enrollment: { accepted: true, reason_codes: [], physical_truth_verified: false }, current: { effective_approved: calActive, active_revision: calActive ? calRevision : null },
    status: calStatus, retired: calRetired, last_job_id: calLastJob, report_id: calReport });
  const role = options.role ?? 'owner';
  const user = { id: role === 'owner' ? ownerId : targetId, display_name: 'Synthetic ' + role, roles: [role], csrf_token: csrf, session_id: 'synthetic-session' };
  let content = { name: 'Synthetic kit', kit_sku: 'KIT-1', calibration_profile_id: 'fixture-profile', reference_asset_ids: ['fixture-asset'], data_origin: 'synthetic',
    constraints: [{ constraint_id: 'washers', part_class_id: 'washer', expected_count: 2, dimension_mm: null, permitted_variant_ids: [], required_visibility: 'Flat and separated', unsupported_properties: ['material', 'hidden contents'] }] };
  if (options.physicalRecipeCase) content.data_origin = 'physical';
  let recipeJobStarted = false, recipeSubmissions = 0;
  let revision = 1, stateVersion = 1, approved = false, retired = false;
  const runtime = { runtime_epoch: 1, control_version: 2, inspection_enabled: false, local_instance_current: true, environment: 'synthetic_demo', artifact_sha256: 'a'.repeat(64), controls_sha256: 'b'.repeat(64), reason: 'startup' };
  await page.addInitScript(() => {
    const state = { requests: 0 }; Reflect.set(window, 'workbenchCameraFixture', state);
    Object.defineProperty(navigator.mediaDevices, 'getUserMedia', { value: async () => { state.requests++; throw new Error('Workbench must not request a camera'); } });
    const fetch = window.fetch.bind(window); const uploads: unknown[] = []; Reflect.set(window, 'referenceFixtureUploads', uploads);
    window.fetch = async (input, init) => {
      if (init?.body instanceof FormData) uploads.push({ metadata: JSON.parse(String(init.body.get('metadata'))), size: (init.body.get('image') as File).size });
      return fetch(input, init);
    };
  });
  await page.route('**/api/v1/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname.slice('/api/v1'.length), method = request.method();
    const json = (value: unknown, status = 200) => route.fulfill({ json: value, status });
    if (method !== 'GET') {
      expect(request.headers()['x-csrf-token']).toBe(csrf); expect(request.headers()['idempotency-key']).toBeTruthy();
      writes.push({ path, method, body: request.postData() && !request.headers()['content-type']?.startsWith('multipart/') ? request.postDataJSON() : undefined, version: request.headers()['if-match'], key: request.headers()['idempotency-key'] });
    }
    if (path === '/me') return json(user, signedOut ? 401 : restricted ? 403 : 200);
    if (path === '/review/context') {
      const q = new URL(request.url()).searchParams, tuple = { after_observation_id: q.get('after_observation_id'), action_id: q.get('action_id'), before_observation_id: q.get('before_observation_id') };
      if (options.mismatchedLabelContext) tuple.before_observation_id = labelAfter;
      return json(sourceContext(tuple));
    }
    if (path === '/labels' && method === 'GET') return json({ labels: savedLabel ? [savedLabel] : [], next_cursor: null });
    if (path === '/labels' || path === '/labels/' + labelId + '/revisions') {
      const body = request.postDataJSON(); const old = savedLabel;
      savedLabel = { ...body, tuple: { after_observation_id: body.after_observation_id, action_id: body.action_id, before_observation_id: body.before_observation_id },
        id: labelId, revision: old ? old.revision + 1 : 1, latest_revision: old ? old.revision + 1 : 1, state_version: old ? old.state_version + 1 : 1,
        source_context: sourceContext(body), sha256: 'd'.repeat(64), previous_sha256: old?.sha256 ?? null, conflict_codes: [],
        independence_verified: false, physical_truth_verified: false, machine_pass: false };
      // Emulate commit-with-lost-confirmation; exact retry returns the same committed label.
      if (options.ambiguousLabel && writes.filter(item => item.path === path).length === 1) return route.abort('failed');
      if (options.ambiguousLabel && old) savedLabel = old;
      labelEpoch++; return json(savedLabel, 201);
    }
    if (path === '/labels/' + labelId) return savedLabel ? json(savedLabel) : json({}, 404);
    if (path === '/auth/session') return json(restricted ? { status: 'invitation_pending', invitation_id: inviteId, session_id: user.session_id, csrf_token: csrf } : { status: 'member', ...user });
    if (path === '/auth/notice') return options.noticeFail ? json({}, 503) : json({ version: noticeChanged ? 'notice-v2' : 'notice-v1', text: 'Synthetic processing notice. Required operation only.', sha256: (noticeChanged ? 'e' : 'd').repeat(64), optional_improvement_default: false, optional_publicity_default: false });
    if (path === '/purposes/options') { policyReads++; return json({ max_lifetime_ms: 120000, server_time_ms: Date.now() + policyReads * 1000,
      notice: { version: noticeChanged ? 'notice-v2' : 'notice-v1', text: 'Synthetic operational reference notice.', sha256: (noticeChanged ? 'e' : 'd').repeat(64), optional_improvement_default: false, optional_publicity_default: false },
      ...(originalNotice ? { original_capture_notice: { version: 'original-capture-v1', sha256: 'a'.repeat(64), text: 'Synthetic original image retention notice. Three nonrefundable attempts; earlier purpose or seven days.' } } : {}) }); }
    if (path === '/purposes' && method === 'GET') return json({ purposes: [purpose], next_cursor: null });
    if (path === '/purposes' && method === 'POST') {
      purpose.expires_at_ms = request.postDataJSON().expires_at_ms; purpose.source_permission_reference = request.postDataJSON().source_permission_reference;
      if (request.postDataJSON().original_capture_retention_acknowledged === true) Object.assign(purpose, { original_capture_retention_allowed: true, original_capture_notice_sha256: request.postDataJSON().original_capture_notice_sha256 });
      if (options.ambiguousPurpose && writes.filter(item => item.path === path).length === 1) return route.abort('failed');
      return json(purpose, 201);
    }
    if (path === '/purposes/' + purposeId) return json(purpose);
    if (path === '/purposes/' + purposeId + '/withdraw') { purpose.withdrawn = true; purpose.state_version++; return json(purpose); }
    if (path === '/reference-assets' && method === 'POST') {
      const raw = request.postDataBuffer()!, boundary = request.headers()['content-type'].split('boundary=')[1];
      const start = raw.indexOf('\r\n\r\n') + 4, end = raw.indexOf('\r\n--' + boundary, start);
      expect(start).toBeGreaterThan(3); expect(end).toBeGreaterThan(start);
      reference.source_sha256 = createHash('sha256').update(raw.subarray(start, end)).digest('hex'); reference.expires_at_ms = purpose.expires_at_ms;
      if (options.ambiguousReference && writes.filter(item => item.path === path).length === 1) return route.abort('failed');
      return json(reference, 201);
    }
    if (path === '/reference-assets/' + referenceId) return purpose.withdrawn ? json({}, 503) : json(reference);
    if (path === '/calibrations' && method === 'GET') return json({ calibrations: [{ id: calibrationId, name: calRequest.name }], next_cursor: null });
    if (path === '/calibrations' || (path === '/calibrations/' + calibrationId + '/draft' && method === 'PUT')) {
      calRequest = request.postDataJSON(); calLastJob = enrollmentJob; calStatus = 'draft';
      if (options.ambiguousEnrollment && writes.filter(item => item.path === path).length === 1) return route.abort('failed');
      return json({ id: enrollmentJob, calibration_id: calibrationId, status: options.pendingCalibration ? 'processing' : 'completed', kind: 'enrollment' }, 201);
    }
    if (path === '/calibrations/' + calibrationId + '/draft') return json(calDraft());
    if (path === '/calibration-jobs/' + enrollmentJob) return json({ id: enrollmentJob, calibration_id: calibrationId, status: 'completed', kind: 'enrollment' });
    if (path === '/calibrations/' + calibrationId + '/qualify') {
      calVersion += 2; calReport = calibrationReport; calLastJob = calibrationReport; calStatus = options.failedCalibration ? 'qualification_failed' : 'qualified';
      return json({ id: calibrationReport, calibration_id: calibrationId, status: 'completed', kind: 'qualification', report_id: calibrationReport }, 201);
    }
    if (path === '/calibrations/' + calibrationId + '/reports/' + calibrationReport) return json({ id: calibrationReport, calibration_id: calibrationId, revision: calRevision,
      state_version: calVersion, profile_sha256: 'a'.repeat(64), passed: !options.failedCalibration, eligible_for_approval: !options.failedCalibration && !options.physicalCalibration,
      physical_truth_verified: false, independence_verified: false, requires_physical_assurance: options.physicalCalibration ?? false, remaining_validity_ms: options.ttl ?? 60000,
      results: [{ asset_id: referenceId, expected: 'supported', matched: true, diagnostic: { accepted: true, reason_codes: [], blur_variance: 100, max_reprojection_error_px: 0.2 } },
        { asset_id: rejectedReference, expected: 'rejected', matched: !options.failedCalibration, diagnostic: { accepted: options.failedCalibration ?? false, reason_codes: ['markers_missing_duplicate_or_extra'], blur_variance: null, max_reprojection_error_px: null } }] });
    if (path === '/calibrations/' + calibrationId + '/approve') { calVersion++; calActive = true; calStatus = 'approved'; return json(calDraft()); }
    if (path === '/calibrations/' + calibrationId + '/retire') { calVersion++; calActive = false; calRetired = true; calStatus = 'retired'; calReport = null; return json(calDraft()); }
    if (path === '/users') return options.denied ? json({}, 403) : json({ users: [{ ...user, enabled: true, access_version: 1 }, { id: targetId, display_name: 'Synthetic successor', roles: ['operator'], enabled: true, access_version: 1 }], next_cursor: null });
    if (path.includes('/users/')) return json({ access_version: 2 });
    if (path === '/invitations' && method === 'POST') {
      if (options.ambiguousInvite && writes.filter(item => item.path === path).length === 1) return route.abort('failed');
      return json({ id: inviteId, capability, delivery_status: 'NOT_SENT', expires_at_ms: Date.now() + 60000 }, 201);
    }
    const invitation = { id: inviteId, target_subject: 'synthetic-target', roles: ['operator'], status: 'pending', state_version: 1, delivery_status: 'NOT_SENT', expires_at_ms: Date.now() + 60000 };
    if (path === '/invitations') return json({ invitations: [invitation], next_cursor: null });
    if (path === '/invitations/' + inviteId) return json(invitation);
    if (path === '/invitations/' + inviteId + '/accept' || path === '/invitations/' + inviteId + '/decline') { restricted = false; signedOut = true; return json({ sign_in_required: true }); }
    if (path === '/invitations/' + inviteId + '/revoke') return json({ status: 'revoked' });
    if (path === '/owner-transfers') return json({ id: transferId, expires_at_ms: Date.now() + 60000 }, 201);
    if (path === '/owner-transfers/' + transferId) return json({ id: transferId, source_id: ownerId, target_id: targetId, source_name: 'Synthetic owner', target_name: 'Synthetic successor', source_version: 1, target_version: 1,
      status: 'pending', remaining_validity_ms: options.ttl ?? 60000, eligible_for_accept: role !== 'owner', requires_recent_mfa: false });
    if (path.endsWith('/accept') && path.startsWith('/owner-transfers/')) { signedOut = true; return json({ owner_id: targetId, sign_in_required: true }); }
    const recipeJob = () => ({id:qualificationId,recipe_id:recipeId,status:options.pendingRecipeQualification?'processing':'completed',report_id:options.pendingRecipeQualification?null:qualificationId,remaining_ms:30000});
    if (path === '/recipes/' + recipeId + '/qualify') {
      recipeSubmissions++; if (!recipeJobStarted) { recipeJobStarted = true; stateVersion += options.pendingRecipeQualification ? 1 : 2; }
      if (options.ambiguousRecipeQualification && recipeSubmissions === 1) return route.abort('failed');
      return json(recipeJob(),201);
    }
    if (path === '/recipe-qualification-jobs/' + qualificationId) return json(recipeJob());
    if (path === '/recipes/' + recipeId + '/qualification-reports/' + qualificationId) return json({id:qualificationId,recipe_id:recipeId,
      recipe_revision:options.mismatchRecipeReport?revision+1:revision,passed:!options.failedRecipeCase&&!options.physicalRecipeCase,eligible_for_approval:!options.failedRecipeCase&&!options.physicalRecipeCase&&!options.supersededRecipeQualification,diagnostic_passed:!options.failedRecipeCase,
      physical_truth_verified:false,independence_verified:false,sha256:'f'.repeat(64),remaining_validity_ms:options.ttl??30000,
      results:['complete','incorrect','challenge'].map((kind,i)=>({asset_id:'81000000-0000-4000-8000-'+String(i+1).padStart(12,'0'),kind,
        matched:!options.failedRecipeCase||i!==1,findings:[i===2?'UNOBSERVABLE':i===1?'VIOLATED':'SATISFIED'],measured_counts:[i===1?1:2],quality_ok:i!==2}))});
    if (path === '/recipes' && method === 'GET') return json({ recipes: [{ id: recipeId, name: content.name }], next_cursor: null });
    if (path === '/recipes' || (path.endsWith('/draft') && method === 'PUT')) { content = request.postDataJSON().content; revision++; stateVersion++; return json({ id: recipeId, state_version: stateVersion }); }
    if (path.endsWith('/draft')) return json({ id: recipeId, revision, state_version: stateVersion, content, retired, last_qualification_job_id: recipeJobStarted ? qualificationId : null, current: { effective_approved: approved, active_revision: approved ? revision : null } });
    if (path.includes('/qualifications/')) return json({ id: qualificationId, recipe_id: recipeId, recipe_revision: options.mismatchQualification ? revision + 1 : revision, state_version: stateVersion, data_origin: content.data_origin,
      passed: !options.failed && !options.failedRecipeCase && !options.physicalRecipeCase, eligible_for_approval: !options.failed && !options.failedRecipeCase && !options.physicalRecipeCase && !options.supersededRecipeQualification, artifact_sha256: runtime.artifact_sha256, recipe_sha256: 'e'.repeat(64), reviewer_id: targetId,
      environment: 'synthetic_demo', reason_codes: options.failed ? ['FAILED_QUALIFICATION'] : [], remaining_qualification_ms: options.ttl ?? 60000 });
    if (path.endsWith('/approve')) { approved = true; stateVersion++; return json({ id: recipeId, state_version: stateVersion }); }
    if (path.endsWith('/retire')) { retired = true; approved = false; stateVersion++; return json({ id: recipeId, state_version: stateVersion }); }
    if (path === '/admin/runtime') return json(runtime);
    if (path.startsWith('/admin/readiness/')) {
      if (options.delay) await new Promise(resolve => setTimeout(resolve, options.delay));
      return json({ id: receiptId, eligible_for_enable: true, ...runtime, receipt_sha256: 'f'.repeat(64), checks: { ...checks, worker: !options.failedReadiness }, remaining_validity_ms: options.ttl ?? 60000 });
    }
    if (path === '/admin/enable-inspection' || path === '/admin/disable-inspection') { runtime.inspection_enabled = path.includes('/enable-'); runtime.control_version++; return json({ current: runtime }); }
    if (path === '/auth/logout') return options.logoutFail ? route.abort('failed') : route.fulfill({ status: 204 });
    throw new Error('Unexpected synthetic workbench request: ' + method + ' ' + path);
  });
  return { writes, get content() { return content; }, showOriginalNotice() { originalNotice = true; }, changeNotice() { noticeChanged = true; }, revokeGrant() { user.roles = []; } };
}
async function open(page: Page) {
  await page.goto('/'); await page.getByRole('button', { name: 'Open invited workspace' }).click();
  await page.getByRole('button', { name: 'Review and administration', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Review and administration', exact: true })).toBeFocused();
}
async function recipe(page: Page) {
  await page.getByRole('button', { name: 'Recipes and qualification', exact: true }).click();
  await page.getByRole('button', { name: 'Load recipe candidates' }).click();
  await page.getByRole('combobox', { name: 'Recipe candidate', exact: true }).selectOption(recipeId);
  await page.getByRole('button', { name: 'Read recipe draft' }).click();
  await expect(page.getByLabel('Recipe name', { exact: true })).toHaveValue('Synthetic kit');
}
async function qualify(page: Page) {
  await page.getByLabel('Qualification run ID', { exact: true }).fill(qualificationId);
  await page.getByRole('button', { name: 'Review qualification', exact: true }).click();
  await expect(page.getByText(/Reviewer reference:/)).toBeVisible();
}

test('flat-reference enrollment requires finite ordered bounds and saves only an inactive revision',async({page})=>{
  const state=await fixture(page);await open(page);await recipe(page);
  const enroll=page.getByRole('checkbox',{name:'Enroll a measured flat-reference aspect interval for part 1',exact:true});
  await expect(enroll).not.toBeChecked();await enroll.check();
  await expect(page.getByText(/It does not measure 3D flatness or height/)).toBeVisible();
  const save=page.getByRole('button',{name:'Save inactive draft revision',exact:true});await expect(save).toBeDisabled();
  const minimum=page.getByLabel('Minimum flat-reference aspect 1',{exact:true}),maximum=page.getByLabel('Maximum flat-reference aspect 1',{exact:true});
  await minimum.fill('0');await maximum.fill('4');await expect(save).toBeDisabled();
  await minimum.fill('5');await expect(save).toBeDisabled();await minimum.fill('2');await maximum.fill('2001');await expect(save).toBeDisabled();
  await maximum.fill('6');await expect(save).toBeEnabled();await save.click();
  await expect(page.getByText('Draft revision saved. It stays inactive until matching qualification and explicit owner approval.',{exact:true})).toBeVisible();
  expect(state.writes).toHaveLength(1);expect(state.writes[0].body.content.constraints[0].flat_reference_aspect_ratio).toEqual({minimum:2,maximum:6});
  expect(state.writes[0].path).toBe('/recipes/'+recipeId+'/draft');
  await expect(page.getByText('Effective approved revision: none. A draft does not replace this active binding.',{exact:true})).toBeVisible();
});

test('flat-reference removal omits the optional field from the saved recipe',async({page})=>{
  const state=await fixture(page);await open(page);await recipe(page);
  const enroll=page.getByRole('checkbox',{name:'Enroll a measured flat-reference aspect interval for part 1',exact:true});
  await enroll.check();await page.getByLabel('Minimum flat-reference aspect 1',{exact:true}).fill('2');await page.getByLabel('Maximum flat-reference aspect 1',{exact:true}).fill('6');
  await enroll.uncheck();await expect(page.getByLabel('Minimum flat-reference aspect 1',{exact:true})).toHaveCount(0);
  await page.getByRole('button',{name:'Save inactive draft revision',exact:true}).click();
  await expect(page.getByText('Draft revision saved. It stays inactive until matching qualification and explicit owner approval.',{exact:true})).toBeVisible();
  expect(state.writes).toHaveLength(1);expect(state.writes[0].body.content.constraints[0]).not.toHaveProperty('flat_reference_aspect_ratio');
});

test('flat-reference edit invalidates the previous qualification review',async({page})=>{
  const state=await fixture(page);await open(page);await recipe(page);await qualify(page);
  await page.getByRole('checkbox',{name:/I reviewed the qualification and intend/}).check();
  await expect(page.getByRole('button',{name:'Approve qualified revision',exact:true})).toBeEnabled();
  await page.getByRole('checkbox',{name:'Enroll a measured flat-reference aspect interval for part 1',exact:true}).check();
  await expect(page.getByRole('button',{name:'Approve qualified revision',exact:true})).toHaveCount(0);
  await expect(page.getByText('Unsaved edits. Previous qualification review has been cleared.',{exact:true})).toBeVisible();
  expect(state.writes).toHaveLength(0);
});

test('flat-reference configuration is read-only for a reviewer',async({page})=>{
  const state=await fixture(page,{role:'reviewer'});await open(page);await recipe(page);
  await expect(page.getByRole('checkbox',{name:'Enroll a measured flat-reference aspect interval for part 1',exact:true})).toBeDisabled();
  await expect(page.getByRole('button',{name:'Save inactive draft revision',exact:true})).toBeDisabled();expect(state.writes).toHaveLength(0);
});

test('restricted invitee reviews notice and explicitly accepts without a camera or implicit optional reuse', async ({ page }) => {
  const state = await fixture(page, { restricted: true }); await page.goto('/'); await page.getByRole('button', { name: 'Open invited workspace' }).click();
  await expect(page.getByRole('heading', { name: 'Your invitation' })).toBeFocused();
  await expect(page.getByRole('button', { name: 'Accept invitation', exact: true })).toBeDisabled();
  await page.getByLabel('Private invitation capability', { exact: true }).fill(capability);
  await page.getByRole('checkbox', { name: /I read the current processing notice/ }).check();
  await page.getByRole('button', { name: 'Accept invitation', exact: true }).click();
  await expect(page.getByRole('status')).toContainText('Sign in afresh');
  expect(state.writes).toHaveLength(1); expect(state.writes[0].body).toEqual({ capability, notice_version: 'notice-v1', notice_sha256: 'd'.repeat(64) });
  await expect(page.getByLabel('Private invitation capability', { exact: true })).toHaveCount(0);
  expect(await page.evaluate(() => ({ camera: Reflect.get(window, 'workbenchCameraFixture').requests, local: localStorage.length, session: sessionStorage.length }))).toEqual({ camera: 0, local: 0, session: 0 });
});

test('invitation decline needs no capability or notice acknowledgment', async ({ page }) => {
  const state = await fixture(page, { restricted: true }); await page.goto('/'); await page.getByRole('button', { name: 'Open invited workspace' }).click();
  await page.getByRole('button', { name: 'Decline invitation', exact: true }).click(); await expect(page.getByRole('status')).toContainText('declined');
  expect(state.writes[0].path).toBe('/invitations/' + inviteId + '/decline');
});

test('owner invitation is NOT_SENT and capability is masked, ephemeral and explicitly forgotten', async ({ page }) => {
  const state = await fixture(page); await open(page);
  await page.getByLabel('Provider subject', { exact: true }).fill('synthetic-target'); await page.getByLabel('Target email', { exact: true }).fill('target@example.invalid');
  await page.getByRole('checkbox', { name: /I verified the intended identity/ }).check();
  await page.getByRole('button', { name: 'Create invitation record' }).click(); await expect(page.getByText(/Invitation ID:/)).toContainText('NOT_SENT');
  await expect(page.getByLabel('Private capability', { exact: true })).toHaveAttribute('type', 'password');
  await page.screenshot({ path: 'evidence/local/workbench-synthetic-owner.png', fullPage: true });
  await page.getByRole('button', { name: 'Reveal capability' }).click(); await expect(page.getByLabel('Private capability', { exact: true })).toHaveValue(capability);
  await page.getByRole('button', { name: 'Forget capability' }).click(); await expect(page.getByLabel('Private capability', { exact: true })).toHaveCount(0);
  expect(state.writes).toHaveLength(1); expect(state.writes[0].body.roles).toEqual(['operator']); expect(page.url()).not.toContain(capability);
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
});

test('access edits and ownership initiation bind the reviewed account version', async ({ page }) => {
  const state = await fixture(page); await open(page); await page.getByRole('button', { name: 'Load accounts', exact: true }).click();
  await page.getByRole('combobox', { name: 'Person to review', exact: true }).selectOption(targetId);
  await expect(page.getByRole('button', { name: 'Save access', exact: true })).toBeDisabled();
  await page.getByRole('checkbox', { name: 'reviewer', exact: true }).first().check();
  await page.getByRole('checkbox', { name: /I reviewed this person/ }).check(); await page.getByRole('button', { name: 'Save access', exact: true }).click();
  await expect(page.getByText('Access changed. The person must sign in afresh.')).toBeVisible();
  expect(state.writes[0]).toMatchObject({ method: 'PATCH', version: '1', body: { roles: ['operator', 'reviewer'], enabled: true } });
  await page.getByRole('combobox', { name: 'Person to review', exact: true }).selectOption(targetId); await page.getByRole('checkbox', { name: /I reviewed this person/ }).check();
  await page.getByRole('button', { name: 'Start ownership handoff' }).click(); await expect(page.getByText(/Ownership handoff ID:/)).toContainText(transferId);
  await page.getByRole('button', { name: 'Ownership handoff', exact: true }).click(); await page.getByRole('button', { name: 'Review ownership handoff' }).click();
  await expect(page.getByRole('button', { name: 'Accept ownership handoff' })).toBeDisabled();
});

test('bound successor explicitly accepts then must sign in afresh', async ({ page }) => {
  const state = await fixture(page, { role: 'operator' }); await open(page);
  await expect(page.getByRole('button', { name: 'Accounts', exact: true })).toHaveCount(0);
  await page.getByLabel('Handoff ID', { exact: true }).fill(transferId); await page.getByRole('button', { name: 'Review ownership handoff' }).click();
  await page.getByRole('checkbox', { name: /I am the intended successor/ }).check(); await page.getByRole('button', { name: 'Accept ownership handoff' }).click();
  await expect(page.getByText('Account authority changed. Sign in afresh before continuing.')).toBeVisible();
  expect(state.writes[0].path).toBe('/owner-transfers/' + transferId + '/accept');
});

test('reviewer can inspect failed qualification but cannot edit, approve or administer', async ({ page }) => {
  const state = await fixture(page, { role: 'reviewer', failed: true }); await open(page); await recipe(page); await qualify(page);
  await expect(page.getByLabel('Recipe name', { exact: true })).toBeDisabled(); await expect(page.getByText(/Recorded check FAILED/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Approve qualified revision' })).toHaveCount(0); await expect(page.getByRole('button', { name: 'Runtime controls' })).toHaveCount(0);
  await page.screenshot({ path: 'evidence/local/workbench-synthetic-reviewer.png', fullPage: true });
  expect(state.writes).toHaveLength(0);
});

test('owner reviews a qualified immutable draft and explicit approval is version bound', async ({ page }) => {
  const state = await fixture(page); await open(page); await recipe(page); await qualify(page);
  await expect(page.getByRole('button', { name: 'Approve qualified revision' })).toBeDisabled();
  await page.getByRole('checkbox', { name: /I reviewed the qualification/ }).check(); await page.getByRole('button', { name: 'Approve qualified revision' }).click();
  await expect(page.getByText('Owner approval recorded for the matching qualified revision. This is not beta launch approval.')).toBeVisible();
  expect(state.writes[0]).toMatchObject({ path: '/recipes/' + recipeId + '/approve', version: '1', body: { qualification_id: qualificationId } });
});

test('editing clears qualification review and saving remains an inactive revision', async ({ page }) => {
  const state = await fixture(page); await open(page); await recipe(page); await qualify(page);
  await page.getByLabel('Recipe name', { exact: true }).fill('Revised synthetic kit'); await expect(page.getByText(/Reviewer reference:/)).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Review qualification', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Save inactive draft revision' }).click();
  await expect(page.getByText('Draft revision saved. It stays inactive until matching qualification and explicit owner approval.')).toBeVisible();
  expect(state.content.name).toBe('Revised synthetic kit'); expect(state.writes[0]).toMatchObject({ method: 'PUT', version: '1' });
  expect(state.writes.some(item => item.path.endsWith('/approve'))).toBe(false);
});

test('invalid counts block draft save and failed qualifications block owner approval', async ({ page }) => {
  const state = await fixture(page, { failed: true }); await open(page); await recipe(page); await qualify(page);
  await expect(page.getByRole('checkbox', { name: /I reviewed the qualification/ })).toBeDisabled();
  await page.getByLabel('Expected count 1', { exact: true }).fill('21'); await expect(page.getByRole('button', { name: 'Save inactive draft revision' })).toBeDisabled();
  expect(state.writes).toHaveLength(0);
});

test('runtime review cannot enable until explicit confirmation; writes bind the control version', async ({ page }) => {
  const state = await fixture(page); await open(page); await page.getByRole('button', { name: 'Runtime controls' }).click();
  await page.getByRole('button', { name: 'Load runtime status' }).click(); await page.getByLabel('Existing readiness receipt ID', { exact: true }).fill(receiptId);
  await page.getByRole('button', { name: 'Review readiness receipt' }).click(); await expect(page.getByRole('button', { name: 'Enable inspection admission' })).toBeDisabled();
  expect(state.writes).toHaveLength(0); await page.getByRole('checkbox', { name: /I reviewed the existing assurance/ }).check();
  await page.getByRole('button', { name: 'Enable inspection admission' }).click(); await expect(page.getByText(/Inspection admission updated/)).toBeVisible();
  expect(state.writes[0]).toMatchObject({ path: '/admin/enable-inspection', version: '2', body: { receipt_id: receiptId } });
  await page.getByLabel('Stop reason', { exact: true }).fill('supervised stop'); await page.getByRole('button', { name: 'Disable inspection admission' }).click();
  await expect(page.getByText('Inspection admission disabled. Treat prior observations as historical.')).toBeVisible(); expect(state.writes[1].version).toBe('3');
});

test('delayed readiness cannot renew its request-start expiry', async ({ page }) => {
  const state = await fixture(page, { delay: 450, ttl: 250 }); await open(page); await page.getByRole('button', { name: 'Runtime controls' }).click();
  await page.getByRole('button', { name: 'Load runtime status' }).click(); await page.getByLabel('Existing readiness receipt ID', { exact: true }).fill(receiptId); await page.getByRole('button', { name: 'Review readiness receipt' }).click();
  await expect(page.getByText('Review expired or was cleared. Review a current receipt again.')).toBeVisible(); await expect(page.getByRole('checkbox', { name: /I reviewed the existing assurance/ })).toBeDisabled();
  expect(state.writes).toHaveLength(0);
});

test('unconfirmed sign-out removes privileged controls and allows explicit retry', async ({ page }) => {
  await fixture(page, { logoutFail: true }); await open(page); await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByText(/Server sign-out is unconfirmed/)).toBeVisible(); await expect(page.getByRole('button', { name: 'Retry sign out' })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Load accounts', exact: true })).toHaveCount(0);
});

test('owner MFA denial exposes reauthentication rather than successful administration', async ({ page }) => {
  const state = await fixture(page, { denied: true }); await open(page); await page.getByRole('button', { name: 'Load accounts', exact: true }).click();
  await expect(page.getByText(/Your current session cannot perform this action/)).toBeVisible(); await expect(page.getByRole('link', { name: 'Sign in with recent MFA' })).toHaveAttribute('href', '/api/v1/auth/login?mfa=required');
  expect(state.writes).toHaveLength(0);
});


test('notice failure never prevents a voluntary invitation decline', async ({ page }) => {
  const state = await fixture(page, { restricted: true, noticeFail: true }); await page.goto('/'); await page.getByRole('button', { name: 'Open invited workspace' }).click();
  await expect(page.getByText(/Current processing notice unavailable/)).toBeVisible(); await expect(page.getByRole('button', { name: 'Accept invitation', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Decline invitation', exact: true }).click(); await expect(page.getByRole('status')).toContainText('declined');
  expect(state.writes).toHaveLength(1); expect(state.writes[0].path).toContain('/decline');
});

test('changed notice clears acknowledgement and capability without accepting stale terms', async ({ page }) => {
  const state = await fixture(page, { restricted: true }); await page.goto('/'); await page.getByRole('button', { name: 'Open invited workspace' }).click();
  await page.getByLabel('Private invitation capability', { exact: true }).fill(capability); await page.getByRole('checkbox', { name: /I read the current processing notice/ }).check();
  state.changeNotice(); await page.getByRole('button', { name: 'Accept invitation', exact: true }).click();
  await expect(page.getByRole('status')).toContainText('notice changed'); await expect(page.getByLabel('Private invitation capability', { exact: true })).toHaveValue('');
  await expect(page.getByRole('checkbox', { name: /I read the current processing notice/ })).not.toBeChecked(); expect(state.writes).toHaveLength(0);
  await page.getByRole('button', { name: 'Decline invitation', exact: true }).click(); await expect(page.getByRole('status')).toContainText('declined');
});

test('failed readiness checks and mismatched qualifications cannot become browser approval', async ({ page }) => {
  const state = await fixture(page, { failedReadiness: true, mismatchQualification: true }); await open(page); await recipe(page);
  await page.getByLabel('Qualification run ID', { exact: true }).fill(qualificationId); await page.getByRole('button', { name: 'Review qualification', exact: true }).click();
  await expect(page.getByText(/Qualification does not match this draft/)).toBeVisible(); await expect(page.getByRole('button', { name: 'Approve qualified revision' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Runtime controls' }).click(); await page.getByRole('button', { name: 'Load runtime status' }).click();
  await page.getByLabel('Existing readiness receipt ID', { exact: true }).fill(receiptId); await page.getByRole('button', { name: 'Review readiness receipt' }).click();
  await expect(page.getByText(/existing receipt does not support this runtime/)).toBeVisible(); await expect(page.getByRole('button', { name: 'Enable inspection admission' })).toBeDisabled(); expect(state.writes).toHaveLength(0);
});

test('changed grants between review and approval prevent the write', async ({ page }) => {
  const state = await fixture(page); await open(page); await recipe(page); await qualify(page); await page.getByRole('checkbox', { name: /I reviewed the qualification/ }).check();
  state.revokeGrant(); await page.getByRole('button', { name: 'Approve qualified revision' }).click();
  await expect(page.getByText(/Your account or grant changed/)).toBeVisible(); expect(state.writes).toHaveLength(0);
});

test('interrupted delayed review cannot return as valid and navigation waits for its outcome', async ({ page }) => {
  const state = await fixture(page, { delay: 700 }); await open(page); await page.getByRole('button', { name: 'Runtime controls' }).click(); await page.getByRole('button', { name: 'Load runtime status' }).click();
  await page.getByLabel('Existing readiness receipt ID', { exact: true }).fill(receiptId);
  const pending = page.waitForRequest(request => request.url().includes('/admin/readiness/'));
  await page.getByRole('button', { name: 'Review readiness receipt' }).click(); await pending;
  await expect(page.getByRole('button', { name: 'Accounts', exact: true })).toBeDisabled(); await expect(page.getByRole('button', { name: 'Return to inspections' })).toBeDisabled();
  await page.evaluate(() => window.dispatchEvent(new Event('offline')));
  await expect(page.getByText('Review interrupted. Refresh the current record before acting.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Enable inspection admission' })).toBeDisabled(); await expect(page.getByRole('button', { name: 'Accounts', exact: true })).toBeEnabled(); expect(state.writes).toHaveLength(0);
});

test('owner retirement and invitation revocation use the reviewed resource versions', async ({ page }) => {
  const state = await fixture(page); await open(page); await page.getByRole('button', { name: 'Load invitations', exact: true }).click();
  await page.getByRole('button', { name: 'Revoke invitation for synthetic-target' }).click();
  await expect(page.getByText('Invitation revoked.', { exact: true })).toBeVisible();
  expect(state.writes[0]).toMatchObject({ path: '/invitations/' + inviteId + '/revoke', version: '1' });
  await recipe(page); await page.getByLabel('Retirement reason', { exact: true }).fill('Unsupported setup'); await page.getByRole('button', { name: 'Retire this recipe' }).click();
  await expect(page.getByText('Recipe retired. Prior live approvals cannot be reused.')).toBeVisible(); expect(state.writes[1]).toMatchObject({ path: '/recipes/' + recipeId + '/retire', version: '1', body: { reason: 'Unsupported setup' } });
});


test('explicit unchanged retry reuses its in-memory idempotency key after an unconfirmed create', async ({ page }) => {
  const state = await fixture(page, { ambiguousInvite: true }); await open(page);
  await page.getByLabel('Provider subject', { exact: true }).fill('synthetic-target'); await page.getByLabel('Target email', { exact: true }).fill('target@example.invalid');
  await page.getByRole('checkbox', { name: /I verified the intended identity/ }).check(); await page.getByRole('button', { name: 'Create invitation record' }).click();
  await expect(page.getByText(/The operation outcome is unconfirmed/)).toBeVisible(); expect(state.writes).toHaveLength(1);
  await page.getByRole('checkbox', { name: /I verified the intended identity/ }).check(); await page.getByRole('button', { name: 'Create invitation record' }).click();
  await expect(page.getByText(/Invitation ID:/)).toContainText('NOT_SENT'); expect(state.writes).toHaveLength(2);
  expect(state.writes[0].key).toBe(state.writes[1].key); expect(state.writes[0].body).toEqual(state.writes[1].body);
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
});


test('workbench supports keyboard navigation, zoom and forced colors without horizontal loss', async ({ page }) => {
  await fixture(page); await open(page);
  await page.keyboard.press('Tab'); await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeFocused();
  await page.keyboard.press('Tab'); await expect(page.getByRole('button', { name: 'Retained evidence', exact: true })).toBeFocused();
  await page.keyboard.press('Tab'); await expect(page.getByRole('button', { name: 'Accounts', exact: true })).toBeFocused();
  await page.keyboard.press('Tab'); await expect(page.getByRole('button', { name: 'Recipes and qualification', exact: true })).toBeFocused(); await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Recipe drafts and qualification' })).toBeVisible();
  await page.setViewportSize({ width: 800, height: 900 }); await page.evaluate(() => { document.documentElement.style.zoom = '2'; }); await page.emulateMedia({ forcedColors: 'active' });
  await page.getByRole('button', { name: 'Load recipe candidates' }).click(); await page.getByRole('combobox', { name: 'Recipe candidate', exact: true }).selectOption(recipeId); await page.getByRole('button', { name: 'Read recipe draft' }).click();
  await expect(page.getByLabel('Recipe name', { exact: true })).toHaveValue('Synthetic kit');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
});


async function referencePurpose(page: Page) {
  await page.getByRole('button', { name: 'Reference media', exact: true }).click(); await page.getByRole('button', { name: 'Read reference-use notice' }).click();
  await page.getByLabel('Source permission reference', { exact: true }).fill('owned-photo-1'); await page.getByLabel('Operational-use duration in seconds', { exact: true }).fill('60');
  await page.getByRole('checkbox', { name: /I have authority for this operational use/ }).check(); await page.getByRole('button', { name: 'Record operational purpose', exact: true }).click();
}
async function chooseReference(page: Page) {
  const encoded = await page.evaluate(() => { const canvas = document.createElement('canvas'); canvas.width = 64; canvas.height = 64; const context = canvas.getContext('2d')!; context.fillStyle = '#246048'; context.fillRect(0, 0, 64, 64); return canvas.toDataURL('image/png').split(',')[1]; });
  await page.getByLabel('Reference image', { exact: true }).setInputFiles({ name: 'synthetic-local-reference.png', mimeType: 'image/png', buffer: Buffer.from(encoded, 'base64') });
  await expect(page.getByRole('img', { name: 'Selected local reference photo' })).toBeVisible();
}

test('original retention notice is separate, defaults off and clears after scope edits', async ({ page }) => {
  const state = await fixture(page); state.showOriginalNotice(); await open(page);
  await page.getByRole('button', { name: 'Reference media', exact: true }).click(); await page.getByRole('button', { name: 'Read reference-use notice' }).click();
  const choice = page.getByRole('checkbox', { name: /I separately attest permission/ });
  await expect(choice).not.toBeChecked(); await choice.check();
  await page.getByLabel('Source permission reference', { exact: true }).fill('original-rights'); await expect(choice).not.toBeChecked();
  await page.getByLabel('Operational-use duration in seconds', { exact: true }).fill('60');
  await page.getByRole('checkbox', { name: /I have authority for this operational use/ }).check();
  await page.getByRole('button', { name: 'Record operational purpose', exact: true }).click();
  await expect(page.getByText(/Operational purpose recorded as your attestation/)).toBeVisible();
  expect(state.writes[0].body.original_capture_retention_acknowledged).toBeUndefined();
  expect(state.writes[0].body.original_capture_notice_sha256).toBeUndefined();
});

test('original retention attestation binds its notice and uncertain retries preserve exact intent', async ({ page }) => {
  const state = await fixture(page, { ambiguousPurpose: true }); state.showOriginalNotice(); await open(page);
  await page.getByRole('button', { name: 'Reference media', exact: true }).click(); await page.getByRole('button', { name: 'Read reference-use notice' }).click();
  await page.getByLabel('Source permission reference', { exact: true }).fill('original-rights'); await page.getByLabel('Operational-use duration in seconds', { exact: true }).fill('60');
  const choice = page.getByRole('checkbox', { name: /I separately attest permission/ });
  await choice.check(); await page.getByRole('checkbox', { name: /I have authority for this operational use/ }).check();
  await page.getByRole('button', { name: 'Record operational purpose', exact: true }).click();
  await expect(page.getByText(/The operation outcome is unconfirmed/)).toBeVisible(); await expect(choice).not.toBeChecked();
  await choice.check(); await page.getByRole('checkbox', { name: /I have authority for this operational use/ }).check();
  await page.getByRole('button', { name: 'Record operational purpose', exact: true }).click();
  await expect(page.getByText(/Operational purpose recorded as your attestation/)).toBeVisible();
  expect(state.writes[0].body.original_capture_retention_acknowledged).toBe(true); expect(state.writes[0].body.original_capture_notice_sha256).toBe('a'.repeat(64));
  expect(state.writes[1].body).toEqual(state.writes[0].body); expect(state.writes[1].key).toBe(state.writes[0].key);
  await expect(page.getByText(/Runtime configuration and release approval are separate/)).toBeVisible();
});

test('owner records operational purpose and explicitly previews/stores reference without certifying physical truth', async ({ page }) => {
  const state = await fixture(page); await open(page); await referencePurpose(page);
  await expect(page.getByText(/Operational purpose recorded as your attestation/)).toBeVisible(); expect(state.writes[0].body.operational_use_acknowledged).toBe(true);
  await chooseReference(page); await expect(page.getByRole('button', { name: 'Store private reference' })).toBeDisabled();
  await page.getByRole('checkbox', { name: /I reviewed the entire selected image/ }).check(); await page.getByRole('button', { name: 'Store private reference' }).click();
  await expect(page.getByText(/Verified reference stored privately/)).toBeVisible(); await expect(page.getByText(/Physical truth: unverified/)).toBeVisible();
  await expect(page.getByRole('img', { name: 'Selected local reference photo' })).toHaveCount(0);
  const uploads = await page.evaluate(() => Reflect.get(window, 'referenceFixtureUploads'));
  expect(uploads).toHaveLength(1); expect(uploads[0].metadata).toEqual({ purpose_id: purposeId, source_permission_reference: 'owned-photo-1', data_origin: 'synthetic', expires_at_ms: state.writes[0].body.expires_at_ms });
  expect(await page.evaluate(() => Reflect.get(window, 'workbenchCameraFixture').requests)).toBe(0);
  await page.screenshot({ path: 'evidence/local/reference-synthetic-owner.png', fullPage: true });
});

test('uncertain purpose retry freezes expiry and reuses its original operation key', async ({ page }) => {
  const state = await fixture(page, { ambiguousPurpose: true }); await open(page); await referencePurpose(page);
  await expect(page.getByText(/The operation outcome is unconfirmed/)).toBeVisible(); expect(state.writes).toHaveLength(1);
  await page.getByRole('checkbox', { name: /I have authority for this operational use/ }).check(); await page.getByRole('button', { name: 'Record operational purpose', exact: true }).click();
  await expect(page.getByText(/Operational purpose recorded as your attestation/)).toBeVisible(); expect(state.writes).toHaveLength(2);
  expect(state.writes[0].key).toBe(state.writes[1].key); expect(state.writes[0].body).toEqual(state.writes[1].body);
});

test('uncertain reference retry retains source and key until explicit same-body retry succeeds', async ({ page }) => {
  const state = await fixture(page, { ambiguousReference: true }); await open(page); await referencePurpose(page); await chooseReference(page);
  await page.getByRole('checkbox', { name: /I reviewed the entire selected image/ }).check(); await page.getByRole('button', { name: 'Store private reference' }).click();
  await expect(page.getByText(/The operation outcome is unconfirmed/)).toBeVisible(); await expect(page.getByRole('img', { name: 'Selected local reference photo' })).toBeVisible();
  await page.getByRole('checkbox', { name: /I reviewed the entire selected image/ }).check(); await page.getByRole('button', { name: 'Store private reference' }).click();
  await expect(page.getByText(/Verified reference stored privately/)).toBeVisible(); const writes = state.writes.filter(item => item.path === '/reference-assets');
  expect(writes).toHaveLength(2); expect(writes[0].key).toBe(writes[1].key); expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
});

test('purpose withdrawal clears upload authority and reviewer has metadata-only access', async ({ page }) => {
  const state = await fixture(page); await open(page); await referencePurpose(page); await chooseReference(page);
  await page.getByRole('checkbox', { name: /Withdraw this purpose and invalidate/ }).check(); await page.getByRole('button', { name: 'Withdraw operational purpose', exact: true }).click();
  await expect(page.getByText(/Purpose withdrawn. Future dependent use is denied/)).toBeVisible(); await expect(page.getByRole('checkbox', { name: /I reviewed the entire selected image/ })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Store private reference' })).toBeDisabled(); expect(state.writes[1]).toMatchObject({ path: '/purposes/' + purposeId + '/withdraw', version: '1' });
});

test('reviewer lists purposes and reads scoped reference metadata without upload or purpose writes', async ({ page }) => {
  const state = await fixture(page, { role: 'reviewer' }); await open(page); await page.getByRole('button', { name: 'Reference media', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Read reference-use notice' })).toHaveCount(0); await expect(page.getByLabel('Reference image', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Load operational purposes' }).click(); await page.getByRole('combobox', { name: 'Recorded purpose', exact: true }).selectOption(purposeId); await page.getByRole('button', { name: 'Read operational purpose', exact: true }).click();
  await expect(page.getByText(/Independent rights verification: absent/)).toBeVisible(); await page.getByLabel('Reference asset ID', { exact: true }).fill(referenceId); await page.getByRole('button', { name: 'Read reference metadata', exact: true }).click();
  await expect(page.getByText(/Physical truth: unverified/)).toBeVisible(); expect(state.writes).toHaveLength(0);
});


async function enrollCamera(page: Page, physical = false) {
  await page.getByRole('button', { name: 'Camera calibration', exact: true }).click();
  await page.getByLabel('Setup name', { exact: true }).fill('Synthetic camera setup'); await page.getByLabel('Camera identifier', { exact: true }).fill('synthetic-camera');
  await page.getByLabel('Enrollment reference ID', { exact: true }).fill(referenceId); await page.getByRole('button', { name: 'Read enrollment reference', exact: true }).click();
  if (physical) {
    for (const [label, value] of [['Maximum marker movement in pixels','2'],['Maximum planar residual in pixels','1'],['Chosen uncertainty bound in millimetres','0.5'],['Minimum region area in pixels','30'],['Minimum focus variance','1'],['Foreground gray threshold','127']]) await page.getByLabel(label, { exact: true }).fill(value);
  } else await page.getByRole('button', { name: 'Use synthetic practice settings' }).click();
  await page.getByRole('button', { name: 'Enroll camera draft', exact: true }).click();
}
async function qualifyCamera(page: Page) {
  await page.getByLabel('Case 2 reference ID', { exact: true }).fill(rejectedReference);
  await page.getByRole('checkbox', { name: /I reviewed these expected cases/ }).check(); await page.getByRole('button', { name: 'Run calibration diagnostics' }).click();
  await page.getByRole('button', { name: 'Review calibration report', exact: true }).click();
  await expect(page.getByText(/Diagnostic report:/)).toBeVisible();
}

test('owner enrolls a draft, reviews actual-case report, explicitly approves and retires calibration', async ({ page }) => {
  const state = await fixture(page); await open(page); await enrollCamera(page);
  await expect(page.getByText(/Enrollment geometry was derived by the server/)).toBeVisible();
  expect(state.writes[0].body).not.toHaveProperty('profile_id'); expect(state.writes[0].body).not.toHaveProperty('enrolled_image_corners');
  await qualifyCamera(page); await expect(page.getByRole('button', { name: 'Approve qualified calibration', exact: true })).toBeDisabled();
  await page.getByRole('checkbox', { name: /I reviewed this exact diagnostic scope/ }).check(); await page.getByRole('button', { name: 'Approve qualified calibration', exact: true }).click();
  await expect(page.getByText(/Calibration approval recorded for the qualified scope/)).toBeVisible();
  expect(state.writes[2]).toMatchObject({ path: '/calibrations/' + calibrationId + '/approve', version: '3', body: { report_id: calibrationReport } });
  await page.getByLabel('Calibration retirement reason', { exact: true }).fill('Camera moved'); await page.getByRole('button', { name: 'Retire calibration', exact: true }).click();
  await expect(page.getByText('Calibration retired. Historical geometry cannot be reused as current.')).toBeVisible();
  expect(state.writes[3].version).toBe('4');
});

test('failed calibration report cannot become owner approval', async ({ page }) => {
  const state = await fixture(page, { failedCalibration: true }); await open(page); await enrollCamera(page); await qualifyCamera(page);
  await expect(page.getByText(/FAILED expected cases/)).toBeVisible(); await expect(page.getByRole('checkbox', { name: /I reviewed this exact diagnostic scope/ })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Approve qualified calibration', exact: true })).toBeDisabled(); expect(state.writes).toHaveLength(2);
});

test('physical declaration and successful geometry keep approval held for reviewed physical evidence', async ({ page }) => {
  const state = await fixture(page, { physicalCalibration: true }); await open(page); await enrollCamera(page, true); await qualifyCamera(page);
  await expect(page.getByText(/Physical approval held:/)).toBeVisible(); await expect(page.getByRole('button', { name: 'Approve qualified calibration', exact: true })).toBeDisabled();
  expect(state.writes.some(item => item.path.endsWith('/approve'))).toBe(false);
});

test('uncertain enrollment retries the original body and operation key without another setup', async ({ page }) => {
  const state = await fixture(page, { ambiguousEnrollment: true }); await open(page); await enrollCamera(page);
  await expect(page.getByRole('button', { name: 'Retry original calibration request' })).toBeVisible(); await expect(page.getByLabel('Setup name', { exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Retry original calibration request' }).click(); await expect(page.getByText(/Enrollment geometry was derived by the server/)).toBeVisible();
  expect(state.writes).toHaveLength(2); expect(state.writes[0].key).toBe(state.writes[1].key); expect(state.writes[0].body).toEqual(state.writes[1].body);
});

test('pending enrollment blocks another run and recovers through the original job', async ({ page }) => {
  const state = await fixture(page, { pendingCalibration: true }); await open(page); await enrollCamera(page);
  await expect(page.getByText(/Original job: processing/)).toBeVisible(); await expect(page.getByRole('button', { name: 'Enroll camera draft', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Refresh calibration job' }).click(); await expect(page.getByText(/Enrollment geometry was derived by the server/)).toBeVisible(); expect(state.writes).toHaveLength(1);
});

test('reviewer reads calibration metadata but cannot enroll, qualify, approve or retire', async ({ page }) => {
  const state = await fixture(page, { role: 'reviewer' }); await open(page); await page.getByRole('button', { name: 'Camera calibration', exact: true }).click();
  await page.getByRole('button', { name: 'Load calibration candidates', exact: true }).click(); await page.getByRole('combobox', { name: 'Calibration candidate', exact: true }).selectOption(calibrationId);
  await page.getByRole('button', { name: 'Read calibration draft', exact: true }).click(); await expect(page.getByLabel('Setup name', { exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Run calibration diagnostics', exact: true })).toBeDisabled(); await expect(page.getByRole('button', { name: 'Retire calibration', exact: true })).toHaveCount(0); expect(state.writes).toHaveLength(0);
});

test('editing calibration settings clears the previous qualification preview and approval', async ({ page }) => {
  const state = await fixture(page); await open(page); await enrollCamera(page); await qualifyCamera(page);
  await page.getByLabel('Maximum marker movement in pixels', { exact: true }).fill('3');
  await expect(page.getByText(/Diagnostic report:/)).toHaveCount(0); await expect(page.getByRole('button', { name: 'Review calibration report', exact: true })).toBeDisabled();
  expect(state.writes).toHaveLength(2);
});


async function labelReview(page: Page) {
  await open(page); await page.getByRole('button', { name: 'Outcome labels', exact: true }).click();
  await page.getByRole('textbox', { name: 'Before observation ID', exact: true }).fill(labelBefore);
  await page.getByRole('textbox', { name: 'Acknowledged action ID (optional)', exact: true }).fill(labelAction);
  await page.getByRole('textbox', { name: 'After observation ID (optional)', exact: true }).fill(labelAfter);
  await page.getByRole('button', { name: 'Review source tuple', exact: true }).click();
}
async function labelJudgment(page: Page) {
  await page.getByRole('combobox', { name: 'Outcome', exact: true }).selectOption('resolved');
  for (const part of ['washer', 'nut', 'bolt', 'flat_bracket']) await page.getByRole('spinbutton', { name: 'Ground truth ' + part, exact: true }).fill('1');
  await page.getByRole('combobox', { name: 'Review method', exact: true }).selectOption('synthetic_fixture');
  await page.getByRole('spinbutton', { name: 'Full review duration (milliseconds)', exact: true }).fill('1500');
  await page.getByRole('textbox', { name: 'Review or correction note', exact: true }).fill('Synthetic manual judgment');
  await page.getByRole('checkbox', { name: 'I declare independence; this declaration remains unverified', exact: true }).check();
  await page.getByRole('checkbox', { name: 'I reviewed the exact sources and limits; this human label is not a machine pass', exact: true }).check();
}
test('reviewer records an operational label and appends a correction without claiming independent truth', async ({ page }) => {
  const state = await fixture(page, { role: 'reviewer' }); await labelReview(page); await labelJudgment(page);
  await page.getByRole('button', { name: 'Save operational label', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Operational label saved as immutable revision 1' })).toBeVisible();
  await expect(page.getByText(/First revision/)).toBeVisible();
  await page.getByRole('button', { name: 'Review source tuple', exact: true }).click();
  await page.getByRole('combobox', { name: 'Outcome', exact: true }).selectOption('unresolved');
  await page.getByRole('textbox', { name: 'Review or correction note', exact: true }).fill('Prior judgment corrected');
  await page.getByRole('checkbox', { name: 'I reviewed the exact sources and limits; this human label is not a machine pass', exact: true }).check();
  await page.getByRole('button', { name: 'Append label correction', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Operational label saved as immutable revision 2' })).toBeVisible();
  expect(state.writes.filter(item => item.path.startsWith('/labels')).map(item => item.version)).toEqual([undefined, '1']);
  expect(state.writes.some(item => item.path.includes('approve') || item.path.includes('enable'))).toBeFalsy();
});
test('owner can inspect label source metadata but requires a separate reviewer grant to label', async ({ page }) => {
  const state = await fixture(page); await labelReview(page);
  await expect(page.getByText('Your current grant permits metadata review only. An explicit reviewer grant is required to label.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save operational label', exact: true })).toHaveCount(0); expect(state.writes).toHaveLength(0);
});
test('unknown label write freezes intent and retries the same payload and key', async ({ page }) => {
  const state = await fixture(page, { role: 'reviewer', ambiguousLabel: true }); await labelReview(page); await labelJudgment(page);
  await page.getByRole('button', { name: 'Save operational label', exact: true }).click();
  await expect(page.getByText(/Write outcome unconfirmed/)).toBeVisible();
  await expect(page.getByRole('textbox', { name: 'Review or correction note', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Retry unchanged label write', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Operational label saved as immutable revision 1' })).toBeVisible();
  const writes = state.writes.filter(item => item.path === '/labels'); expect(writes).toHaveLength(2); expect(writes[0].key).toBe(writes[1].key); expect(writes[0].body).toEqual(writes[1].body);
});
test('expired label source review blocks saving and edited tuple clears review context', async ({ page }) => {
  const state = await fixture(page, { role: 'reviewer', ttl: 500 }); await labelReview(page); await labelJudgment(page);
  await expect(page.getByText(/Review expired or interrupted/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save operational label', exact: true })).toBeDisabled();
  await page.getByRole('textbox', { name: 'Before observation ID', exact: true }).fill(labelAfter);
  await expect(page.getByText(/origin synthetic; software/)).toHaveCount(0); expect(state.writes).toHaveLength(0);
});
test('mismatched label source context is rejected before any write', async ({ page }) => {
  const state = await fixture(page, { role: 'reviewer', mismatchedLabelContext: true }); await labelReview(page);
  await expect(page.getByRole('status').filter({ hasText: 'Source review does not match the requested tuple.' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save operational label', exact: true })).toBeDisabled(); expect(state.writes).toHaveLength(0);
});


async function enterRecipeCases(page:Page) {
  for(let i=1;i<=3;i++)await page.getByLabel('Case '+i+' reference asset ID',{exact:true}).fill('81000000-0000-4000-8000-'+String(i).padStart(12,'0'));
  await page.getByRole('checkbox',{name:/I reviewed these comparison inputs/}).check();
}

test('owner measures recipe cases, reads the report and separately reviews the refreshed draft',async({page})=>{
  const state=await fixture(page);await open(page);await recipe(page);await enterRecipeCases(page);
  await page.getByRole('button',{name:'Run recipe qualification cases',exact:true}).click();
  await expect(page.getByText('Recorded job: completed. Completion never activates the recipe.')).toBeVisible();
  expect(state.writes).toHaveLength(1);expect(state.writes[0].version).toBe('1');
  await page.getByRole('button',{name:'Read measured recipe report'}).click();
  await expect(page.getByText('Diagnostic comparison: matched. Qualification: eligible for separate review.')).toBeVisible();
  await page.getByRole('button',{name:'Reload draft to review this qualification'}).click();
  await page.getByRole('button',{name:'Review qualification',exact:true}).click();
  await expect(page.getByRole('button',{name:'Approve qualified revision'})).toBeDisabled();
  await page.getByRole('checkbox',{name:/I reviewed the qualification and intend/}).check();await page.getByRole('button',{name:'Approve qualified revision'}).click();
  await expect(page.getByText('Owner approval recorded for the matching qualified revision. This is not beta launch approval.')).toBeVisible();
  expect(state.writes[1]).toMatchObject({path:'/recipes/'+recipeId+'/approve',version:'3'});
});

test('uncertain recipe qualification freezes its original case intent and never starts another run',async({page})=>{
  const state=await fixture(page,{ambiguousRecipeQualification:true});await open(page);await recipe(page);await enterRecipeCases(page);
  await page.getByRole('button',{name:'Run recipe qualification cases',exact:true}).click();
  await expect(page.getByText(/Outcome unconfirmed. Retry the same frozen request/)).toBeVisible();
  await expect(page.getByLabel('Case 1 reference asset ID',{exact:true})).toBeDisabled();
  await page.getByRole('button',{name:'Retry unchanged recipe qualification'}).click();
  await expect(page.getByText('Recorded job: completed. Completion never activates the recipe.')).toBeVisible();
  expect(state.writes).toHaveLength(2);expect(state.writes[0]).toEqual(state.writes[1]);
});

test('physical recipe diagnostic success stays held and cannot become owner approval',async({page})=>{
  await fixture(page,{physicalRecipeCase:true});await open(page);await recipe(page);await enterRecipeCases(page);
  await page.getByRole('button',{name:'Run recipe qualification cases',exact:true}).click();await page.getByRole('button',{name:'Read measured recipe report'}).click();
  await expect(page.getByText('Diagnostic comparison: matched. Qualification: held or failed.')).toBeVisible();
  await page.getByRole('button',{name:'Reload draft to review this qualification'}).click();await page.getByRole('button',{name:'Review qualification',exact:true}).click();
  await expect(page.getByRole('button',{name:'Approve qualified revision'})).toBeDisabled();
});

test('failed recipe cases stay inspectable and mismatched reports never offer approval review',async({page})=>{
  await fixture(page,{failedRecipeCase:true});await open(page);await recipe(page);await enterRecipeCases(page);
  await page.getByRole('button',{name:'Run recipe qualification cases',exact:true}).click();await page.getByRole('button',{name:'Read measured recipe report'}).click();
  await expect(page.getByText('Diagnostic comparison: failed. Qualification: held or failed.')).toBeVisible();
  await expect(page.getByText(/incorrect: mismatch/)).toBeVisible();
});

test('mismatched recipe report revision is rejected before it can be used',async({page})=>{
  await fixture(page,{mismatchRecipeReport:true});await open(page);await recipe(page);await enterRecipeCases(page);
  await page.getByRole('button',{name:'Run recipe qualification cases',exact:true}).click();await page.getByRole('button',{name:'Read measured recipe report'}).click();
  await expect(page.getByRole('status',{name:'Recipe qualification message'})).toContainText('does not match this draft');
  await expect(page.getByRole('button',{name:'Reload draft to review this qualification'})).toHaveCount(0);
});

test('pending recipe qualification supports explicit job reads without automatic resubmission',async({page})=>{
  const state=await fixture(page,{pendingRecipeQualification:true});await open(page);await recipe(page);await enterRecipeCases(page);
  await page.getByRole('button',{name:'Run recipe qualification cases',exact:true}).click();await expect(page.getByText('Recorded job: processing. Completion never activates the recipe.')).toBeVisible();
  await page.getByRole('button',{name:'Read recipe qualification job'}).click();
  await expect(page.getByRole('button',{name:'Read measured recipe report'})).toBeDisabled();expect(state.writes).toHaveLength(1);
});


test('hidden recipe report clears its use-for-review control without rerunning cases',async({page})=>{
  const state=await fixture(page);await open(page);await recipe(page);await enterRecipeCases(page);
  await page.getByRole('button',{name:'Run recipe qualification cases',exact:true}).click();await page.getByRole('button',{name:'Read measured recipe report'}).click();
  await expect(page.getByRole('button',{name:'Reload draft to review this qualification'})).toBeVisible();
  await page.evaluate(()=>{Object.defineProperty(document,'visibilityState',{configurable:true,get:()=> 'hidden'});document.dispatchEvent(new Event('visibilitychange'));});
  await expect(page.getByRole('button',{name:'Reload draft to review this qualification'})).toHaveCount(0);expect(state.writes).toHaveLength(1);
});


test('superseded recipe report stays inspectable but cannot offer current approval',async({page})=>{
  await fixture(page,{supersededRecipeQualification:true});await open(page);await recipe(page);await enterRecipeCases(page);
  await page.getByRole('button',{name:'Run recipe qualification cases',exact:true}).click();await page.getByRole('button',{name:'Read measured recipe report'}).click();
  await expect(page.getByText('Diagnostic comparison: matched. Qualification: held or failed.')).toBeVisible();
  await page.getByRole('button',{name:'Reload draft to review this qualification'}).click();await page.getByRole('button',{name:'Review qualification',exact:true}).click();
  await expect(page.getByRole('button',{name:'Approve qualified revision'})).toBeDisabled();
});


test('reviewer reads measured recipe reports without case submission or approval controls',async({page})=>{
  const state=await fixture(page,{role:'reviewer'});await open(page);await recipe(page);
  await expect(page.getByRole('button',{name:'Run recipe qualification cases',exact:true})).toHaveCount(0);
  await page.getByLabel('Recipe qualification job ID',{exact:true}).fill(qualificationId);await page.getByRole('button',{name:'Read recipe qualification job'}).click();
  await page.getByRole('button',{name:'Read measured recipe report'}).click();
  await expect(page.getByText('Diagnostic comparison: matched. Qualification: eligible for separate review.')).toBeVisible();
  await page.getByRole('button',{name:'Reload draft to review this qualification'}).click();await page.getByRole('button',{name:'Review qualification',exact:true}).click();
  await expect(page.getByRole('button',{name:'Approve qualified revision'})).toHaveCount(0);expect(state.writes).toHaveLength(0);
});


for (const state of ['running', 'disabled', 'drain_failed']) {
  test('owner explicitly reads minimized maintenance snapshot: ' + state, async ({ page }) => {
    const fixtureState = await fixture(page); const requests: string[] = [];
    await page.route('**/api/v1/admin/maintenance', route => {
      requests.push(route.request().method());
      return route.fulfill({ json: { enabled: state !== 'disabled', state, local_instance_current: true, thread_alive: state === 'running', active_step: false,
        drain_failed: state === 'drain_failed', counts: { polls: 4, attempts: 2, succeeded: 1, held: 1, errors: 0 },
        last_reason: 'AUTHORITY_HELD', poll_ms: 250, page_size: 5, steps_per_minute: 60, drain_ms: 1000 } });
    });
    await open(page); await page.getByRole('button', { name: 'Runtime controls', exact: true }).click();
    expect(requests).toEqual([]);
    await page.getByRole('button', { name: 'Load maintenance status', exact: true }).click();
    await expect(page.getByText('Snapshot: ' + state + '.', { exact: false })).toBeVisible();
    await expect(page.getByText('Last reason: AUTHORITY_HELD.', { exact: false })).toBeVisible();
    expect(requests).toEqual(['GET']); expect(fixtureState.writes).toEqual([]);
    await expect(page.getByRole('button', { name: 'Start maintenance', exact: true })).toHaveCount(0);
  });
}

test('malformed maintenance refresh clears the previous snapshot without writes', async ({ page }) => {
  const state = await fixture(page); let reads = 0;
  await page.route('**/api/v1/admin/maintenance', route => route.fulfill({ json: {
    enabled: true, state: 'running', local_instance_current: true, thread_alive: true, active_step: false, drain_failed: false,
    counts: { polls: 1, attempts: 0, succeeded: 0, held: 0, errors: 0 }, last_reason: null,
    poll_ms: 250, page_size: ++reads === 1 ? 5 : 26, steps_per_minute: 60, drain_ms: 1000 } }));
  await open(page); await page.getByRole('button', { name: 'Runtime controls', exact: true }).click();
  await page.getByRole('button', { name: 'Load maintenance status', exact: true }).click();
  await expect(page.getByText('Snapshot: running.', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'Load maintenance status', exact: true }).click();
  await expect(page.getByText('Maintenance information is unavailable.', { exact: true })).toBeVisible();
  await expect(page.getByText('Snapshot: running.', { exact: false })).toHaveCount(0);
  expect(state.writes).toEqual([]);
});


const improvementPreviewId='96000000-0000-4000-8000-000000000001', improvementPermissionId='97000000-0000-4000-8000-000000000001';
async function improvementFixture(page:Page, options:{role?:string;ambiguousConfirm?:boolean;ambiguousWithdraw?:boolean;expired?:boolean;delay?:number;ttl?:number}={}) {
  await fixture(page,{role:options.role});const writes:{path:string;body:any;key:string;version:string|undefined}[]=[];
  const now=Date.now(), notice={version:'optional-synthetic-v1',sha256:'a'.repeat(64),text:'Synthetic separate optional-use notice. Not real consent.'};
  const assets=[{id:referenceId,kind:'reference',sha256:'d'.repeat(64),data_origin:'synthetic',purpose_id:purposeId,source_permission_reference:'original-synthetic-permission',expires_at_ms:now+50000}];
  let committed=false,withdrawn=false,derivedAllowed=false,confirmAttempts=0,withdrawAttempts=0;
  const grant=(id=improvementPermissionId)=>({id,state_version:withdrawn||id!==improvementPermissionId?2:1,scope_sha256:'b'.repeat(64),grant_sha256:'c'.repeat(64),
    withdrawn:withdrawn||id!==improvementPermissionId,usable:!withdrawn&&id===improvementPermissionId,optional_improvement:true,optional_publicity:false,rights_independently_verified:false,
    physical_truth_verified:false,independence_verified:false,derived_review_metadata_allowed:derivedAllowed,authority_basis:'owner_attestation',documented_permission_reference:'separate-synthetic-record',expires_at_ms:now+50000,held_reason:withdrawn?'WITHDRAWN':null,assets,notice});
  const preview=()=>({id:improvementPreviewId,state_version:committed?2:1,status:committed?'committed':'preview',scope_sha256:'b'.repeat(64),assets,
    remaining_review_ms:options.expired?0:options.ttl??30000,server_time_ms:now,source_expires_at_ms:now+50000,max_lifetime_ms:60000,can_confirm:!committed&&!options.expired,permission_id:committed?improvementPermissionId:null,notice});
  await page.route(url=>url.pathname.startsWith('/api/v1/privacy/improvement'),async route=>{
    const req=route.request(),path=new URL(req.url()).pathname.replace('/api/v1','');
    if(req.method()==='POST')writes.push({path,body:req.postData()?req.postDataJSON():null,key:req.headers()['idempotency-key'],version:req.headers()['if-match']});
    if(path==='/privacy/improvement-options')return route.fulfill({json:{notice,server_time_ms:now,max_lifetime_ms:60000,max_assets:16}});
    if(path==='/privacy/improvement-previews'&&req.method()==='POST'){
      if(options.delay)await new Promise(resolve=>setTimeout(resolve,options.delay));return route.fulfill({json:preview()});
    }
    if(path==='/privacy/improvement-previews/'+improvementPreviewId)return route.fulfill({json:preview()});
    if(path==='/privacy/improvement-permissions'&&req.method()==='POST'){
      committed=true;derivedAllowed=req.postDataJSON().derived_review_metadata_acknowledged===true;if(options.ambiguousConfirm&&confirmAttempts++===0)return route.abort('failed');return route.fulfill({json:grant()});
    }
    if(path==='/privacy/improvement-permissions/'+improvementPermissionId+'/withdraw'){
      withdrawn=true;if(options.ambiguousWithdraw&&withdrawAttempts++===0)return route.abort('failed');return route.fulfill({json:grant()});
    }
    if(path==='/privacy/improvement-permissions')return route.fulfill({json:{permissions:[grant()],next_cursor:null}});
    if(path.startsWith('/privacy/improvement-permissions/'))return route.fulfill({json:grant(path.split('/').at(-1))});
    throw new Error('Unexpected optional permission request '+path);
  });
  await open(page);
  return {writes,now};
}
async function prepareImprovement(page:Page) {
  await page.getByRole('button',{name:'Optional improvement permissions',exact:true}).click();
  await page.getByRole('button',{name:'Load improvement notice',exact:true}).click();
  await page.getByLabel('Selected improvement asset IDs',{exact:true}).fill(referenceId);
  await page.getByRole('button',{name:'Preview optional improvement scope',exact:true}).click();
  await expect(page.getByLabel('Documented optional permission reference',{exact:true})).toBeVisible();
  await page.getByLabel('Documented optional permission reference',{exact:true}).fill('separate-synthetic-record');
}
async function acknowledgeImprovement(page:Page) {
  await page.getByLabel('I hold documented authorization for optional improvement use of these exact assets.',{exact:true}).check();
  await page.getByLabel('This use is optional and revocable; it does not authorize publicity or certify truth or independence.',{exact:true}).check();
}

test('owner reviews separate optional scope and explicitly confirms then withdraws',async({page})=>{
  const state=await improvementFixture(page);await prepareImprovement(page);
  await expect(page.getByRole('button',{name:'Confirm optional improvement permission',exact:true})).toBeDisabled();
  await acknowledgeImprovement(page);await page.getByRole('button',{name:'Confirm optional improvement permission',exact:true}).click();
  await expect(page.getByText('Separate owner attestation recorded. No data was trained on or published.',{exact:true})).toBeVisible();
  const created=state.writes.find(w=>w.path==='/privacy/improvement-permissions')!;
  expect(created.body).toMatchObject({confirmed_scope_sha256:'b'.repeat(64),optional_improvement_acknowledged:true,limitations_acknowledged:true,expires_at_ms:state.now+50000});expect(created.version).toBe('1');
  await expect(page.getByRole('button',{name:'Withdraw optional improvement permission',exact:true})).toBeDisabled();
  await page.getByLabel('Stop future improvement use; already received copies cannot be recalled.',{exact:true}).check();
  await page.getByRole('button',{name:'Withdraw optional improvement permission',exact:true}).click();
  await expect(page.getByText('Withdrawn: yes.',{exact:false})).toBeVisible();expect(state.writes.at(-1)?.version).toBe('1');
});

test('reviewer reads optional permission without owner grant controls',async({page})=>{
  const state=await improvementFixture(page,{role:'reviewer'});await page.getByRole('button',{name:'Optional improvement permissions',exact:true}).click();
  await expect(page.getByRole('button',{name:'Load improvement notice',exact:true})).toHaveCount(0);
  await page.getByRole('button',{name:'List improvement permissions',exact:true}).click();await page.getByRole('button',{name:'Read improvement permission '+improvementPermissionId,exact:true}).click();
  await expect(page.getByText('Usable: yes.',{exact:false})).toBeVisible();await expect(page.getByRole('button',{name:'Withdraw optional improvement permission',exact:true})).toHaveCount(0);expect(state.writes).toEqual([]);
});

test('operator has no optional-permission administration controls',async({page})=>{
  await improvementFixture(page,{role:'operator'});await expect(page.getByRole('button',{name:'Optional improvement permissions',exact:true})).toHaveCount(0);
});

test('unconfirmed optional grant retries the immutable scope version key and expiry',async({page})=>{
  const state=await improvementFixture(page,{ambiguousConfirm:true});await prepareImprovement(page);await acknowledgeImprovement(page);
  await page.getByRole('button',{name:'Confirm optional improvement permission',exact:true}).click();await expect(page.getByRole('button',{name:'Retry unchanged improvement request',exact:true})).toBeVisible();
  await expect(page.getByLabel('Permission duration in seconds',{exact:true})).toBeDisabled();
  await page.getByRole('button',{name:'Retry unchanged improvement request',exact:true}).click();
  await expect(page.getByText('Separate owner attestation recorded. No data was trained on or published.',{exact:true})).toBeVisible();
  const writes=state.writes.filter(w=>w.path==='/privacy/improvement-permissions');expect(writes).toHaveLength(2);expect(writes[1]).toEqual(writes[0]);
});

test('lost confirmation recovers through exact preview without another grant intent',async({page})=>{
  const state=await improvementFixture(page,{ambiguousConfirm:true});await prepareImprovement(page);await acknowledgeImprovement(page);
  await page.getByRole('button',{name:'Confirm optional improvement permission',exact:true}).click();await expect(page.getByRole('button',{name:'Retry unchanged improvement request',exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Read improvement preview',exact:true}).click();await expect(page.getByText('Usable: yes.',{exact:false})).toBeVisible();
  await expect(page.getByRole('button',{name:'Retry unchanged improvement request',exact:true})).toHaveCount(0);expect(state.writes.filter(w=>w.path==='/privacy/improvement-permissions')).toHaveLength(1);
});

for(const variant of ['expired','delayed','hidden'])test('optional permission review cannot renew after '+variant,async({page})=>{
  const state=await improvementFixture(page,{expired:variant==='expired',delay:variant==='delayed'?400:0,ttl:variant==='delayed'?200:30000});await prepareImprovement(page);await acknowledgeImprovement(page);
  if(variant==='hidden')await page.evaluate(()=>{Object.defineProperty(document,'visibilityState',{configurable:true,value:'hidden'});document.dispatchEvent(new Event('visibilitychange'));});
  await expect(page.getByRole('button',{name:'Confirm optional improvement permission',exact:true})).toBeDisabled();expect(state.writes.filter(w=>w.path==='/privacy/improvement-permissions')).toEqual([]);
});

test('unrelated withdrawn permission cannot resolve an uncertain withdrawal',async({page})=>{
  await improvementFixture(page,{ambiguousWithdraw:true});await page.getByRole('button',{name:'Optional improvement permissions',exact:true}).click();
  await page.getByLabel('Improvement permission ID',{exact:true}).fill(improvementPermissionId);await page.getByRole('button',{name:'Read improvement permission',exact:true}).click();
  await page.getByLabel('Stop future improvement use; already received copies cannot be recalled.',{exact:true}).check();await page.getByRole('button',{name:'Withdraw optional improvement permission',exact:true}).click();
  await expect(page.getByRole('button',{name:'Retry unchanged improvement request',exact:true})).toBeVisible();
  await page.getByLabel('Improvement permission ID',{exact:true}).fill('97000000-0000-4000-8000-000000000002');await page.getByRole('button',{name:'Read improvement permission',exact:true}).click();
  await expect(page.getByText('Withdrawn: yes.',{exact:false})).toBeVisible();await expect(page.getByRole('button',{name:'Retry unchanged improvement request',exact:true})).toBeVisible();
  await page.getByLabel('Improvement permission ID',{exact:true}).fill(improvementPermissionId);await page.getByRole('button',{name:'Read improvement permission',exact:true}).click();
  await expect(page.getByRole('button',{name:'Retry unchanged improvement request',exact:true})).toHaveCount(0);
});


const datasetId='98000000-0000-4000-8000-000000000001',datasetGroup='1'.repeat(64);
async function datasetFixture(page:Page,options:{role?:string;unknown?:'create'|'advance';completed?:boolean;badPage?:boolean}={}){
  const role=options.role??'reviewer';await fixture(page,{role:role==='combined'?'owner':role});
  if(role==='combined')await page.route('**/api/v1/me',route=>route.fulfill({json:{id:ownerId,display_name:'Synthetic owner reviewer',roles:['owner','reviewer'],csrf_token:csrf,session_id:'dataset-session'}}));
  const writes:{path:string;body:any;key:string;version:string|undefined}[]=[];let status=options.completed?'completed':'queued',version=1,attempts=0,groupSplit='FROZEN_TEST';
  let body:any={selections:[{label_id:labelId,label_revision:1,split:'DEVELOPMENT',permissions:[{id:improvementPermissionId,state_version:1}]}],historical_diagnostic_acknowledged:true,frozen_holdout_acknowledged:false};
  const job=()=>({id:datasetId,kind:'dataset_manifest',state_version:version,status,example_count:body.selections.length,prepared_count:status==='completed'?body.selections.length:0,steps_reserved:status==='completed'?1:0,
    splits:{DEVELOPMENT:1,VALIDATION:0,FROZEN_TEST:0},manifest_sha256:status==='completed'?'a'.repeat(64):null,receipt_usable:status==='completed'&&role!=='owner',failure_reason:null,prior_exposure_unknown:true,
    independent_benchmark_qualified:false,can_advance:status==='queued'&&role!=='owner',can_cancel:status==='queued',can_retire:status==='completed'});
  const group=()=>({id:datasetGroup,state_version:groupSplit==='DEVELOPMENT'?2:1,category:'kit',split:groupSplit,generation:groupSplit==='DEVELOPMENT'?2:1,can_declassify:groupSplit!=='DEVELOPMENT',independent_benchmark_qualified:false});
  await page.route(url=>url.pathname.startsWith('/api/v1/datasets/')||url.pathname.startsWith('/api/v1/jobs/'+datasetId),async route=>{
    const req=route.request(),path=new URL(req.url()).pathname.replace('/api/v1','');
    if(req.method()==='POST')writes.push({path,body:req.postDataJSON(),key:req.headers()['idempotency-key'],version:req.headers()['if-match']});
    if(path==='/datasets/manifests'&&req.method()==='POST'){body=req.postDataJSON();if(options.unknown==='create'&&attempts++===0)return route.abort('failed');return route.fulfill({json:job()});}
    if(path==='/datasets/manifests')return route.fulfill({json:{datasets:[job()],next_cursor:null}});
    if(path==='/jobs/'+datasetId+'/advance'){status='completed';version=3;if(options.unknown==='advance'&&attempts++===0)return route.abort('failed');return route.fulfill({json:job()});}
    if(path.endsWith('/cancel')){status='cancelled';version++;return route.fulfill({json:job()});}
    if(path.endsWith('/retire')){status='retired';version++;return route.fulfill({json:job()});}
    if(path.endsWith('/declassify')){groupSplit='DEVELOPMENT';return route.fulfill({json:group()});}
    if(path.startsWith('/datasets/groups/'))return route.fulfill({json:group()});
    if(path.endsWith('/request'))return route.fulfill({json:body});
    if(path.endsWith('/examples'))return route.fulfill({json:{dataset_id:datasetId,manifest_sha256:options.badPage?'0'.repeat(64):'a'.repeat(64),examples:[{index:0,label_id:labelId,label_revision:1,split:'DEVELOPMENT',data_origin:'synthetic',content_sha256:'b'.repeat(64),
      groups:['kit','session','operator'].map((category,i)=>({id:String(i+1).repeat(64),category,generation:1})),physical_truth_verified:false,independence_verified:false,independent_benchmark_qualified:false}],next_index:null,prior_exposure_unknown:true,independent_benchmark_qualified:false}});
    return route.fulfill({json:job()});
  });
  await open(page);await page.getByRole('button',{name:'Dataset manifests',exact:true}).click();return{writes};
}
async function datasetSelection(page:Page){
  await page.getByLabel('Dataset label ID',{exact:true}).fill(labelId);await page.getByLabel('Dataset permission ID',{exact:true}).fill(improvementPermissionId);await page.getByRole('button',{name:'Add dataset selection',exact:true}).click();
}
async function readDataset(page:Page){await page.getByLabel('Dataset ID',{exact:true}).fill(datasetId);await page.getByRole('button',{name:'Read dataset status',exact:true}).click();}

test('reviewer creates and prepares a diagnostic dataset then reads audited example metadata',async({page})=>{
  const state=await datasetFixture(page);await datasetSelection(page);await expect(page.getByRole('button',{name:'Create dataset manifest',exact:true})).toBeDisabled();
  await page.getByLabel('I reviewed the complete selections and request historical diagnostics, not training or live activation.',{exact:true}).check();await page.getByRole('button',{name:'Create dataset manifest',exact:true}).click();
  await expect(page.getByText('Prepared 0/1',{exact:false})).toBeVisible();await page.getByRole('button',{name:'Advance one dataset step',exact:true}).click();
  await expect(page.getByText('Receipt usable: yes.',{exact:false})).toBeVisible();await page.getByRole('button',{name:'Read dataset examples',exact:true}).click();
  await expect(page.getByText('Example 0:',{exact:false})).toBeVisible();expect(state.writes[1].version).toBe('1');await expect(page.getByRole('button',{name:'Declassify dataset group',exact:true})).toHaveCount(0);
});

test('owner dataset status never inherits reviewer creation or example controls',async({page})=>{
  await datasetFixture(page,{role:'owner',completed:true});await expect(page.getByRole('button',{name:'Create dataset manifest',exact:true})).toHaveCount(0);await readDataset(page);
  await expect(page.getByRole('button',{name:'Read dataset examples',exact:true})).toHaveCount(0);await expect(page.getByRole('button',{name:'Retire dataset manifest',exact:true})).toBeDisabled();
});

for(const unknown of ['create','advance'] as const)test('uncertain dataset '+unknown+' preserves exact body key and version',async({page})=>{
  const state=await datasetFixture(page,{unknown});await datasetSelection(page);await page.getByLabel('I reviewed the complete selections and request historical diagnostics, not training or live activation.',{exact:true}).check();
  await page.getByRole('button',{name:'Create dataset manifest',exact:true}).click();
  if(unknown==='advance'){await expect(page.getByText('Prepared 0/1',{exact:false})).toBeVisible();await page.getByRole('button',{name:'Advance one dataset step',exact:true}).click();}
  await expect(page.getByRole('button',{name:'Retry unchanged dataset request',exact:true})).toBeVisible();await page.getByRole('button',{name:'Retry unchanged dataset request',exact:true}).click();
  await expect(page.getByRole('button',{name:'Retry unchanged dataset request',exact:true})).toHaveCount(0);const target=unknown==='create'?'/datasets/manifests':'/jobs/'+datasetId+'/advance';const writes=state.writes.filter(w=>w.path===target);expect(writes).toHaveLength(2);expect(writes[1]).toEqual(writes[0]);
});

test('dataset plans expose every selection through pagination and frozen use needs separate acknowledgment',async({page})=>{
  await datasetFixture(page);await page.getByText('Import a prepared selection plan',{exact:true}).click();
  const values=Array.from({length:21},(_,i)=>({label_id:'99000000-0000-4000-8000-'+String(i+1).padStart(12,'0'),label_revision:1,split:'FROZEN_TEST',permissions:[{id:improvementPermissionId,state_version:1}]}));
  await page.getByLabel('Dataset selection plan JSON',{exact:true}).fill(JSON.stringify(values));await page.getByRole('button',{name:'Review imported dataset selections',exact:true}).click();
  await expect(page.getByText('Selection page 1 of 2.',{exact:false})).toBeVisible();await page.getByRole('button',{name:'Next selection page',exact:true}).click();await expect(page.getByText(values[20].label_id+' revision 1:',{exact:false})).toBeVisible();
  await page.getByLabel('I reviewed the complete selections and request historical diagnostics, not training or live activation.',{exact:true}).check();await expect(page.getByRole('button',{name:'Create dataset manifest',exact:true})).toBeDisabled();
  await page.getByLabel('Prior exposure and independent benchmark qualification are unverified, and access is recorded.',{exact:true}).check();await expect(page.getByRole('button',{name:'Create dataset manifest',exact:true})).toBeEnabled();
});

test('dataset declassification acknowledgment cannot approve retirement and clears stale receipt display',async({page})=>{
  const state=await datasetFixture(page,{role:'combined',completed:true});await readDataset(page);await page.getByLabel('Dataset consequence reason',{exact:true}).fill('retire-reviewed');
  await page.getByLabel('Dataset group SHA-256',{exact:true}).fill(datasetGroup);await page.getByRole('button',{name:'Read dataset group',exact:true}).click();await page.getByLabel('Declassification reason',{exact:true}).fill('used-for-development');
  await page.getByLabel('Declassify this group to DEVELOPMENT and invalidate previous dependent receipts.',{exact:true}).check();await expect(page.getByRole('button',{name:'Retire dataset manifest',exact:true})).toBeDisabled();
  await page.getByRole('button',{name:'Declassify dataset group',exact:true}).click();await expect(page.getByText('Group kit: DEVELOPMENT; generation 2.',{exact:false})).toBeVisible();await expect(page.getByText('Receipt usable: yes.',{exact:false})).toHaveCount(0);
  expect(state.writes[0].body).toEqual({acknowledged:true,reason:'used-for-development'});expect(state.writes[0].version).toBe('1');
});

test('dataset manifest mismatch blocks example display',async({page})=>{
  await datasetFixture(page,{completed:true,badPage:true});await readDataset(page);await page.getByRole('button',{name:'Read dataset examples',exact:true}).click();await expect(page.getByText('Dataset example page is unavailable.',{exact:true})).toBeVisible();await expect(page.getByText('Example 0:',{exact:false})).toHaveCount(0);
});

test('derived review metadata permission is a distinct default-off owner choice',async({page})=>{
  const state=await improvementFixture(page);await prepareImprovement(page);const label='I also hold documented optional-use authorization for associated outcome counts, review method and duration metadata. This is needed for labelled datasets.';
  await expect(page.getByLabel(label,{exact:true})).not.toBeChecked();await page.getByLabel(label,{exact:true}).check();await acknowledgeImprovement(page);await page.getByRole('button',{name:'Confirm optional improvement permission',exact:true}).click();
  await expect(page.getByText('Associated review metadata allowed: yes.',{exact:true})).toBeVisible();expect(state.writes.find(w=>w.path==='/privacy/improvement-permissions')?.body.derived_review_metadata_acknowledged).toBe(true);
});


const policyId = 'a1000000-0000-4000-8000-000000000001', otherPolicyId = 'a1000000-0000-4000-8000-000000000002';
async function policyFixture(page: Page, options: { role?: string; existing?: boolean; lostOnce?: boolean; badReply?: boolean } = {}) {
  await fixture(page, { role: options.role ?? 'reviewer' });
  const writes: { path: string; body: any; key: string; version: string | undefined }[] = [], committed = new Map<string, any>();
  let number = 1, saved = { name: 'Fixture policy', algorithm: 'reason_priority_v1', priority: ['SEPARATE_REGION', 'PLACE_FLAT', 'RECAPTURE'] }, lost = false;
  const record = (id = policyId, revision = number) => ({ id, state_version: number, latest_revision: number, revision, revision_sha256: 'a'.repeat(64), previous_sha256: revision === 1 ? null : 'b'.repeat(64),
    behavior_sha256: 'c'.repeat(64), spec: saved, status: 'draft', evaluation_status: 'NOT_VERIFIED', binding_current: true, promotion_available: false, live_effect: 'none_from_draft_write', can_revise: options.role !== 'owner' && revision === number });
  await page.route('**/api/v1/policies**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname.replace('/api/v1', '');
    const json = (value: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) });
    if (request.method() === 'POST') {
      const body = request.postDataJSON(), key = request.headers()['idempotency-key'];
      writes.push({ path, body, key, version: request.headers()['if-match'] });
      let result = committed.get(key);
      if (!result) { if (path.endsWith('/revisions')) number++; saved = body; result = record(); committed.set(key, result); }
      if (options.lostOnce && !lost) { lost = true; return route.abort('failed'); }
      return json(options.badReply ? { ...result, promotion_available: true } : result, 201);
    }
    if (path === '/policies') return json({ policies: options.existing || committed.size ? [record()] : [], next_cursor: null });
    const id = path.split('/')[2], revision = Number(url.searchParams.get('revision') ?? number);
    return json(record(id, revision));
  });
  await open(page); await page.getByRole('button', { name: 'Policy candidates', exact: true }).click();
  return { writes, committed };
}
const policyAck = 'I reviewed this distinct ordering. It is a proposal, not an evaluated improvement or activation.';
async function newPolicy(page: Page) { await page.getByLabel('Policy name', { exact: true }).fill('Reviewed ordering'); await page.getByLabel(policyAck, { exact: true }).check(); }
async function openPolicy(page: Page) { await page.getByRole('button', { name: 'Load policy drafts', exact: true }).click(); await page.getByRole('button', { name: 'Open policy Fixture policy revision 1', exact: true }).click(); }

test('policy reviewer saves an inactive draft and appends an exact-version revision', async ({ page }) => {
  const state = await policyFixture(page); await newPolicy(page);
  await expect(page.getByText('Open Historical comparisons for a bounded diagnostic of action choices on recorded reasons.', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'Save policy draft', exact: true }).click();
  await expect(page.getByText('Policy draft revision recorded. This write does not qualify or activate it. Keep the exact proposal for a future reviewed comparison.')).toBeVisible();
  await page.getByLabel('Policy name', { exact: true }).fill('Revised ordering'); await expect(page.getByLabel(policyAck, { exact: true })).not.toBeChecked();
  await page.getByLabel(policyAck, { exact: true }).check(); await page.getByRole('button', { name: 'Append policy revision', exact: true }).click();
  await expect(page.getByText('revision 2 of 2;', { exact: false })).toBeVisible();
  expect(state.writes).toHaveLength(2); expect(state.writes[1].version).toBe('1'); expect(state.writes[1].path).toBe('/policies/' + policyId + '/revisions');
  expect(state.writes.every(w => !('approved' in w.body) && w.body.algorithm === 'reason_priority_v1')).toBe(true);
  await page.screenshot({ path: 'evidence/local/policy-synthetic-reviewer.png', fullPage: true });
});

test('policy duplicate priorities and edited targets cannot approve a write', async ({ page }) => {
  const state = await policyFixture(page, { existing: true }); await openPolicy(page);
  await page.getByRole('combobox', { name: 'Policy priority 2', exact: true }).selectOption('SEPARATE_REGION'); await page.getByLabel(policyAck, { exact: true }).check();
  await expect(page.getByRole('button', { name: 'Append policy revision', exact: true })).toBeDisabled();
  await page.getByRole('combobox', { name: 'Policy priority 2', exact: true }).selectOption('PLACE_FLAT'); await page.getByLabel(policyAck, { exact: true }).check();
  await page.getByLabel('Policy ID', { exact: true }).fill(otherPolicyId); await expect(page.getByLabel(policyAck, { exact: true })).not.toBeChecked(); await page.getByLabel(policyAck, { exact: true }).check();
  await expect(page.getByRole('button', { name: 'Append policy revision', exact: true })).toBeDisabled(); expect(state.writes).toHaveLength(0);
});

test('policy lost creation freezes intent through unrelated read and unchanged retry', async ({ page }) => {
  const state = await policyFixture(page, { lostOnce: true }); await newPolicy(page); await page.getByRole('button', { name: 'Save policy draft', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry unchanged policy write', exact: true })).toBeVisible(); await expect(page.getByLabel('Policy name', { exact: true })).toBeDisabled();
  await page.getByLabel('Policy ID', { exact: true }).fill(otherPolicyId); await page.getByRole('button', { name: 'Read policy revision', exact: true }).click();
  await expect(page.getByText('Metadata read; the original write is still unconfirmed. Retry its unchanged intent.')).toBeVisible();
  await page.getByRole('button', { name: 'Retry unchanged policy write', exact: true }).click(); await expect(page.getByRole('button', { name: 'Retry unchanged policy write', exact: true })).toHaveCount(0);
  expect(state.writes).toHaveLength(2); expect(state.writes[1]).toEqual(state.writes[0]); expect(state.committed.size).toBe(1);
});

test('policy lost revision preserves original version and body', async ({ page }) => {
  const state = await policyFixture(page, { lostOnce: true, existing: true }); await openPolicy(page);
  await page.getByLabel('Policy name', { exact: true }).fill('Changed once'); await page.getByLabel(policyAck, { exact: true }).check(); await page.getByRole('button', { name: 'Append policy revision', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry unchanged policy write', exact: true })).toBeVisible(); await page.getByRole('button', { name: 'Retry unchanged policy write', exact: true }).click();
  await expect(page.getByText('revision 2 of 2;', { exact: false })).toBeVisible(); expect(state.writes[1]).toEqual(state.writes[0]); expect(state.writes[1].version).toBe('1');
});

test('policy owner reviews candidate metadata without gaining reviewer or activation controls', async ({ page }) => {
  const state = await policyFixture(page, { role: 'owner', existing: true }); await openPolicy(page);
  await expect(page.getByText('Owner access can review draft metadata. Creating or revising requires a separate reviewer grant.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save policy draft', exact: true })).toHaveCount(0); await expect(page.getByRole('button', { name: /Promote policy|Rollback policy/ })).toHaveCount(0); expect(state.writes).toHaveLength(0);
});

test('policy unsupported activation reply stays unconfirmed and exit performs no new write', async ({ page }) => {
  const state = await policyFixture(page, { badReply: true }); await newPolicy(page); await page.getByRole('button', { name: 'Save policy draft', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry unchanged policy write', exact: true })).toBeVisible(); await expect(page.getByRole('button', { name: 'Finish without another write', exact: true })).toBeDisabled();
  await page.getByLabel('I understand forgetting retry details does not undo or determine the server result.', { exact: true }).check(); await page.getByRole('button', { name: 'Finish without another write', exact: true }).click();
  await expect(page.getByText('Retry details forgotten; the server result remains unresolved and may already exist. Review saved drafts with the owner before a separate new intent.')).toBeVisible(); expect(state.writes).toHaveLength(1);
});

test('operator does not acquire policy candidate access from workbench navigation', async ({ page }) => {
  await fixture(page, { role: 'operator' }); await open(page); await expect(page.getByRole('button', { name: 'Policy candidates', exact: true })).toHaveCount(0);
});

const evaluationId = 'a2000000-0000-4000-8000-000000000001', otherEvaluationId = 'a2000000-0000-4000-8000-000000000002';
const historicalAck = 'I reviewed these exact inputs for historical diagnostics only.';
async function evaluationFixture(page: Page, options: { role?: string; frozen?: boolean; completed?: boolean; lost?: 'create' | 'advance'; badCounts?: boolean; badPage?: boolean; ttl?: number;
  vision?: boolean; visionDisabled?: boolean; badVisionCounts?: boolean; badVisionMeasurement?: boolean; unknownVision?: boolean } = {}) {
  await fixture(page, { role: options.role ?? 'reviewer' });
  let status = options.completed ? 'completed' : 'queued', version = options.completed ? 3 : 1, lost = false;
  const writes: { path: string; body: any; key: string; version?: string }[] = [], committed = new Map<string, any>();
  const record = (id = evaluationId) => ({ id, kind: 'policy_evaluation', state_version: version, status, policy_id: policyId, policy_revision: 1,
    policy_revision_sha256: 'a'.repeat(64), manifest_id: datasetId, manifest_sha256: 'b'.repeat(64), candidate_name: 'Fixture comparison', example_count: 1,
    prepared_count: status === 'completed' || status === 'retired' ? 1 : 0, steps_reserved: status === 'queued' ? 0 : 1,
    remaining_ms: options.ttl ?? 30000, lease_remaining_ms: 0, report_sha256: status === 'completed' || status === 'retired' ? 'e'.repeat(64) : null,
    failure_reason: null, runner: options.vision ? 'vision_replay_v1' : 'decision_replay_v1', diagnostic_only: true, independent_benchmark_qualified: false, promotion_eligible: false, operator_effort_measured: false,
    ...(options.vision ? { candidate_recipe_id: recipeId, candidate_recipe_revision: 1, candidate_recipe_state_version: 1, candidate_recipe_sha256: 'f'.repeat(64) } : {}),
    can_advance: options.role !== 'owner' && status === 'queued', can_cancel: status === 'queued', can_retire: status === 'completed' });
  const body = { runner: options.vision ? 'vision_replay_v1' : 'decision_replay_v1', policy_id: policyId, policy_revision: 1, policy_state_version: 1, policy_revision_sha256: 'a'.repeat(64),
    manifest_id: datasetId, manifest_sha256: 'b'.repeat(64), historical_diagnostic_acknowledged: true, frozen_holdout_acknowledged: !!options.frozen,
    ...(options.vision ? { candidate_recipe_id: recipeId, candidate_recipe_revision: 1, candidate_recipe_state_version: 1, candidate_recipe_sha256: 'f'.repeat(64), vision_measurement_acknowledged: true } : {}) };
  const sideCounts = (observed: boolean) => ({ observed_match: observed ? 1 : 0, counterfactual_unknown: observed ? 0 : 1, no_recorded_outcome: 0,
    not_actionable: 0, incorrect_finding: 0, declared_resolved: observed ? 1 : 0, declared_unresolved: 0,
    ...(options.vision ? { measurements: 1, observable_frames: options.unknownVision ? 0 : 1, count_matches: options.unknownVision ? 0 : options.badVisionCounts ? 2 : 1,
      count_mismatches: 0, unobservable_frames: options.unknownVision ? 1 : 0 } : {}) });
  await page.route('**/api/v1/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname.replace('/api/v1', '');
    const json = (value: unknown, code = 200) => route.fulfill({ status: code, contentType: 'application/json', body: JSON.stringify(value) });
    if (path === '/evaluations/options') return json({ runners: options.visionDisabled ? ['decision_replay_v1'] : ['decision_replay_v1','vision_replay_v1'], promotion_available: false, physical_truth_verified: false });
    if (options.vision && path === '/recipes/' + recipeId + '/draft') return json({ id: recipeId, revision: 1, state_version: 1, recipe_sha256: 'f'.repeat(64), retired: false });
    if (path === '/policies/' + policyId) return json({ id: policyId, revision: 1, latest_revision: 1, state_version: 1, revision_sha256: 'a'.repeat(64),
      binding_current: true, spec: { name: 'Fixture candidate' }, evaluation_status: 'NOT_VERIFIED', promotion_available: false });
    if (path === '/jobs/' + datasetId) return json({ id: datasetId, kind: 'dataset_manifest', status: 'completed', receipt_usable: true, example_count: 1,
      manifest_sha256: 'b'.repeat(64), remaining_ms: options.ttl ?? 30000, splits: { DEVELOPMENT: options.frozen ? 0 : 1, VALIDATION: 0, FROZEN_TEST: options.frozen ? 1 : 0 }, independent_benchmark_qualified: false });
    if (!path.startsWith('/evaluations') && !path.startsWith('/jobs/' + evaluationId)) return route.fallback();
    if (request.method() === 'POST') {
      const key = request.headers()['idempotency-key']; expect(key).toBeTruthy(); expect(request.headers()['x-csrf-token']).toBe(csrf);
      writes.push({ path, body: request.postDataJSON(), key, version: request.headers()['if-match'] });
      let value = committed.get(key);
      if (!value) { if (path.endsWith('/advance')) { status = 'completed'; version = 3; } else if (path.endsWith('/cancel')) { status = 'cancelled'; version++; }
        else if (path.endsWith('/retire')) { status = 'retired'; version++; } value = record(); committed.set(key, value); }
      if (!lost && ((options.lost === 'create' && path === '/evaluations') || (options.lost === 'advance' && path.endsWith('/advance')))) { lost = true; return route.abort('failed'); }
      return json(value, path === '/evaluations' ? 201 : 200);
    }
    if (path === '/evaluations') return json({ evaluations: [record()], next_cursor: null });
    if (path.endsWith('/request')) return json(body);
    if (path.endsWith('/examples')) return json({ id: evaluationId, report_sha256: (options.badPage ? 'f' : 'e').repeat(64), diagnostic_only: true, promotion_eligible: false,
      examples: [{ index: 0, label_id: labelId, label_revision: 1, content_sha256: 'c'.repeat(64), policy_revision_sha256: 'a'.repeat(64), split: options.frozen ? 'FROZEN_TEST' : 'DEVELOPMENT',
        data_origin: 'synthetic', diagnostic_only: true, independent_benchmark_qualified: false, promotion_eligible: false, operator_effort_measured: false,
        baseline: { action: 'SEPARATE_REGION', classification: 'observed_match', declared_resolved: true, ...(options.vision ? {recipe_sha256:'d'.repeat(64),measurements:[visionMeasurement()]} : {}) },
        candidate: { action: 'PLACE_FLAT', classification: 'counterfactual_unknown', declared_resolved: null, ...(options.vision ? {recipe_sha256:'f'.repeat(64),measurements:[visionMeasurement()]} : {}) },
        ...(options.vision ? {runner:'vision_replay_v1',original_frames:1,measurement_count:2,calibration_sha256:'a'.repeat(64),pixel_measurement_performed:true,physical_truth_verified:false} : {}) }], next_index: null });
    const value = record(path.split('/')[2]);
    return json({ ...value, result_header_current: status === 'completed', counts: status === 'completed' ? { baseline: sideCounts(true), candidate: options.badCounts ? { ...sideCounts(false), observed_match: 1 } : sideCounts(false) } : null,
      ...(options.vision ? {pixel_measurement_performed:status==='completed',physical_truth_verified:false} : {}) });
  });
  function visionMeasurement() { return {observation_id:labelBefore,original_asset_id:referenceId,source_sha256:options.badVisionMeasurement?'bad':'e'.repeat(64),calibration_sha256:'a'.repeat(64),
    findings:[options.unknownVision?'UNOBSERVABLE':'SATISFIED'],class_counts:{washer:options.unknownVision?0:1},declared_truth_counts:{washer:1},count_comparison_observable:!options.unknownVision,
    counts_match_declared_truth:options.unknownVision?null:true,physical_truth_verified:false,dimension_truth_accuracy_measured:false}; }
  await open(page); await page.getByRole('button', { name: 'Historical comparisons', exact: true }).click();
  return { writes };
}
async function evaluationInputs(page: Page) {
  await page.getByLabel('Evaluation candidate ID', { exact: true }).fill(policyId); await page.getByLabel('Evaluation dataset ID', { exact: true }).fill(datasetId);
  await page.getByRole('button', { name: 'Read comparison inputs', exact: true }).click(); await expect(page.getByLabel(historicalAck, { exact: true })).toBeVisible();
}
async function evaluationRead(page: Page, id = evaluationId) {
  await page.getByLabel('Evaluation ID', { exact: true }).fill(id); await page.getByRole('button', { name: 'Read evaluation summary', exact: true }).click();
}

const visionAck = 'I separately authorize fresh measurement of the permitted originals. Declared counts are not independent physical truth and completion cannot activate changes.';
async function visionInputs(page: Page) {
  await page.getByRole('combobox', { name: 'Comparison method', exact: true }).selectOption('vision_replay_v1');
  await page.getByLabel('Candidate recipe ID for image comparison', { exact: true }).fill(recipeId);
  await evaluationInputs(page);
}

test('original-image comparison requires separate approval and binds exact source candidate inputs', async ({ page }) => {
  const state = await evaluationFixture(page, { vision: true }); await visionInputs(page);
  await page.getByLabel(historicalAck, { exact: true }).check();
  const create = page.getByRole('button', { name: 'Create original-image comparison', exact: true }); await expect(create).toBeDisabled();
  await page.getByLabel(visionAck, { exact: true }).check(); await create.click();
  await expect(page.getByText('Evaluation operation recorded.', { exact: false })).toBeVisible();
  await evaluationRead(page); await page.getByRole('button', { name: 'Advance one comparison step', exact: true }).click(); await evaluationRead(page);
  await expect(page.getByRole('table', { name: 'Pixel measurements against declared counts; unknown frames remain unknown', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Read comparison examples', exact: true }).click();
  await expect(page.getByText('2 fresh measurements; exact geometry hash', { exact: false })).toBeVisible();
  await expect(page.getByText('Physical truth and dimension-truth accuracy remain unverified.', { exact: false })).toBeVisible();
  expect(state.writes).toHaveLength(2);
  expect(state.writes[0].body).toEqual({ runner: 'vision_replay_v1', policy_id: policyId, policy_revision: 1, policy_state_version: 1,
    policy_revision_sha256: 'a'.repeat(64), manifest_id: datasetId, manifest_sha256: 'b'.repeat(64), historical_diagnostic_acknowledged: true,
    frozen_holdout_acknowledged: false, candidate_recipe_id: recipeId, candidate_recipe_revision: 1, candidate_recipe_state_version: 1,
    candidate_recipe_sha256: 'f'.repeat(64), vision_measurement_acknowledged: true });
});

test('original-image comparison candidate edit withdraws both approvals', async ({ page }) => {
  const state = await evaluationFixture(page, { vision: true }); await visionInputs(page);
  await page.getByLabel(historicalAck, { exact: true }).check(); await page.getByLabel(visionAck, { exact: true }).check();
  await expect(page.getByRole('button', { name: 'Create original-image comparison', exact: true })).toBeEnabled();
  await page.getByLabel('Candidate recipe ID for image comparison', { exact: true }).fill(otherEvaluationId);
  await expect(page.getByRole('button', { name: 'Create original-image comparison', exact: true })).toBeDisabled();
  await expect(page.getByLabel(visionAck, { exact: true })).toHaveCount(0); expect(state.writes).toHaveLength(0);
});

test('original-image comparison lost create preserves exact recipe binding and retry intent', async ({ page }) => {
  const state = await evaluationFixture(page, { vision: true, lost: 'create' }); await visionInputs(page);
  await page.getByLabel(historicalAck, { exact: true }).check(); await page.getByLabel(visionAck, { exact: true }).check();
  await page.getByRole('button', { name: 'Create original-image comparison', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry unchanged evaluation request', exact: true })).toBeVisible();
  await evaluationRead(page, otherEvaluationId); await page.getByRole('button', { name: 'Retry unchanged evaluation request', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry unchanged evaluation request', exact: true })).toHaveCount(0);
  expect(state.writes).toHaveLength(2); expect(state.writes[0]).toEqual(state.writes[1]);
});

test('original-image comparison unavailable capability blocks create', async ({ page }) => {
  const state = await evaluationFixture(page, { vision: true, visionDisabled: true });
  await page.getByRole('combobox', { name: 'Comparison method', exact: true }).selectOption('vision_replay_v1');
  await page.getByLabel('Candidate recipe ID for image comparison', { exact: true }).fill(recipeId);
  await page.getByLabel('Evaluation candidate ID', { exact: true }).fill(policyId); await page.getByLabel('Evaluation dataset ID', { exact: true }).fill(datasetId);
  await page.getByRole('button', { name: 'Read comparison inputs', exact: true }).click();
  await expect(page.getByText('Original-image comparisons are unavailable here. Use recorded-action review or ask the owner.', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Create original-image comparison', exact: true })).toBeDisabled(); expect(state.writes).toHaveLength(0);
});

test('original-image comparison withholds inconsistent pixel summary counts', async ({ page }) => {
  await evaluationFixture(page, { vision: true, completed: true, badVisionCounts: true }); await evaluationRead(page);
  await expect(page.getByText('Evaluation summary is incomplete or its counts do not reconcile.', { exact: true })).toBeVisible();
  await expect(page.getByRole('table')).toHaveCount(0);
});

test('original-image comparison withholds malformed measurement provenance', async ({ page }) => {
  await evaluationFixture(page, { vision: true, completed: true, badVisionMeasurement: true }); await evaluationRead(page);
  await page.getByRole('button', { name: 'Read comparison examples', exact: true }).click();
  await expect(page.getByText('Evaluation page is incomplete or does not match this report.', { exact: true })).toBeVisible();
  await expect(page.getByText('2 fresh measurements', { exact: false })).toHaveCount(0);
});

test('original-image comparison unobservable frames remain unknown', async ({ page }) => {
  await evaluationFixture(page, { vision: true, completed: true, unknownVision: true }); await evaluationRead(page);
  const table = page.getByRole('table', { name: 'Pixel measurements against declared counts; unknown frames remain unknown', exact: true });
  await expect(table.getByRole('row', { name: 'unobservable_frames 1 1', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Read comparison examples', exact: true }).click();
  await expect(page.getByText('count agreement unknown.', { exact: false })).toHaveCount(2);
});

test('original-image comparison owner sees metadata without reviewer source controls', async ({ page }) => {
  const state = await evaluationFixture(page, { role: 'owner', vision: true, completed: true }); await evaluationRead(page);
  await expect(page.getByRole('table', { name: 'Pixel measurements against declared counts; unknown frames remain unknown', exact: true })).toBeVisible();
  for (const name of ['Create original-image comparison', 'Read comparison examples', 'Read original comparison request', 'Advance one comparison step'])
    await expect(page.getByRole('button', { name, exact: true })).toHaveCount(0);
  expect(state.writes).toHaveLength(0);
});

test('historical comparison reviewer creates exact diagnostics and sees unknown outcomes after one step', async ({ page }) => {
  const state = await evaluationFixture(page); await evaluationInputs(page); await page.getByLabel(historicalAck, { exact: true }).check();
  await page.getByRole('button', { name: 'Create historical comparison', exact: true }).click(); await expect(page.getByText('Evaluation operation recorded.', { exact: false })).toBeVisible();
  await evaluationRead(page); await page.getByRole('button', { name: 'Advance one comparison step', exact: true }).click(); await evaluationRead(page);
  await expect(page.getByRole('table', { name: 'All completed examples, including unknowns' })).toBeVisible();
  await page.getByRole('button', { name: 'Read comparison examples', exact: true }).click();
  await expect(page.getByText('candidate: PLACE_FLAT, counterfactual_unknown. Declared resolution: unknown.', { exact: false })).toBeVisible();
  expect(state.writes).toHaveLength(2); expect(state.writes[0].body).toEqual({ runner: 'decision_replay_v1', policy_id: policyId, policy_revision: 1, policy_state_version: 1,
    policy_revision_sha256: 'a'.repeat(64), manifest_id: datasetId, manifest_sha256: 'b'.repeat(64), historical_diagnostic_acknowledged: true, frozen_holdout_acknowledged: false });
  expect(state.writes[1].version).toBe('1'); expect(state.writes[1].body).toEqual({});
});

test('historical comparison frozen review is distinct and edited inputs withdraw acknowledgment', async ({ page }) => {
  const state = await evaluationFixture(page, { frozen: true }); await evaluationInputs(page); await page.getByLabel(historicalAck, { exact: true }).check();
  await expect(page.getByRole('button', { name: 'Create historical comparison', exact: true })).toBeDisabled();
  await page.getByLabel('Frozen data access is recorded and does not establish untouched or independent qualification.', { exact: true }).check();
  await expect(page.getByRole('button', { name: 'Create historical comparison', exact: true })).toBeEnabled();
  await page.getByLabel('Evaluation candidate ID', { exact: true }).fill(otherPolicyId);
  await expect(page.getByRole('button', { name: 'Create historical comparison', exact: true })).toBeDisabled(); expect(state.writes).toHaveLength(0);
});

test('historical comparison lost create retains exact intent through unrelated readback', async ({ page }) => {
  const state = await evaluationFixture(page, { lost: 'create' }); await evaluationInputs(page); await page.getByLabel(historicalAck, { exact: true }).check();
  await page.getByRole('button', { name: 'Create historical comparison', exact: true }).click(); await expect(page.getByRole('button', { name: 'Retry unchanged evaluation request', exact: true })).toBeVisible();
  await evaluationRead(page, otherEvaluationId); await expect(page.getByRole('button', { name: 'Retry unchanged evaluation request', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Retry unchanged evaluation request', exact: true }).click(); await expect(page.getByRole('button', { name: 'Retry unchanged evaluation request', exact: true })).toHaveCount(0);
  expect(state.writes).toHaveLength(2); expect(state.writes[0]).toEqual(state.writes[1]);
});

test('historical comparison lost step preserves original key version and body', async ({ page }) => {
  const state = await evaluationFixture(page, { lost: 'advance' }); await evaluationRead(page); await page.getByRole('button', { name: 'Advance one comparison step', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry unchanged evaluation request', exact: true })).toBeVisible(); await evaluationRead(page);
  await page.getByRole('button', { name: 'Retry unchanged evaluation request', exact: true }).click(); await expect(page.getByRole('button', { name: 'Retry unchanged evaluation request', exact: true })).toHaveCount(0);
  expect(state.writes).toHaveLength(2); expect(state.writes[0]).toEqual(state.writes[1]);
});

test('historical comparison owner sees aggregate diagnostics and retires without reviewer access', async ({ page }) => {
  const state = await evaluationFixture(page, { role: 'owner', completed: true }); await evaluationRead(page);
  await expect(page.getByRole('table', { name: 'All completed examples, including unknowns' })).toBeVisible();
  for (const name of ['Create historical comparison', 'Read comparison examples', 'Read original comparison request', 'Advance one comparison step']) await expect(page.getByRole('button', { name, exact: true })).toHaveCount(0);
  await page.getByLabel('Comparison retirement reason code', { exact: true }).fill('retire reviewed'); await page.getByLabel('Retirement preserves history, advances DATA and invalidates dependent current use.', { exact: true }).check();
  await expect(page.getByRole('button', { name: 'Retire comparison', exact: true })).toBeDisabled();
  await page.getByLabel('Comparison retirement reason code', { exact: true }).fill('retire-reviewed'); await expect(page.getByLabel('Retirement preserves history, advances DATA and invalidates dependent current use.', { exact: true })).not.toBeChecked();
  await page.getByLabel('Retirement preserves history, advances DATA and invalidates dependent current use.', { exact: true }).check(); await page.getByRole('button', { name: 'Retire comparison', exact: true }).click();
  await expect(page.getByRole('table')).toHaveCount(0); expect(state.writes[0].body).toEqual({ acknowledged: true, reason: 'retire-reviewed' }); expect(state.writes[0].version).toBe('3');
});

for (const mode of ['offline', 'hidden', 'expiry']) test('historical comparison withdraws reviewed input on ' + mode, async ({ page }) => {
  const state = await evaluationFixture(page, { ttl: mode === 'expiry' ? 1200 : 30000 }); await evaluationInputs(page); await page.getByLabel(historicalAck, { exact: true }).check();
  await expect(page.getByRole('button', { name: 'Create historical comparison', exact: true })).toBeEnabled();
  if (mode === 'offline') await page.evaluate(() => window.dispatchEvent(new Event('offline')));
  if (mode === 'hidden') await page.evaluate(() => { Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' }); document.dispatchEvent(new Event('visibilitychange')); });
  await expect(page.getByRole('button', { name: 'Create historical comparison', exact: true })).toBeDisabled(); expect(state.writes).toHaveLength(0);
});

test('historical comparison rejects inconsistent summary counts and mismatched page hashes', async ({ page }) => {
  await evaluationFixture(page, { completed: true, badCounts: true }); await evaluationRead(page);
  await expect(page.getByText('Evaluation summary is incomplete or its counts do not reconcile.', { exact: true })).toBeVisible(); await expect(page.getByRole('table')).toHaveCount(0);
});

test('historical comparison mismatched example page is withheld', async ({ page }) => {
  await evaluationFixture(page, { completed: true, badPage: true }); await evaluationRead(page); await page.getByRole('button', { name: 'Read comparison examples', exact: true }).click();
  await expect(page.getByText('Evaluation page is incomplete or does not match this report.', { exact: true })).toBeVisible(); await expect(page.getByText('Example 1;', { exact: false })).toHaveCount(0);
});

test('historical comparison uncertain safe exit performs no new write', async ({ page }) => {
  const state = await evaluationFixture(page, { lost: 'create' }); await evaluationInputs(page); await page.getByLabel(historicalAck, { exact: true }).check();
  await page.getByRole('button', { name: 'Create historical comparison', exact: true }).click(); await expect(page.getByRole('button', { name: 'Finish without another evaluation write', exact: true })).toBeDisabled();
  await page.getByLabel('I understand the server outcome stays unresolved and may already exist; exiting only forgets local retry details.', { exact: true }).check();
  await page.getByRole('button', { name: 'Finish without another evaluation write', exact: true }).click(); await expect(page.getByText('Local retry details forgotten.', { exact: false })).toBeVisible(); expect(state.writes).toHaveLength(1);
});

test('historical comparison controls do not appear for an operator-only account', async ({ page }) => {
  await fixture(page, { role: 'operator' }); await open(page); await expect(page.getByRole('button', { name: 'Historical comparisons', exact: true })).toHaveCount(0);
});

test('historical comparison example delivery cannot renew the original summary deadline', async ({ page }) => {
  await evaluationFixture(page, { completed: true, ttl: 2500 }); await evaluationRead(page);
  await expect(page.getByRole('table', { name: 'All completed examples, including unknowns' })).toBeVisible();
  await page.waitForTimeout(1800); // Controlled delayed read inside the original synthetic validity window.
  await page.getByRole('button', { name: 'Read comparison examples', exact: true }).click();
  await expect(page.getByText('Example 1;', { exact: false })).toBeVisible();
  await expect(page.getByRole('table')).toHaveCount(0, { timeout: 1000 });
  await expect(page.getByText('Example 1;', { exact: false })).toHaveCount(0);
});


const leaveAcknowledgment = 'I understand only local retry details will be discarded and the server outcome must still be investigated.';

test('workbench guarded departure covers malformed replies without sending another write', async ({ page }) => {
  const state = await policyFixture(page, { badReply: true }); await newPolicy(page);
  await page.getByRole('button', { name: 'Save policy draft', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry unchanged policy write', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Historical comparisons', exact: true }).click();
  const dialog = page.getByRole('alertdialog', { name: 'Leave unconfirmed work?' }); await expect(dialog).toBeFocused();
  await page.keyboard.press('Tab'); await expect(dialog.getByRole('button', { name: 'Keep working here', exact: true })).toBeFocused();
  await page.keyboard.press('Escape'); await expect(dialog).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Historical comparisons', exact: true })).toBeFocused();
  await page.getByRole('button', { name: 'Historical comparisons', exact: true }).click();
  await dialog.getByLabel(leaveAcknowledgment, { exact: true }).check(); await dialog.getByRole('button', { name: 'Leave and investigate', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Historical comparisons', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByRole('button', { name: 'Retry unchanged policy write', exact: true })).toHaveCount(0);
  expect(state.writes).toHaveLength(1); expect(state.committed.size).toBe(1);
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
});

test('workbench guarded return preserves the panel until the user explicitly leaves', async ({ page }) => {
  const state = await policyFixture(page, { lostOnce: true }); await newPolicy(page);
  await page.getByRole('button', { name: 'Save policy draft', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry unchanged policy write', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Return to inspections', exact: true }).click();
  const dialog = page.getByRole('alertdialog', { name: 'Leave unconfirmed work?' }); await expect(dialog).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Review and administration', exact: true })).toHaveCount(1);
  await dialog.getByLabel(leaveAcknowledgment, { exact: true }).check(); await dialog.getByRole('button', { name: 'Leave and investigate', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Review and administration', exact: true })).toHaveCount(0);
  expect(state.writes).toHaveLength(1);
});

test('workbench guarded sign out remains available after an informed no-retry exit', async ({ page }) => {
  const state = await policyFixture(page, { lostOnce: true }); await newPolicy(page); let logouts = 0;
  page.on('request', request => { if (new URL(request.url()).pathname === '/api/v1/auth/logout' && request.method() === 'POST') logouts++; });
  await page.getByRole('button', { name: 'Save policy draft', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry unchanged policy write', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  const dialog = page.getByRole('alertdialog', { name: 'Leave unconfirmed work?' }); await expect(dialog).toBeVisible(); expect(logouts).toBe(0);
  await dialog.getByLabel(leaveAcknowledgment, { exact: true }).check(); await dialog.getByRole('button', { name: 'Leave and investigate', exact: true }).click();
  await expect(page.getByText('Signed out of ProofPack.', { exact: true })).toBeVisible(); expect(logouts).toBe(1); expect(state.writes).toHaveLength(1);
});

test('workbench guarded navigation clears after the panel explicitly finishes its unresolved intent', async ({ page }) => {
  const state = await policyFixture(page, { badReply: true }); await newPolicy(page);
  await page.getByRole('button', { name: 'Save policy draft', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry unchanged policy write', exact: true })).toBeVisible();
  await page.getByLabel('I understand forgetting retry details does not undo or determine the server result.', { exact: true }).check();
  await page.getByRole('button', { name: 'Finish without another write', exact: true }).click();
  await page.getByRole('button', { name: 'Historical comparisons', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Historical comparisons', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByRole('alertdialog')).toHaveCount(0); expect(state.writes).toHaveLength(1);
});

test('workbench guarded navigation includes an implicit invitation transport failure', async ({ page }) => {
  const state = await fixture(page, { ambiguousInvite: true }); await open(page);
  await page.getByLabel('Provider subject', { exact: true }).fill('synthetic-target'); await page.getByLabel('Target email', { exact: true }).fill('target@example.invalid');
  await page.getByRole('checkbox', { name: /I verified the intended identity/ }).check(); await page.getByRole('button', { name: 'Create invitation record' }).click();
  await expect(page.getByText(/The operation outcome is unconfirmed/)).toBeVisible();
  await page.getByRole('button', { name: 'Runtime controls', exact: true }).click();
  const dialog = page.getByRole('alertdialog', { name: 'Leave unconfirmed work?' }); await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: 'Keep working here', exact: true }).click();
  await page.getByRole('checkbox', { name: /I verified the intended identity/ }).check(); await page.getByRole('button', { name: 'Create invitation record' }).click();
  await expect(page.getByText(/Invitation ID:/)).toContainText('NOT_SENT');
  expect(state.writes[1].key).toBe(state.writes[0].key); expect(state.writes[1].body).toEqual(state.writes[0].body);
  await page.getByRole('button', { name: 'Runtime controls', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Runtime controls', exact: true })).toHaveAttribute('aria-pressed', 'true'); await expect(page.getByRole('alertdialog')).toHaveCount(0);
});
