import { test, expect, type Page } from '@playwright/test';

const source = 'a1000000-0000-4000-8000-000000000001', policy = 'a2000000-0000-4000-8000-000000000001', jobId = 'a3000000-0000-4000-8000-000000000001';
const flags = { qualification_eligible: false, promotion_eligible: false, physical_truth_verified: false, independent_benchmark_qualified: false };
const ack = 'I understand preparation does not qualify or activate the policy.';
async function fixture(page: Page, settings: { role?: string; complete?: boolean; held?: boolean; lost?: boolean; badFlag?: boolean; badCounts?: boolean; badPage?: boolean; decisionOnly?: boolean; ttl?: number; delay?: number } = {}) {
  const errors: string[] = []; page.on('pageerror', e => errors.push(e.message));
  const role = settings.role ?? 'reviewer'; const user = { id: 'a4000000-0000-4000-8000-000000000001', session_id: 'preparation-fixture', display_name: 'Synthetic ' + role, csrf_token: 'c'.repeat(43), roles: [role] };
  let status = settings.complete ? 'completed' : 'queued', version = 1, lost = false;
  const writes: { path: string; body: any; key: string; version?: string }[] = [], pages: number[] = [], requests = new Map<string, any>();
  const body = { policy_id: policy, source_evaluation_id: source, source_evaluation_state_version: 4, source_report_sha256: 'a'.repeat(64), preparation_only_acknowledged: true };
  const record = () => ({ id: jobId, kind: 'policy_qualification_preparation', state_version: version, status, policy_id: policy, source_evaluation_id: source,
    source_report_sha256: 'a'.repeat(64), software_cases: 170, source_examples: 1, planned_count: 171, prepared_count: ['completed', 'retired'].includes(status) ? 171 : status === 'processing' ? 1 : 0,
    steps_reserved: ['completed', 'retired'].includes(status) ? 171 : status === 'processing' ? 1 : 0, remaining_ms: settings.ttl ?? 30000, lease_remaining_ms: 0,
    source_current: !settings.held, report_current: status === 'completed' && !settings.held, report_sha256: status === 'completed' || status === 'retired' ? 'b'.repeat(64) : null,
    counts: status === 'completed' && !settings.held ? { software_pass: settings.badCounts ? 171 : 169, software_fail: 1, source_entries_verified: 1 } : null,
    can_advance: role === 'reviewer' && !settings.held && ['queued', 'processing'].includes(status), failure_reason: null,
    blocking_reasons: ['INDEPENDENT_EVIDENCE_REQUIRED'], qualification_status: 'not_qualified', ...flags, ...(settings.badFlag ? { promotion_eligible: true } : {}) });
  await page.route('**/api/v1/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname.slice('/api/v1'.length);
    const json = (value: unknown, status = 200) => route.fulfill({ json: value, status });
    if (path === '/me') return json(user);
    if (path === '/recipes') return json({ recipes: [], next_cursor: null });
    if (path === '/evaluations/' + source) return json({ id: source, policy_id: policy, state_version: 4, runner: settings.decisionOnly ? 'decision_replay_v1' : 'vision_replay_v1', status: 'completed', result_header_current: true,
      remaining_ms: settings.ttl ?? 30000, report_sha256: 'a'.repeat(64), example_count: 1, promotion_eligible: false, independent_benchmark_qualified: false, physical_truth_verified: false, pixel_measurement_performed: true });
    if (path === '/qualification-preparations/options') return json({ software_cases: 170, max_source_examples: 170, max_steps: 340, lifetime_ms: 3600000, lease_ms: 15000,
      page_size: 20, image_evaluation_required: true, preparation_only: true, registry_sha256: 'c'.repeat(64), implementation_sha256: 'd'.repeat(64), ...flags });
    if (path === '/qualification-preparations' && request.method() === 'GET') return json({ preparations: [{ ...record(), source_current: null, report_current: null, currency_not_checked: true }], scope: url.searchParams.get('scope'), next_cursor: null });
    if (path === '/qualification-preparations/' + jobId + '/request') return json(body);
    if (path === '/qualification-preparations/' + jobId + '/entries') {
      const start = Number(url.searchParams.get('start')); pages.push(start);
      if (settings.delay) await new Promise(resolve => setTimeout(resolve, settings.delay));
      const end = Math.min(start + 20, 171);
      return json({ id: jobId, entries: Array.from({ length: end - start }, (_, i) => start + i < 170
        ? { phase: 'software_contract', case: { id: 'software-' + (start + i) }, passed: start + i !== 2 }
        : { phase: 'source_evaluation_integrity', source_index: settings.badPage ? 99 : 0, source_entry_sha256: 'e'.repeat(64), source_report_sha256: 'a'.repeat(64), physical_truth_verified: false, new_pixel_measurement: false }), next_index: end === 171 ? null : end, ...flags });
    }
    if (request.method() === 'POST') {
      const key = request.headers()['idempotency-key']; expect(key).toBeTruthy(); expect(request.headers()['x-csrf-token']).toBe(user.csrf_token);
      writes.push({ path, body: request.postDataJSON(), key, version: request.headers()['if-match'] });
      let result = requests.get(key);
      if (!result) {
        if (path.endsWith('/advance')) status = 'processing';
        if (path.endsWith('/cancel')) status = 'cancelled';
        if (path.endsWith('/retire')) status = 'retired';
        version++; result = record(); requests.set(key, result);
      }
      if (settings.lost && !lost) { lost = true; return route.abort('failed'); }
      return json(result, path === '/qualification-preparations' ? 201 : 200);
    }
    if (path === '/qualification-preparations/' + jobId) return json(record());
    return json({ code: 'RESOURCE_UNAVAILABLE', message: 'Synthetic route not configured' }, 403);
  });
  await page.goto('/'); await page.getByRole('button', { name: 'Open invited workspace' }).click();
  await page.getByRole('button', { name: 'Review and administration', exact: true }).click();
  if (role !== 'operator') await page.getByRole('button', { name: 'Qualification preparation', exact: true }).click();
  return { writes, pages, errors, body };
}
async function review(page: Page) {
  await page.getByLabel('Source evaluation ID', { exact: true }).fill(source);
  await page.getByRole('button', { name: 'Review preparation inputs', exact: true }).click();
}
async function read(page: Page) {
  await page.getByLabel('Preparation ID', { exact: true }).fill(jobId);
  await page.getByRole('button', { name: 'Read preparation summary', exact: true }).click();
}

test('reviewer prepares exact image source, discovers original job and advances with a refreshed version', async ({ page }) => {
  const state = await fixture(page); await review(page);
  await expect(page.getByText(/170 software cases plus 1 source entries/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Create qualification preparation', exact: true })).toBeDisabled();
  await page.getByLabel(ack, { exact: true }).check(); await page.getByRole('button', { name: 'Create qualification preparation', exact: true }).click();
  await expect(page.getByText(/Preparation operation recorded/)).toBeVisible(); expect(state.writes[0].body).toEqual(state.body);
  await page.getByRole('button', { name: 'Find recorded preparations', exact: true }).click();
  await page.getByRole('button', { name: 'Open preparation ' + jobId, exact: true }).click();
  await page.getByRole('button', { name: 'Advance one preparation step', exact: true }).click();
  await expect(page.getByText(/Preparation operation recorded/)).toBeVisible(); expect(state.writes[1].version).toBe('2'); expect(state.writes[1].body).toEqual({});
  await read(page); await page.getByRole('button', { name: 'Read original preparation request', exact: true }).click();
  await expect(page.getByLabel('Source evaluation ID', { exact: true })).toHaveValue(source); expect(state.errors).toEqual([]);
});

test('uncertain preparation creation preserves one unchanged intent across discovery and hidden review', async ({ page }) => {
  const state = await fixture(page, { lost: true }); await review(page); await page.getByLabel(ack, { exact: true }).check();
  await page.getByRole('button', { name: 'Create qualification preparation', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry unchanged preparation request', exact: true })).toBeVisible();
  await page.evaluate(() => { Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' }); document.dispatchEvent(new Event('visibilitychange')); });
  await page.evaluate(() => { Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' }); document.dispatchEvent(new Event('visibilitychange')); });
  await page.getByRole('button', { name: 'Find recorded preparations', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry unchanged preparation request', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Retry unchanged preparation request', exact: true }).click();
  await expect(page.getByText(/Preparation operation recorded/)).toBeVisible(); expect(state.writes).toHaveLength(2);
  expect(state.writes[1]).toEqual(state.writes[0]); expect(state.errors).toEqual([]);
});

test('complete preparation retains software failure, reads every bounded page and retires explicitly', async ({ page }) => {
  const state = await fixture(page, { complete: true }); await read(page);
  await expect(page.getByText(/Software passed: 169; software failed: 1; source entries verified: 1/)).toBeVisible();
  await page.getByRole('button', { name: 'Read preparation entries', exact: true }).click();
  await expect(page.getByText('Software case software-2: failed', { exact: true })).toBeVisible();
  for (let start = 20; start <= 160; start += 20) { await page.getByRole('button', { name: 'Next preparation entry page', exact: true }).click(); await expect.poll(() => state.pages.includes(start)).toBe(true); }
  await expect(page.getByText(/Source entry 1: prior report integrity verified/)).toBeVisible(); expect(state.pages).toEqual([0,20,40,60,80,100,120,140,160]);
  await page.getByLabel('Preparation retirement reason code', { exact: true }).fill('review-finished');
  await page.getByLabel('Retirement preserves history, advances DATA and invalidates dependent use.', { exact: true }).check();
  await page.getByRole('button', { name: 'Retire preparation', exact: true }).click(); await expect(page.getByText(/Preparation operation recorded/)).toBeVisible();
  expect(state.writes[0].body).toEqual({ acknowledged: true, reason: 'review-finished' }); expect(state.writes[0].version).toBe('1'); expect(state.errors).toEqual([]);
});

test('owner sees aggregate preparation only and may cancel unresolved work', async ({ page }) => {
  const state = await fixture(page, { role: 'owner' }); await read(page);
  await expect(page.getByLabel('Source evaluation ID', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Advance one preparation step', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Read original preparation request', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Cancel unfinished preparation', exact: true }).click(); await expect(page.getByText(/Preparation operation recorded/)).toBeVisible();
  expect(state.writes[0].path).toBe('/jobs/' + jobId + '/cancel'); expect(state.errors).toEqual([]);
});

test('owner can inspect complete aggregate counts without reviewer entries or source intent', async ({ page }) => {
  const state = await fixture(page, { role: 'owner', complete: true }); await read(page);
  await expect(page.getByText(/Software passed: 169; software failed: 1; source entries verified: 1/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Read preparation entries', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Read original preparation request', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Advance one preparation step', exact: true })).toHaveCount(0);
  expect(state.writes).toEqual([]); expect(state.pages).toEqual([]);
});

test('uncertain manual step retries its original target, version, body and key', async ({ page }) => {
  const state = await fixture(page, { lost: true }); await read(page);
  await page.getByRole('button', { name: 'Advance one preparation step', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry unchanged preparation request', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Retry unchanged preparation request', exact: true }).click();
  await expect(page.getByText(/Preparation operation recorded/)).toBeVisible(); expect(state.writes).toHaveLength(2);
  expect(state.writes[1]).toEqual(state.writes[0]); expect(state.writes[0].version).toBe('1'); expect(state.writes[0].path).toBe('/jobs/' + jobId + '/advance');
});

test('operator receives no preparation navigation', async ({ page }) => {
  const state = await fixture(page, { role: 'operator' }); await expect(page.getByRole('button', { name: 'Qualification preparation', exact: true })).toHaveCount(0); expect(state.writes).toEqual([]);
});

test('decision-only source cannot prepare qualification', async ({ page }) => {
  const state = await fixture(page, { decisionOnly: true }); await review(page); await expect(page.getByText(/Read a complete current original-image comparison/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Create qualification preparation', exact: true })).toHaveCount(0); expect(state.writes).toEqual([]);
});

for (const mode of ['held', 'badFlag', 'badCounts'] as const) test('preparation rejects misleading or unavailable report: ' + mode, async ({ page }) => {
  const state = await fixture(page, { complete: true, [mode]: true }); await read(page);
  await expect(page.getByText(/Software passed:/)).toHaveCount(0); await expect(page.getByRole('button', { name: 'Read preparation entries', exact: true })).toHaveCount(0); expect(state.writes).toEqual([]);
});

for (const mode of ['expiry', 'hidden', 'offline'] as const) test('preparation clears reviewed input authority: ' + mode, async ({ page }) => {
  const state = await fixture(page, { ttl: mode === 'expiry' ? 1200 : 30000 }); await review(page); await page.getByLabel(ack, { exact: true }).check();
  if (mode === 'expiry') await page.waitForTimeout(1300);
  else await page.evaluate(kind => { if (kind === 'hidden') { Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' }); document.dispatchEvent(new Event('visibilitychange')); } else window.dispatchEvent(new Event('offline')); }, mode);
  await expect(page.getByRole('button', { name: 'Create qualification preparation', exact: true })).toHaveCount(0); expect(state.writes).toEqual([]);
});

test('delayed preparation entries cannot restore hidden report authority', async ({ page }) => {
  const state = await fixture(page, { complete: true, delay: 400 }); await read(page);
  await page.getByRole('button', { name: 'Read preparation entries', exact: true }).click(); await expect.poll(() => state.pages.length).toBe(1);
  await page.evaluate(() => { Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' }); document.dispatchEvent(new Event('visibilitychange')); });
  await expect(page.getByText(/Software passed:/)).toHaveCount(0); await page.waitForTimeout(500); await expect(page.getByText(/Software case software-/)).toHaveCount(0); expect(state.errors).toEqual([]);
});

test('wrong source entry clears preparation counts and entries without a new write', async ({ page }) => {
  const state = await fixture(page, { complete: true, badPage: true }); await read(page);
  await page.getByRole('button', { name: 'Read preparation entries', exact: true }).click();
  for (let start = 20; start <= 160; start += 20) { await page.getByRole('button', { name: 'Next preparation entry page', exact: true }).click(); await expect.poll(() => state.pages.includes(start)).toBe(true); }
  await expect(page.getByText('Preparation page does not match its complete report.', { exact: true })).toBeVisible();
  await expect(page.getByText(/Software passed:/)).toHaveCount(0); await expect(page.getByText(/Source entry 1:/)).toHaveCount(0); expect(state.writes).toEqual([]);
});
