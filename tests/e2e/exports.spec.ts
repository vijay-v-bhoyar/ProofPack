/** Intercepted identities/APIs and a genuine synthetic metadata ZIP; no AWS/human proof. */
import { test, expect, type Page } from '@playwright/test';
import { createHash } from 'node:crypto';
const inspection = '61000000-0000-4000-8000-000000000001', jobId = '62000000-0000-4000-8000-000000000001', ticketId = '63000000-0000-4000-8000-000000000001';
const manifest = '{"schema_version":1,"historical":true,"current_approval":false,"media":[]}';
const archive = Buffer.from('UEsDBBQAAAAAAAAAIQCaRUFOSgAAAEoAAAANAAAAbWFuaWZlc3QuanNvbnsic2NoZW1hX3ZlcnNpb24iOjEsImhpc3RvcmljYWwiOnRydWUsImN1cnJlbnRfYXBwcm92YWwiOmZhbHNlLCJtZWRpYSI6W119UEsBAhQAFAAAAAAAAAAhAJpFQU5KAAAASgAAAA0AAAAAAAAAAAAAAIABAAAAAG1hbmlmZXN0Lmpzb25QSwUGAAAAAAEAAQA7AAAAdQAAAAAA', 'base64');
const manifestHash = createHash('sha256').update(manifest).digest('hex');
const errors = new WeakMap<Page, string[]>();
test.beforeEach(async ({ page }) => { const list: string[] = []; errors.set(page, list); page.on('pageerror', error => list.push(error.message)); });
test.afterEach(async ({ page }) => { expect(errors.get(page)).toEqual([]); });
async function fixture(page: Page, options: { role?: string; lost?: string; badJob?: boolean; badArchive?: boolean; oversized?: boolean; ttl?: number; unavailable?: boolean } = {}) {
  const writes: { path: string; key: string; version?: string; body: unknown }[] = [];
  let created = false, version = 1, status = 'queued', steps = 0, selected: string[] = [];
  const seen = new Set<string>(), ticket = { id: ticketId, job_id: jobId, ticket: ticketId + '.' + 't'.repeat(43), remaining_ms: options.ttl ?? 30000, usable: true, historical: true, current_approval: false };
  const job = () => ({ id: jobId, kind: 'inspection_export', state_version: version, status, inspection_id: inspection, inspection_revision: 3,
    historical: true, current_approval: !!options.badJob, remaining_ms: 60000, lease_remaining_ms: 0, scanned_rows: steps * 10, record_count: steps + 1,
    selected_asset_ids: selected, manifest_sha256: status === 'completed' || status === 'cancelled' ? manifestHash : null,
    can_advance: status === 'queued', can_issue_ticket: status === 'completed', can_cancel: status !== 'cancelled', failure_reason: null });
  await page.addInitScript(() => {
    const original = window.fetch.bind(window); const state = { abortedDownloads: 0 }; Reflect.set(window, 'exportFetchFixture', state);
    window.fetch = (input, init) => {
      if (String(input).endsWith('/download')) init?.signal?.addEventListener('abort', () => state.abortedDownloads++);
      return original(input, init);
    };
  });
  await page.route('**/api/v1/**', async route => {
    const r = route.request(), path = new URL(r.url()).pathname.slice('/api/v1'.length), key = r.headers()['idempotency-key'];
    const json = (value: unknown, code = 200) => route.fulfill({ json: value, status: code });
    if (r.method() === 'POST') { expect(r.headers()['x-csrf-token']).toBe('c'.repeat(43)); writes.push({ path, key, version: r.headers()['if-match'], body: r.postDataJSON() }); }
    if (path === '/me') return json({ id: '10000000-0000-4000-8000-000000000001', display_name: 'Synthetic member', roles: [options.role ?? 'operator'], csrf_token: 'c'.repeat(43), session_id: 'synthetic-session' });
    if (path === '/inspections/' + inspection + '/export-context') return json({ inspection_id: inspection, state_version: 3, state_as_recorded: 'CLOSED', latest_asset_id: null, max_assets: 3, historical: true, current_approval: false, can_create: true });
    if (path === '/inspections/' + inspection + '/exports' && r.method() === 'GET') return json({ inspection_id: inspection, jobs: created ? [{ id: jobId, state_version: version, status, created_at_ms: Date.now() }] : [], next_cursor: null, historical: true, current_approval: false });
    if (path === '/inspections/' + inspection + '/exports') {
      created = true; selected = r.postDataJSON().selected_asset_ids;
      if (options.lost === 'create' && !seen.has(key)) { seen.add(key); return route.abort('failed'); }
      return json(job(), 201);
    }
    if (path === '/jobs/' + jobId && r.method() === 'GET') return json(job());
    if (path === '/jobs/' + jobId + '/advance') {
      if (!seen.has(key)) { seen.add(key); steps++; version += 2; if (steps >= 2) status = 'completed'; if (options.lost === 'advance') return route.abort('failed'); }
      return json(job());
    }
    if (path === '/jobs/' + jobId + '/cancel') { status = 'cancelled'; version++; return json(job()); }
    if (path === '/jobs/' + jobId + '/download-tickets') {
      if (options.lost === 'ticket' && !seen.has(key)) { seen.add(key); return route.abort('failed'); }
      return json(ticket, 201);
    }
    if (path === '/jobs/' + jobId + '/download') {
      expect(r.headers()['x-export-ticket']).toBe(ticket.ticket); expect(r.url()).not.toContain(ticketId);
      if (options.unavailable) return json({}, 403);
      return route.fulfill({ body: archive, headers: { 'content-type': 'application/zip', 'content-length': String(options.oversized ? 8388609 : archive.length),
        'x-export-job-id': jobId, 'x-content-sha256': options.badArchive ? 'a'.repeat(64) : createHash('sha256').update(archive).digest('hex'),
        'x-manifest-sha256': manifestHash, 'x-remaining-validity-ms': '30000', 'x-export-historical': 'true' } });
    }
    if (path === '/auth/logout') return route.fulfill({ status: 204 });
    return json({});
  });
  await page.goto('/'); await page.getByRole('button', { name: 'Open invited workspace' }).click(); await page.getByRole('button', { name: 'Review and administration', exact: true }).click();
  return writes;
}
async function open(page: Page) { await page.getByRole('button', { name: 'Historical exports', exact: true }).click(); }
async function create(page: Page) {
  await page.getByLabel('Export inspection ID', { exact: true }).fill(inspection); await page.getByRole('button', { name: 'Read inspection export scope' }).click();
  await page.getByRole('checkbox', { name: /I reviewed this historical inspection/ }).check(); await page.getByRole('button', { name: 'Create historical export' }).click();
}
async function complete(page: Page) {
  await create(page); await page.getByRole('button', { name: 'Advance one export page' }).click(); await expect(page.getByText(/Scanned rows: 10/)).toBeVisible();
  await page.getByRole('button', { name: 'Advance one export page' }).click(); await expect(page.getByText(/Job .*completed/)).toBeVisible();
}
async function ticket(page: Page) {
  await page.getByRole('checkbox', { name: /I request my permitted historical copy/ }).check(); await page.getByRole('button', { name: 'Request one-use export ticket' }).click();
}

test('operator prepares historical manifest, explicitly fetches and forgets verified ZIP', async ({ page }) => {
  const writes = await fixture(page); await open(page); await complete(page); await ticket(page);
  await page.getByRole('button', { name: 'Fetch historical archive once' }).click();
  await expect(page.getByRole('link', { name: 'Save prepared historical archive' })).toHaveAttribute('download', 'proofpack-' + jobId + '.zip');
  await expect(page.getByRole('button', { name: 'Fetch historical archive once' })).toBeDisabled();
  expect(writes.map(w => w.version)).toEqual(['3', '1', '3', '5']);
  await page.getByRole('button', { name: 'Forget prepared archive' }).click(); await expect(page.getByRole('link', { name: 'Save prepared historical archive' })).toHaveCount(0);
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
});

for (const lost of ['create', 'advance', 'ticket']) test('uncertain export ' + lost + ' preserves exact request and version', async ({ page }) => {
  const writes = await fixture(page, { lost }); await open(page); await create(page);
  if (lost !== 'create') await page.getByRole('button', { name: 'Advance one export page' }).click();
  if (lost === 'ticket') { await page.getByRole('button', { name: 'Advance one export page' }).click(); await ticket(page); }
  await expect(page.getByRole('button', { name: 'Retry unchanged export request' })).toBeVisible();
  const original = writes.at(-1)!; expect(original.path).toBe(lost === 'create' ? '/inspections/' + inspection + '/exports' : '/jobs/' + jobId + '/' + (lost === 'ticket' ? 'download-tickets' : 'advance'));
  await page.getByRole('button', { name: 'Retry unchanged export request' }).click();
  await expect(page.getByRole('button', { name: 'Retry unchanged export request' })).toHaveCount(0); expect(writes.at(-1)).toEqual(original);
});

test('lost create is discoverable by inspection after leaving local intent', async ({ page }) => {
  const writes = await fixture(page, { lost: 'create' }); await open(page); await create(page);
  await expect(page.getByRole('button', { name: 'Retry unchanged export request' })).toBeVisible();
  await page.getByRole('button', { name: 'Ownership handoff' }).click();
  const leave = page.getByRole('alertdialog', { name: 'Leave unconfirmed work?' });
  await expect(leave).toBeVisible();
  await expect(leave.getByRole('button', { name: 'Leave and investigate' })).toBeDisabled();
  await leave.getByRole('checkbox', { name: /I understand only local retry details/ }).check();
  await leave.getByRole('button', { name: 'Leave and investigate' }).click();
  await open(page);
  await page.getByLabel('Export inspection ID', { exact: true }).fill(inspection); await page.getByRole('button', { name: 'Find recorded exports' }).click();
  await page.getByRole('button', { name: 'Read export ' + jobId + ' · queued', exact: true }).click();
  await expect(page.getByText(/Job .*queued/)).toBeVisible(); expect(writes.filter(w => w.path.endsWith('/exports'))).toHaveLength(1);
});

test('cancel requires acknowledgment and prevents another ticket', async ({ page }) => {
  await fixture(page); await open(page); await complete(page);
  await expect(page.getByRole('button', { name: 'Cancel export delivery' })).toBeDisabled();
  await page.getByRole('checkbox', { name: /Cancel future export delivery/ }).check(); await page.getByRole('button', { name: 'Cancel export delivery' }).click();
  await expect(page.getByText(/Job .*cancelled/)).toBeVisible(); await expect(page.getByRole('button', { name: 'Request one-use export ticket' })).toBeDisabled();
});

for (const fault of ['badArchive', 'oversized', 'unavailable']) test('rejects ' + fault + ' without saving or silently replaying a consumed ticket', async ({ page }) => {
  await fixture(page, { [fault]: true }); await open(page); await complete(page); await ticket(page);
  await page.getByRole('button', { name: 'Fetch historical archive once' }).click(); await expect(page.getByRole('button', { name: 'Fetch historical archive once' })).toBeDisabled();
  await expect(page.getByRole('link', { name: 'Save prepared historical archive' })).toHaveCount(0);
  await expect.poll(() => page.evaluate(() => Reflect.get(window, 'exportFetchFixture').abortedDownloads), { timeout: 1000 }).toBeGreaterThan(0);
  await expect(page.getByRole('button', { name: 'Request one-use export ticket' })).toBeDisabled();
  await page.getByRole('button', { name: 'Read export job', exact: true }).click();
  await page.getByRole('checkbox', { name: /I request my permitted historical copy/ }).check();
  await expect(page.getByRole('button', { name: 'Request one-use export ticket' })).toBeEnabled();
});

test('hidden page forgets a prepared local copy and ticket', async ({ page }) => {
  await fixture(page); await open(page); await complete(page); await ticket(page); await page.getByRole('button', { name: 'Fetch historical archive once' }).click();
  await expect(page.getByRole('link', { name: 'Save prepared historical archive' })).toBeVisible();
  await page.evaluate(() => { Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'hidden' }); document.dispatchEvent(new Event('visibilitychange')); });
  await expect(page.getByRole('link', { name: 'Save prepared historical archive' })).toHaveCount(0);
});

test('owner-only account does not acquire export/media authority', async ({ page }) => {
  const writes = await fixture(page, { role: 'owner' }); await expect(page.getByRole('button', { name: 'Historical exports', exact: true })).toHaveCount(0); expect(writes).toHaveLength(0);
});

test('mismatched current-approval response remains unconfirmed rather than accepted', async ({ page }) => {
  await fixture(page, { badJob: true }); await open(page); await create(page);
  await expect(page.getByRole('button', { name: 'Retry unchanged export request' })).toBeVisible(); await expect(page.getByRole('button', { name: 'Advance one export page' })).toHaveCount(0);
});

test('reading creation scope clears an older job approval before acknowledging a new action', async ({ page }) => {
  await fixture(page); await open(page); await complete(page); await page.getByRole('checkbox', { name: /I request my permitted historical copy/ }).check();
  await page.getByRole('button', { name: 'Read inspection export scope' }).click();
  await expect(page.getByRole('button', { name: 'Request one-use export ticket' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Create historical export' })).toBeDisabled();
});

test('export controls support keyboard selection and narrow desktop layout', async ({ page }) => {
  await page.setViewportSize({ width: 960, height: 800 }); await fixture(page); await open(page);
  await page.getByLabel('Export inspection ID', { exact: true }).focus(); await page.keyboard.insertText(inspection); await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: 'Read inspection export scope' })).toBeFocused(); await page.keyboard.press('Enter');
  await page.getByRole('checkbox', { name: /I reviewed this historical inspection/ }).focus(); await page.keyboard.press('Space'); await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: 'Create historical export' })).toBeFocused();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
