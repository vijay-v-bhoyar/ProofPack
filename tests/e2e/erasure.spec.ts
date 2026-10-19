import { test, expect, type Page } from '@playwright/test';
import { createHash } from 'node:crypto';

const assetId = '81000000-0000-4000-8000-000000000001', previewId = '82000000-0000-4000-8000-000000000001', jobId = '83000000-0000-4000-8000-000000000001';
const errors = new WeakMap<Page, string[]>();
test.beforeEach(async ({ page }) => { const items: string[] = []; errors.set(page, items); page.on('pageerror', error => items.push(error.message)); });
test.afterEach(async ({ page }) => { expect(errors.get(page)).toEqual([]); });
async function fixture(page: Page, options: { role?: string; ttl?: number; delay?: number; activeLease?: boolean; badDigest?: boolean; wrongScope?: boolean; fullErasure?: boolean; lost?: string; targetMismatch?: boolean } = {}) {
  const writes: { path: string; body: unknown; key?: string; version?: string }[] = [];
  const scope = { assets: [{ asset_revision: 1, id: assetId, kind: 'reference', receipt_sha256: 'b'.repeat(64), sha256: 'a'.repeat(64) }],
    kind: 'selected_live_asset_versions', schema_version: 1, storage_binding_sha256: 'c'.repeat(64) };
  const hash = createHash('sha256').update(JSON.stringify(scope)).digest('hex');
  let committed = false, steps = 0;
  const preview = () => ({ id: previewId, state_version: committed ? 2 : 1, scope, scope_sha256: options.badDigest ? 'd'.repeat(64) : hash,
    status: committed ? 'committed' : 'preview', job_id: committed ? jobId : null, remaining_ms: options.ttl ?? 30000, can_confirm: !committed,
    erasure_complete: false, remaining_duties: ['dependent_metadata', 'orphans_and_restore', 'backups', 'recipient_copies'] });
  const job = () => ({ id: jobId, kind: 'asset_erasure', state_version: 1 + steps * 2, status: options.activeLease ? 'processing' : steps > 1 ? 'metadata_pending' : 'queued',
    scope_sha256: options.wrongScope ? 'e'.repeat(64) : hash,
    assets: [{ id: assetId, kind: 'reference', live_versions_removed: steps > 1, delete_acknowledgments: steps ? 2 : 0, checked_at_ms: steps > 1 ? Date.now() : null }],
    lease_remaining_ms: options.activeLease ? 15000 : 0, last_error: null, target_matches_current_config: !options.targetMismatch, can_advance: !options.activeLease && steps < 2,
    erasure_complete: !!options.fullErasure, dependent_metadata_erased: false, backups_erased: false, downloaded_copies_recalled: false });
  const seen = new Set<string>();
  await page.route('**/api/v1/**', async route => {
    const r = route.request(), path = new URL(r.url()).pathname.slice('/api/v1'.length), key = r.headers()['idempotency-key'];
    const json = (value: unknown) => route.fulfill({ json: value });
    if (r.method() === 'POST') {
      expect(r.headers()['x-csrf-token']).toBe('c'.repeat(43)); expect(key).toBeTruthy();
      writes.push({ path, body: r.postDataJSON(), key, version: r.headers()['if-match'] });
    }
    if (path === '/me') return json({ id: '10000000-0000-4000-8000-000000000001', display_name: 'Synthetic owner', roles: [options.role ?? 'owner'], csrf_token: 'c'.repeat(43), session_id: 'synthetic-session' });
    if (path === '/privacy/deletion-previews') {
      if (options.delay) await new Promise(resolve => setTimeout(resolve, options.delay));
      if (options.lost === 'preview' && !seen.has(key)) { seen.add(key); return route.abort('failed'); }
      return json(preview());
    }
    if (path === '/privacy/deletion-previews/' + previewId) return json(preview());
    if (path === '/privacy/deletions') {
      committed = true;
      if (options.lost === 'confirm' && !seen.has(key)) { seen.add(key); return route.abort('failed'); }
      return json(job());
    }
    if (path === '/jobs/' + jobId + '/advance') {
      if (!seen.has(key)) { steps++; seen.add(key); if (options.lost === 'advance') return route.abort('failed'); }
      return json(job());
    }
    if (path === '/jobs/' + jobId) return json(job());
    if (path === '/auth/logout') return route.fulfill({ status: 204 });
    if (path === '/stations') return json({ stations: [] });
    return json({});
  });
  await page.goto('/'); await page.getByRole('button', { name: 'Open invited workspace' }).click();
  await page.getByRole('button', { name: 'Review and administration', exact: true }).click();
  return writes;
}
async function open(page: Page) { await page.getByRole('button', { name: 'Selected asset cleanup', exact: true }).click(); }
async function preview(page: Page) {
  await page.getByLabel('Asset UUIDs, separated by spaces or commas').fill(assetId);
  await page.getByRole('button', { name: 'Preview selected asset cleanup' }).click();
}
async function confirm(page: Page) {
  await page.getByRole('checkbox', { name: /I authorize irreversible/ }).check();
  await page.getByRole('checkbox', { name: /I understand metadata/ }).check();
  await page.getByRole('button', { name: 'Commit reviewed asset denial' }).click();
}

test('owner reviews exact asset then performs bounded cleanup without a full-erasure claim', async ({ page }) => {
  const writes = await fixture(page); await open(page); await preview(page);
  await expect(page.getByText(/source revision 1/)).toContainText(assetId);
  await expect(page.getByRole('button', { name: 'Commit reviewed asset denial' })).toBeDisabled();
  await confirm(page);
  await expect(page.getByText(/Job .*queued/)).toContainText('Full erasure: incomplete');
  await page.getByRole('button', { name: 'Advance one cleanup page' }).click();
  await expect(page.getByText(/delete acknowledgments 2/)).toBeVisible();
  await page.getByRole('button', { name: 'Advance one cleanup page' }).click();
  await expect(page.getByText(/Job .*metadata_pending/)).toContainText('Backups erased: no');
  await expect(page.getByRole('button', { name: 'Advance one cleanup page' })).toBeDisabled();
  expect(writes.map(w => w.path)).toEqual(['/privacy/deletion-previews', '/privacy/deletions', '/jobs/' + jobId + '/advance', '/jobs/' + jobId + '/advance']);
  expect(writes[1].version).toBe('1'); expect(writes[2].version).toBe('1'); expect(writes[3].version).toBe('3');
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
});

for (const lost of ['preview', 'confirm', 'advance']) test('lost ' + lost + ' retries exactly the original request after possible commit', async ({ page }) => {
  const writes = await fixture(page, { lost }); await open(page); await preview(page);
  if (lost !== 'preview') await confirm(page);
  if (lost === 'advance') await page.getByRole('button', { name: 'Advance one cleanup page' }).click();
  await expect(page.getByRole('button', { name: 'Retry unchanged cleanup request' })).toBeVisible();
  const original = writes.at(-1)!;
  await page.getByRole('button', { name: 'Retry unchanged cleanup request' }).click();
  await expect(page.getByRole('button', { name: 'Retry unchanged cleanup request' })).toHaveCount(0);
  expect(writes.at(-1)).toEqual(original);
  if (lost === 'advance') await expect(page.getByText(/delete acknowledgments 2/)).toBeVisible();
});

for (const fault of ['badDigest', 'wrongScope', 'fullErasure']) test('rejects ' + fault + ' rather than accepting misleading cleanup evidence', async ({ page }) => {
  await fixture(page, { [fault]: true }); await open(page); await preview(page);
  if (fault !== 'badDigest') await confirm(page);
  await expect(page.getByRole('button', { name: 'Retry unchanged cleanup request' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Advance one cleanup page' })).toHaveCount(0);
  if (fault === 'badDigest') await expect(page.getByRole('checkbox', { name: /I authorize irreversible/ })).toHaveCount(0);
});

test('expired and interrupted review cannot approve assets and selection edits clear acknowledgment', async ({ page }) => {
  await fixture(page, { ttl: 1200 }); await open(page); await preview(page);
  await page.getByRole('checkbox', { name: /I authorize irreversible/ }).check();
  await expect(page.getByRole('button', { name: 'Commit reviewed asset denial' })).toBeDisabled();
  await expect(page.getByText(/Review expired, interrupted or ineligible/)).toBeVisible({ timeout: 3000 });
  await expect(page.getByRole('checkbox', { name: /I authorize irreversible/ })).not.toBeChecked();
  await page.getByRole('button', { name: 'Read deletion preview' }).click();
  await page.getByRole('checkbox', { name: /I authorize irreversible/ }).check();
  await page.evaluate(() => window.dispatchEvent(new Event('offline')));
  await expect(page.getByRole('checkbox', { name: /I authorize irreversible/ })).not.toBeChecked();
  await page.getByLabel('Asset UUIDs, separated by spaces or commas').fill(assetId + ',' + assetId);
  await expect(page.getByRole('button', { name: 'Preview selected asset cleanup' })).toBeDisabled();
});

test('lost confirmation can be recovered by preview readback after leaving the panel', async ({ page }) => {
  const writes = await fixture(page, { lost: 'confirm' }); await open(page); await preview(page); await confirm(page);
  await expect(page.getByRole('button', { name: 'Retry unchanged cleanup request' })).toBeVisible();
  await page.getByRole('button', { name: 'Accounts', exact: true }).click();
  const leave = page.getByRole('alertdialog', { name: 'Leave unconfirmed work?' });
  await expect(leave).toBeVisible();
  await expect(leave.getByRole('button', { name: 'Leave and investigate' })).toBeDisabled();
  await leave.getByRole('checkbox', { name: /I understand only local retry details/ }).check();
  await leave.getByRole('button', { name: 'Leave and investigate' }).click();
  await open(page);
  await page.getByLabel('Deletion preview ID', { exact: true }).fill(previewId);
  await page.getByRole('button', { name: 'Read deletion preview' }).click();
  await expect(page.getByLabel('Cleanup job ID', { exact: true })).toHaveValue(jobId);
  await page.getByRole('button', { name: 'Read cleanup job' }).click();
  await expect(page.getByText(/Job .*queued/)).toBeVisible();
  expect(writes.filter(w => w.path === '/privacy/deletions')).toHaveLength(1);
});

test('storage target mismatch permits progress read but blocks cleanup steps', async ({ page }) => {
  await fixture(page, { targetMismatch: true }); await open(page);
  await page.getByLabel('Cleanup job ID', { exact: true }).fill(jobId); await page.getByRole('button', { name: 'Read cleanup job' }).click();
  await expect(page.getByText(/Storage target matches: no/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Advance one cleanup page' })).toBeDisabled();
});

for (const role of ['reviewer', 'operator']) test(role + ' has no owner cleanup controls', async ({ page }) => {
  const writes = await fixture(page, { role });
  await expect(page.getByRole('button', { name: 'Selected asset cleanup', exact: true })).toHaveCount(0); expect(writes).toHaveLength(0);
});

test('delayed preview cannot renew an expired review from its response time', async ({ page }) => {
  await fixture(page, { ttl: 400, delay: 700 }); await open(page); await preview(page);
  await expect(page.getByText(/Review expired, interrupted or ineligible/)).toBeVisible();
  await expect(page.getByRole('checkbox', { name: /I authorize irreversible/ })).toBeDisabled();
});

test('active lease exposes progress but requires a fresh job read before another step', async ({ page }) => {
  await fixture(page, { activeLease: true }); await open(page);
  await page.getByLabel('Cleanup job ID', { exact: true }).fill(jobId); await page.getByRole('button', { name: 'Read cleanup job' }).click();
  await expect(page.getByText(/Job .*processing/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Advance one cleanup page' })).toBeDisabled();
});

test('cleanup selection and exact approval are keyboard accessible at narrow desktop width', async ({ page }) => {
  await page.setViewportSize({ width: 960, height: 800 }); await fixture(page); await open(page);
  await page.getByLabel('Asset UUIDs, separated by spaces or commas').focus(); await page.keyboard.insertText(assetId);
  await page.keyboard.press('Tab'); await expect(page.getByRole('button', { name: 'Preview selected asset cleanup' })).toBeFocused(); await page.keyboard.press('Enter');
  const ack = page.getByRole('checkbox', { name: /I authorize irreversible/ }); await expect(ack).toBeEnabled(); await ack.focus();
  await page.keyboard.press('Space'); await page.keyboard.press('Tab'); await page.keyboard.press('Space'); await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: 'Commit reviewed asset denial' })).toBeFocused();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
