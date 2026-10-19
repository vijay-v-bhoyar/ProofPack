// Actual rendered bundle with synthetic API routes; no provider/human proof.
import { test, expect, type Page } from '@playwright/test';
const ID = 'a1000000-0000-4000-8000-000000000001';
const OTHER = 'a1000000-0000-4000-8000-000000000002';
async function setup(page: Page, roles = ['operator']) {
  const errors: string[] = [], writes: string[] = [], reads: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  const state = { roles, fault: '', ttl: 30000 };
  await page.route('**/api/v1/**', route => {
    const req = route.request(), url = new URL(req.url()), path = url.pathname.replace('/api/v1', '');
    const send = (data: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
    if (req.method() !== 'GET') { writes.push(path); return send({ code: 'DENIED' }, 403); }
    reads.push(url.pathname + url.search);
    if (path === '/me') return send({ id: OTHER, session_id: 'approved-session', display_name: 'Synthetic member', roles: state.roles, csrf_token: 'x'.repeat(43) });
    if (path === '/stations') return send({ stations: [] });
    if (path === '/policies/active' || path.startsWith('/policies/')) {
      if (state.fault === 'denied') return send({ code: 'RESOURCE_UNAVAILABLE' }, 404);
      const result = { policy: { id: state.fault === 'wrong-id' ? OTHER : ID, revision: state.fault === 'wrong-revision' ? 2 : 1, revision_sha256: 'a'.repeat(64), behavior_sha256: 'b'.repeat(64), name: 'Synthetic approved policy', mode: 'deterministic_policy' },
        active_version: 1, current: state.fault !== 'held', current_qualification_verified: state.fault !== 'held', remaining_ms: state.fault === 'held' ? 0 : state.ttl,
        historical_head: true, inspection_enablement_granted: state.fault === 'enablement', scope: 'summary' };
      if (state.fault === 'private') return send({ ...result, qualification_id: OTHER });
      if (state.fault === 'none') return send({ ...result, policy: null, active_version: 0, current: false, current_qualification_verified: false, remaining_ms: 0, historical_head: false });
      return send(result);
    }
    return send({ code: 'DENIED' }, 403);
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Open invited workspace' }).click();
  await page.getByRole('button', { name: 'Review and administration', exact: true }).click();
  await page.getByRole('button', { name: 'Approved policy', exact: true }).click();
  return { state, errors, writes, reads };
}
async function exact(page: Page) {
  await page.getByLabel('Approved policy ID', { exact: true }).fill(ID);
  await page.getByLabel('Approved policy revision (optional)', { exact: true }).fill('1');
  await page.getByRole('button', { name: 'Read exact approved policy', exact: true }).click();
}
for (const role of ['operator', 'owner', 'reviewer']) test(`${role} can inspect only a minimized approved record without a write`, async ({ page }) => {
  const f = await setup(page, [role]); await exact(page);
  await expect(page.getByText('Qualification current at this bounded read.', { exact: false })).toBeVisible();
  expect(f.reads).toContain('/api/v1/policies/' + ID + '?view=approved&revision=1');
  expect(f.writes).toEqual([]); expect(f.errors).toEqual([]);
  if (role === 'operator') await expect(page.getByRole('button', { name: 'Policy candidates', exact: true })).toHaveCount(0);
});
for (const fault of ['wrong-id', 'wrong-revision', 'enablement', 'private']) test(`withholds ${fault} response instead of showing current approval`, async ({ page }) => {
  const f = await setup(page); f.state.fault = fault; await exact(page);
  await expect(page.locator('section[aria-labelledby="approved-policy-title"]').getByRole('status')).toContainText(/unavailable|does not match/);
  await expect(page.getByText('Qualification current at this bounded read.', { exact: false })).toHaveCount(0);
  expect(f.writes).toEqual([]); expect(f.errors).toEqual([]);
});
for (const trigger of ['edit', 'offline', 'expiry', 'failed-read']) test(`withdraws the current indication on ${trigger}`, async ({ page }) => {
  const f = await setup(page); if (trigger === 'expiry') f.state.ttl = 900;
  await exact(page); await expect(page.getByText('Qualification current at this bounded read.', { exact: false })).toBeVisible();
  if (trigger === 'edit') await page.getByLabel('Approved policy ID', { exact: true }).fill(OTHER);
  if (trigger === 'offline') await page.evaluate(() => window.dispatchEvent(new Event('offline')));
  if (trigger === 'failed-read') { f.state.fault = 'denied'; await page.getByRole('button', { name: 'Read exact approved policy', exact: true }).click(); }
  await expect(page.getByText('Qualification current at this bounded read.', { exact: false })).toHaveCount(0);
  expect(f.writes).toEqual([]); expect(f.errors).toEqual([]);
});
test('held and absent installed records offer manual checking without inspection authority', async ({ page }) => {
  const f = await setup(page); f.state.fault = 'held'; await exact(page);
  await expect(page.getByText('Historical or held record.', { exact: false })).toBeVisible();
  f.state.fault = 'none'; await page.getByRole('button', { name: 'Read installed approved policy', exact: true }).click();
  await expect(page.locator('section[aria-labelledby="approved-policy-title"]').getByRole('status')).toContainText('No approved policy is installed');
  expect(f.writes).toEqual([]); expect(f.errors).toEqual([]);
});
test('approved selection works with keyboard, zoom and forced colors', async ({ page }) => {
  const f = await setup(page); await page.setViewportSize({ width: 800, height: 900 });
  await page.emulateMedia({ forcedColors: 'active' }); await page.evaluate(() => { document.documentElement.style.zoom = '2'; });
  const input = page.getByLabel('Approved policy ID', { exact: true }); await input.focus(); await page.keyboard.type(ID);
  await page.keyboard.press('Tab'); await page.keyboard.type('1'); await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: 'Read exact approved policy', exact: true })).toBeFocused(); await page.keyboard.press('Enter');
  await expect(page.getByText('Qualification current at this bounded read.', { exact: false })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  expect(f.writes).toEqual([]); expect(f.errors).toEqual([]);
});
