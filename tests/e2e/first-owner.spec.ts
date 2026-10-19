import { test, expect } from '@playwright/test';

test('first-owner entry explains approval, owner-only access and recovery before navigation', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.bringToFront();
  await page.route('**/api/v1/auth/setup-owner', route => route.fulfill({ status: 503,
    contentType: 'text/plain', body: 'Offline fixture: first-owner setup unavailable without configured approval.' }));
  await page.goto('/');
  await expect(page.getByRole('status')).toContainText('Inspections are not available yet');
  await page.getByText('First owner setup', { exact: true }).click();
  await expect(page.getByText(/deployment administrator has approved your exact account/)).toBeVisible();
  await expect(page.getByText(/inspections remain disabled/)).toBeVisible();
  await expect(page.getByText(/confirmation is lost, start a fresh setup sign-in/)).toBeVisible();
  expect(await page.locator('video').count()).toBe(0);
  await page.getByRole('link', { name: 'Set up the approved first owner' }).click();
  await expect(page).toHaveURL(/\/api\/v1\/auth\/setup-owner$/);
  await expect(page.locator('body')).toContainText('Offline fixture: first-owner setup unavailable');
  expect(errors).toEqual([]);
});
