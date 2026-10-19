import { test, expect } from '@playwright/test';
import path from 'node:path';

test('unconfigured service gives an honest safe starting point', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.bringToFront();
  await page.goto('/');
  // React mounts asynchronously after navigation. Establish the rendered
  // starting state before sending Tab; an empty document can focus browser UI.
  await expect(page).toHaveTitle('ProofPack — visible kit checks');
  await expect(page.getByRole('status')).toContainText('Inspections are not available yet');
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'Skip to main content' })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#main')).toBeFocused();
  await page.getByRole('button', { name: 'Check again' }).click();
  await expect(page.getByRole('status')).toContainText('Inspections are not available yet');
  await page.getByText('Camera, privacy and participation', { exact: true }).click();
  await expect(page.getByText(/only after your explicit action/)).toBeVisible();
  await page.screenshot({ path: path.resolve(__dirname, '../../evidence/local/foundation-desktop.png'), fullPage: true });
  expect(errors).toEqual([]);
});

test('transport failure offers retry without starting capture', async ({ page }) => {
  await page.route('**/health/ready', route => route.abort('failed'));
  await page.goto('/');
  await expect(page.getByRole('status')).toContainText('Connection unavailable');
  await expect(page.getByRole('button', { name: 'Check again' })).toBeEnabled();
  expect(await page.locator('video').count()).toBe(0);
});
