import { test, expect } from '@playwright/test';

test('diagnostic: keyboard dispatch works on an independent static document', async ({ page }) => {
  await page.setContent('<!doctype html><html lang="en"><title>Input diagnostic</title><button>Diagnostic button</button></html>');
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: 'Diagnostic button' })).toBeFocused();
  await page.getByRole('button', { name: 'Diagnostic button' }).click();
});
