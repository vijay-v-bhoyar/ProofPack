import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '../../tests/e2e',
  fullyParallel: false,
  workers: 1,
  use: { baseURL: process.env.PROOFPACK_BROWSER_URL ?? 'http://127.0.0.1:8000', channel: 'chrome', trace: 'retain-on-failure' },
  reporter: [['list'], ['junit', { outputFile: 'evidence/local/browser-tests.xml' }]],
});
