import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { expect, test, type Page } from '@playwright/test';

// Run on an ephemeral real CORE stack with its bootstrap administrator.
// The browser uses the login form and real API; no demo seed, route mocks,
// injected session, investigation or hosted model call is needed.
const artifacts = process.env.AISOC_BYOK_ARTIFACTS ?? '';

async function signIn(page: Page, destination: string) {
  const email = process.env.AISOC_BYOK_E2E_EMAIL;
  const password = process.env.AISOC_BYOK_E2E_PASSWORD;
  if (!email || !password) throw new Error('Set the bootstrap administrator credentials for CORE BYOK acceptance');
  await page.goto(`/login?next=${encodeURIComponent(destination)}`);
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page).toHaveURL(new URL(destination, 'http://localhost:3000').href);
}

async function screenshot(page: Page, name: string) {
  if (!artifacts) throw new Error('Set AISOC_BYOK_ARTIFACTS to retain real-stack evidence');
  await mkdir(artifacts, { recursive: true });
  await page.screenshot({ path: path.join(artifacts, `${name}.png`), fullPage: true });
}

test.beforeEach(async ({ baseURL }) => {
  // These credentials belong to a disposable CI stack, never a deployed tenant.
  expect(baseURL).toBe('http://localhost:3000');
  if (!artifacts) throw new Error('AISOC_BYOK_ARTIFACTS is required');
  await mkdir(artifacts, { recursive: true });
});

test.afterEach(async ({ page }, testInfo) => {
  if (testInfo.status !== testInfo.expectedStatus) {
    await screenshot(page, `byok-failure-${testInfo.title.replace(/[^a-z0-9]+/gi, '-')}`);
  }
});

test('BYOK model guidance distinguishes hosted defaults from endpoint identifiers', async ({ page }) => {
  await signIn(page, '/settings?tab=deployment');
  await page.getByRole('button', { name: 'Configure BYOK', exact: true }).click();
  await page.getByRole('combobox', { name: 'Provider', exact: true }).selectOption('openai');
  await expect(page.getByPlaceholder('provider default')).toBeVisible();
  await expect(page.getByText('Provider-specific identifier. Leave blank for the selected provider default.')).toBeVisible();
  await screenshot(page, 'byok-settings-hosted');

  await page.getByRole('combobox', { name: 'Provider', exact: true }).selectOption('local-ollama');
  await expect(page.getByPlaceholder('model, deployment, or gateway alias')).toBeVisible();
  await expect(page.getByText('Enter the model served by this endpoint, its deployment name, or a gateway alias.')).toBeVisible();
  await screenshot(page, 'byok-settings-local');
});
