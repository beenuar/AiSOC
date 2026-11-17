/** Browser navigation uses the real console; API responses are synthetic test fixtures. */
import { expect, test, type Page } from '@playwright/test';

const SOURCE_ID = '22222222-2222-4222-8222-222222222222';
const RELATED_ID = '33333333-3333-4333-8333-333333333333';
const ALERT_ID = '44444444-4444-4444-8444-444444444444';
const ALERT_TITLE = 'Synthetic test: shared alert evidence';

const SOURCE = {
  id: SOURCE_ID,
  case_number: 'INC-TEST-001',
  title: 'Synthetic test: suspicious activity on finance workstation',
  description: 'Synthetic browser-test data used to verify related-case navigation.',
  status: 'investigating',
  severity: 'high',
  alert_ids: [ALERT_ID],
  tags: { labels: [] },
  mitre_techniques: [],
  created_at: '2026-11-16T10:00:00Z',
  updated_at: '2026-11-16T10:00:00Z',
};

const RELATED = {
  id: RELATED_ID,
  case_number: 'INC-TEST-002',
  title: 'Synthetic test: earlier lateral movement',
  severity: 'critical',
  status: 'closed',
  created_at: '2026-11-15T09:00:00Z',
  reason: 'shared_alerts',
  shared_alert_count: 1,
  shared_alert_ids: [ALERT_ID],
  shared_observable_count: 2,
  shared_observables: [
    { kind: 'host', value: 'finance-workstation' },
    { kind: 'ip', value: '192.0.2.40' },
  ],
};

async function mockBackend(page: Page, failFirst = false) {
  let sourceReads = 0;
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === `/api/v1/cases/${SOURCE_ID}/related`) {
      sourceReads += 1;
      if (failFirst && sourceReads === 1) {
        await route.fulfill({ status: 503, json: { detail: 'Synthetic service failure' } });
      } else {
        await route.fulfill({ json: { related: [RELATED], limit: 20, has_more: false } });
      }
      return;
    }
    const fixtures: Record<string, unknown> = {
      '/api/v1/auth/me': {
        id: 'related-cases-test-user',
        email: 'analyst@example.com',
        role: 'admin',
        tenant_id: 'related-cases-test-tenant',
        preferences: {},
      },
      [`/api/v1/cases/${SOURCE_ID}`]: SOURCE,
      [`/api/v1/cases/${RELATED_ID}`]: { ...SOURCE, ...RELATED, alert_ids: [ALERT_ID] },
      [`/api/v1/cases/${RELATED_ID}/related`]: { related: [], limit: 20, has_more: false },
      [`/api/v1/alerts/${ALERT_ID}`]: {
        id: ALERT_ID,
        title: ALERT_TITLE,
        description: 'Synthetic alert used to verify the evidence link reaches its detail page.',
        severity: 'high',
        status: 'new',
        source: 'test',
        created_at: SOURCE.created_at,
        updated_at: SOURCE.updated_at,
        risk_score: 70,
        confidence: 70,
        tags: [],
        iocs: [],
        mitre_attack: [],
      },
      [`/api/v1/cases/${SOURCE_ID}/timeline`]: { events: [] },
      [`/api/v1/cases/${RELATED_ID}/timeline`]: { events: [] },
      [`/api/v1/cases/${SOURCE_ID}/investigations`]: { runs: [] },
      [`/api/v1/cases/${RELATED_ID}/investigations`]: { runs: [] },
      [`/api/v1/war-rooms/cases/${SOURCE_ID}`]: [],
      [`/api/v1/war-rooms/cases/${RELATED_ID}`]: [],
      '/api/v1/contextual/actions': { actions: [] },
    };
    if (Object.hasOwn(fixtures, path)) {
      await route.fulfill({ json: fixtures[path] });
    } else {
      await route.fulfill({ status: 503, json: { detail: 'Auxiliary service unavailable in browser test' } });
    }
  });
}

test('related evidence is visible and opens the selected case', async ({ page }, testInfo) => {
  await mockBackend(page);
  await page.goto(`/cases/${SOURCE_ID}`);
  const panel = page.getByRole('region', { name: 'Related cases' });
  await expect(panel.getByText('1 shared alert', { exact: true })).toBeVisible();
  await expect(panel.getByText('2 shared observables', { exact: true })).toBeVisible();
  await expect(panel.getByText('finance-workstation', { exact: true })).toBeVisible();
  await expect(panel.getByText('192.0.2.40', { exact: true })).toBeVisible();
  await expect(panel.getByText('closed', { exact: true })).toBeVisible();
  await expect(panel.getByRole('link', { name: ALERT_ID })).toHaveAttribute('href', `/alerts/${ALERT_ID}`);
  await testInfo.attach('related-cases-synthetic-fixture', {
    body: await panel.screenshot(),
    contentType: 'image/png',
  });

  await panel.getByRole('link', { name: ALERT_ID }).click();
  await expect(page).toHaveURL(new RegExp(`/alerts/${ALERT_ID}$`));
  await expect(page.getByRole('heading', { level: 1, name: ALERT_TITLE })).toBeVisible();
  await page.goBack();
  await expect(panel.getByRole('link', { name: /INC-TEST-002/ })).toBeVisible();

  await panel.getByRole('link', { name: /INC-TEST-002/ }).click();
  await expect(page).toHaveURL(new RegExp(`/cases/${RELATED_ID}$`));
  await expect(page.getByRole('heading', { level: 1, name: RELATED.title })).toBeVisible();
  await expect(panel.getByText('No related cases found', { exact: true })).toBeVisible();
  await expect(panel.getByText('finance-workstation', { exact: true })).toHaveCount(0);
});

test('a failed lookup remains an error until an explicit retry succeeds', async ({ page }) => {
  await mockBackend(page, true);
  await page.goto(`/cases/${SOURCE_ID}`);
  const panel = page.getByRole('region', { name: 'Related cases' });
  await expect(panel.getByRole('alert')).toContainText('Could not load related cases');
  await expect(panel.getByText('No related cases found', { exact: true })).toHaveCount(0);
  await panel.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(panel.getByRole('link', { name: /INC-TEST-002/ })).toBeVisible();
  await expect(panel.getByRole('alert')).toHaveCount(0);
});
