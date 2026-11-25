/**
 * The incident timeline in the running console.
 *
 * Browser navigation and rendering are real; API responses are synthetic
 * test fixtures, so nothing here claims anything about the pipeline. What
 * it does claim is the thing a unit test cannot: that an analyst reaching
 * the tab sees the alerts and the events behind them in one chronological
 * list, and that when the lake cannot be read the page says so instead of
 * showing an empty one.
 */
import { expect, test, type Page } from '@playwright/test';

const CASE_ID = '55555555-5555-4555-8555-555555555555';
const ALERT_ID = '66666666-6666-4666-8666-666666666666';

const CASE_BODY = {
  id: CASE_ID,
  case_number: 'INC-TEST-010',
  title: 'Synthetic test: credential access on a domain controller',
  description: 'Synthetic browser-test data used to verify the incident timeline.',
  status: 'investigating',
  severity: 'critical',
  alert_ids: [ALERT_ID],
  tags: { labels: [] },
  mitre_techniques: [],
  created_at: '2026-05-14T08:00:00Z',
  updated_at: '2026-05-14T08:30:00Z',
};

const TIMELINE = {
  case_id: CASE_ID,
  alert_count: 1,
  event_count: 2,
  events_available: true,
  events_unavailable_reason: null,
  source_event_ids_truncated: false,
  truncation_note: '',
  disclaimer:
    'Times are taken from the source records themselves. This is a chronology of what was observed, not a confirmed account of what caused what.',
  entries: [
    {
      kind: 'event',
      at: '2026-05-14T08:02:00Z',
      title: 'process_create',
      alert_id: ALERT_ID,
      action: 'process_create',
      user_name: 'svc-backup',
      hostname: 'WIN-DC01',
      source_ip: '10.20.30.40',
    },
    {
      kind: 'event',
      at: '2026-05-14T08:04:00Z',
      title: 'lsass_access',
      alert_id: ALERT_ID,
      action: 'lsass_access',
      user_name: 'svc-backup',
      hostname: 'WIN-DC01',
      source_ip: '10.20.30.40',
    },
    {
      kind: 'alert',
      at: '2026-05-14T08:10:00Z',
      title: 'Credential dumping via LSASS access',
      alert_id: ALERT_ID,
      severity: 'critical',
      chain_stage: 'credential-access',
      chain_position: 2,
      connector_type: 'crowdstrike_falcon',
      mitre_techniques: ['T1003'],
    },
  ],
};

/** The core-profile shape: no ClickHouse, so the lake cannot be read. */
const TIMELINE_NO_LAKE = {
  ...TIMELINE,
  event_count: 0,
  events_available: false,
  events_unavailable_reason:
    'The event lake is not configured on this deployment, so the raw events behind these alerts cannot be shown.',
  entries: TIMELINE.entries.filter((e) => e.kind === 'alert'),
};

async function mockBackend(page: Page, timeline: unknown) {
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const fixtures: Record<string, unknown> = {
      '/api/v1/auth/me': {
        id: 'incident-timeline-test-user',
        email: 'analyst@example.invalid',
        role: 'admin',
        tenant_id: 'incident-timeline-test-tenant',
        preferences: {},
      },
      [`/api/v1/cases/${CASE_ID}`]: CASE_BODY,
      [`/api/v1/cases/${CASE_ID}/incident-timeline`]: timeline,
      [`/api/v1/cases/${CASE_ID}/timeline`]: { events: [] },
      [`/api/v1/cases/${CASE_ID}/related`]: { related: [], limit: 20, has_more: false },
      [`/api/v1/cases/${CASE_ID}/investigations`]: { runs: [] },
      [`/api/v1/war-rooms/cases/${CASE_ID}`]: [],
      '/api/v1/contextual/actions': { actions: [] },
    };
    if (Object.hasOwn(fixtures, path)) {
      await route.fulfill({ json: fixtures[path] });
    } else {
      await route.fulfill({
        status: 503,
        json: { detail: 'Auxiliary service unavailable in browser test' },
      });
    }
  });
}

test('the timeline shows alerts and the events behind them, oldest first', async ({ page }) => {
  await mockBackend(page, TIMELINE);
  await page.goto(`/cases/${CASE_ID}?tab=incident-timeline`);

  // The alert and both of its events are all on the page.
  await expect(page.getByText('Credential dumping via LSASS access')).toBeVisible();
  await expect(page.getByText('process_create')).toBeVisible();
  await expect(page.getByText('lsass_access')).toBeVisible();

  // Read in the order they happened: both events precede the alert.
  // Scoped to the chronology's own list — an unscoped `ol li` also matches
  // the sidebar navigation, which happens to contain the word "access".
  const rows = page.getByRole('list', { name: 'Incident chronology' }).locator('li');
  const joined = (await rows.allInnerTexts()).join('\n');
  expect(joined.indexOf('process_create')).toBeLessThan(joined.indexOf('lsass_access'));
  expect(joined.indexOf('lsass_access')).toBeLessThan(
    joined.indexOf('Credential dumping via LSASS access'),
  );

  // The kill-chain stage groups the alert, and the disclaimer is present.
  await expect(page.getByText(/credential-access/i).first()).toBeVisible();
  await expect(page.getByText(/not a confirmed account of what caused what/i)).toBeVisible();
});

test('a deployment without the lake says so rather than showing no events', async ({ page }) => {
  await mockBackend(page, TIMELINE_NO_LAKE);
  await page.goto(`/cases/${CASE_ID}?tab=incident-timeline`);

  await expect(page.getByText(/not configured on this deployment/i)).toBeVisible();
  // Losing the lake must not lose the alerts.
  await expect(page.getByText('Credential dumping via LSASS access')).toBeVisible();
  // And it must not invent events.
  await expect(page.getByText('process_create')).toHaveCount(0);
});
