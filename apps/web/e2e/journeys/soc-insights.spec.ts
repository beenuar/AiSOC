/** Real console rendering with explicitly synthetic API and realtime fixtures. */
import { expect, test, type Page, type WebSocketRoute } from '@playwright/test';
import type { SOCInsightsResponse } from '../../src/lib/api';

const TENANT = '77777777-7777-4777-8777-777777777777';
const USER = {
  id: 'soc-insights-browser-test',
  email: 'analyst@example.invalid',
  role: 'admin',
  tenant_id: TENANT,
  preferences: {},
};

function snapshot(window: SOCInsightsResponse['window'] = '24h'): SOCInsightsResponse {
  const definitions = [
    ['mtta', 'MTTA', 1.5, 'hours'],
    ['mttr', 'MTTR', 3.5, 'hours'],
    ['fp_rate', 'FP rate', 0.25, 'pct'],
    ['alerts_per_day', 'Alerts / day', window === '24h' ? 24 : 70, 'count'],
    ['cases_per_day', 'Cases / day', 8, 'count'],
    ['agent_cost_per_investigation', 'Agent cost / investigation', 0, 'usd'],
    ['analyst_hours_saved', 'Analyst hours saved', 3, 'hours_saved'],
  ] as const;
  return {
    window,
    tenant_id: TENANT,
    generated_at: '2026-11-19T03:00:00Z',
    manual_investigation_minutes: 45,
    tiles: definitions.map(([key, label, value, unit]) => ({
      key, label, value, unit,
      sample_count: key === 'agent_cost_per_investigation' ? 0 : 4,
      previous_value: value * 2,
      delta_pct: key === 'agent_cost_per_investigation' ? null : -50,
      sparkline: { points: Array.from({ length: 24 }, (_, i) => i % 5) },
    })),
  };
}

async function prepare(page: Page) {
  await page.addInitScript(({ tenant, user }) => {
    localStorage.setItem('aisoc.activeTenantId', tenant);
    localStorage.setItem('aisoc.responder.user', JSON.stringify(user));
    localStorage.setItem('aisoc.responder.accessToken', 'synthetic-browser-fixture');
    localStorage.setItem('aisoc-theme', 'dark');
  }, { tenant: TENANT, user: USER });
  let socket: WebSocketRoute | undefined;
  await page.routeWebSocket('**/ws/insights?*', (ws) => { socket = ws; });
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/v1/insights/soc') {
      const window = new URL(route.request().url()).searchParams.get('window') as SOCInsightsResponse['window'];
      await route.fulfill({ json: snapshot(window) });
    } else if (path === '/api/v1/realtime/ticket') {
      await route.fulfill({ json: { token: 'synthetic-ticket', tenant_id: TENANT, expires_in: 60 } });
    } else if (path === '/api/v1/auth/me' || path === '/api/v1/auth/me/preferences') {
      await route.fulfill({ json: USER });
    } else if (path === '/api/v1/tenants/me' || path === '/api/v1/tenants/identity') {
      await route.fulfill({ json: { id: TENANT, name: 'Synthetic browser-test tenant', mssp_role: null } });
    } else {
      await route.fulfill({ status: 503, json: { detail: 'Auxiliary service unavailable in browser test' } });
    }
  });
  return {
    async poke() {
      await expect.poll(() => Boolean(socket)).toBe(true);
      socket!.send(JSON.stringify({ type: 'insights_updated' }));
    },
  };
}

test('insights use the console theme, spacing and route title', async ({ page }, testInfo) => {
  await prepare(page);
  await page.goto('/dashboards/soc-insights');
  const grid = page.getByTestId('soc-insights-tiles');
  await expect(grid.locator(':scope > div')).toHaveCount(7);
  await expect(page.getByRole('banner').getByText('SOC Insights', { exact: true })).toBeVisible();

  const heading = page.getByRole('main').getByRole('heading', { level: 1, name: 'SOC Insights' });
  const mainBox = await page.getByRole('main').boundingBox();
  const headingBox = await heading.boundingBox();
  expect(headingBox!.x - mainBox!.x).toBe(24);
  const card = grid.locator(':scope > div').first();
  await expect(card).toHaveCSS('background-color', 'rgb(20, 25, 38)');
  await expect(card).toHaveCSS('border-radius', '12px');
  await testInfo.attach('soc-insights-dark-synthetic-fixture', {
    body: await page.screenshot({ fullPage: true }), contentType: 'image/png',
  });

  await page.getByRole('button', { name: 'Switch to light theme' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  const expectedCard = await page.evaluate(() => {
    const probe = document.createElement('div');
    probe.style.backgroundColor = 'var(--surface-card)';
    document.body.append(probe);
    const color = getComputedStyle(probe).backgroundColor;
    probe.remove();
    return color;
  });
  await expect(card).toHaveCSS('background-color', expectedCard);
  await testInfo.attach('soc-insights-light-synthetic-fixture', {
    body: await page.screenshot({ fullPage: true }), contentType: 'image/png',
  });

  await page.setViewportSize({ width: 390, height: 844 });
  await expect(grid).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await testInfo.attach('soc-insights-mobile-synthetic-fixture', {
    body: await page.getByRole('main').locator(':scope > div').screenshot({ animations: 'disabled' }),
    contentType: 'image/png',
  });
});

test('realtime refresh and retry preserve the last successful snapshot', async ({ page }) => {
  const realtime = await prepare(page);
  await page.goto('/dashboards/soc-insights');
  const grid = page.getByTestId('soc-insights-tiles');
  await expect(grid).toBeVisible();
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  await page.route('**/api/v1/insights/soc?*', async (route) => {
    await pending;
    await route.fulfill({ status: 503, json: { detail: 'Synthetic refresh failure' } });
  });
  await realtime.poke();
  await expect(page.getByRole('main').getByRole('status')).toHaveText('Refreshing…');
  await expect(grid).toBeVisible();
  await expect(page.getByLabel('Loading SOC insights')).toHaveCount(0);
  release();
  await expect(page.getByRole('main').getByRole('alert')).toContainText('Showing the last successful update');
  await expect(grid).toBeVisible();
  await page.unroute('**/api/v1/insights/soc?*');
  await page.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(page.getByRole('main').getByRole('alert')).toHaveCount(0);
  await expect(grid).toBeVisible();
});

test('changing the window waits for the matching snapshot', async ({ page }) => {
  await prepare(page);
  await page.goto('/dashboards/soc-insights');
  const grid = page.getByTestId('soc-insights-tiles');
  await expect(grid.getByText('24', { exact: true })).toBeVisible();
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  await page.route('**/api/v1/insights/soc?window=7d', async (route) => {
    await pending;
    await route.fulfill({ json: snapshot('7d') });
  });
  await page.getByRole('radiogroup', { name: 'Window', exact: true }).getByRole('radio', { name: '7d', exact: true }).click();
  await expect(page.getByLabel('Loading SOC insights')).toBeVisible();
  await expect(grid).toHaveCount(0);
  release();
  await expect(grid.getByText('70', { exact: true })).toBeVisible();
  await expect(grid.getByText('24', { exact: true })).toHaveCount(0);
});
