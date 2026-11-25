/**
 * Native browser selection, clipboard and drag/drop in the running console.
 * HTTP responses are synthetic fixtures; no API/database behavior is claimed.
 */
import { expect, test, type Locator, type Page, type TestInfo } from '@playwright/test';
import type { DashboardMetrics } from '../../src/lib/api';

const ORDER_KEY = 'aisoc:dashboard:widget-order';
const INITIAL_ORDER = [
  'top-metrics', 'charts-row', 'welcome', 'funnel-kpis',
  'efficiency-and-pipeline', 'bottom-row', 'soc-performance',
];
const TENANT = '88888888-8888-4888-8888-888888888888';
const USER = {
  id: 'dashboard-reorder-browser-test',
  email: 'analyst@example.invalid',
  role: 'admin',
  tenant_id: TENANT,
  preferences: {},
};
const METRICS: DashboardMetrics = {
  alerts: {
    total: 4, new: 2, critical: 1, high: 1, medium: 1, low: 1,
    resolvedToday: 0, active: 4, criticalActive: 1, mttr: 0, mttr_sample_count: 0,
  },
  cases: { open: 1, inProgress: 1, resolvedThisWeek: 0 },
  sources: [], topMitre: [], alertsTrend: [], threatsBySource: [],
};

function widget(page: Page, id: string) {
  return page.getByLabel(`Dashboard widget: ${id}`, { exact: true });
}

async function currentOrder(page: Page) {
  return page.locator('[aria-label^="Dashboard widget:"]').evaluateAll((nodes) =>
    nodes.map((node) => node.getAttribute('aria-label')!.replace('Dashboard widget: ', '')),
  );
}

async function expectIdle(page: Page) {
  await expect(page.locator('[aria-label^="Dashboard widget:"].opacity-40')).toHaveCount(0);
  await expect(page.locator('[aria-label^="Dashboard widget:"].ring-2')).toHaveCount(0);
  await expect.poll(() => currentOrder(page)).toEqual(INITIAL_ORDER);
  await expect.poll(() => page.evaluate((key) => JSON.parse(localStorage.getItem(key)!), ORDER_KEY))
    .toEqual(INITIAL_ORDER);
}

async function capture(page: Page, testInfo: TestInfo, name: string) {
  const path = testInfo.outputPath(`${name}.png`);
  await page.screenshot({ path, animations: 'disabled' });
  await testInfo.attach(name, { path, contentType: 'image/png' });
}

/** Mouse input starts an actual native drag; no DragEvent is dispatched. */
async function dragOver(page: Page, source: Locator, target: Locator) {
  await source.hover();
  const from = await source.boundingBox();
  const to = await target.boundingBox();
  expect(from).not.toBeNull();
  expect(to).not.toBeNull();
  const start = { x: from!.x + from!.width / 2, y: from!.y + from!.height / 2 };
  const end = { x: to!.x + to!.width / 2, y: to!.y + 28 };
  await page.mouse.move(start.x, start.y);
  await page.mouse.down();
  await page.mouse.move(start.x + 10, start.y + 10, { steps: 4 });
  await page.mouse.move(end.x, end.y, { steps: 12 });
  // A second move over the target ensures a native dragover after dragenter.
  await page.mouse.move(end.x + 1, end.y);
}

test.beforeEach(async ({ page }) => {
  await page.addInitScript(({ key, order, tenant, user }) => {
    // Preserve reordered storage on reload instead of re-seeding it.
    if (localStorage.getItem(key) === null) localStorage.setItem(key, JSON.stringify(order));
    localStorage.setItem('aisoc.activeTenantId', tenant);
    localStorage.setItem('aisoc.responder.user', JSON.stringify(user));
    // A synthetic, unsigned JWT-shaped token exercises the frontend's valid
    // session branch. Authentication itself is intercepted below.
    const payload = btoa(JSON.stringify({ sub: user.id, exp: Math.floor(Date.now() / 1000) + 3600 }));
    localStorage.setItem('aisoc.responder.accessToken', `eyJhbGciOiJub25lIn0.${payload}.synthetic-fixture`);
    localStorage.setItem('aisoc-theme', 'dark');
  }, { key: ORDER_KEY, order: INITIAL_ORDER, tenant: TENANT, user: USER });
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/v1/metrics/dashboard') {
      await route.fulfill({ json: METRICS });
    } else if (path === '/api/v1/connectors') {
      await route.fulfill({ json: { connectors: [], total: 0 } });
    } else if (path === '/api/v1/auth/me' || path === '/api/v1/auth/me/preferences') {
      await route.fulfill({ json: USER });
    } else if (path === '/api/v1/tenants/me' || path === '/api/v1/tenants/identity') {
      await route.fulfill({ json: { id: TENANT, name: 'Synthetic browser-test tenant', mssp_role: null } });
    } else {
      await route.fulfill({ status: 503, json: { detail: 'Auxiliary service unavailable in browser test' } });
    }
  });
  await page.goto('/dashboard');
  await expect(widget(page, 'top-metrics').getByRole('link', { name: /^Active Alerts/ })).toBeVisible();
  await expect.poll(() => currentOrder(page)).toEqual(INITIAL_ORDER);
});

test('dashboard text can be selected with the mouse and copied', async ({ page, context }, testInfo) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.evaluate(() => navigator.clipboard.writeText('clipboard-before-dashboard-selection'));
  const title = widget(page, 'top-metrics').getByRole('heading', { name: 'Security Operations Center' });
  await title.scrollIntoViewIfNeeded();
  await capture(page, testInfo, 'dashboard-before-text-selection');
  // A Range measures the rendered text only; selection is made by the mouse.
  const bounds = await title.evaluate((heading) => {
    const range = document.createRange();
    range.selectNodeContents(heading);
    const box = range.getBoundingClientRect();
    return { x: box.x, y: box.y, width: box.width, height: box.height };
  });
  await page.mouse.move(bounds.x, bounds.y + bounds.height / 2);
  await page.mouse.down();
  await page.mouse.move(bounds.x + bounds.width + 1, bounds.y + bounds.height / 2, { steps: 20 });
  await page.mouse.up();
  await capture(page, testInfo, 'dashboard-after-text-selection');
  await expect.poll(() => page.evaluate(() => window.getSelection()?.toString()))
    .toBe('Security Operations Center');
  await page.keyboard.press('ControlOrMeta+C');
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText()))
    .toBe('Security Operations Center');
  await expectIdle(page);
});

test('clicking the reorder handle does not start a drag', async ({ page }) => {
  const source = widget(page, 'top-metrics');
  await source.hover();
  await source.getByRole('button', { name: 'Drag to reorder', exact: true }).click();
  await widget(page, 'charts-row').hover();
  await expectIdle(page);
});

test('only the handle reorders widgets and persists their order after reload', async ({ page }, testInfo) => {
  const source = widget(page, 'top-metrics');
  const target = widget(page, 'charts-row');
  await capture(page, testInfo, 'dashboard-before-reorder');
  await dragOver(page, source.getByRole('button', { name: 'Drag to reorder', exact: true }), target);
  await expect(source).toHaveCSS('opacity', '0.4');
  await expect(target).toHaveClass(/ring-2/);
  await page.mouse.up();
  const reordered = ['charts-row', 'top-metrics', ...INITIAL_ORDER.slice(2)];
  await expect.poll(() => currentOrder(page)).toEqual(reordered);
  await expect.poll(() => page.evaluate((key) => JSON.parse(localStorage.getItem(key)!), ORDER_KEY))
    .toEqual(reordered);
  await capture(page, testInfo, 'dashboard-after-reorder');
  await page.reload();
  await expect.poll(() => currentOrder(page)).toEqual(reordered);
  await expect(page.locator('[aria-label^="Dashboard widget:"].opacity-40')).toHaveCount(0);
});

test('dragging a dashboard link does not start widget reordering', async ({ page }) => {
  const source = widget(page, 'top-metrics').getByRole('link', { name: /^Active Alerts/ });
  await dragOver(page, source, widget(page, 'charts-row'));
  // Links have their own native drag. They must not set widget drag state.
  await expectIdle(page);
  await page.keyboard.press('Escape');
  await page.mouse.up();
  await expectIdle(page);
});

test('Escape cancels a handle drag without committing the hovered target', async ({ page }) => {
  const source = widget(page, 'top-metrics');
  const target = widget(page, 'charts-row');
  await dragOver(page, source.getByRole('button', { name: 'Drag to reorder', exact: true }), target);
  await expect(source).toHaveCSS('opacity', '0.4');
  await expect(target).toHaveClass(/ring-2/);
  await page.keyboard.press('Escape');
  await page.mouse.up();
  await expectIdle(page);
});

test('dropping outside the widgets cancels the reorder', async ({ page }) => {
  const source = widget(page, 'top-metrics');
  const target = widget(page, 'charts-row');
  await dragOver(page, source.getByRole('button', { name: 'Drag to reorder', exact: true }), target);
  await expect(target).toHaveClass(/ring-2/);
  // Use the side gutter so travelling toward the banner cannot cross the
  // source widget again and mask a stale-hover reorder on dragend.
  const banner = await page.getByRole('banner').boundingBox();
  const box = await target.boundingBox();
  expect(banner).not.toBeNull();
  expect(box).not.toBeNull();
  const gutterX = box!.x - 12;
  const bannerCenterY = banner!.y + banner!.height / 2;
  await page.mouse.move(gutterX, box!.y + 28, { steps: 16 });
  await page.mouse.move(gutterX, bannerCenterY, { steps: 16 });
  await page.mouse.move(banner!.x + banner!.width / 2, bannerCenterY);
  await expect(target).toHaveClass(/ring-2/);
  await page.mouse.up();
  await expectIdle(page);
});
