/**
 * Exercise alert drilldowns through the real Next router and browser history.
 * Backend responses are synthetic transport fixtures; API/PostgreSQL filter
 * semantics are covered separately from these navigation regressions.
 */
import { expect, test, type Page } from "@playwright/test";

const NOW = Date.now();
const FIXTURES = [
  ["critical-new", "critical", "new", 2],
  ["critical-escalated", "critical", "escalated", 3],
  ["critical-resolved", "critical", "resolved", 4],
  ["critical-old", "critical", "triaged", 48],
  ["high-recent", "high", "investigating", 5],
  ["low-old", "low", "new", 72],
  ["medium-false-positive", "medium", "false_positive", 6],
  ["info-new", "info", "new", 8],
] as const;

const ALERTS = FIXTURES.map(([label, severity, status, age], index) => ({
  id: `00000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
  title: `Synthetic drilldown fixture: ${label}`,
  severity,
  status,
  created_at: new Date(NOW - age * 3_600_000).toISOString(),
  updated_at: new Date(NOW - age * 3_600_000).toISOString(),
  event_time: new Date(NOW - age * 3_600_000).toISOString(),
  tags: [],
  mitre_tactics: [],
  mitre_techniques: [],
  affected_ips: [],
  affected_hosts: [],
  affected_users: [],
}));

function counts(rows: typeof ALERTS, field: "severity" | "status") {
  return rows.reduce<Record<string, number>>((result, row) => {
    result[row[field]] = (result[row[field]] ?? 0) + 1;
    return result;
  }, {});
}

async function mockBackend(page: Page) {
  const alertRequests: URLSearchParams[] = [];
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/api/v1/alerts") {
      const params = url.searchParams;
      alertRequests.push(new URLSearchParams(params));
      const rows = ALERTS.filter((row) =>
        (!params.has("severity") || row.severity === params.get("severity")) &&
        (!params.has("status") || row.status === params.get("status")) &&
        (params.get("unresolved_only") !== "true" ||
          !["resolved", "false_positive"].includes(row.status)) &&
        (!params.has("created_within_hours") ||
          Date.parse(row.created_at) >= NOW - Number(params.get("created_within_hours")) * 3_600_000),
      );
      await route.fulfill({ json: {
        items: rows,
        total: rows.length,
        page: 1,
        page_size: Number(params.get("page_size") ?? 25),
        facets: {
          by_severity: counts(rows, "severity"),
          by_status: counts(rows, "status"),
          unresolved: rows.filter((row) => !["resolved", "false_positive"].includes(row.status)).length,
        },
      } });
      return;
    }

    const fixtures: Record<string, unknown> = {
      "/api/v1/auth/me": {
        id: "drilldown-test-user",
        email: "analyst@example.com",
        role: "soc_analyst",
        tenant_id: "drilldown-test-tenant",
        preferences: {},
      },
      "/api/v1/alerts/stats": {
        total: 8,
        new_last_24h: 6,
        critical_open: 3,
        by_severity: counts(ALERTS, "severity"),
        by_status: counts(ALERTS, "status"),
      },
      // A saved default must not override an explicit drilldown, including
      // the unfiltered Total link and the URL left after clearing all chips.
      "/api/v1/saved-views": [{
        id: "drilldown-default",
        view_type: "alerts",
        name: "Synthetic low-severity default",
        filters: { severity: "low" },
        columns: null,
        is_default: true,
        created_at: new Date(NOW).toISOString(),
        updated_at: new Date(NOW).toISOString(),
      }],
    };
    if (Object.hasOwn(fixtures, url.pathname)) {
      await route.fulfill({ json: fixtures[url.pathname] });
      return;
    }
    await route.fulfill({
      status: 503,
      json: { detail: "Auxiliary service unavailable in drilldown navigation fixture" },
    });
  });
  return alertRequests;
}

async function expectRows(page: Page, labels: readonly string[]) {
  await expect(page.getByRole("tab", { name: "Alerts", exact: true })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByTestId("saved-view-chip-drilldown-default")).toHaveAttribute("aria-pressed", "false");
  await expect(page.getByRole("link", { name: /Synthetic drilldown fixture:/ })).toHaveCount(labels.length);
  for (const label of labels) {
    await expect(page.getByText(`Synthetic drilldown fixture: ${label}`, { exact: true })).toBeVisible();
  }
}

test("removing every drilldown chip survives reload and retains unrelated URL state", async ({ page }) => {
  const requests = await mockBackend(page);
  await page.goto("/alerts?view=alerts&severity=critical&status=escalated&unresolved_only=true&created_within_hours=24&keep=a&keep=b#queue");
  await expectRows(page, ["critical-escalated"]);
  await expect(page.getByText("Escalated", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Remove status filter", exact: true }).click();
  await expectRows(page, ["critical-new", "critical-escalated"]);
  await expect(page).toHaveURL((url) => !url.searchParams.has("status"));
  await page.getByRole("button", { name: "Remove unresolved-only filter", exact: true }).click();
  await expectRows(page, ["critical-new", "critical-escalated", "critical-resolved"]);
  await expect(page).toHaveURL((url) => !url.searchParams.has("unresolved_only"));

  await page.reload();
  await expectRows(page, ["critical-new", "critical-escalated", "critical-resolved"]);
  await expect(page.getByRole("button", { name: "Remove unresolved-only filter" })).toHaveCount(0);
  await page.getByRole("button", { name: "Remove created-within-hours filter", exact: true }).click();
  await expectRows(page, ["critical-new", "critical-escalated", "critical-resolved", "critical-old"]);
  await page.getByRole("button", { name: "All severities", exact: true }).click();
  await expectRows(page, FIXTURES.map(([label]) => label));
  await expect(page).toHaveURL((url) =>
    url.searchParams.get("view") === "alerts" &&
    ["severity", "status", "unresolved_only", "created_within_hours"].every((key) => !url.searchParams.has(key)) &&
    url.searchParams.getAll("keep").join(",") === "a,b" && url.hash === "#queue",
  );
  await page.reload();
  await expectRows(page, FIXTURES.map(([label]) => label));
  expect(requests.at(-1)?.get("page_size")).toBe("25");
  expect(requests.at(-1)?.get("pageSize")).toBeNull();
});

test("a removed filter stays removed after leaving the route and traversing history", async ({ page }) => {
  await mockBackend(page);
  await page.goto("/alerts?view=alerts&severity=critical&unresolved_only=true");
  await expectRows(page, ["critical-new", "critical-escalated", "critical-old"]);
  await page.getByRole("button", { name: "Remove unresolved-only filter", exact: true }).click();
  const criticalRows = ["critical-new", "critical-escalated", "critical-resolved", "critical-old"];
  await expectRows(page, criticalRows);
  await page.getByRole("link", { name: "SOC Operations", exact: true }).click();
  await expect(page.getByRole("main").getByRole("heading", { name: "SOC operations", exact: true })).toBeVisible();

  await page.goBack();
  await expectRows(page, criticalRows);
  await expect(page).toHaveURL((url) => url.pathname === "/alerts" && !url.searchParams.has("unresolved_only"));
  await expect(page.getByRole("button", { name: "Remove unresolved-only filter" })).toHaveCount(0);
  await page.goForward();
  await expect(page.getByRole("main").getByRole("heading", { name: "SOC operations", exact: true })).toBeVisible();
  await page.goBack();
  await expectRows(page, criticalRows);
});

test("clear filters on an empty drilldown keeps the unfiltered alerts queue after reload", async ({ page }) => {
  await mockBackend(page);
  await page.goto("/alerts?view=alerts&status=resolved&unresolved_only=true&created_within_hours=24&keep=empty#queue");
  await expect(page.getByText("No alerts match these filters", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  await expectRows(page, FIXTURES.map(([label]) => label));
  await expect(page).toHaveURL((url) =>
    url.searchParams.get("view") === "alerts" && url.searchParams.get("keep") === "empty" &&
    !url.searchParams.has("status") && !url.searchParams.has("unresolved_only") &&
    !url.searchParams.has("created_within_hours") && url.hash === "#queue",
  );
  await page.reload();
  await expectRows(page, FIXTURES.map(([label]) => label));
});

test("posture links navigate with their accessible names and visible keyboard focus", async ({ page }) => {
  await mockBackend(page);
  await page.goto("/dashboards/operations");
  const posture = page.getByRole("region", { name: "Alert posture", exact: true });
  const total = posture.getByRole("link", { name: "View all 8 alerts", exact: true });
  await total.click();
  await expectRows(page, FIXTURES.map(([label]) => label));
  await page.goBack();

  await posture.getByRole("link", { name: "View 6 alerts created in the last 24 hours", exact: true }).click();
  await expectRows(page, ["critical-new", "critical-escalated", "critical-resolved", "high-recent", "medium-false-positive", "info-new"]);
  await page.goBack();
  const criticalOpen = posture.getByRole("link", { name: "View 3 critical open alerts", exact: true });
  await criticalOpen.click();
  await expectRows(page, ["critical-new", "critical-escalated", "critical-old"]);
  await page.goBack();

  // The first Critical link is the small segment; the second is its legend.
  const criticalSegment = posture.getByRole("link", { name: "View 4 Critical alerts", exact: true }).first();
  await criticalOpen.focus();
  await page.keyboard.press("Tab");
  await expect(criticalSegment).toBeFocused();
  await expect(criticalSegment).toHaveCSS("outline-style", "solid");
  await expect(criticalSegment).toHaveCSS("outline-width", "2px");
  await expect(criticalSegment).toHaveCSS("outline-offset", "2px");
  expect(await criticalSegment.evaluate((link) => getComputedStyle(link.parentElement!).overflow)).toBe("visible");
  await page.keyboard.press("Enter");
  await expectRows(page, ["critical-new", "critical-escalated", "critical-resolved", "critical-old"]);
  await page.goBack();
  await posture.getByRole("link", { name: "View 1 Escalated alerts", exact: true }).last().click();
  await expectRows(page, ["critical-escalated"]);
  await expect(page.getByText("Escalated", { exact: true })).toBeVisible();
});

test("invalid URL filters are omitted from the alerts request", async ({ page }) => {
  const requests = await mockBackend(page);
  await page.goto("/alerts?view=alerts&severity=urgent&status=bad%20status&unresolved_only=maybe&created_within_hours=0");
  await expectRows(page, FIXTURES.map(([label]) => label));
  const lastRequest = requests.at(-1);
  expect(lastRequest).toBeDefined();
  for (const key of ["severity", "status", "unresolved_only", "created_within_hours"]) {
    expect(lastRequest?.has(key), key).toBe(false);
  }
});
