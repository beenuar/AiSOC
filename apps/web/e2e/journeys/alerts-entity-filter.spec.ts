/**
 * Entity-filter navigation through the real console and Next router.
 * All backend data here is synthetic; the API's SQL predicates and tenant
 * isolation are exercised separately against PostgreSQL.
 */
import { expect, test, type Page } from "@playwright/test";

const NOW = Date.now();
const HOST = "SYNTHETIC-WIN-01";
const RESERVED_USER = String.raw`LAB\alice+admin@example.test?team=A&B#ops`;

function alert(index: number, label: string, type: string, value: string, severity = "high") {
  return {
    id: `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`,
    title: `Synthetic entity fixture: ${label}`,
    severity,
    status: "new",
    created_at: new Date(NOW - index * 60_000).toISOString(),
    updated_at: new Date(NOW - index * 60_000).toISOString(),
    event_time: new Date(NOW - index * 60_000).toISOString(),
    entities: [{ type, value }],
    tags: [],
    mitre_tactics: [],
    mitre_techniques: [],
    affected_hosts: [],
    affected_users: [],
    affected_ips: [],
  };
}

const HOST_ALERTS = Array.from({ length: 30 }, (_, index) =>
  alert(index + 1, `host ${index + 1}`, "host", HOST),
);
const ALERTS = [
  ...HOST_ALERTS,
  alert(31, "user with the host's name", "user", HOST),
  alert(32, "different-case host", "host", HOST.toLowerCase()),
  alert(33, "reserved user high", "user", RESERVED_USER),
  alert(34, "reserved user low", "user", RESERVED_USER, "low"),
  alert(35, "unrelated host", "host", "SYNTHETIC-WIN-02"),
];

const RISK_ENTITY = {
  tenant_id: "synthetic-entity-tenant",
  entity_type: "user",
  entity_value: RESERVED_USER,
  score: 45,
  display_score: 45,
  threshold: 80,
  promoted: false,
  last_seen: new Date(NOW - 60_000).toISOString(),
  first_seen: new Date(NOW - 3_600_000).toISOString(),
  alert_count: 2,
  severity_histogram: { critical: 0, high: 1, medium: 0, low: 1, info: 0 },
  hosts: [],
  contributions: [],
};

function counts(rows: typeof ALERTS, field: "severity" | "status") {
  return rows.reduce<Record<string, number>>((result, row) => {
    result[row[field]] = (result[row[field]] ?? 0) + 1;
    return result;
  }, {});
}

async function mockBackend(page: Page, options: { savedViewsGate?: Promise<void> } = {}) {
  const requests: URLSearchParams[] = [];
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/api/v1/alerts") {
      const params = url.searchParams;
      requests.push(new URLSearchParams(params));
      const rows = ALERTS.filter((row) =>
        (!params.has("severity") || row.severity === params.get("severity")) &&
        (!params.has("status") || row.status === params.get("status")) &&
        (!params.has("entity_value") || row.entities.some((entity) =>
          entity.value === params.get("entity_value") &&
          (!params.has("entity_type") || entity.type === params.get("entity_type")),
        )),
      );
      const pageNumber = Number(params.get("page") ?? 1);
      const pageSize = Number(params.get("page_size") ?? 25);
      const offset = (pageNumber - 1) * pageSize;
      await route.fulfill({ json: {
        items: rows.slice(offset, offset + pageSize),
        total: rows.length,
        page: pageNumber,
        page_size: pageSize,
        pages: Math.ceil(rows.length / pageSize),
        facets: {
          by_severity: counts(rows, "severity"),
          by_status: counts(rows, "status"),
          unresolved: rows.length,
        },
      } });
      return;
    }

    const detail = ALERTS.find((row) => url.pathname === `/api/v1/alerts/${row.id}`);
    if (detail) {
      await route.fulfill({ json: {
        ...detail,
        narrative: "Synthetic entity-filter selection fixture.",
        related_entities: [],
        mini_timeline: [],
        recommended_actions: [],
      } });
      return;
    }

    const fixtures: Record<string, unknown> = {
      "/api/v1/auth/me": {
        id: "synthetic-entity-user",
        email: "synthetic-analyst@example.test",
        role: "soc_analyst",
        tenant_id: "synthetic-entity-tenant",
        preferences: {},
      },
      "/api/v1/saved-views": [
        {
          id: "entity-conflicting-default",
          view_type: "alerts",
          name: "Synthetic low-severity default",
          filters: { severity: "low" },
          columns: null,
          is_default: true,
          created_at: new Date(NOW).toISOString(),
          updated_at: new Date(NOW).toISOString(),
        },
        {
          id: "entity-user-preset",
          view_type: "alerts",
          name: "Synthetic user preset",
          filters: { entityType: "user", entityValue: RESERVED_USER, severity: "high" },
          columns: null,
          is_default: false,
          created_at: new Date(NOW).toISOString(),
          updated_at: new Date(NOW).toISOString(),
        },
      ],
      "/api/v1/fusion/entity-risk/queue": {
        tenant_id: "synthetic-entity-tenant", threshold: 80, entities: [RISK_ENTITY],
      },
      "/api/v1/fusion/entity-risk/stats": {
        tenant_id: "synthetic-entity-tenant", threshold: 80, total: 1, promoted: 0,
        bands: { critical: 0, high: 0, medium: 1, low: 0 }, alert_count: 2,
      },
    };
    if (url.pathname.startsWith("/api/v1/fusion/entity-risk/user/")) {
      await route.fulfill({ json: RISK_ENTITY });
      return;
    }
    if (Object.hasOwn(fixtures, url.pathname)) {
      if (url.pathname === "/api/v1/saved-views") await options.savedViewsGate;
      await route.fulfill({ json: fixtures[url.pathname] });
      return;
    }
    await route.fulfill({
      status: 503,
      json: { detail: "Auxiliary service unavailable in synthetic entity-filter fixture" },
    });
  });
  return requests;
}

async function expectRows(page: Page, labels: readonly string[]) {
  await expect(page.getByRole("tab", { name: "Alerts", exact: true })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("link", { name: /Synthetic entity fixture:/ })).toHaveCount(labels.length);
  for (const label of labels) {
    await expect(page.getByText(`Synthetic entity fixture: ${label}`, { exact: true })).toBeVisible();
  }
}

test("applying an entity preserves other filters, encodes its value, and resets pagination", async ({ page }, testInfo) => {
  const requests = await mockBackend(page);
  await page.goto("/alerts?view=alerts&page=2&severity=high&status=new&keep=a&keep=b#queue");
  await expect(page.getByText("Page 2", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: /Synthetic entity fixture:/ })).toHaveCount(9);
  const beforePath = testInfo.outputPath("before-entity-filter-synthetic-data.png");
  await page.screenshot({ path: beforePath, fullPage: true });
  await testInfo.attach("before-entity-filter-synthetic-data", { path: beforePath, contentType: "image/png" });
  const requestsBeforeDraft = requests.length;

  await page.getByLabel("Entity type", { exact: true }).selectOption("user");
  await page.getByLabel("Entity value", { exact: true }).fill(`  ${RESERVED_USER}  `);
  await expect(page.getByText("Page 2", { exact: true })).toBeVisible();
  expect(requests).toHaveLength(requestsBeforeDraft);
  expect(new URL(page.url()).searchParams.has("entity_value")).toBe(false);

  await page.getByRole("button", { name: "Apply entity filter", exact: true }).click();
  await expectRows(page, ["reserved user high"]);
  await expect(page).toHaveURL((url) =>
    url.searchParams.get("entity_type") === "user" &&
    url.searchParams.get("entity_value") === RESERVED_USER &&
    !url.searchParams.has("page") && url.searchParams.get("severity") === "high" &&
    url.searchParams.get("status") === "new" &&
    url.searchParams.getAll("keep").join(",") === "a,b" && url.hash === "#queue",
  );
  expect(requests.at(-1)?.get("entity_type")).toBe("user");
  expect(requests.at(-1)?.get("entity_value")).toBe(RESERVED_USER);
  expect(requests.at(-1)?.get("page")).toBe("1");
  expect(requests.at(-1)?.has("entityType")).toBe(false);
  expect(requests.at(-1)?.has("entityValue")).toBe(false);
  await expect(page.getByTestId("saved-view-chip-entity-conflicting-default")).toHaveAttribute("aria-pressed", "false");
  const afterPath = testInfo.outputPath("after-entity-filter-synthetic-data.png");
  await page.screenshot({ path: afterPath, fullPage: true });
  await testInfo.attach("after-entity-filter-synthetic-data", { path: afterPath, contentType: "image/png" });

  await page.reload();
  await expectRows(page, ["reserved user high"]);
  await expect(page.getByLabel("Entity type", { exact: true })).toHaveValue("user");
  await expect(page.getByLabel("Entity value", { exact: true })).toHaveValue(RESERVED_USER);
});

test("entity filtering spans pages and removal keeps the remaining queue filters", async ({ page }) => {
  const requests = await mockBackend(page);
  await page.goto("/alerts?view=alerts&severity=high&status=new");
  await page.getByLabel("Entity type", { exact: true }).selectOption("host");
  await page.getByLabel("Entity value", { exact: true }).fill(HOST);
  await page.getByLabel("Entity value", { exact: true }).press("Enter");
  await expectRows(page, Array.from({ length: 25 }, (_, index) => `host ${index + 1}`));
  await expect(page.getByText("Showing 25 of 30 alerts", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await expectRows(page, Array.from({ length: 5 }, (_, index) => `host ${index + 26}`));
  await expect(page.getByText("Showing 5 of 30 alerts", { exact: true })).toBeVisible();
  expect(requests.at(-1)?.get("entity_type")).toBe("host");
  expect(requests.at(-1)?.get("entity_value")).toBe(HOST);
  expect(requests.at(-1)?.get("page")).toBe("2");

  await page.getByRole("button", { name: "Remove entity filter", exact: true }).click();
  await expect(page.getByText("Page 1", { exact: true })).toBeVisible();
  await expect(page.getByText("Showing 25 of 34 alerts", { exact: true })).toBeVisible();
  await expect(page).toHaveURL((url) =>
    !url.searchParams.has("entity_type") && !url.searchParams.has("entity_value") &&
    !url.searchParams.has("page") && url.searchParams.get("severity") === "high" &&
    url.searchParams.get("status") === "new",
  );
  // Clearing can reuse the unfiltered SWR cache. Reload before checking a
  // fresh HTTP request, rather than requiring an unnecessary duplicate read.
  await page.reload();
  await expect(page.getByRole("button", { name: "Remove entity filter", exact: true })).toHaveCount(0);
  await expect(page.getByText("Showing 25 of 34 alerts", { exact: true })).toBeVisible();
  expect(requests.at(-1)?.has("entity_type")).toBe(false);
  expect(requests.at(-1)?.has("entity_value")).toBe(false);
});

test("an exact no-match is empty and clearing it survives a reload", async ({ page }) => {
  await mockBackend(page);
  const query = new URLSearchParams({ view: "alerts", entity_type: "host", entity_value: "SYNTHETIC-WIN", keep: "empty" });
  await page.goto(`/alerts?${query}#queue`);
  await expect(page.getByText("No alerts match these filters", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  await expect(page.getByText("Showing 25 of 35 alerts", { exact: true })).toBeVisible();
  await expect(page).toHaveURL((url) =>
    url.searchParams.get("view") === "alerts" && url.searchParams.get("keep") === "empty" &&
    !url.searchParams.has("entity_type") && !url.searchParams.has("entity_value") && url.hash === "#queue",
  );
  await page.reload();
  await expect(page.getByText("Showing 25 of 35 alerts", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Remove entity filter", exact: true })).toHaveCount(0);
});

test("changing and clearing the entity scope clears row and bulk selection", async ({ page }) => {
  await mockBackend(page);
  await page.goto("/alerts?view=alerts");
  await page.getByRole("checkbox", { name: "Select Synthetic entity fixture: host 1", exact: true }).check();
  await page.getByRole("link", { name: /Synthetic entity fixture: host 1\b/ }).click();
  await expect(page.getByRole("region", { name: "Bulk triage", exact: true })).toBeVisible();
  await expect(page.getByRole("complementary", { name: "Investigation rail", exact: true })
    .getByRole("heading", { name: "Synthetic entity fixture: host 1", exact: true })).toBeVisible();

  await page.getByLabel("Entity type", { exact: true }).selectOption("user");
  await page.getByLabel("Entity value", { exact: true }).fill(RESERVED_USER);
  await page.getByRole("button", { name: "Apply entity filter", exact: true }).click();
  await expectRows(page, ["reserved user high", "reserved user low"]);
  await expect(page.getByRole("region", { name: "Bulk triage", exact: true })).toHaveCount(0);
  await expect(page.getByRole("complementary", { name: "Investigation rail (no alert selected)", exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Remove entity filter", exact: true }).click();
  await expect(page.getByText("Showing 25 of 35 alerts", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Bulk triage", exact: true })).toHaveCount(0);
  await expect(page.getByRole("complementary", { name: "Investigation rail (no alert selected)", exact: true })).toBeVisible();
  await expect(page.getByRole("checkbox", { name: "Select Synthetic entity fixture: host 1", exact: true })).not.toBeChecked();
});

test("all-type deep links and saved entity presets restore through navigation history", async ({ page }) => {
  const requests = await mockBackend(page);
  await page.goto(`/alerts?${new URLSearchParams({ view: "alerts", entity_value: HOST, pageSize: "50" })}`);
  await expectRows(page, [...HOST_ALERTS.map((_, index) => `host ${index + 1}`), "user with the host's name"]);
  expect(requests.at(-1)?.has("entity_type")).toBe(false);
  await page.getByRole("button", { name: "Synthetic user preset", exact: true }).click();
  await expectRows(page, ["reserved user high"]);
  await expect(page.getByLabel("Entity type", { exact: true })).toHaveValue("user");
  await expect(page.getByLabel("Entity value", { exact: true })).toHaveValue(RESERVED_USER);
  await expect(page).toHaveURL((url) => url.searchParams.get("entity_value") === RESERVED_USER && url.searchParams.get("entity_type") === "user");

  await page.getByRole("link", { name: "SOC Operations", exact: true }).click();
  await expect(page.getByRole("main").getByRole("heading", { name: "SOC operations", exact: true })).toBeVisible();
  await page.goBack();
  await expectRows(page, ["reserved user high"]);
  await expect(page.getByLabel("Entity value", { exact: true })).toHaveValue(RESERVED_USER);
  await page.goForward();
  await expect(page.getByRole("main").getByRole("heading", { name: "SOC operations", exact: true })).toBeVisible();
  await page.goBack();
  await expectRows(page, ["reserved user high"]);
});

test("explicitly selecting a preset restores its committed entity even when the pair is unchanged", async ({ page }) => {
  await mockBackend(page);
  await page.goto(`/alerts?${new URLSearchParams({ view: "alerts", entity_type: "user", entity_value: RESERVED_USER })}`);
  await expectRows(page, ["reserved user high", "reserved user low"]);
  const entityType = page.getByLabel("Entity type", { exact: true });
  const entityValue = page.getByLabel("Entity value", { exact: true });
  await entityType.selectOption("host");
  await entityValue.fill(HOST);
  await expectRows(page, ["reserved user high", "reserved user low"]);

  await page.getByRole("button", { name: "Synthetic user preset", exact: true }).click();
  await expectRows(page, ["reserved user high"]);
  await expect(entityType).toHaveValue("user");
  await expect(entityValue).toHaveValue(RESERVED_USER);
  await expect(page).toHaveURL((url) =>
    url.searchParams.get("entity_type") === "user" && url.searchParams.get("entity_value") === RESERVED_USER &&
    url.searchParams.get("severity") === "high",
  );
});

test("a delayed saved default cannot replace an entity filter the analyst already applied", async ({ page }) => {
  let releaseDefault = () => {};
  const savedViewsGate = new Promise<void>((resolve) => { releaseDefault = resolve; });
  await mockBackend(page, { savedViewsGate });
  await page.goto("/alerts");
  await page.getByRole("tab", { name: "Alerts", exact: true }).click();
  await page.getByLabel("Entity type", { exact: true }).selectOption("host");
  await page.getByLabel("Entity value", { exact: true }).fill(HOST);
  await page.getByRole("button", { name: "Apply entity filter", exact: true }).click();
  await expect(page.getByText("Showing 25 of 30 alerts", { exact: true })).toBeVisible();

  releaseDefault();
  await expect(page.getByTestId("saved-view-chip-entity-conflicting-default")).toBeVisible();
  await expect(page.getByTestId("saved-view-chip-entity-conflicting-default")).toHaveAttribute("aria-pressed", "false");
  await expect(page.getByText("Showing 25 of 30 alerts", { exact: true })).toBeVisible();
  await expect(page).toHaveURL((url) =>
    url.searchParams.get("entity_type") === "host" && url.searchParams.get("entity_value") === HOST &&
    !url.searchParams.has("severity"),
  );
});

test("a delayed saved default cannot replace an entity draft before Apply", async ({ page }) => {
  let releaseDefault = () => {};
  const savedViewsGate = new Promise<void>((resolve) => { releaseDefault = resolve; });
  await mockBackend(page, { savedViewsGate });
  await page.goto("/alerts");
  await page.getByRole("tab", { name: "Alerts", exact: true }).click();
  const entityType = page.getByLabel("Entity type", { exact: true });
  const entityValue = page.getByLabel("Entity value", { exact: true });
  await entityType.selectOption("host");
  await entityValue.fill(HOST);

  releaseDefault();
  await expect(page.getByTestId("saved-view-chip-entity-conflicting-default")).toHaveAttribute("aria-pressed", "false");
  await expect(entityType).toHaveValue("host");
  await expect(entityValue).toHaveValue(HOST);
  await expect(page).toHaveURL((url) => !url.searchParams.has("entity_value") && !url.searchParams.has("severity"));

  await page.getByRole("button", { name: "Apply entity filter", exact: true }).click();
  await expect(page.getByText("Showing 25 of 30 alerts", { exact: true })).toBeVisible();
  await expect(page).toHaveURL((url) =>
    url.searchParams.get("entity_type") === "host" && url.searchParams.get("entity_value") === HOST &&
    !url.searchParams.has("severity"),
  );
});

test("the entity drawer opens its alert queue without applying a conflicting saved default", async ({ page }) => {
  const requests = await mockBackend(page);
  await page.goto("/alerts");
  await expect(page.getByRole("tab", { name: "Entities", exact: true })).toHaveAttribute("aria-selected", "true");
  await page.getByText(RESERVED_USER, { exact: true }).click();
  const pivot = page.getByRole("link", { name: "View all alerts for this entity", exact: true });
  const href = await pivot.getAttribute("href");
  expect(href).not.toBeNull();
  const target = new URL(href!, page.url());
  expect(target.searchParams.get("view")).toBe("alerts");
  expect(target.searchParams.get("entity_type")).toBe("user");
  expect(target.searchParams.get("entity_value")).toBe(RESERVED_USER);

  await pivot.click();
  await expectRows(page, ["reserved user high", "reserved user low"]);
  expect(requests.at(-1)?.get("entity_type")).toBe("user");
  expect(requests.at(-1)?.get("entity_value")).toBe(RESERVED_USER);
  expect(requests.at(-1)?.has("severity")).toBe(false);
  await expect(page.getByTestId("saved-view-chip-entity-conflicting-default")).toHaveAttribute("aria-pressed", "false");

  // Returning to Entities leaves the same URL in place. A second pivot to
  // that exact href must still switch the active tab back to Alerts.
  const entityUrl = page.url();
  await page.getByRole("tab", { name: "Entities", exact: true }).click();
  await page.getByText(RESERVED_USER, { exact: true }).click();
  await page.getByRole("link", { name: "View all alerts for this entity", exact: true }).click();
  await expectRows(page, ["reserved user high", "reserved user low"]);
  await expect(page).toHaveURL(entityUrl);
});
