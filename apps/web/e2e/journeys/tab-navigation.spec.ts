/**
 * URL-backed sections through the real Next router and browser history.
 * Only backend HTTP responses are intercepted; navigation, reloads, and
 * Back/Forward use the running application rather than a router substitute.
 */
import { createRequire } from "node:module";
import { expect, test, type Page } from "@playwright/test";

const { JSDOM } = createRequire(__filename)("jsdom") as {
  JSDOM: { fragment(html: string): DocumentFragment };
};

const CASE_ID = "CASE-TAB-001";
const CASE = {
  id: CASE_ID,
  title: "Tab navigation regression fixture",
  description: "A synthetic case used only by this browser test.",
  status: "investigating",
  severity: "medium",
  alert_ids: [],
  tags: { labels: [] },
  mitre_techniques: [],
  created_at: "2026-06-28T08:30:00Z",
  updated_at: "2026-06-28T08:30:00Z",
  tasks: [],
};

// Keep this list independent of the component's allowlist: a section removed
// from URL parsing must not also disappear from the regression expectations.
const SETTINGS_SECTIONS = [
  ["deployment", "Deployment & AI"],
  ["profile", "Profile"],
  ["workspace", "Workspace"],
  ["integrations", "Integrations"],
  ["autonomy", "Autonomy guardrails"],
  ["api-keys", "API keys"],
  ["scim", "SCIM provisioning"],
  ["branding", "Branding"],
  ["retention", "Retention"],
  ["rule-packs", "Rule packs"],
  ["delegations", "Delegations"],
  ["notifications", "Notifications"],
  ["appearance", "Appearance"],
  ["audit", "Audit log"],
  ["about", "About AiSOC"],
] as const;

async function mockBackend(page: Page) {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const fixtures: Record<string, unknown> = {
      "/api/v1/auth/me": {
        id: "tab-test-user",
        email: "analyst@example.com",
        role: "admin",
        tenant_id: "tab-test-tenant",
        preferences: {},
      },
      "/api/v1/connectors": [],
      "/api/v1/connectors/catalog": { connectors: [] },
      "/api/v1/api-keys": [],
      "/api/v1/scim-tokens": [],
      "/api/v1/llm/credentials": null,
      "/api/v1/onboarding/status": {
        first_run: true,
        steps: [
          {
            key: "model",
            label: "Choose where the AI runs",
            done: false,
            why: "Choose a provider for this test tenant.",
            href: null,
            detail: null,
          },
        ],
        connectors: 0,
        alerts: 0,
        sample_data_loaded: false,
      },
      "/api/v1/llm/runtime": {
        placement: "cpu",
        detail: "The local test model is running on the CPU.",
        options: [],
      },
      [`/api/v1/cases/${CASE_ID}`]: CASE,
      [`/api/v1/cases/${CASE_ID}/timeline`]: { events: [] },
      [`/api/v1/cases/${CASE_ID}/investigations`]: { runs: [] },
      [`/api/v1/war-rooms/cases/${CASE_ID}`]: [],
      "/api/v1/investigations": [],
      "/api/v1/contextual/actions": { actions: [] },
    };

    if (Object.hasOwn(fixtures, path)) {
      await route.fulfill({ json: fixtures[path] });
      return;
    }

    // An unavailable auxiliary service must not stop section navigation.
    // Do not invent successful envelopes for APIs irrelevant to this test.
    await route.fulfill({
      status: 503,
      json: { detail: "Auxiliary service unavailable in tab navigation fixture" },
    });
  });
}

function settingsButton(page: Page, label: string) {
  return page
    .getByRole("navigation", { name: "Settings sections" })
    .getByRole("button", { name: new RegExp(`^${label}`) });
}

async function expectSettingsSection(page: Page, heading: string) {
  await expect(
    page.getByRole("heading", { name: heading, exact: true }),
  ).toBeVisible();
  const label = heading === "About AiSOC" ? "About" : heading;
  await expect(settingsButton(page, label)).toHaveAttribute("aria-current", "page");
}

async function expectTabUrl(page: Page, tab: string, queryKey: string, hash: string) {
  await expect(page).toHaveURL((url) =>
    url.searchParams.get("tab") === tab &&
    url.searchParams.get(queryKey) === "kept" &&
    url.hash === hash,
  );
}

test("Settings server HTML renders every requested section before hydration", async ({ request }) => {
  for (const [id, heading] of [
    ...SETTINGS_SECTIONS,
    ["unknown", "Profile"],
    ["", "Profile"],
  ]) {
    const response = await request.get(`/settings?tab=${id}`);
    expect(response.status()).toBe(200);
    // Parse actual heading elements; serialized instructions inside scripts
    // remain text, and the inert fragment does not execute or load resources.
    const document = JSDOM.fragment(await response.text());
    const headings = Array.from(document.querySelectorAll("h2"),
      (heading) => heading.textContent);
    expect(headings, `server-rendered section for ?tab=${id}`).toContain(heading);
  }
});

test("every Settings section can be opened directly by URL", async ({ page }) => {
  await mockBackend(page);
  for (const [id, heading] of SETTINGS_SECTIONS) {
    await test.step(id, async () => {
      await page.goto(`/settings?tab=${id}`);
      await expectSettingsSection(page, heading);
    });
  }
});

test("missing, empty, and unknown Settings tabs show Profile", async ({ page }) => {
  await mockBackend(page);
  for (const href of ["/settings", "/settings?tab=", "/settings?tab=unknown"]) {
    await page.goto(href);
    await expectSettingsSection(page, "Profile");
  }
});

test("Settings clicks, reload, and Back/Forward keep URL and section aligned", async ({ page }) => {
  await mockBackend(page);
  await page.goto("/settings?tab=profile&source=kept#preferences");
  await expect(page.getByRole("heading", { name: "Profile", exact: true })).toBeVisible();

  await settingsButton(page, "Deployment & AI").click();
  await expectTabUrl(page, "deployment", "source", "#preferences");
  await expectSettingsSection(page, "Deployment & AI");

  await settingsButton(page, "Appearance").click();
  await expectTabUrl(page, "appearance", "source", "#preferences");
  await expectSettingsSection(page, "Appearance");

  await page.goBack();
  await expectTabUrl(page, "deployment", "source", "#preferences");
  await expectSettingsSection(page, "Deployment & AI");

  await page.goBack();
  await expectSettingsSection(page, "Profile");
  await page.goForward();
  await expectSettingsSection(page, "Deployment & AI");
  await page.reload();
  await expectTabUrl(page, "deployment", "source", "#preferences");
  await expectSettingsSection(page, "Deployment & AI");
});

test("the onboarding provider link opens Deployment & AI", async ({ page }) => {
  await mockBackend(page);
  await page.goto("/onboarding");
  await page.getByRole("link", { name: "Use my own provider", exact: true }).click();
  await expect(page).toHaveURL(/\/settings\?tab=deployment$/);
  await expectSettingsSection(page, "Deployment & AI");
});

test("case sections survive reload and browser history without losing other URL state", async ({ page }) => {
  await mockBackend(page);
  await page.goto(`/cases/${CASE_ID}?tab=overview&window=kept#evidence`);
  await expect(page.getByRole("heading", { name: CASE.title, exact: true })).toBeVisible();
  await expect(page.getByText("No alerts linked", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: /^Ledger/ }).click();
  await expectTabUrl(page, "ledger", "window", "#evidence");
  await expect(page.getByText("No investigations recorded yet", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: /^report$/i }).click();
  await expectTabUrl(page, "report", "window", "#evidence");
  await expect(page.getByText("No report yet", { exact: true })).toBeVisible();

  await page.goBack();
  await expectTabUrl(page, "ledger", "window", "#evidence");
  await expect(page.getByText("No investigations recorded yet", { exact: true })).toBeVisible();
  await page.goBack();
  await expect(page.getByText("No alerts linked", { exact: true })).toBeVisible();
  await page.goForward();
  await expect(page.getByText("No investigations recorded yet", { exact: true })).toBeVisible();
  await page.reload();
  await expectTabUrl(page, "ledger", "window", "#evidence");
  await expect(page.getByText("No investigations recorded yet", { exact: true })).toBeVisible();
});

test("case links select the requested section and unknown tabs fall back to Overview", async ({ page }) => {
  await mockBackend(page);
  await page.goto(`/cases/${CASE_ID}?tab=report`);
  await expect(page.getByText("No report yet", { exact: true })).toBeVisible();
  await page.goto(`/cases/${CASE_ID}?tab=ledger`);
  await expect(page.getByText("No investigations recorded yet", { exact: true })).toBeVisible();
  await page.goto(`/cases/${CASE_ID}?tab=unknown`);
  await expect(page.getByText("No alerts linked", { exact: true })).toBeVisible();
});

for (const [query, destination] of [
  ["tab=cases", "/responder/case"],
  ["tab=oncall", "/responder/oncall"],
  ["tab=unknown", "/responder/triage"],
  ["tab=cases&tab=oncall", "/responder/triage"],
] as const) {
  test(`installed responder shortcut ?${query} redirects to ${destination}`, async ({ request }) => {
    const response = await request.get(`/responder?${query}`, { maxRedirects: 0 });
    if (response.status() === 307) {
      expect(new URL(response.headers().location, response.url()).pathname).toBe(destination);
    } else {
      // Awaiting searchParams may suspend after headers were streamed. Next
      // then sends its redirect instruction in the response body instead.
      expect(response.status()).toBe(200);
      expect(await response.text()).toContain(`NEXT_REDIRECT;replace;${destination};307;`);
    }
  });
}
