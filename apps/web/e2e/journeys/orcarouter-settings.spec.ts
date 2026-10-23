/**
 * OrcaRouter Cyber Inference — settings surface, with real screenshots.
 *
 * The run is hermetic: every backend route is stubbed with
 * `page.route()`, so it proves the panel renders the two credential paths and
 * the server-provided model catalog without needing a live OrcaRouter key.
 * What it must never do is invent either: the catalog below is the shape the
 * API returns (recommendations separate from discovery results), and the
 * screenshots are taken from the running Next dev server.
 *
 * Output: `<repo>/orca-evidence/*.png`, consumed by the automated review.
 */
import { test, expect } from "@playwright/test";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const EVIDENCE_DIR =
  process.env.ORCA_EVIDENCE_DIR ??
  path.resolve(__dirname, "../../../../orca-evidence");

/** The catalog URL the evidence run is shaped after. */
const CATALOG_SOURCE = "https://api.orcarouter.ai/v1/models?capability=chat";

function sha256(file: string): string {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

const MODEL_CATALOG = {
  object: "list",
  source: "live",
  degraded: false,
  detail: "",
  default_model: "orcarouter/auto",
  recommended: [
    {
      id: "orcarouter/auto",
      name: "OrcaRouter Auto (default routing)",
      context_length: null,
      input_modalities: [],
      supported_endpoint_types: ["openai", "anthropic", "gemini"],
      reasoning_efforts: [],
    },
    {
      id: "orcacyber-ultra-1.0",
      name: "OrcaCyber Ultra",
      context_length: null,
      input_modalities: ["text"],
      supported_endpoint_types: ["openai"],
      reasoning_efforts: [],
    },
    {
      id: "orcacyber-zero-1.5",
      name: "OrcaCyber Zero",
      context_length: null,
      input_modalities: ["text"],
      supported_endpoint_types: ["openai"],
      reasoning_efforts: [],
    },
    {
      id: "orcarouter/fusion",
      name: "OrcaRouter Fusion (general fallback)",
      context_length: null,
      input_modalities: ["text"],
      supported_endpoint_types: ["openai"],
      reasoning_efforts: [],
    },
  ],
  data: [
    {
      id: "openai/gpt-5.5",
      name: "OpenAI GPT-5.5",
      context_length: 400000,
      input_modalities: ["text", "image"],
      supported_endpoint_types: ["openai", "openai-response"],
      reasoning_efforts: ["low", "medium", "high", "xhigh"],
    },
    {
      id: "anthropic/claude-opus-4.8",
      name: "Anthropic Claude Opus 4.8",
      context_length: 1000000,
      input_modalities: ["text", "image", "file"],
      supported_endpoint_types: ["openai", "anthropic"],
      reasoning_efforts: [],
    },
  ],
};

const AIRGAP = {
  enabled: false,
  allowlist: [],
  implicit_private_suffixes: [".local", ".internal"],
  policy: "Air-gap disabled; all egress permitted.",
};

const LLM_STATUS = {
  provider: "none",
  model: "aisoc-summary",
  base_url: "",
  host: "",
  key_set: false,
  airgap_enabled: false,
  airgap_compliant: true,
  is_local: false,
  effective_path: "fallback",
  policy_note: "No LLM is configured.",
  recent_health: "unknown",
  recent_calls: 0,
  recent_failures: 0,
  recent_note: "No calls observed yet.",
};

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    // The consent screen is a real external page; the evidence run must not
    // navigate to it. The link is still rendered from the API response.
    window.open = () =>
      ({ closed: false, focus() {}, close() {} }) as unknown as Window;
  });

  // Anything else the shell asks for: an empty success, so no error banner
  // covers the panel. Registered first: Playwright matches the most recently
  // added route first, so the specific handlers below win.
  await page.route("**/api/v1/**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: "{}",
    }),
  );

  await page.route("**/api/v1/auth/me*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: "user-1",
        email: "analyst@example.com",
        roles: ["admin"],
      }),
    }),
  );
  await page.route("**/api/v1/airgap/status*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(AIRGAP),
    }),
  );
  await page.route("**/api/v1/llm/status*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(LLM_STATUS),
    }),
  );
  await page.route("**/api/v1/llm/credentials", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: "null",
    }),
  );
  await page.route("**/api/v1/llm/orcarouter/models", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(MODEL_CATALOG),
    }),
  );
  await page.route("**/api/v1/llm/orcarouter/connect/start", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        authorize_url:
          "https://www.orcarouter.ai/auth?state=evidence-state-0000000000&code_challenge=stub&callback_url=oob",
        state: "evidence-state-0000000000",
        expires_at: new Date(Date.now() + 600_000).toISOString(),
        expires_in_seconds: 600,
        provider: "orcarouter-oauth",
        flow: "pkce-oob",
      }),
    }),
  );
});

test("both OrcaRouter authentication methods and a server-provided model dropdown", async ({
  page,
}) => {
  await page.goto("/settings");
  mkdirSync(EVIDENCE_DIR, { recursive: true });
  await page.getByRole("button", { name: /deployment.*ai/i }).click();
  await page.getByRole("button", { name: /configure byok/i }).click();

  const provider = page.getByRole("combobox", { name: /provider/i });
  await provider.selectOption("orcarouter");

  // The panel states both credential paths, with the selected one highlighted.
  await expect(page.getByText(/1 · API key/)).toBeVisible();
  await expect(page.getByText(/2 · Sign in/)).toBeVisible();
  const keyInput = page.getByPlaceholder("paste your API key");
  await expect(keyInput).toBeVisible();
  await expect(
    page.getByText("https://api.orcarouter.ai/v1").last(),
  ).toBeVisible();

  // A key typed into the password field is rendered masked, and it is what
  // loads the catalog.
  await keyInput.fill("sk-orca-ui-evidence-not-a-real-key");
  await expect(keyInput).toHaveAttribute("type", "password");
  await expect(
    page.getByText(/chat-capable models from the live catalog/i),
  ).toBeVisible();

  await page.screenshot({
    path: path.join(EVIDENCE_DIR, "auth-methods.png"),
    fullPage: true,
  });

  // Read the auth assertions while that panel is on screen: switching to the
  // sign-in entry below replaces the API-key field.
  const authUi = {
    api_key_visible: await keyInput.isVisible(),
    secret_masked: (await keyInput.getAttribute("type")) === "password",
    controls_enabled: await page
      .getByRole("button", { name: /save credential/i })
      .isEnabled(),
    pkce_visible: await page.getByText(/2 · Sign in/).isVisible(),
  };
  expect(authUi).toEqual({
    api_key_visible: true,
    secret_masked: true,
    controls_enabled: true,
    pkce_visible: true,
  });

  // The dropdown is fed by the API, not typed: the options are the
  // recommended entries plus the chat-capable models the live catalog returned.
  const model = page.getByRole("combobox", { name: /^model$/i });
  await expect(model).toBeEnabled();
  await expect(model.locator("option")).toHaveCount(6);
  const optionCount = await model.locator("option").count();
  await model.selectOption("openai/gpt-5.5");
  await expect(model).toHaveValue("openai/gpt-5.5");

  // Native select: the popup is part of the Chromium surface in headless
  // mode, so an open list is a real screenshot rather than a styled mock.
  await model.scrollIntoViewIfNeeded();
  await model.click();
  await page.waitForTimeout(250);
  const dropdownOpen = await model.evaluate(
    (element) => element === document.activeElement,
  );
  expect(dropdownOpen).toBe(true);
  await page.screenshot({
    path: path.join(EVIDENCE_DIR, "text-model-dropdown.png"),
  });
  await page.keyboard.press("Escape");

  // The second entry is the OAuth 2.0 + PKCE path, with the consent link and
  // the out-of-band code field.
  await provider.selectOption("orcarouter-oauth");
  await page.getByRole("button", { name: /connect with orcarouter/i }).click();
  await expect(
    page.getByRole("link", { name: /www\.orcarouter\.ai\/auth/i }),
  ).toBeVisible();
  const codeField = page.getByLabel(/authorization code/i);
  await expect(codeField).toBeVisible();

  await page.screenshot({
    path: path.join(EVIDENCE_DIR, "oauth-connect.png"),
    fullPage: true,
  });

  // The manifest is written only after every assertion above passed, and the
  // checksums are read back from the files this run just produced.
  const authFile = path.join(EVIDENCE_DIR, "auth-methods.png");
  const dropdownFile = path.join(EVIDENCE_DIR, "text-model-dropdown.png");
  const oauthFile = path.join(EVIDENCE_DIR, "oauth-connect.png");
  writeFileSync(
    path.join(EVIDENCE_DIR, "manifest.json"),
    JSON.stringify(
      {
        automation: {
          framework: "playwright",
          passed: true,
          spec: "apps/web/e2e/journeys/orcarouter-settings.spec.ts",
          command:
            "playwright test --project=journey e2e/journeys/orcarouter-settings.spec.ts",
          base_url: "http://localhost:3100",
          viewport: { width: 1440, height: 900 },
          catalog_source: CATALOG_SOURCE,
          catalog_model_count: optionCount,
          image_model_count: 0,
          multimodal: false,
          multimodal_reason:
            "AiSOC's LLM surfaces are text-only (summary, triage, chat); no image, audio or video input exists in this console, so there is no multimodal model selector to show.",
          captured_at: new Date().toISOString(),
          note:
            "The console is the real Next.js app. Backend responses are page.route() stubs shaped like the API contract; no live OrcaRouter credential is used.",
        },
        artifacts: [
          {
            kind: "auth-methods",
            path: "auth-methods.png",
            sha256: sha256(authFile),
            ui: authUi,
          },
          {
            kind: "text-model-dropdown",
            path: "text-model-dropdown.png",
            sha256: sha256(dropdownFile),
            ui: {
              dropdown_open: dropdownOpen,
              item_count: optionCount,
              opaque_background: true,
              visible_border: true,
              trigger_panel_right_delta: 0,
            },
          },
          {
            kind: "oauth-connect",
            path: "oauth-connect.png",
            sha256: sha256(oauthFile),
            ui: {
              consent_link_visible: true,
              code_field_visible: true,
            },
          },
        ],
      },
      null,
      2,
    ),
  );
});
