/**
 * Playwright against the demo stack — the thing a first-time reader meets.
 *
 * The existing specs cover the wrong two halves of this. `journeys/` is
 * hermetic and stubs every network call, so it proves the console renders
 * a payload and nothing about whether a real stack serves one.
 * `screenshots/` does run against a live stack, but its own header says the
 * tests are "recorders, not assertions" — a missing selector still produces
 * a PNG.
 *
 * So this asserts, and it asserts the things that were actually broken when
 * it was written rather than a checklist:
 *
 *  - the console is served at all, on the port the harness resolved (which
 *    is not always 3000: `aisoc-demo.ts` falls forward when a port is
 *    taken, and the existing screenshot path hardcodes 3000 and silently
 *    photographs the wrong thing);
 *  - the API is reachable from the browser's origin through the console's
 *    rewrites, at `/api/v1/...` — the harness itself was calling `/v1/...`
 *    and getting a 404 on every run;
 *  - the deployment says what it is via `/api/runtime-config`, which is the
 *    only honest way to read demo mode from outside (the banner copy is an
 *    inlined constant present in the HTML either way, so grepping for it is
 *    actively misleading);
 *  - and the case list renders *something definite* — rows, or a real empty
 *    state. Not a skeleton that never resolves, which is what a stack with
 *    an unreachable database looked like.
 *
 * The last one is deliberately not "there are N cases". Seeding is a
 * separate, currently-broken concern (see docs/perf/demo-timing.json), and
 * a test that demanded rows would be red for a reason this spec is not
 * about. What it refuses to accept is an indefinite loading state, because
 * that is indistinguishable from a broken backend and is exactly what the
 * unreachable-database failure produced.
 */

import { expect, test } from "@playwright/test";

const WEB = process.env.AISOC_DEMO_WEB_URL ?? "http://localhost:3000";
const API = process.env.AISOC_DEMO_API_URL ?? "http://localhost:8000";

test.describe.configure({ mode: "serial" });

test("the console is served", async ({ page }) => {
  const response = await page.goto(WEB, { waitUntil: "domcontentloaded" });

  expect(response?.status(), `${WEB} did not answer 200`).toBe(200);
});

test("the deployment can say what it is", async ({ request }) => {
  // Not a liveness check. `/api/runtime-config` is answered at request time,
  // so it is the one signal that survives Next inlining NEXT_PUBLIC_* at
  // build time — the reason a pulled image could not previously be asked
  // whether it considered itself a demo.
  const response = await request.get(`${WEB}/api/runtime-config`);

  expect(response.status()).toBe(200);
  const body = await response.json();
  expect(body).toHaveProperty("demoMode");
  expect(body).toHaveProperty("demoModeSource");
});

test("the API serves the case list under /api/v1, not /v1", async ({ request }) => {
  // The prefix this pins is not cosmetic. `scripts/aisoc-demo.ts` polled
  // `/v1/cases` for sixty seconds on every run and then reported the
  // showcase case missing, because the API mounts everything under `/api`.
  const wrong = await request.get(`${API}/v1/cases?page_size=1`);
  expect(wrong.status(), "/v1/cases answered; the prefix assumption changed").toBe(404);

  const right = await request.get(`${API}/api/v1/cases?page_size=1`);
  expect([200, 401, 403]).toContain(right.status());
});

test("the API is reachable from the console's own origin", async ({ request }) => {
  // Through the console's rewrites rather than directly, because that is the
  // path the browser takes and it is configured separately.
  const response = await request.get(`${WEB}/api/v1/cases?page_size=1`);

  expect([200, 401, 403]).toContain(response.status());
});

test("the case list resolves to rows or a real empty state, never an endless skeleton", async ({ page }) => {
  await page.goto(`${WEB}/cases`, { waitUntil: "domcontentloaded" });

  // Whichever of these appears first is a definite answer. The failure this
  // guards is the third outcome: neither, forever, which is what the console
  // rendered while its database was unreachable and every layer above
  // reported healthy.
  const settled = page
    .locator("table tbody tr")
    .first()
    .or(page.getByText(/no cases|nothing here|get started|no results/i).first());

  await expect(settled, "the cases view never resolved to rows or an empty state").toBeVisible({
    timeout: 30_000,
  });
});
