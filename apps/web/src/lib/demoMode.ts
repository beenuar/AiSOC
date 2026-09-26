/**
 * Demo-mode helpers for a hosted demo deployment.
 *
 * Deliberately not naming a hostname: this module ships to every
 * self-hoster, and a specific deployment's domain in a shared component is
 * how one install's branding ends up inside another's product.
 *
 * Reads `NEXT_PUBLIC_DEMO_MODE` (set by `infra/fly/web/fly.toml`) to flag-gate
 * write actions in the UI:
 *
 *   - `isDemoMode()`            → true when the deployment is the hosted demo
 *   - `demoBannerMessage()`     → the banner copy to render at the top of every page
 *   - `demoDeeplink()`          → the `/cases/INC-RT-001?tab=ledger` deeplink the
 *                                 README "Live Demo" button targets, so we land
 *                                 visitors on a hot, mid-investigation view
 *
 * The component side of this lives at `components/demo/DemoBanner.tsx`.
 *
 * Why a module instead of inlining `process.env`? Three reasons:
 *
 *   1. Tree-shake-friendly: pages that never call these helpers don't bundle
 *      the banner copy.
 *   2. Single source of truth: server actions, client components, and tests
 *      all read demo state through one shim.
 *   3. Test seam: stories/tests can monkey-patch `__setDemoModeForTests` to
 *      render the banner regardless of build env.
 *
 * NEXT_PUBLIC_* vars are inlined at build time by Next, so this module can
 * safely run in both Server and Client components.
 */

const TRUTHY = new Set(['1', 'true', 'yes', 'on']);

let _override: boolean | null = null;

/** Where the answer came from, so an operator never has to infer it. */
export type DemoModeSource =
  /** `AISOC_DEMO_MODE` in the running container. Outranks the compiled value. */
  | 'runtime'
  /** `NEXT_PUBLIC_DEMO_MODE`, fixed when the image was built. */
  | 'build'
  /** Neither was set. Not a demo. */
  | 'default'
  /** `__setDemoModeForTests` is in force. */
  | 'test-override';

function truthy(raw: string | undefined): boolean | null {
  const v = raw?.toLowerCase().trim() ?? '';
  if (v === '') return null;
  return TRUTHY.has(v);
}

/**
 * The single authoritative answer to "is this deployment a demo", and where it
 * came from.
 *
 * Two flags used to decide this and neither could be reconciled from outside
 * the container. `AISOC_DEMO_MODE` gates the API service's seed at run time,
 * while the console read `NEXT_PUBLIC_DEMO_MODE`, which Next inlines when the
 * image is *built* — so on a pulled image the console's answer was fixed at
 * build time and could disagree with the API's, with nothing to consult but
 * the rendered page. `AISOC_DEMO_MODE` now answers here too and outranks the
 * compiled value; `GET /api/runtime-config` reports the result.
 *
 * Runtime environment is only readable server-side, so in the browser this
 * returns the compiled answer. That is the first-paint value — `DemoBanner`
 * reconciles it against the endpoint, which cannot be stale.
 */
export function demoModeReport(): { enabled: boolean; source: DemoModeSource } {
  if (_override !== null) return { enabled: _override, source: 'test-override' };

  // `typeof window` is the client/server test Next itself compiles against;
  // AISOC_DEMO_MODE carries no NEXT_PUBLIC_ prefix, so it is never inlined
  // into the browser bundle and reading it there yields undefined.
  if (typeof window === 'undefined') {
    const runtime = truthy(process.env.AISOC_DEMO_MODE);
    if (runtime !== null) return { enabled: runtime, source: 'runtime' };
  }

  const build = truthy(process.env.NEXT_PUBLIC_DEMO_MODE);
  if (build !== null) return { enabled: build, source: 'build' };

  return { enabled: false, source: 'default' };
}

/** Returns `true` when this deployment is a demo. */
export function isDemoMode(): boolean {
  return demoModeReport().enabled;
}

/** Banner copy shown at the top of every page in demo mode. */
export function demoBannerMessage(): string {
  return (
    process.env.NEXT_PUBLIC_DEMO_BANNER?.trim() ||
    'Demo data resets daily at 00:00 UTC. All write actions are disabled.'
  );
}

/**
 * Deeplink to land visitors directly on a live, mid-investigation view.
 *
 * Default targets `/cases/INC-RT-001?tab=ledger` — the in-flight LockBit 3.0
 * ransomware investigation seeded by `services/api/app/scripts/seed_demo.py`.
 * `INC-RT-001` is the showcase scenario: detector fired moments ago, encryption
 * is in progress, and the ledger streams the agent's live decisions. Operators
 * can override with `NEXT_PUBLIC_DEMO_DEEPLINK` to feature a different incident.
 */
export function demoDeeplink(): string {
  return process.env.NEXT_PUBLIC_DEMO_DEEPLINK?.trim() || '/cases/INC-RT-001?tab=ledger';
}

/**
 * Test-only escape hatch. **Do not call from product code.** Stories and unit
 * tests use this to render the banner without forking `process.env`.
 */
export function __setDemoModeForTests(value: boolean | null): void {
  _override = value;
}
