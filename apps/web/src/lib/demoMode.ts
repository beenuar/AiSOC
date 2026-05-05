/**
 * Demo-mode helpers for the hosted demo at tryaisoc.com.
 *
 * Reads `NEXT_PUBLIC_DEMO_MODE` (set by `infra/fly/web/fly.toml`) to flag-gate
 * write actions in the UI:
 *
 *   - `isDemoMode()`            → true when the deployment is the hosted demo
 *   - `demoBannerMessage()`     → the banner copy to render at the top of every page
 *   - `demoDeeplink()`          → the `/cases/INC-001?tab=ledger` deeplink the
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

/** Returns `true` when the build is the hosted demo. */
export function isDemoMode(): boolean {
  if (_override !== null) return _override;
  const v = process.env.NEXT_PUBLIC_DEMO_MODE?.toLowerCase().trim() ?? '';
  return TRUTHY.has(v);
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
 * Default targets `/cases/INC-001?tab=ledger` because the seed kicks off
 * an investigation against `INC-001` and the ledger tab streams events.
 */
export function demoDeeplink(): string {
  return process.env.NEXT_PUBLIC_DEMO_DEEPLINK?.trim() || '/cases/INC-001?tab=ledger';
}

/**
 * Test-only escape hatch. **Do not call from product code.** Stories and unit
 * tests use this to render the banner without forking `process.env`.
 */
export function __setDemoModeForTests(value: boolean | null): void {
  _override = value;
}
