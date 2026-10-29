/**
 * What the root URL (`/`) of this deployment is for.
 *
 * A clean self-hosted install's root must land an operator on their console,
 * not on a marketing page. That is not hypothetical: discussion #1549 is an
 * operator who deployed on a clean server and found that "the default
 * homepage is not the dashboard or the login page". The marketing landing is
 * real content — but it is the *project site's* homepage, and a specific
 * deployment serving it at `/` is the same class of defect as one install's
 * branding showing up inside another's product.
 *
 * The default is therefore the console: `/` redirects to `/login`, which
 * already routes onward (first run → the onboarding wizard, an authenticated
 * session → `/dashboard`, a sanitized `?next=` when one was asked for). A
 * deployment that *is* the public project site opts back in by setting
 * `AISOC_MARKETING_HOME` in the running container.
 *
 * Runtime (`AISOC_MARKETING_HOME`) outranks build time
 * (`NEXT_PUBLIC_MARKETING_HOME`) for the same reason `AISOC_DEMO_MODE`
 * outranks its build-time twin in `demoMode.ts`: Next inlines `NEXT_PUBLIC_*`
 * values when the image is *built*, so on a pulled image the compiled answer
 * is frozen and the running container's environment is the only thing an
 * operator can actually steer. This module is read from a Server Component
 * on a `force-dynamic` route, so the runtime value is consulted on every
 * request rather than baked at build.
 */

const TRUTHY = new Set(['1', 'true', 'yes', 'on']);

let _override: boolean | null = null;

/** Where the answer came from, so an operator never has to infer it. */
export type HomeRouteSource =
  /** `AISOC_MARKETING_HOME` in the running container. Outranks the compiled value. */
  | 'runtime'
  /** `NEXT_PUBLIC_MARKETING_HOME`, fixed when the image was built. */
  | 'build'
  /** Neither was set. The root is the console. */
  | 'default'
  /** `__setMarketingHomeForTests` is in force. */
  | 'test-override';

export interface HomeRouteReport {
  /** True when `/` renders the marketing landing page. */
  marketing: boolean;
  source: HomeRouteSource;
}

function truthy(raw: string | undefined): boolean | null {
  const v = raw?.toLowerCase().trim() ?? '';
  if (v === '') return null;
  return TRUTHY.has(v);
}

/**
 * The single authoritative answer to "what does `/` serve here", and where
 * it came from. Reads the environment on every call — no module-level cache —
 * so the running container's value, not the first request's, is what wins.
 */
export function homeRouteReport(): HomeRouteReport {
  if (_override !== null) {
    return { marketing: _override, source: 'test-override' };
  }
  const runtime = truthy(process.env.AISOC_MARKETING_HOME);
  if (runtime !== null) {
    return { marketing: runtime, source: 'runtime' };
  }
  const build = truthy(process.env.NEXT_PUBLIC_MARKETING_HOME);
  if (build !== null) {
    return { marketing: build, source: 'build' };
  }
  return { marketing: false, source: 'default' };
}

/** Test seam, mirroring `__setDemoModeForTests`. Pass `null` to clear. */
export function __setMarketingHomeForTests(value: boolean | null): void {
  _override = value;
}
