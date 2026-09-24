'use client';

/**
 * DemoAutoLogin — silent auto-login for a public demo deployment.
 *
 * On a public demo we never want a visitor to land on `/cases` and see mock
 * rows because no JWT is in `localStorage`. This component runs once on mount
 * inside `AppShell`, and when:
 *
 *   1. `isDemoMode()` is true (NEXT_PUBLIC_DEMO_MODE=true), AND
 *   2. the build supplied demo credentials, AND
 *   3. there's no existing access token,
 *
 * it logs in as the demo user the deployment seeded and then triggers a global
 * SWR revalidation so every `useSWR` hook on the page swaps its `fallbackData`
 * mocks for the freshly-fetched live data.
 *
 * The credentials come only from the build environment, never from a literal
 * in this file — see the constants below.
 *
 * Renders nothing. Failures are swallowed silently — most demo endpoints
 * (cases list, alerts list, dashboard widgets) work without a JWT thanks to
 * the demo tenant default, so a failed auto-login still leaves the page
 * readable.
 *
 * Self-hosted builds skip this entirely because `isDemoMode()` returns false.
 */

import { useEffect } from 'react';
import { useSWRConfig } from 'swr';
import { authApi } from '@/lib/api';
import { isDemoMode } from '@/lib/demoMode';

// No fallback literals. These are inlined by Next at build time wherever they
// are referenced, so a hardcoded default here would put a working login pair
// into the bundle of every build — including one made with demo mode off and
// shipped to somebody's own deployment. A demo build passes them explicitly;
// anything else gets empty strings and the effect below does nothing.
const DEMO_EMAIL = process.env.NEXT_PUBLIC_DEMO_AUTOLOGIN_EMAIL?.trim() ?? '';
const DEMO_PASSWORD = process.env.NEXT_PUBLIC_DEMO_AUTOLOGIN_PASSWORD?.trim() ?? '';

export function DemoAutoLogin() {
  const { mutate } = useSWRConfig();

  useEffect(() => {
    // Only run client-side. Demo flag is build-time inlined, but we double
    // check at runtime so a test override via `__setDemoModeForTests` works.
    if (!isDemoMode()) return;
    if (!DEMO_EMAIL || !DEMO_PASSWORD) return;
    if (typeof window === 'undefined') return;

    // Already authenticated? Nothing to do — let the existing session ride.
    if (authApi.isAuthenticated()) return;

    let cancelled = false;
    (async () => {
      try {
        await authApi.login(DEMO_EMAIL, DEMO_PASSWORD);
        if (cancelled) return;
        // Force every SWR key on the page to refetch with the new bearer
        // token. Passing `() => true` matches all keys; `undefined` data
        // tells SWR to drop its cache entry and rerun the fetcher.
        await mutate(() => true, undefined, { revalidate: true });
      } catch {
        // Swallow — most read endpoints still work without auth on the
        // demo tenant, so a failed auto-login degrades gracefully.
      }
    })();

    return () => {
      cancelled = true;
    };
    // mutate is stable across renders per SWR docs; keep deps minimal so the
    // effect runs exactly once per mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return null;
}
