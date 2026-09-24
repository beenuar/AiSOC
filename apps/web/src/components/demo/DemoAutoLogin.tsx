'use client';

/**
 * DemoAutoLogin — silent auto-login for a public demo deployment.
 *
 * On the public demo we never want a visitor to land on `/cases` and see mock
 * rows because no JWT is in `localStorage`. This component runs once on mount
 * inside `AppShell`, and when:
 *
 *   1. `isDemoMode()` is true (NEXT_PUBLIC_DEMO_MODE=true), AND
 *   2. there's no existing access token,
 *
 * it logs in as the well-known demo user (`demo@example.com` / `aisoc-demo` —
 * the same credentials displayed on `/login`) and then triggers a global SWR
 * revalidation so every `useSWR` hook on the page swaps its `fallbackData`
 * mocks for the freshly-fetched live data.
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

const DEMO_EMAIL =
  process.env.NEXT_PUBLIC_DEMO_AUTOLOGIN_EMAIL?.trim() || 'demo@example.com';
const DEMO_PASSWORD =
  process.env.NEXT_PUBLIC_DEMO_AUTOLOGIN_PASSWORD?.trim() || 'aisoc-demo';

export function DemoAutoLogin() {
  const { mutate } = useSWRConfig();

  useEffect(() => {
    // Only run client-side. Demo flag is build-time inlined, but we double
    // check at runtime so a test override via `__setDemoModeForTests` works.
    if (!isDemoMode()) return;
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
