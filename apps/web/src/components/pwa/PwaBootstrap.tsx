'use client';

/**
 * Mounts once at the app root to wire up the service worker, listen for
 * SW lifecycle events, and surface install/update prompts. Renders nothing.
 *
 * Phase 4B - Mobile responder PWA.
 */

import { useEffect } from 'react';

import { registerServiceWorker } from '@/lib/pwa';

export function PwaBootstrap(): null {
  useEffect(() => {
    // Skip in dev unless explicitly enabled — the SW caches aggressively
    // and breaks HMR. Production builds always register.
    const enabledInDev =
      process.env.NEXT_PUBLIC_ENABLE_SW_IN_DEV === 'true';
    if (process.env.NODE_ENV !== 'production' && !enabledInDev) {
      return;
    }

    let cancelled = false;

    void registerServiceWorker('/sw.js', '/').then((reg) => {
      if (cancelled || !reg) return;

      // Surface "new version available" so the user can refresh into it.
      reg.addEventListener('updatefound', () => {
        const installing = reg.installing;
        if (!installing) return;
        installing.addEventListener('statechange', () => {
          if (
            installing.state === 'installed' &&
            navigator.serviceWorker.controller
          ) {
            // A new SW is waiting. Fire a custom event so any UI surface
            // (e.g. a toast in AppShell) can prompt for reload.
            window.dispatchEvent(
              new CustomEvent('aisoc:sw:update-available', {
                detail: { registration: reg },
              }),
            );
          }
        });
      });
    });

    // When the controller changes (because the user accepted an update),
    // reload once so the page is served by the new SW.
    let refreshed = false;
    const onControllerChange = () => {
      if (refreshed) return;
      refreshed = true;
      window.location.reload();
    };
    navigator.serviceWorker?.addEventListener(
      'controllerchange',
      onControllerChange,
    );

    return () => {
      cancelled = true;
      navigator.serviceWorker?.removeEventListener(
        'controllerchange',
        onControllerChange,
      );
    };
  }, []);

  return null;
}

export default PwaBootstrap;
