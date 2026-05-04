'use client';

/**
 * DemoBanner — top-of-page strip rendered on the hosted demo at demo.aisoc.dev.
 *
 * Sits inside `AppShell` above the TopBar so it covers every authenticated
 * page. Renders nothing when `NEXT_PUBLIC_DEMO_MODE !== 'true'`, so self-hosted
 * deployments never see it.
 *
 * Accessibility: announced via role="status" so screen readers pick up the
 * "writes are disabled" message at page load. Not dismissible — visitors have
 * to know writes will 403, otherwise they'll think the app is broken.
 */

import { isDemoMode, demoBannerMessage } from '@/lib/demoMode';

export function DemoBanner() {
  if (!isDemoMode()) return null;

  return (
    <div
      role="status"
      aria-live="polite"
      className="
        fixed top-0 left-60 right-0 z-50
        flex items-center justify-center gap-3
        h-9 px-4
        text-xs font-medium
        bg-gradient-to-r from-amber-500/15 via-amber-400/20 to-amber-500/15
        text-amber-200
        border-b border-amber-500/30
        backdrop-blur-sm
      "
    >
      <span aria-hidden="true" className="text-amber-300">
        ●
      </span>
      <span>{demoBannerMessage()}</span>
      <span aria-hidden="true" className="text-amber-500/60">
        |
      </span>
      <a
        href="https://github.com/beenuar/AiSOC#quickstart"
        target="_blank"
        rel="noopener noreferrer"
        className="underline underline-offset-2 hover:text-amber-100 transition-colors"
      >
        Self-host AiSOC →
      </a>
    </div>
  );
}
