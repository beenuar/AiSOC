'use client';

import { useCallback } from 'react';
import { useSearchParams } from 'next/navigation';

/** Keep deep links, tab clicks and browser history on the same source of truth. */
export function useUrlTab<T extends string>(tabs: readonly T[], defaultTab: T) {
  const searchParams = useSearchParams();
  const tab = tabs.find((candidate) => candidate === searchParams?.get('tab')) ?? defaultTab;

  const setTab = useCallback((next: T) => {
    const url = new URL(window.location.href);
    const current = tabs.find((candidate) => candidate === url.searchParams.get('tab')) ?? defaultTab;
    if (next === current) return;

    url.searchParams.set('tab', next);
    // Next's App Router observes native History updates. Passing fresh state
    // lets it preserve its own routing metadata and notify useSearchParams.
    // This also retains other filters and the fragment without scrolling.
    window.history.pushState(null, '', `${url.pathname}${url.search}${url.hash}`);
  }, [tabs, defaultTab]);

  return [tab, setTab] as const;
}
