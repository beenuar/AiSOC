'use client';

import { useEffect } from 'react';
import { usePathname } from 'next/navigation';

import { DEFAULT_BRANDING, useBranding } from '@/hooks/useBranding';

/**
 * Put the organisation's product name in the browser tab.
 *
 * Next resolves the `metadata` export at build time, in a process with no
 * request and therefore no tenant, so the tab title is a compiled literal and
 * the browser is the only place it can be corrected. Rewriting here rather
 * than replacing outright keeps whatever a route contributed — a page that
 * renders `Honeytokens | AiSOC` becomes `Honeytokens | Acme Shield` rather
 * than losing the section it names.
 *
 * Re-runs on navigation because Next sets the title again on each route, and
 * a rewrite that ran once would be undone by the next page the analyst opens.
 */
export function BrandedDocumentTitle() {
  const { branding } = useBranding();
  const pathname = usePathname();

  useEffect(() => {
    if (!branding.is_white_labelled) return;
    const platform = DEFAULT_BRANDING.product_name;
    if (!document.title.includes(platform)) return;
    document.title = document.title.split(platform).join(branding.product_name);
  }, [branding.is_white_labelled, branding.product_name, pathname]);

  return null;
}
