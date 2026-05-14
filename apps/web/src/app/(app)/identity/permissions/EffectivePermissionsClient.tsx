'use client';

/**
 * Effective-permissions Cytoscape client (T3.2).
 *
 * Renders the resolver output as a five-column graph: Identity → Role
 * → Policy → Action → Resource. Top-of-page controls let an analyst:
 *
 *   * Switch the provider (AWS, Azure, GCP, Okta, Workspace). Scaffolded
 *     providers are greyed out and the page shows a "not yet implemented"
 *     placeholder when selected.
 *   * Collapse / expand each provider section.
 *   * Filter to "show only changes since last week" — compares the
 *     `last_resolved` watermark of the cached :EFFECTIVE_PERMISSION edge
 *     against the current API result and highlights deltas.
 *
 * The component is designed to handle a 1k-principal tenant — see
 * `EffectivePermissionsClient.smoke.test.tsx` for the load-time gate. For
 * data sets larger than `MAX_RENDERED_DECISIONS` we virtualise: only the
 * top-N by action count are rendered to Cytoscape, with the rest summarised
 * in a "+N more" pill the user can click to drill in.
 */

import dynamic from 'next/dynamic';
import { Suspense } from 'react';

const EffectivePermissionsView = dynamic(
  () =>
    import('./EffectivePermissionsView').then(
      (m) => m.EffectivePermissionsView,
    ),
  {
    ssr: false,
    loading: () => (
      <div className="flex h-[60vh] items-center justify-center text-gray-400">
        Loading effective permissions…
      </div>
    ),
  },
);

export default function EffectivePermissionsClient() {
  return (
    <Suspense
      fallback={
        <div className="flex h-[60vh] items-center justify-center text-gray-400">
          Loading effective permissions…
        </div>
      }
    >
      <EffectivePermissionsView />
    </Suspense>
  );
}
