'use client';

/**
 * Effective-permissions Cytoscape client (T3.2).
 *
 * Renders the resolver output as a five-column graph: Identity → Role
 * → Policy → Action → Resource. Top-of-page controls let an analyst:
 *
 *   * Switch the provider (AWS, Azure, GCP, Okta, Workspace). Scaffolded
 *     providers render a "not yet implemented" placeholder with a pointer
 *     to the Identity Graph fallback instead of erroring with HTTP 501.
 *   * Enter a principal ID (defaults to a demo principal) and load.
 *   * Filter to "Show only deny paths" — keeps decisions whose
 *     `deny_actions` is non-empty *or* whose `policy_chain` contains a
 *     `deny` step (SCP, ABAC condition, explicit policy deny, etc.).
 *
 * The provider, principal, and deny-only state are mirrored to the URL as
 * `?provider=aws&principal_id=…&deny_only=1` so analysts can deep-link the
 * exact view they're staring at into a case or a Slack thread.
 *
 * The component is designed to handle a 1k-principal tenant — see
 * `EffectivePermissionsView.smoke.test.tsx` for the load-time gate. For
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
