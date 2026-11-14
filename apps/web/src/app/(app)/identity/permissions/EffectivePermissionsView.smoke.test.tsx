/**
 * Effective-permissions UI smoke + behaviour tests (T3.2).
 *
 * Two layers of assertion, both intentionally hermetic:
 *
 * 1. Performance smoke — the synchronous payload→Cytoscape-elements
 *    transform handles a 1k-decision payload within a generous wall-clock
 *    budget, with and without the "deny only" filter applied. The
 *    Cytoscape DOM is capped at `MAX_RENDERED_DECISIONS` so the result is
 *    bounded regardless of input size.
 * 2. Filter behaviour — `filterDenyPaths` actually filters by deny
 *    semantics rather than the old broken `last_resolved` clock check.
 *
 * The tests use a deterministic synthesised payload — no external data,
 * no real Cytoscape canvas — so they stay fast and CI-friendly.
 */

import { describe, expect, it } from 'vitest';

import {
  buildElements,
  filterDenyPaths,
  type ResolverResultPayload,
} from './EffectivePermissionsView';

function syntheticPayload(decisions: number): ResolverResultPayload {
  return {
    provider: 'aws',
    principal_id: 'arn:aws:iam::111122223333:user/perf-bot',
    coverage: 'full',
    resolver_version: 'v1.0',
    last_resolved: '2026-05-13T12:00:00Z',
    decisions: Array.from({ length: decisions }, (_, idx) => ({
      principal_id: 'u-perf',
      resource_id: `res-${idx}`,
      resource_kind: 's3:object',
      resource_arn: `arn:aws:s3:::perf-bucket-${idx}/key.csv`,
      actions: ['s3:GetObject', 's3:PutObject', 's3:ListBucket'],
      deny_actions: idx % 50 === 0 ? ['s3:DeleteObject'] : [],
      policy_chain: [
        {
          kind: 'policy',
          id: `policy-${idx % 17}`,
          name: `Policy ${idx % 17}`,
          effect: 'allow' as const,
          via: idx % 3 === 0 ? `g-${idx % 11}` : null,
        },
        {
          kind: 'scp',
          id: 'scp-baseline',
          name: 'SCPAllowBaseline',
          effect: 'allow' as const,
          via: null,
        },
      ],
    })),
    notes: [],
  };
}

describe('EffectivePermissionsView (smoke)', () => {
  // NOTE: the 3s budget below covers the synchronous payload→Cytoscape
  // element transform *only*. Real first-paint also pays for the
  // `fcose` layout that runs inside the component's `useEffect`, which
  // is dominated by graph topology and Cytoscape internals. If
  // analysts report slow first-paint on real tenants, profile the
  // layout phase in the browser; tightening this transform won't help.
  it('builds elements for 1000 decisions in < 3s', () => {
    const payload = syntheticPayload(1000);

    const start = performance.now();
    const elements = buildElements(payload, false);
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(3000);
    expect(elements.length).toBeGreaterThan(0);
  });

  it('applies the "deny only" filter without slowing down', () => {
    const payload = syntheticPayload(1000);

    const start = performance.now();
    const elements = buildElements(payload, true);
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(3000);
    expect(elements.length).toBeGreaterThan(0);
  });
});

describe('filterDenyPaths', () => {
  it('keeps only decisions with deny actions or deny chain steps', () => {
    const payload = syntheticPayload(1000);
    // synthetic payload puts deny_actions on every 50th decision → 20 of 1000.
    const denyOnly = filterDenyPaths(payload.decisions);
    expect(denyOnly.length).toBe(20);
    for (const decision of denyOnly) {
      const hasDenyAction = decision.deny_actions.length > 0;
      const hasDenyStep = decision.policy_chain.some((s) => s.effect === 'deny');
      expect(hasDenyAction || hasDenyStep).toBe(true);
    }
  });

  it('returns an empty list when no decisions deny anything', () => {
    const payload = syntheticPayload(10);
    // Strip the every-50th deny seed (10 < 50 so it's already empty, but be explicit).
    const cleaned = payload.decisions.map((d) => ({ ...d, deny_actions: [] }));
    expect(filterDenyPaths(cleaned)).toEqual([]);
  });

  it('keeps decisions whose policy chain carries a deny step', () => {
    const base = syntheticPayload(1).decisions[0];
    const denied = {
      ...base,
      deny_actions: [],
      policy_chain: [
        ...base.policy_chain,
        {
          kind: 'scp' as const,
          id: 'scp-deny',
          name: 'SCPDenyExfiltration',
          effect: 'deny' as const,
          via: null,
        },
      ],
    };
    expect(filterDenyPaths([denied])).toEqual([denied]);
  });
});
