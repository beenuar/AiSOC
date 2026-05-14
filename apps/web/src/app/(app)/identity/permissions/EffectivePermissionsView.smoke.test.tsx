/**
 * Effective-permissions UI smoke test (T3.2).
 *
 * Two assertions, both intentionally hermetic:
 *
 * 1. The synchronous payload-to-Cytoscape-elements transform handles a
 *    1k-principal-tenant-shaped payload (1000 decisions, ~3000 actions,
 *    ~2000 chain steps) within a generous wall-clock budget. The
 *    Cytoscape DOM is capped at `MAX_RENDERED_DECISIONS` so the result is
 *    bounded regardless of input size.
 * 2. Switching the "show only changes since last week" filter is O(n)
 *    over the input — re-running the transform with the toggle on must
 *    complete in roughly the same budget.
 *
 * The smoke test uses a deterministic synthesised payload — no external
 * data, no real Cytoscape canvas — so it stays fast and CI-friendly.
 */

import { describe, expect, it } from 'vitest';

import {
  buildElements,
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
  it('builds elements for 1000 decisions in < 3s', () => {
    const payload = syntheticPayload(1000);
    const since = new Date('2026-05-06T12:00:00Z').toISOString();

    const start = performance.now();
    const elements = buildElements(payload, false, since);
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(3000);
    expect(elements.length).toBeGreaterThan(0);
  });

  it('applies the "changes since last week" filter without slowing down', () => {
    const payload = syntheticPayload(1000);
    const since = new Date('2026-05-06T12:00:00Z').toISOString();

    const start = performance.now();
    const elements = buildElements(payload, true, since);
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(3000);
    expect(elements.length).toBeGreaterThan(0);
  });
});
