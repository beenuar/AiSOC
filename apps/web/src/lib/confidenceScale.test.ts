/**
 * `Alert.confidenceScore` has to mean one thing.
 *
 * Confidence reaches the console on two keys at two different scales: the API
 * surfaces `confidence` as an integer 0-100, and fusion's `confidence_score`
 * is the raw [0.0, 1.0] float the band was derived from. `normalizeAlert`
 * accepted whichever appeared first and passed it through unchanged, so the
 * field's scale depended on the payload — and its consumers disagreed about
 * what they were reading. `AlertDetailView` multiplied by 100 and rendered a
 * real confidence of 21 as **2100%**; `AttackStory` divided and rendered the
 * same value as **21/100**. Each was correct for one payload shape, and each
 * had a passing test because its own mock used the scale it assumed.
 *
 * These assertions are on the boundary rather than on either view, because
 * that is the only place the ambiguity can be removed once.
 *
 * Against the pre-change tree, `normalises fusion's raw float` fails
 * (0.21 arrives as 0.21) and `prefers the canonical integer` fails
 * (`confidence_score` won).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { alertsApi } from '@/lib/api';

function respondWith(alert: Record<string, unknown>) {
  return vi.fn(async () =>
    new Response(JSON.stringify({ id: 'a1', title: 't', severity: 'medium', status: 'new', ...alert }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

beforeEach(() => {
  vi.stubGlobal('fetch', respondWith({}));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('confidence normalises to one scale at the API boundary', () => {
  it('passes the API\u2019s canonical 0-100 integer through unchanged', async () => {
    vi.stubGlobal('fetch', respondWith({ confidence: 21, confidence_label: 'low' }));

    const alert = await alertsApi.get('a1');

    expect(alert.confidenceScore).toBe(21);
  });

  it("normalises fusion's raw [0,1] float to the same 0-100 scale", async () => {
    vi.stubGlobal('fetch', respondWith({ confidence_score: 0.21 }));

    const alert = await alertsApi.get('a1');

    expect(alert.confidenceScore).toBe(21);
  });

  it('prefers the canonical integer when a payload carries both keys', async () => {
    // A fused alert read back through the API carries both. Taking
    // `confidence_score` first meant the row and the detail view could show
    // 0.21 and 21 for the same alert.
    vi.stubGlobal('fetch', respondWith({ confidence: 21, confidence_score: 0.21 }));

    const alert = await alertsApi.get('a1');

    expect(alert.confidenceScore).toBe(21);
  });

  it('decides the scale from the key, never from the magnitude', async () => {
    // The tempting shortcut is `v <= 1 ? v * 100 : v`. A genuine confidence
    // of 1/100 is then indistinguishable from a raw score of 1.0, and the
    // least-confident alert in the estate renders as the most confident.
    vi.stubGlobal('fetch', respondWith({ confidence: 1 }));
    expect((await alertsApi.get('a1')).confidenceScore).toBe(1);

    vi.stubGlobal('fetch', respondWith({ confidence_score: 1.0 }));
    expect((await alertsApi.get('a1')).confidenceScore).toBe(100);
  });

  it('leaves confidence absent when the payload carries neither key', async () => {
    // Legacy alerts predate the fusion confidence columns. Absent has to stay
    // absent so the views can omit the section rather than print a zero.
    vi.stubGlobal('fetch', respondWith({}));

    expect((await alertsApi.get('a1')).confidenceScore).toBeUndefined();
  });
});
