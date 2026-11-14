/**
 * `Alert.riskScore` has to mean one thing — the sibling of `confidenceScale`.
 *
 * `normalizeAlert` resolved it as `risk_score ?? ai_score ?? confidence ?? 0`
 * across three keys carrying two different scales:
 *
 *   `risk_score`  fusion's vendor-supplied risk, a [0,1] float
 *                 (`services/fusion/app/services/confidence.py` documents it
 *                 as "0-1, vendor-provided")
 *   `ai_score`    the model's score, a [0,1] float — `metrics.py` buckets it
 *                 "across [0, 1]", and `seed_demo.py` writes 0.74-0.97
 *   `confidence`  the API's canonical 0-100 integer
 *
 * The `alerts` table has no `risk_score` column and `AlertResponse` does not
 * emit one, so the live path is `ai_score`: a real alert scoring 0.85 reached
 * the console as `riskScore = 0.85`. `InvestigationRail` rendered
 * `Math.round(0.85)` as **risk 1** while `AlertDetailView` rendered the raw
 * **0.85**, so one alert showed two different numbers on two surfaces.
 *
 * The trailing `?? 0` is the other half. An alert carrying none of the three
 * keys is unscored, and publishing a confident `0` for an unmeasured quantity
 * is the thing this repo's honesty rules exist to stop — the rail already has
 * a guard to omit the chip, which the `?? 0` made unreachable.
 *
 * Against the pre-change tree, every test below except
 * `passes the canonical 0-100 integer through` fails.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { alertsApi } from '@/lib/api';

function respondWith(alert: Record<string, unknown>) {
  return vi.fn(
    async () =>
      new Response(
        JSON.stringify({ id: 'a1', title: 't', severity: 'medium', status: 'new', ...alert }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
  );
}

beforeEach(() => {
  vi.stubGlobal('fetch', respondWith({}));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('risk normalises to one scale at the API boundary', () => {
  it("normalises the model's raw [0,1] `ai_score` to the 0-100 scale", async () => {
    vi.stubGlobal('fetch', respondWith({ ai_score: 0.85 }));

    expect((await alertsApi.get('a1')).riskScore).toBe(85);
  });

  it("normalises fusion's raw [0,1] `risk_score` to the same scale", async () => {
    vi.stubGlobal('fetch', respondWith({ risk_score: 0.42 }));

    expect((await alertsApi.get('a1')).riskScore).toBe(42);
  });

  it('passes the canonical 0-100 integer through when only `confidence` is present', async () => {
    vi.stubGlobal('fetch', respondWith({ confidence: 85 }));

    expect((await alertsApi.get('a1')).riskScore).toBe(85);
  });

  it('decides the scale from the key, never from the magnitude', async () => {
    // The tempting shortcut is `v <= 1 ? v * 100 : v`. A genuine confidence of
    // 1/100 is then indistinguishable from a model score of 1.0, and the
    // lowest-risk alert in the estate renders as the highest.
    vi.stubGlobal('fetch', respondWith({ ai_score: 1 }));
    expect((await alertsApi.get('a1')).riskScore).toBe(100);

    vi.stubGlobal('fetch', respondWith({ confidence: 1 }));
    expect((await alertsApi.get('a1')).riskScore).toBe(1);
  });

  it('leaves an unscored alert unscored rather than publishing a zero', async () => {
    // `?? 0` turned "nobody scored this" into "scored zero risk". The rail
    // already guards on `typeof riskScore === 'number'` to omit the chip; the
    // default made that guard unreachable.
    vi.stubGlobal('fetch', respondWith({}));

    expect((await alertsApi.get('a1')).riskScore).toBeUndefined();
  });

  it('keeps a genuine zero score distinct from an absent one', async () => {
    // The negative control for the test above: a fix that mapped 0 to
    // undefined would pass it and would lose a real measurement.
    vi.stubGlobal('fetch', respondWith({ ai_score: 0 }));

    expect((await alertsApi.get('a1')).riskScore).toBe(0);
  });

  it('is idempotent on an already-normalised alert', async () => {
    // The console's own camelCase field is the 0-100 output name. Re-reading
    // one must not multiply it by 100 again.
    vi.stubGlobal('fetch', respondWith({ riskScore: 85 }));

    expect((await alertsApi.get('a1')).riskScore).toBe(85);
  });

  it('prefers the dedicated risk keys over confidence', async () => {
    // Confidence answers "how sure are we", risk answers "how bad is it".
    // Confidence is only a fallback when nothing scored the alert's risk.
    vi.stubGlobal('fetch', respondWith({ ai_score: 0.9, confidence: 20 }));

    expect((await alertsApi.get('a1')).riskScore).toBe(90);
  });
});
