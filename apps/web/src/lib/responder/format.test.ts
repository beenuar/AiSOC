/**
 * format — unit tests
 * ===================
 *
 * The mobile responder UI leans on these formatters to keep severity, status
 * and time strings consistent across the alert/case surface. They're pure
 * functions, so we test them directly without a DOM.
 *
 * Coverage map:
 *   - severityTone: every tier in the v1.5 five-tier ladder
 *     (`critical | high | medium | low | info`) has a tone entry, ranks are
 *     strictly monotonic, fallback path returns `info` rather than throwing,
 *     and case-insensitive matching works (some upstreams emit `"Critical"`).
 *
 * If a refactor accidentally drops a tier — e.g. squashes `critical` back into
 * `high` like the pre-v1.5 four-tier ladder — these tests catch it before the
 * mobile UI starts rendering blanks for P1 incidents.
 */

import { describe, expect, it } from 'vitest';

import { severityTone } from './format';

describe('severityTone', () => {
  const tiers = ['critical', 'high', 'medium', 'low', 'info'] as const;

  it.each(tiers)('returns a tone for %s', (tier) => {
    const tone = severityTone(tier);
    expect(tone.bg).toMatch(/^bg-/);
    expect(tone.fg).toMatch(/^text-/);
    expect(tone.border).toMatch(/^border-l-/);
    expect(tone.glyph).toHaveLength(1);
    expect(typeof tone.rank).toBe('number');
  });

  it('assigns strictly monotonic ranks across the five-tier ladder', () => {
    const ranks = tiers.map((t) => severityTone(t).rank);
    // critical = 4, high = 3, medium = 2, low = 1, info = 0 — so the list as
    // ordered should be strictly descending.
    expect(ranks).toEqual([4, 3, 2, 1, 0]);
  });

  it('falls back to the info tone for unknown severities', () => {
    const info = severityTone('info');
    const unknown = severityTone('not-a-real-severity');
    expect(unknown).toEqual(info);
  });

  it('falls back to the info tone for nullish severities', () => {
    const info = severityTone('info');
    expect(severityTone(null)).toEqual(info);
    expect(severityTone(undefined)).toEqual(info);
    expect(severityTone('')).toEqual(info);
  });

  it('is case-insensitive (some upstreams emit Title-Case)', () => {
    expect(severityTone('Critical')).toEqual(severityTone('critical'));
    expect(severityTone('HIGH')).toEqual(severityTone('high'));
    expect(severityTone('Medium')).toEqual(severityTone('medium'));
  });

  it('uses distinct background colors for each tier', () => {
    // Catches a refactor where someone copy-pastes a row but forgets to
    // update the color — easy to miss in code review.
    const bgs = new Set(tiers.map((t) => severityTone(t).bg));
    expect(bgs.size).toBe(tiers.length);
  });

  it('uses the red palette for critical (P1 wallboard contract)', () => {
    // The wallboard relies on `red` being the unambiguous P1 signal. If a
    // theme refactor recolors `critical` to e.g. magenta, this catches it.
    const crit = severityTone('critical');
    expect(crit.bg).toContain('red');
    expect(crit.fg).toContain('red');
    expect(crit.border).toContain('red');
  });
});
