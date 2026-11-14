/**
 * The responder formatting helpers are pure functions the mobile surface
 * leans on for every list row, so each branch is pinned: the relative-time
 * ladder, the "until" inverse, the five severity tones with their ranks, and
 * the status maps — including the rule the CASE_STATUS comment records, that
 * only the six database statuses exist and anything else falls through to a
 * grey tone that still shows the raw label rather than lying with a known one.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { alertStatusTone, caseStatusTone, formatRelative, formatUntil, severityTone } from './format';

const NOW = new Date('2026-10-12T12:00:00Z');

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
});

afterEach(() => {
  vi.useRealTimers();
});

describe('formatRelative', () => {
  it('renders a dash for nothing, and for garbage', () => {
    expect(formatRelative(null)).toBe('—');
    expect(formatRelative(undefined)).toBe('—');
    expect(formatRelative('not-a-date')).toBe('—');
  });

  it('walks the ladder: just now, seconds, minutes, hours, days', () => {
    expect(formatRelative(new Date(NOW.getTime() - 2_000).toISOString())).toBe('just now');
    expect(formatRelative(new Date(NOW.getTime() - 30_000).toISOString())).toBe('30s ago');
    expect(formatRelative(new Date(NOW.getTime() - 5 * 60_000).toISOString())).toBe('5m ago');
    expect(formatRelative(new Date(NOW.getTime() - 3 * 3_600_000).toISOString())).toBe('3h ago');
    expect(formatRelative(new Date(NOW.getTime() - 2 * 86_400_000).toISOString())).toBe('2d ago');
  });

  it('falls back to a calendar date past a week', () => {
    const old = new Date(NOW.getTime() - 30 * 86_400_000).toISOString();
    expect(formatRelative(old)).not.toMatch(/ago$/);
  });

  it('clamps the future to now rather than inventing negative time', () => {
    expect(formatRelative(new Date(NOW.getTime() + 60_000).toISOString())).toBe('just now');
  });
});

describe('formatUntil', () => {
  it('is null for nothing, garbage, and the past', () => {
    expect(formatUntil(null)).toBeNull();
    expect(formatUntil('not-a-date')).toBeNull();
    expect(formatUntil(new Date(NOW.getTime() - 1_000).toISOString())).toBeNull();
  });

  it('renders minutes, hours and days ahead', () => {
    expect(formatUntil(new Date(NOW.getTime() + 25 * 60_000).toISOString())).toBe('25m');
    expect(formatUntil(new Date(NOW.getTime() + 5 * 3_600_000).toISOString())).toBe('5h');
    expect(formatUntil(new Date(NOW.getTime() + 3 * 86_400_000).toISOString())).toBe('3d');
  });
});

describe('severityTone', () => {
  it('ranks the five tiers in order', () => {
    const ranks = ['info', 'low', 'medium', 'high', 'critical'].map((s) => severityTone(s).rank);
    expect(ranks).toEqual([0, 1, 2, 3, 4]);
  });

  it('is case-insensitive and falls back to info for the unknown', () => {
    expect(severityTone('CRITICAL').glyph).toBe('C');
    expect(severityTone('made-up').rank).toBe(0);
    expect(severityTone(null).rank).toBe(0);
  });
});

describe('alertStatusTone', () => {
  it('labels the known statuses', () => {
    expect(alertStatusTone('new').label).toBe('New');
    expect(alertStatusTone('false_positive').label).toBe('FP');
    expect(alertStatusTone('snoozed').label).toBe('Snoozed');
  });

  it('an unknown status keeps its own name in grey rather than borrowing a known label', () => {
    const tone = alertStatusTone('quarantined');
    expect(tone.label).toBe('quarantined');
    expect(tone.bg).toContain('slate');
  });
});

describe('caseStatusTone', () => {
  it('covers exactly the six statuses the database permits', () => {
    for (const s of ['new', 'triaged', 'investigating', 'contained', 'resolved', 'closed']) {
      expect(caseStatusTone(s).label.toLowerCase()).toBe(s);
    }
  });

  it('the statuses nothing can write fall through honestly', () => {
    // `open` and `pending` were map entries nothing could match; the fix was
    // to delete them, so they must render as themselves in grey.
    expect(caseStatusTone('open').label).toBe('open');
    expect(caseStatusTone('pending').bg).toContain('slate');
  });
});
