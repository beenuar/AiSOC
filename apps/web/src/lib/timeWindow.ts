/**
 * Global time-window primitives (W4).
 *
 * The console used to scatter ad-hoc `'24h'` strings, ad-hoc `'7d'`
 * selectors, and `hours_back: 24` query params across every dashboard,
 * which meant the Operations view could be showing "last 7 days" while
 * the SLA tile next to it was hard-coded to "last 24 hours". That
 * inconsistency confused operators and broke any honest read of pipeline
 * health.
 *
 * This module defines the single canonical set of windows the console
 * supports, plus the (URL-stable) IDs we'll persist in user prefs and
 * write into query params. The TimeWindowContext + TimeWindowSelector
 * both consume these — no new ad-hoc windows should be added here
 * without thinking through which API endpoints can actually serve them.
 */

export type TimeWindow = '1h' | '24h' | '7d' | '30d';

/** Ordered tuple drives the dropdown render order (left → right, shortest → longest). */
export const TIME_WINDOWS: readonly TimeWindow[] = ['1h', '24h', '7d', '30d'] as const;

/** Whatever the user has not chosen anything yet — keep matching the legacy default. */
export const DEFAULT_TIME_WINDOW: TimeWindow = '24h';

/** Short label used in tight chrome (e.g. the TopBar pill). */
export const TIME_WINDOW_SHORT_LABEL: Record<TimeWindow, string> = {
  '1h': '1h',
  '24h': '24h',
  '7d': '7d',
  '30d': '30d',
};

/** Long label used in dropdown menus and tooltips. */
export const TIME_WINDOW_LONG_LABEL: Record<TimeWindow, string> = {
  '1h': 'Last hour',
  '24h': 'Last 24 hours',
  '7d': 'Last 7 days',
  '30d': 'Last 30 days',
};

/** Hours represented by each window (used by `hours_back=` query params). */
export const TIME_WINDOW_HOURS: Record<TimeWindow, number> = {
  '1h': 1,
  '24h': 24,
  '7d': 24 * 7,
  '30d': 24 * 30,
};

/** Milliseconds — useful for computing relative "since" timestamps client-side. */
export const TIME_WINDOW_MS: Record<TimeWindow, number> = {
  '1h': 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000,
};

/** Type guard — anything we pull off localStorage or URL params should pass through this. */
export function isTimeWindow(value: unknown): value is TimeWindow {
  return value === '1h' || value === '24h' || value === '7d' || value === '30d';
}

/**
 * Convert a window into the ISO "since" timestamp some endpoints prefer.
 * Caller passes `now` for deterministic tests; defaults to `Date.now()`.
 */
export function sinceFor(window: TimeWindow, now: number = Date.now()): string {
  return new Date(now - TIME_WINDOW_MS[window]).toISOString();
}

/** localStorage key for the user's last-chosen window. */
export const TIME_WINDOW_STORAGE_KEY = 'aisoc.timeWindow';
