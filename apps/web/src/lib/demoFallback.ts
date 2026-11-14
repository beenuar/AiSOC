/**
 * Gate for seeded sample data so it can never masquerade as tenant state.
 *
 * Across the console, roughly three dozen components carried a `MOCK_*` /
 * `DEMO_*` array of plausible-looking security data — alerts on named hosts,
 * connectors with last-sync times, SLA percentages, MITRE coverage cells — and
 * served it whenever the API call failed or had not yet resolved. None of it
 * was gated on demo mode.
 *
 * Two reasons that is worse than an empty state.
 *
 * A fabricated alert is indistinguishable from a real one. An operator seeing
 * "Ransomware encryption behaviour on WIN-DC01" has no way to know the backend
 * was unreachable, and acting on it, or reporting that the estate is clean
 * because the fabricated numbers looked healthy, are both real outcomes.
 *
 * And it persists. SWR v2 disables `revalidateOnMount` whenever `fallbackData`
 * is supplied, so a component that passes a mock unconditionally may never
 * fetch at all — the sample data is not a first-paint placeholder, it is what
 * the view shows until something else forces a revalidation.
 *
 * Passing `undefined` to `fallbackData` is equivalent to omitting it, so
 * wrapping a mock in `demoFallback` restores normal fetch-and-error behaviour
 * outside the hosted demo while leaving the demo itself populated.
 */

import { isDemoMode } from '@/lib/demoMode';

/**
 * Returns `mock` only in the hosted demo, otherwise `undefined`.
 *
 * Use for SWR `fallbackData` and for any initial state that would otherwise
 * render fabricated domain data:
 *
 * ```ts
 * const { data, error } = useSWR('/alerts', fetcher, {
 *   fallbackData: demoFallback(MOCK_ALERTS),
 * });
 * ```
 */
export function demoFallback<T>(mock: T): T | undefined {
  return isDemoMode() ? mock : undefined;
}

/**
 * Whether a caller may substitute sample data right now.
 *
 * For `catch` blocks and imperative paths, where the honest alternative is an
 * error state rather than an absent value:
 *
 * ```ts
 * catch (err) {
 *   if (canUseDemoData()) setRows(MOCK_ROWS);
 *   else setError('Could not load alerts.');
 * }
 * ```
 */
export function canUseDemoData(): boolean {
  return isDemoMode();
}
