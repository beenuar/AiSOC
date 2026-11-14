/**
 * Changing the time window changes what is fetched.
 *
 * The defect
 * ----------
 * The console shipped a global time-window selector in the header, with a
 * provider that persisted the choice to localStorage *and* to the user's
 * server-side preferences so it roamed between browsers. `useTimeWindow()`
 * had **zero** data-fetching consumers: the only callers were the selector
 * itself and its own tests.
 *
 * So the control worked perfectly and drove nothing. `DashboardView`'s SWR
 * key was the constant string `'dashboard-metrics'`, and `period="24h"` was
 * hardcoded into both `<FunnelKpiBar>` and `<EfficiencyReport>`. A user
 * switching to 7d got a re-rendered header, an unchanged dashboard, and no
 * indication that the two disagreed.
 *
 * Why the SWR key matters as much as the request
 * ----------------------------------------------
 * Passing the window to the fetcher alone would not have been enough: SWR
 * caches on the key, so a constant key serves one entry for every window.
 * The fetcher would be called once and its result reused forever. The key has
 * to name its inputs, which is the assertion below.
 */

import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const swrCalls = vi.hoisted(() => [] as unknown[]);
const dashboardCalls = vi.hoisted(() => [] as unknown[]);
const funnelCalls = vi.hoisted(() => [] as unknown[]);

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown, fetcher?: () => unknown) => {
    swrCalls.push(key);
    // Call it so the arguments the component passes are observable. Without
    // this the key could be right while the request carried a stale window.
    try {
      fetcher?.();
    } catch {
      /* a stubbed api may throw; the call itself is what is being recorded */
    }
    return { data: undefined, error: undefined, isLoading: true, mutate: vi.fn() };
  },
}));

vi.mock('@/lib/api', () => ({
  __esModule: true,
  metricsApi: {
    getDashboard: vi.fn((period?: unknown) => {
      dashboardCalls.push(period);
      return Promise.resolve({});
    }),
    getFunnel: vi.fn((period?: unknown) => {
      funnelCalls.push(period);
      return Promise.resolve({});
    }),
    getSOC: vi.fn(() => Promise.resolve({})),
    getAlertTrend: vi.fn(() => Promise.resolve({ data: [] })),
    getPipelineHealth: vi.fn(() => Promise.resolve({})),
  },
  authApi: {
    currentUser: vi.fn(() => null),
    updateUserPreferences: vi.fn(() => Promise.resolve()),
  },
  connectorsApi: { list: vi.fn(() => Promise.resolve([])) },
  alertsApi: { list: vi.fn(() => Promise.resolve({ items: [], total: 0 })) },
}));

vi.mock('@/lib/demoMode', () => ({
  __esModule: true,
  isDemoMode: () => false,
  demoFallback: () => undefined,
}));

import { TIME_WINDOWS, type TimeWindow } from '@/lib/timeWindow';

import { FunnelKpiBar } from './FunnelKpiBar';

describe('the global time window drives the fetches', () => {
  beforeEach(() => {
    swrCalls.length = 0;
    dashboardCalls.length = 0;
    funnelCalls.length = 0;
    window.localStorage.clear();
  });

  it.each(TIME_WINDOWS)('a %s window reaches the funnel request', (period: TimeWindow) => {
    render(<FunnelKpiBar period={period} />);

    expect(funnelCalls).toContain(period);
  });

  it('the funnel SWR key names the window, not just the resource', () => {
    // A constant key is the half of this bug that survives passing the window
    // to the fetcher: SWR would serve one cached entry for every window and
    // the fetcher would run once.
    render(<FunnelKpiBar period="7d" />);

    const keys = swrCalls.map((k) => JSON.stringify(k));
    expect(keys.some((k) => k.includes('7d'))).toBe(true);
  });

  it('two different windows do not share a cache key', () => {
    render(<FunnelKpiBar period="1h" />);
    const first = swrCalls.map((k) => JSON.stringify(k));
    swrCalls.length = 0;
    render(<FunnelKpiBar period="30d" />);
    const second = swrCalls.map((k) => JSON.stringify(k));

    expect(first).not.toEqual(second);
  });

  it('every window the selector offers is one the API accepts', () => {
    // `_PERIOD_QUERY` server-side is `^(1h|24h|7d|30d)$`. A selector offering
    // a fifth value would 422 on every tile, and the control would look
    // broken rather than the contract.
    expect([...TIME_WINDOWS]).toEqual(['1h', '24h', '7d', '30d']);
  });

  it('renders without throwing for each window', () => {
    for (const period of TIME_WINDOWS) {
      const { unmount } = render(<FunnelKpiBar period={period} />);
      expect(screen.getAllByText(/Operations Funnel/i).length).toBeGreaterThan(0);
      unmount();
    }
  });
});
