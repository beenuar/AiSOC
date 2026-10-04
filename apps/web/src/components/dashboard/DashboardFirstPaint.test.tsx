/**
 * First paint is a state, and it is not "empty".
 *
 * `PanelUnavailable` had an error branch and an empty branch. The error
 * branch reads as sufficient — a failed request gets an honest error state —
 * right up until you notice which branch runs *before* the request lands.
 * With no data and no error yet, `/dashboard` rendered the empty branch and
 * asserted **"No alerts in the last 24 hours"**: a measured claim about a
 * window nothing had looked at, made milliseconds before the failing request
 * came back and replaced it.
 *
 * This project has re-learned that shape enough times that the test has to
 * name it: assert on first paint, not only on the error branch. A suite that
 * only ever set an error would have passed against the defect.
 *
 * Both directions. A dashboard that answered "not loaded yet" forever would
 * pass the first assertion and be useless, so a genuinely empty window must
 * still read as empty.
 */
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { TimeWindowProvider } from '@/components/layout/TimeWindowProvider';
import { cleanup, render, screen } from '@testing-library/react';
import { __setDemoModeForTests } from '@/lib/demoMode';

const swrData = vi.hoisted(() => new Map<string, unknown>());
const swrErrors = vi.hoisted(() => new Map<string, unknown>());
const swrLoading = vi.hoisted(() => new Set<string>());

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    // An SWR key is now `['dashboard-metrics', timeWindow]` rather than a
    // bare string, because the window has to be part of the cache key or
    // every window shares one entry. These fixtures name the resource and
    // not the window, so resolve an array key by its head -- the tests here
    // are about what the dashboard *renders*, and threading a window through
    // each one would obscure that without testing anything.
    //
    // That the window reaches the request is a separate assertion, in
    // DashboardTimeWindow.test.tsx, where it is the subject rather than
    // incidental setup.
    const k = typeof key === 'string' ? key : String((key as unknown[])[0]);
    return {
      data: swrData.get(k),
      error: swrErrors.get(k),
      isLoading: swrLoading.has(k),
      mutate: vi.fn(),
    };
  },
}));

vi.mock('@/lib/api', () => ({
  __esModule: true,
  // The dashboard binds to the real `TimeWindowProvider`, which reconciles
  // the window with the signed-in user's stored preference. An absent export
  // makes the provider throw during render, which reads as a component
  // failure rather than a missing mock.
  authApi: {
    currentUser: vi.fn(() => null),
    updateUserPreferences: vi.fn(() => Promise.resolve()),
  },
  metricsApi: {
    getDashboard: vi.fn(),
    getSOC: vi.fn(),
    getFunnel: vi.fn(),
    getPipelineHealth: vi.fn(),
  },
  investigationsApi: { getCostAggregate: vi.fn() },
}));

vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ children, href }: { children: React.ReactNode; href: string }) => <a href={href}>{children}</a>,
}));

vi.mock('next/navigation', () => ({
  __esModule: true,
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/dashboard',
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock('next/dynamic', () => ({
  __esModule: true,
  default: () => function DynamicStub() {
    return null;
  },
}));

vi.mock('@/lib/realtime', () => ({
  __esModule: true,
  useRealtimeChannel: () => ({ status: 'disconnected', lastEvent: null, events: [] }),
}));

import { DashboardView } from './DashboardView';

/** Every panel claim that is a statement about measured data. */
const MEASURED_CLAIMS = [
  /No alerts in the last 24 hours/i,
  /No dashboard metrics yet/i,
  /No severity data/i,
  /No technique coverage yet/i,
];

beforeEach(() => {
  swrData.clear();
  swrErrors.clear();
  swrLoading.clear();
  __setDemoModeForTests(false);
});

afterEach(() => {
  cleanup();
  __setDemoModeForTests(null);
});

describe('the dashboard does not report a result it has not got', () => {
  it('claims nothing on first paint, while the request is still in flight', () => {
    swrLoading.add('dashboard-metrics');

    render(
      <TimeWindowProvider>
        <DashboardView />
      </TimeWindowProvider>,
    );

    for (const claim of MEASURED_CLAIMS) {
      expect(screen.queryByText(claim), `"${claim}" is a measured claim and the request has not landed`).toBeNull();
    }
    expect(screen.getAllByText(/Not loaded yet/i).length).toBeGreaterThan(0);
  });

  it('claims nothing when the response carried no alert totals', () => {
    // Not in flight, no error, and a payload the view cannot read. Equally
    // unmeasured, and the branch a plain `isLoading` check would miss.
    swrData.set('dashboard-metrics', { cases: { open: 0, inProgress: 0, resolvedThisWeek: 0 } });

    render(
      <TimeWindowProvider>
        <DashboardView />
      </TimeWindowProvider>,
    );

    for (const claim of MEASURED_CLAIMS) {
      expect(screen.queryByText(claim)).toBeNull();
    }
    expect(screen.getAllByText(/Not loaded yet/i).length).toBeGreaterThan(0);
  });

  it('still shows the failure when the request failed', () => {
    swrErrors.set('dashboard-metrics', new Error('503 Service Unavailable'));

    render(
      <TimeWindowProvider>
        <DashboardView />
      </TimeWindowProvider>,
    );

    expect(screen.getAllByText(/503 Service Unavailable/i).length).toBeGreaterThan(0);
    expect(screen.queryByText(/No alerts in the last 24 hours/i)).toBeNull();
  });

  it('still reports a genuinely empty window as empty', () => {
    // The other direction. "Not loaded yet" everywhere forever would pass
    // every assertion above and tell an operator nothing.
    swrData.set('dashboard-metrics', {
      alerts: { total: 0, new: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, mttr: 0, mttr_sample_count: 0 },
      cases: { open: 0, inProgress: 0, resolvedThisWeek: 0 },
      sources: [],
      topMitre: [],
      alertsTrend: [],
      threatsBySource: [],
    });

    render(
      <TimeWindowProvider>
        <DashboardView />
      </TimeWindowProvider>,
    );

    expect(screen.getByText(/No alerts in the last 24 hours/i)).toBeInTheDocument();
    expect(screen.queryByText(/Not loaded yet/i)).toBeNull();
  });
});
