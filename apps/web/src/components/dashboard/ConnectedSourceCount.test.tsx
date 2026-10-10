/**
 * The "Connected Sources" tile counts the sources the panel beneath it lists.
 *
 * Two halves of one defect. Server-side, `metrics.sources` was built only
 * from rows of the `connectors` table, so events arriving through `POST
 * /v1/ingest/batch` or a tenant inbox webhook were invisible — a tenant with
 * 522 alerts from three `connector_type` values read **Connected Sources 0**.
 * Client-side, the tile counted `status === 'active'`, a connector *health*
 * value reported by the poller; nothing polls a webhook, so even once the
 * server listed those sources the tile would still have read 0 directly above
 * a panel showing all three.
 *
 * The render test is the one that matters — it asserts the number a user
 * sees. The unit tests pin the predicate's edges, including the two it must
 * *not* count, so "fix the tile" cannot quietly become "count every row".
 *
 * Against the pre-change tree all of these fail.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { TimeWindowProvider } from '@/components/layout/TimeWindowProvider';
import { __setDemoModeForTests } from '@/lib/demoMode';

const swrData = vi.hoisted(() => new Map<string, unknown>());

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    const k = typeof key === 'string' ? key : String((key as unknown[])[0]);
    return { data: swrData.get(k), error: undefined, isLoading: false, mutate: vi.fn() };
  },
}));

vi.mock('@/lib/api', () => ({
  __esModule: true,
  authApi: { currentUser: vi.fn(() => null), updateUserPreferences: vi.fn(() => Promise.resolve()) },
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
  default: ({ children, href }: { children: React.ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
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

import { DashboardView, countConnectedSources } from './DashboardView';

/** What the API now returns for a tenant ingesting over webhooks only. */
const WEBHOOK_ONLY_METRICS = {
  alerts: { total: 522, critical: 12, high: 40, mttr_hours: 0, mttr_sample_count: 0 },
  cases: { open: 0, inProgress: 0, resolvedThisWeek: 0 },
  sources: [
    { name: 'splunk_notable', count: 340, status: 'ingesting' },
    { name: 'aws_eventbridge', count: 150, status: 'ingesting' },
    { name: 'generic_webhook', count: 32, status: 'ingesting' },
  ],
  topMitre: [],
  alertsTrend: [],
};

beforeEach(() => {
  swrData.clear();
  __setDemoModeForTests(false);
});

afterEach(() => {
  cleanup();
  __setDemoModeForTests(null);
});

describe('the dashboard reports sources that are actually delivering', () => {
  it('shows three, not zero, for a tenant ingesting over webhooks', () => {
    swrData.set('dashboard-metrics', WEBHOOK_ONLY_METRICS);

    render(
      <TimeWindowProvider>
        <DashboardView />
      </TimeWindowProvider>,
    );

    // The tile's label and the panel's heading carry the same words — which
    // is exactly why "0" above a list of three reads as a contradiction. The
    // tile is the `<p>`, the panel heading is an `<h3>`.
    const tile = screen
      .getByText('Connected Sources', { selector: 'p' })
      .closest('div') as HTMLElement;

    expect(within(tile).getByText('3')).toBeInTheDocument();
    expect(within(tile).queryByText('0')).toBeNull();
  });
});

describe('a source is connected when it is healthy or delivering', () => {
  it('counts a webhook source that has no connector row and no health', () => {
    expect(countConnectedSources(WEBHOOK_ONLY_METRICS.sources)).toBe(3);
  });

  it('still counts a healthy connector that has delivered nothing yet', () => {
    // Just configured, first poll pending. It is connected.
    expect(countConnectedSources([{ name: 'Prod Okta', count: 0, status: 'active' }])).toBe(1);
  });

  it('does not count a dead connector delivering nothing', () => {
    // The negative control: counting every row would turn the tile into a
    // count of configured integrations, which is a different question.
    expect(countConnectedSources([{ name: 'Broken Splunk', count: 0, status: 'error' }])).toBe(0);
  });

  it('counts a connector that is unhealthy but still delivering', () => {
    // Health says degraded, the events say otherwise. The tile answers "is
    // anything reaching us", so the events win.
    expect(countConnectedSources([{ name: 'Flaky SIEM', count: 91, status: 'error' }])).toBe(1);
  });

  it('counts nothing for a tenant with nothing', () => {
    expect(countConnectedSources([])).toBe(0);
  });
});
