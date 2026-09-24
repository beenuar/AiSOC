/**
 * Data-honesty gate for the two dashboards that carried ungated sample data.
 *
 * Both `DashboardView` and `SOCMetricsDashboard` already wrapped their SWR
 * `fallbackData` in `demoFallback()`, which returns `undefined` outside the
 * hosted demo. Both then defeated that gate a few lines later with an
 * unconditional `const resolved = isValid ? data : MOCK`, so the mock was
 * exactly what rendered during first paint and after any API error — the two
 * states a self-hoster with an empty or unreachable backend spends all their
 * time in.
 *
 * What that published as tenant state: a connector inventory the tenant does
 * not run ("CrowdStrike EDR", 412 events), a MITRE tactic ranking, a 24h
 * volume curve, MTTD/MTTR figures, and an LLM spend line naming models the
 * tenant never configured.
 *
 * These tests assert the negative — that none of those strings can reach the
 * DOM outside demo mode — which is the only form that stays meaningful as the
 * components grow.
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { __setDemoModeForTests } from '@/lib/demoMode';

const swrData = vi.hoisted(() => new Map<string, unknown>());
const swrErrors = vi.hoisted(() => new Map<string, unknown>());

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    const k = typeof key === 'string' ? key : JSON.stringify(key);
    return {
      data: swrData.get(k),
      error: swrErrors.get(k),
      isLoading: false,
      mutate: vi.fn(),
    };
  },
}));

vi.mock('@/lib/api', () => ({
  __esModule: true,
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

// `next/dynamic` returns a promise-loaded chart in production. Under jsdom we
// only care that no fabricated *numbers* reach the DOM, so render nothing.
vi.mock('next/dynamic', () => ({
  __esModule: true,
  default: () => function DynamicStub() {
    return null;
  },
}));

// Realtime + child widgets are exercised by their own suites.
vi.mock('@/lib/realtime', () => ({
  __esModule: true,
  useRealtimeChannel: () => ({ status: 'disconnected', lastEvent: null, events: [] }),
}));

import { DashboardView } from './DashboardView';
import { SOCMetricsDashboard } from './SOCMetricsDashboard';

/**
 * Every string the fabricated payloads would put on screen. Taken verbatim
 * from `MOCK_METRICS` in DashboardView.tsx and `MOCK_SOC_METRICS` /
 * `MOCK_COST_AGGREGATE` in SOCMetricsDashboard.tsx.
 */
const FABRICATED_SOURCE_NAMES = [
  'CrowdStrike EDR',
  'Microsoft Sentinel',
  'AWS CloudTrail',
  'Okta Identity',
  'Google Workspace',
  'GitHub Audit',
];

const FABRICATED_MODEL_NAMES = ['gpt-4o', 'gpt-4o-mini', 'claude-3.5-sonnet'];

function expectNoFabrication(names: string[]) {
  for (const name of names) {
    expect(
      screen.queryByText(new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i')),
      `"${name}" is sample data and must not render outside demo mode`,
    ).toBeNull();
  }
}

beforeEach(() => {
  swrData.clear();
  swrErrors.clear();
  __setDemoModeForTests(false);
});

afterEach(() => {
  cleanup();
  __setDemoModeForTests(null);
});

describe('DashboardView — no fabricated data outside demo mode', () => {
  it('renders an error state, not a mock connector inventory, when the metrics API fails', () => {
    swrErrors.set('dashboard-metrics', new Error('503 Service Unavailable'));

    render(<DashboardView />);

    expectNoFabrication(FABRICATED_SOURCE_NAMES);
    // The failure itself is surfaced rather than swallowed.
    expect(screen.getAllByText(/503 Service Unavailable/i).length).toBeGreaterThan(0);
  });

  it('does not invent a 1247-alert baseline when the API fails', () => {
    swrErrors.set('dashboard-metrics', new Error('network down'));

    render(<DashboardView />);

    expect(screen.queryByText('1247')).toBeNull();
    expect(screen.queryByText('42m')).toBeNull();
  });

  it('shows an honest empty state for sections the API returns empty', () => {
    // A real, reachable API on a tenant that has alerts but no connectors,
    // no technique hits and no trend history yet. Previously each of these
    // empty arrays was swapped for the corresponding mock.
    swrData.set('dashboard-metrics', {
      alerts: { total: 4, new: 1, critical: 0, high: 2, medium: 1, low: 1, resolvedToday: 0, mttr: 11 },
      cases: { open: 0, inProgress: 0, resolvedThisWeek: 0 },
      sources: [],
      topMitre: [],
      alertsTrend: [],
      threatsBySource: [],
    });

    render(<DashboardView />);

    // Real numbers still render.
    expect(screen.getByText('4')).toBeTruthy();
    // Fabricated ones do not.
    expectNoFabrication(FABRICATED_SOURCE_NAMES);
    expect(screen.getByText(/No sources connected/i)).toBeTruthy();
    expect(screen.getByText(/No technique coverage yet/i)).toBeTruthy();
  });

  it('publishes no trend delta it cannot source from the API', () => {
    swrData.set('dashboard-metrics', {
      alerts: { total: 4, new: 1, critical: 0, high: 2, medium: 1, low: 1, resolvedToday: 0, mttr: 11 },
      cases: { open: 0, inProgress: 0, resolvedThisWeek: 0 },
      sources: [],
      topMitre: [],
      alertsTrend: [],
      threatsBySource: [],
    });

    render(<DashboardView />);

    // `/metrics/dashboard` returns no period-over-period comparison, so the
    // "+12% vs yesterday" / "-3% vs yesterday" / "-8% vs last week" literals
    // that used to sit beside the real counts were pure invention.
    expect(screen.queryByText(/vs yesterday/i)).toBeNull();
    expect(screen.queryByText(/vs last week/i)).toBeNull();
  });
});

describe('SOCMetricsDashboard — no fabricated data outside demo mode', () => {
  it('renders no KPI figures when /metrics/soc has not resolved', () => {
    render(<SOCMetricsDashboard />);

    // MOCK_SOC_METRICS values.
    expect(screen.queryByText('1.4')).toBeNull();
    expect(screen.queryByText('6.2')).toBeNull();
    expect(screen.queryByText('14.8')).toBeNull();
    expect(screen.queryByText('1247')).toBeNull();
    expect(screen.getByText(/No SOC performance data yet/i)).toBeTruthy();
  });

  it('never names a model the tenant has not run', () => {
    render(<SOCMetricsDashboard />);

    expectNoFabrication(FABRICATED_MODEL_NAMES);
    expect(screen.queryByText(/\$76\.65/)).toBeNull();
  });

  it('surfaces the API error instead of a baseline', () => {
    swrErrors.set('soc-metrics', new Error('upstream timeout'));

    render(<SOCMetricsDashboard />);

    expect(screen.getByText(/upstream timeout/i)).toBeTruthy();
    expect(screen.queryByText('1.4')).toBeNull();
  });
});

describe('a mean over no samples is unmeasured, not zero', () => {
  /**
   * A live acceptance pass read MTTD/MTTR/MTTC as "0.0 hrs" on a tenant that
   * had resolved nothing: the averages were over zero rows and
   * `float(None or 0.0)` published that as a confident number. Zero hours to
   * respond is the best possible score, so a tenant that had done nothing
   * topped the league table. The API now reports each mean with the count of
   * rows it averaged.
   *
   * The paired `renders the figure when there are samples` case is what stops
   * the fix becoming "blank the tiles": both directions have to hold.
   */
  const KPIS = {
    mttd_hours: 0.0,
    mttr_hours: 0.0,
    mttc_hours: 0.0,
    false_positive_rate: 0,
    escalation_rate: 0,
    alert_volume_7d: 1,
    cases_opened_7d: 2,
    cases_closed_7d: 0,
    analyst_overrides_7d: 0,
  };

  it('says so on every tile whose window contains no closures', () => {
    swrData.set('soc-metrics', {
      kpis: { ...KPIS, mttd_sample_count: 0, mttr_sample_count: 0, mttc_sample_count: 0 },
      attack_heatmap: [],
      calibration_curve: [],
    });

    render(<SOCMetricsDashboard />);

    expect(screen.getAllByText(/not measured/i).length).toBe(3);
    expect(screen.queryByText('0.0')).toBeNull();
  });

  it('renders the figure, and what it was averaged over, once there are samples', () => {
    swrData.set('soc-metrics', {
      kpis: { ...KPIS, mttr_hours: 1.5, mttr_sample_count: 2, cases_closed_7d: 2, mttd_sample_count: 0, mttc_sample_count: 0 },
      attack_heatmap: [],
      calibration_curve: [],
    });

    render(<SOCMetricsDashboard />);

    expect(screen.getByText('1.5')).toBeTruthy();
    expect(screen.getByText(/mean of 2 over 30d/i)).toBeTruthy();
  });

  it('keeps rendering means for an API build that sends no counts', () => {
    // Back-compatibility: the counts are additive, and blanking every tile
    // against an older API would be a worse regression than the bug.
    swrData.set('soc-metrics', {
      kpis: { ...KPIS, mttd_hours: 1.2, mttr_hours: 3.4, mttc_hours: 5.6 },
      attack_heatmap: [],
      calibration_curve: [],
    });

    render(<SOCMetricsDashboard />);

    expect(screen.getByText('3.4')).toBeTruthy();
    expect(screen.queryByText(/not measured/i)).toBeNull();
  });

  /**
   * The same defect as the means, one step removed. `x / n if n > 0 else 0.0`
   * renders an undefined ratio as a confident zero, and for these two the
   * zero is flattering: "0% false positives" and "0% escalated" are the best
   * numbers on the page, and a tenant that had resolved nothing and gated
   * nothing scored both. The API now sends each rate's denominator.
   */
  it('reports both rates as unmeasured when their denominators are empty', () => {
    swrData.set('soc-metrics', {
      kpis: {
        ...KPIS,
        mttd_sample_count: 1,
        mttr_sample_count: 1,
        mttc_sample_count: 1,
        mttd_hours: 1.1,
        mttr_hours: 2.2,
        mttc_hours: 3.3,
        false_positive_rate_sample_count: 0,
        escalation_rate_sample_count: 0,
      },
      attack_heatmap: [],
      calibration_curve: [],
    });

    render(<SOCMetricsDashboard />);

    // Exactly the two rate tiles; the three means have samples here, so a
    // count of two also proves the change did not blank anything else.
    expect(screen.getAllByText(/not measured/i).length).toBe(2);
    expect(screen.getByText(/no resolved alerts in 7d/i)).toBeTruthy();
    expect(screen.getByText(/no gate decisions in 7d/i)).toBeTruthy();
    expect(screen.queryByText('0.0%')).toBeNull();
  });

  it('renders each rate, and what it was computed over, once the denominator is non-empty', () => {
    swrData.set('soc-metrics', {
      kpis: {
        ...KPIS,
        false_positive_rate: 0.25,
        false_positive_rate_sample_count: 8,
        escalation_rate: 0.5,
        escalation_rate_sample_count: 4,
      },
      attack_heatmap: [],
      calibration_curve: [],
    });

    render(<SOCMetricsDashboard />);

    expect(screen.getByText('25.0%')).toBeTruthy();
    expect(screen.getByText(/over 8 resolved alerts in 7d/i)).toBeTruthy();
    expect(screen.getByText('50.0%')).toBeTruthy();
    expect(screen.getByText(/over 4 gate decisions in 7d/i)).toBeTruthy();
  });

  it('keeps rendering rates for an API build that sends no denominators', () => {
    // Same back-compatibility rule as the means: additive fields, and an
    // older API must not blank the tiles.
    swrData.set('soc-metrics', {
      kpis: { ...KPIS, false_positive_rate: 0.1, escalation_rate: 0.2, mttd_sample_count: 1, mttr_sample_count: 1, mttc_sample_count: 1 },
      attack_heatmap: [],
      calibration_curve: [],
    });

    render(<SOCMetricsDashboard />);

    expect(screen.getByText('10.0%')).toBeTruthy();
    expect(screen.getByText('20.0%')).toBeTruthy();
    expect(screen.queryByText(/not measured/i)).toBeNull();
  });

  it('does not label an hours figure as minutes on the operations strip', () => {
    // `alerts.mttr` is hours and the tile rendered it with an `m` suffix, so
    // a 1.5-hour MTTR would have read "1.5m" had it ever been non-zero.
    swrData.set('dashboard-metrics', {
      alerts: { total: 1, new: 1, critical: 0, high: 0, medium: 1, low: 0, resolvedToday: 0, mttr: 1.5, mttr_sample_count: 2 },
      cases: { open: 0, inProgress: 0, resolvedThisWeek: 0 },
      sources: [],
      topMitre: [],
      alertsTrend: [],
      threatsBySource: [],
    });

    render(<DashboardView />);

    expect(screen.getByText('1.5h')).toBeTruthy();
    expect(screen.queryByText('1.5m')).toBeNull();
  });

  it('reports the operations strip MTTR as unmeasured when no case has closed', () => {
    swrData.set('dashboard-metrics', {
      alerts: { total: 1, new: 1, critical: 0, high: 0, medium: 1, low: 0, resolvedToday: 0, mttr: 0, mttr_sample_count: 0 },
      cases: { open: 0, inProgress: 0, resolvedThisWeek: 0 },
      sources: [],
      topMitre: [],
      alertsTrend: [],
      threatsBySource: [],
    });

    render(<DashboardView />);

    expect(screen.getByText(/not measured · no cases closed/i)).toBeTruthy();
    expect(screen.queryByText('0m')).toBeNull();
    expect(screen.queryByText('0.0h')).toBeNull();
  });
});

describe('demo mode still populates the dashboards', () => {
  it('renders the sample connector inventory when the build is the hosted demo', () => {
    // The gate must not have become "never show sample data anywhere" — the
    // hosted demo has no backend of its own and is the reason the mocks exist.
    __setDemoModeForTests(true);
    // In demo mode `demoFallback` supplies the mock as SWR fallbackData, which
    // the mocked SWR above models by seeding the same cache key.
    swrData.set('dashboard-metrics', {
      alerts: { total: 1247, new: 89, critical: 12, high: 43, medium: 156, low: 289, resolvedToday: 67, mttr: 42 },
      cases: { open: 23, inProgress: 15, resolvedThisWeek: 34 },
      sources: [{ name: 'CrowdStrike EDR', count: 412, status: 'active' }],
      topMitre: [{ tactic: 'Execution', count: 89 }],
      alertsTrend: [],
      threatsBySource: [],
    });

    render(<DashboardView />);

    expect(screen.getByText('CrowdStrike EDR')).toBeTruthy();
  });
});
