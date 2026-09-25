/**
 * Data-honesty gate for the SLA dashboard.
 *
 * `fallbackData: demoFallback(MOCK_SLA_METRICS)` was correct. One line later
 * `const metrics = isValidMetrics ? rawMetrics : MOCK_SLA_METRICS` threw the
 * gate away: outside the hosted demo `demoFallback` returns `undefined`, so
 * `isValidMetrics` is falsy on **first paint as well as on error**, and the
 * fabricated set rendered in both — 847 alerts, 23 breaches, a 2.7% breach
 * rate and a 42.5m MTTR, identical on every deployment.
 *
 * The disclosure banner was wired to `metricsError` alone, so during the
 * loading window the invented numbers appeared with nothing saying so. That
 * is why the first-paint case below is the load-bearing one: an error-only
 * test passes against the broken component.
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { axe } from 'vitest-axe';
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
  mutate: vi.fn(),
}));

import { SLADashboard } from './SLADashboard';

const METRICS_KEY = '/api/v1/sla/metrics?days=30';

/** Every figure `MOCK_SLA_METRICS` would put on screen. */
const FABRICATED_FIGURES = ['847', '23', '2.7%', '42.5m', '186', '312', '307'];

function expectNoFabricatedFigures() {
  for (const figure of FABRICATED_FIGURES) {
    expect(
      screen.queryAllByText(figure),
      `"${figure}" comes from MOCK_SLA_METRICS and must not render outside demo mode`,
    ).toHaveLength(0);
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

describe('SLADashboard — first paint', () => {
  /**
   * The state the error-only test cannot see. No data and no error is what
   * every non-demo deployment renders for the duration of the first request,
   * and SWR's `fallbackData` is `undefined` there, so the ternary reached
   * straight past it into the mock.
   */
  it('publishes no SLA figures before the API has answered', () => {
    render(<SLADashboard />);

    expectNoFabricatedFigures();
  });

  it('says the metrics have not loaded rather than showing a number', () => {
    render(<SLADashboard />);

    expect(screen.getByText(/not measured|no SLA data|loading/i)).toBeTruthy();
  });
});

describe('SLADashboard — API failure', () => {
  it('names the failure instead of substituting a baseline', () => {
    swrErrors.set(METRICS_KEY, new Error('HTTP 503'));

    render(<SLADashboard />);

    expectNoFabricatedFigures();
    expect(screen.getByText(/HTTP 503/i)).toBeTruthy();
  });

  it('does not describe fabricated numbers as something to explore', () => {
    swrErrors.set(METRICS_KEY, new Error('HTTP 500'));

    render(<SLADashboard />);

    // The old banner read "showing demo metrics so you can explore the
    // dashboard" on a deployment that is not the demo.
    expect(screen.queryByText(/showing demo metrics/i)).toBeNull();
  });
});

describe('SLADashboard — real data', () => {
  it('renders the tenant figures the API returned', () => {
    swrData.set(METRICS_KEY, {
      period_days: 30,
      computed_at: '2026-05-06T12:00:00Z',
      overall: {
        total_alerts: 6,
        total_breaches: 1,
        breach_rate: 16.7,
        mttd_avg: 3.0,
        mttr_avg: 9.0,
        mttc_avg: 12.0,
      },
      per_severity: {
        high: {
          total: 6,
          breaches: 1,
          breach_rate: 16.7,
          mttd_avg: 3.0,
          mttr_avg: 9.0,
          mttc_avg: 12.0,
          mttd_target: 30,
          mttr_target: 60,
          mttc_target: 120,
        },
      },
      kpi_bar: null,
    });

    render(<SLADashboard />);

    expect(screen.getByText('6')).toBeTruthy();
    expect(screen.getByText('16.7%')).toBeTruthy();
    expectNoFabricatedFigures();
  });

  it('reads an empty tenant as empty, not as 847 alerts', () => {
    swrData.set(METRICS_KEY, {
      period_days: 30,
      computed_at: '2026-05-06T12:00:00Z',
      overall: {
        total_alerts: 0,
        total_breaches: 0,
        breach_rate: 0,
        mttd_avg: null,
        mttr_avg: null,
        mttc_avg: null,
      },
      per_severity: {},
      kpi_bar: null,
    });

    render(<SLADashboard />);

    expectNoFabricatedFigures();
  });
});

describe('SLADashboard — accessibility', () => {
  // The unavailable/not-measured block is new and sits between the page `h1`
  // and the per-severity `h2`s, which is exactly where a heading-order
  // violation appears under the repo's axe gate.
  it('has no violations while the metrics are unavailable', async () => {
    swrErrors.set(METRICS_KEY, new Error('HTTP 503'));

    const { container } = render(<SLADashboard />);

    expect(
      await axe(container, { rules: { 'color-contrast': { enabled: false } } }),
    ).toHaveNoViolations();
  });
});

describe('SLADashboard — hosted demo', () => {
  it('is still populated when the build is the demo', () => {
    __setDemoModeForTests(true);
    // In demo mode `demoFallback` hands the mock to SWR as `fallbackData`,
    // which the mock above models by seeding the same cache key.
    swrData.set(METRICS_KEY, {
      period_days: 30,
      computed_at: '2026-05-06T12:00:00Z',
      overall: {
        total_alerts: 847,
        total_breaches: 23,
        breach_rate: 2.7,
        mttd_avg: 24.4,
        mttr_avg: 42.5,
        mttc_avg: 112.0,
      },
      per_severity: {},
      kpi_bar: null,
    });

    render(<SLADashboard />);

    expect(screen.getByText('847')).toBeTruthy();
  });
});
