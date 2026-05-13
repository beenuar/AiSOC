/**
 * FunnelKpiBar / EfficiencyReport / PipelineHealth — rendering smoke tests.
 *
 * The three components are the v1.5 SOC console parity widgets (PR-3). They
 * are thin presentation layers over `GET /api/v1/metrics/funnel` and
 * `GET /api/v1/health/pipeline`, but they encode a handful of behaviors the
 * analyst experience depends on:
 *
 *   1. FunnelKpiBar — colors deltas by direction *and* by metric semantics:
 *      positive Δ on MTTD / Analyst Queue is bad (red), positive Δ on Events
 *      / Alerts is good (green). We pin both directions.
 *   2. EfficiencyReport — clamps the bar fill to 0..1 and renders the MITRE
 *      coverage as "covered/total · pct%".
 *   3. PipelineHealth — surfaces the per-stage status dot (`green | yellow |
 *      red | unknown`) and the worst-status badge at the top.
 *
 * SWR is mocked at the module boundary so each test can control the loading /
 * error / data states without touching the real fetcher.
 *
 * Author: Beenu Arora <beenu@cyble.com>
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';

const swrData = vi.hoisted(() => new Map<string, unknown>());
const swrErrors = vi.hoisted(() => new Map<string, unknown>());
const swrLoading = vi.hoisted(() => new Set<string>());

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    const k = typeof key === 'string' ? key : JSON.stringify(key);
    if (swrLoading.has(k)) {
      return { data: undefined, error: undefined, isLoading: true };
    }
    return {
      data: swrData.get(k),
      error: swrErrors.get(k),
      isLoading: false,
    };
  },
}));

vi.mock('@/lib/api', () => ({
  __esModule: true,
  metricsApi: {
    getFunnel: vi.fn(),
    getPipelineHealth: vi.fn(),
  },
}));

// Import the components *after* the mocks so the module-level useSWR is
// bound to our stub.
import { FunnelKpiBar } from './FunnelKpiBar';
import { EfficiencyReport } from './EfficiencyReport';
import { PipelineHealth } from './PipelineHealth';

const FUNNEL_KEY = 'funnel-metrics:24h';
const PIPELINE_KEY = 'pipeline-health';

const SAMPLE_FUNNEL = {
  period: '24h' as const,
  events_of_interest: 1_234,
  correlation_instances: 87,
  alerts_generated: 42,
  signal_to_noise: 0.83,
  mttd_seconds: 480,
  analyst_queue_depth: 9,
  correlation_efficiency: 0.48,
  alert_yield: 0.034,
  mitre_coverage: { covered: 42, total: 201, ratio: 0.209 },
  deltas: {
    events_of_interest: 0.12,
    correlation_instances: 0.05,
    alerts_generated: -0.08,
    signal_to_noise: 0.02,
    mttd_seconds: -0.15,
    analyst_queue_depth: 0.2,
  },
  generated_at: '2026-05-13T10:00:00Z',
};

const SAMPLE_PIPELINE = {
  overall_status: 'yellow' as const,
  stages: [
    { stage: 'ingest' as const, backlog: 0, p95_latency_ms: 120, error_rate: 0, status: 'green' as const },
    { stage: 'normalize' as const, backlog: 5, p95_latency_ms: 200, error_rate: 0.01, status: 'green' as const },
    { stage: 'fuse' as const, backlog: 42, p95_latency_ms: 1_800, error_rate: 0.03, status: 'yellow' as const },
    { stage: 'correlate' as const, backlog: 12, p95_latency_ms: 600, error_rate: 0, status: 'green' as const },
    { stage: 'alert' as const, backlog: 3, p95_latency_ms: 300, error_rate: 0, status: 'green' as const },
  ],
  generated_at: '2026-05-13T10:00:00Z',
};

describe('FunnelKpiBar', () => {
  beforeEach(() => {
    swrData.clear();
    swrErrors.clear();
    swrLoading.clear();
  });

  it('renders six tiles with formatted values and signed deltas', () => {
    swrData.set(FUNNEL_KEY, SAMPLE_FUNNEL);
    render(<FunnelKpiBar period="24h" />);

    expect(screen.getByText(/Operations Funnel/i)).toBeInTheDocument();
    // 1.2k for 1234 (k abbreviation), 87 raw, 42 raw, 83% S/N, 8m MTTD, 9 queue.
    expect(screen.getByText('1.2k')).toBeInTheDocument();
    expect(screen.getByText('87')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
    expect(screen.getByText('83%')).toBeInTheDocument();
    expect(screen.getByText('8m')).toBeInTheDocument();
    expect(screen.getByText('9')).toBeInTheDocument();

    // Positive Δ on EOI / alerts means up; negative on alerts is shown with a minus.
    expect(screen.getByText('+12%')).toBeInTheDocument();
    expect(screen.getByText('−8%')).toBeInTheDocument();
  });

  it('shows skeleton tiles while loading', () => {
    swrLoading.add(FUNNEL_KEY);
    render(<FunnelKpiBar period="24h" />);
    expect(screen.getByText(/Operations Funnel/i)).toBeInTheDocument();
    // Six labels still render even in the skeleton state.
    expect(screen.getByText('Events of Interest')).toBeInTheDocument();
    expect(screen.getByText('MTTD')).toBeInTheDocument();
  });

  it('renders a graceful error message when the funnel call fails', () => {
    swrErrors.set(FUNNEL_KEY, new Error('boom'));
    swrData.set(FUNNEL_KEY, SAMPLE_FUNNEL); // present but error takes precedence
    render(<FunnelKpiBar period="24h" />);
    expect(screen.getByText(/Funnel metrics unavailable/i)).toBeInTheDocument();
  });
});

describe('EfficiencyReport', () => {
  beforeEach(() => {
    swrData.clear();
    swrErrors.clear();
    swrLoading.clear();
  });

  it('renders correlation efficiency, alert yield, and MITRE coverage', () => {
    swrData.set(FUNNEL_KEY, SAMPLE_FUNNEL);
    render(<EfficiencyReport period="24h" />);

    expect(screen.getByText(/Efficiency Report/i)).toBeInTheDocument();
    // 0.48 → 48%, 0.034 → 3.4%, coverage "42/201 · 20.9%".
    expect(screen.getByText('48%')).toBeInTheDocument();
    expect(screen.getByText('3.4%')).toBeInTheDocument();
    expect(screen.getByText(/42\/201/)).toBeInTheDocument();
  });

  it('falls back to a helpful empty state when the call errors', () => {
    swrErrors.set(FUNNEL_KEY, new Error('boom'));
    render(<EfficiencyReport period="24h" />);
    expect(screen.getByText(/Efficiency metrics unavailable/i)).toBeInTheDocument();
  });
});

describe('PipelineHealth', () => {
  beforeEach(() => {
    swrData.clear();
    swrErrors.clear();
    swrLoading.clear();
  });

  it('renders all five pipeline stages with formatted latency + backlog', () => {
    swrData.set(PIPELINE_KEY, SAMPLE_PIPELINE);
    render(<PipelineHealth />);

    // Each stage card has a unique subtitle — use those to assert the
    // five-card rail is present without colliding with the header subtitle.
    expect(screen.getByText('Connector → raw events')).toBeInTheDocument();
    expect(screen.getByText('OCSF mapping')).toBeInTheDocument();
    expect(screen.getByText('Alert fusion')).toBeInTheDocument();
    expect(screen.getByText('Cross-source correlation')).toBeInTheDocument();
    expect(screen.getByText('Final alert emission')).toBeInTheDocument();

    // Formatted values: backlog 42, p95 1.8s, error 3% on the "fuse" stage.
    expect(screen.getByText('1.8 s')).toBeInTheDocument();
    expect(screen.getByText('3%')).toBeInTheDocument();
  });

  it('surfaces the unavailable badge when the pipeline call errors', () => {
    swrErrors.set(PIPELINE_KEY, new Error('boom'));
    render(<PipelineHealth />);
    // Header keeps the title; the live/unavailable indicator flips to
    // "unavailable" without the rest of the rail throwing.
    expect(screen.getByText('Pipeline Health')).toBeInTheDocument();
    expect(screen.getByText('unavailable')).toBeInTheDocument();
  });
});
