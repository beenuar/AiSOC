/**
 * SOC operations dashboard.
 *
 * Two properties under test.
 *
 * **Honesty.** Each panel renders real figures, an honest empty state, or an
 * error state — never a plausible-looking number it did not receive. These
 * dashboards have shipped the third option before, so the assertions are
 * written as negatives against the specific failure: nothing numeric on the
 * screen when the API is down.
 *
 * **Isolation.** Each panel owns its own fetch. One dead endpoint must blank
 * one panel and say why, not take the page down and not silently degrade the
 * others. That is asserted directly by failing one endpoint and checking the
 * rest still render their real values.
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { SWRConfig } from 'swr';
import { axe } from 'vitest-axe';

const fleetHealth = vi.hoisted(() => vi.fn());
const deadLetters = vi.hoisted(() => vi.fn());
const alertStats = vi.hoisted(() => vi.fn());
const costDashboard = vi.hoisted(() => vi.fn());
const listApprovals = vi.hoisted(() => vi.fn());
const coverage = vi.hoisted(() => vi.fn());
const getFunnel = vi.hoisted(() => vi.fn());
const getPipelineHealth = vi.hoisted(() => vi.fn());

vi.mock('@/lib/api', () => ({
  __esModule: true,
  operationsApi: { fleetHealth, deadLetters, alertStats },
  costsApi: { dashboard: costDashboard },
  responderApi: { listApprovals },
  detectionApi: { coverage },
  metricsApi: { getFunnel, getPipelineHealth },
}));

vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ children, href }: { children: React.ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}));

import { OperationsDashboard } from './OperationsDashboard';
import { formatStaleness } from './ConnectorFleetPanel';
import { formatWaitingFor } from './ResponseActionsPanel';
import { thinnestTactics } from './DetectionCoveragePanel';

const FLEET = {
  generated_at: '2026-05-06T12:00:00Z',
  state: 'degraded',
  counts: { healthy: 1, degraded: 1, failed: 0, unproven: 0, disabled: 0 },
  connectors: [
    {
      connector_id: 'c-healthy',
      name: 'Prod CloudTrail',
      connector_type: 'aws_cloudtrail',
      state: 'healthy' as const,
      reason: 'Synced 2 minutes ago, within its 5 minute cadence.',
      last_sync: '2026-05-06T11:58:00Z',
      seconds_since_sync: 120,
      poll_interval_seconds: 300,
      missed_intervals: 0.4,
      error_count: 0,
      events_ingested: 48_120,
      oauth_refresh_failures: 0,
      schema_drift_at: null,
    },
    {
      connector_id: 'c-stale',
      name: 'Corp Okta',
      connector_type: 'okta',
      state: 'degraded' as const,
      reason: 'No successful sync for 3.2 poll intervals.',
      last_sync: '2026-05-06T11:44:00Z',
      seconds_since_sync: 960,
      poll_interval_seconds: 300,
      missed_intervals: 3.2,
      error_count: 4,
      events_ingested: 900,
      oauth_refresh_failures: 1,
      schema_drift_at: null,
    },
  ],
};

const DEAD_LETTERS = {
  window_hours: 24,
  total: 17,
  by_reason: [
    { reason: 'schema_validation_failed', count: 12 },
    { reason: 'unknown_tenant', count: 5 },
  ],
  truncated: false,
  dead_letters: [],
};

const ALERT_STATS = {
  total: 128,
  by_severity: { critical: 3, high: 14, medium: 60, low: 51 },
  by_status: { new: 22, investigating: 9, resolved: 80, false_positive: 17 },
  new_last_24h: 22,
  critical_open: 3,
};

const COSTS = {
  tenant_id: 't',
  period: { start: '', end: '', window_days: 7, label: '7d' },
  headline: {
    total_cost_usd: 4.21,
    measured_call_count: 612,
    estimated_cost_usd: 0,
    estimated_call_count: 0,
    unpriced_call_count: 0,
    total_tokens: 1_840_000,
    total_calls: 612,
    total_runs: 96,
    avg_cost_per_run_usd: 0.0438,
  },
  daily_costs: [],
  by_model: [
    {
      model: 'local-llm',
      resolved_model: null,
      runs: 96,
      calls: 612,
      total_prompt_tokens: 1_500_000,
      total_completion_tokens: 340_000,
      total_cost_usd: 4.21,
      measured_call_count: 612,
      estimated_cost_usd: 0,
      estimated_call_count: 0,
      unpriced_call_count: 0,
      imputed_public_cost_usd: 9.1,
      unpriced_tokens: 0,
      avg_latency_ms: 880,
    },
  ],
  top_cases: [],
  action_counts: [],
  byok_savings: {
    is_byok_active: true,
    provider: 'local',
    recorded_cost_usd: 4.21,
    recorded_is_measured: true,
    imputed_public_cost_usd: 9.1,
    unpriced_tokens: 0,
    savings_usd: 4.89,
  },
};

const APPROVALS = {
  items: [
    {
      id: 'ap-1',
      tenant_id: 't',
      run_id: null,
      case_id: 'INC-1',
      alert_id: null,
      requested_by: 'agent',
      required_user_id: null,
      required_topic: null,
      title: 'Isolate WIN-DC01',
      summary: 'Ransomware encryption behaviour observed.',
      risk_level: 'critical' as const,
      action: {},
      status: 'pending' as const,
      decided_by_id: null,
      decided_at: null,
      decision_comment: null,
      expires_at: null,
      created_at: new Date(Date.now() - 45 * 60_000).toISOString(),
      updated_at: '',
    },
  ],
  total: 1,
  page: 1,
  page_size: 25,
  pages: 1,
};

const COVERAGE = {
  tactics: ['Execution', 'Persistence'],
  cells: [
    { techniqueId: 'T1059', tactic: 'Execution', totalRules: 3, activeRules: 2, inactiveRules: 1 },
    { techniqueId: 'T1547', tactic: 'Persistence', totalRules: 2, activeRules: 0, inactiveRules: 2 },
    { techniqueId: 'T1053', tactic: 'Persistence', totalRules: 1, activeRules: 1, inactiveRules: 0 },
    { techniqueId: 'T9999', tactic: null, totalRules: 1, activeRules: 1, inactiveRules: 0 },
  ],
  summary: {
    totalRules: 7,
    activeRules: 4,
    inactiveRules: 3,
    techniques: 4,
    coveredTechniques: 3,
  },
  generatedAt: '2026-05-06T12:00:00Z',
};

const FUNNEL = {
  period: '24h',
  events_of_interest: 1234,
  correlation_instances: 87,
  alerts_generated: 42,
  signal_to_noise: 0.83,
  mttd_seconds: 480,
  analyst_queue_depth: 9,
  correlation_efficiency: 0.48,
  alert_yield: 0.03,
  mitre_coverage: { covered: 3, total: 4, ratio: 0.75 },
  deltas: {
    events_of_interest: 0.1,
    correlation_instances: 0,
    alerts_generated: -0.05,
    signal_to_noise: 0.02,
    mttd_seconds: -0.1,
    analyst_queue_depth: 0,
  },
  generated_at: '2026-05-06T12:00:00Z',
};

const PIPELINE = {
  overall_status: 'green',
  stages: [],
  generated_at: '2026-05-06T12:00:00Z',
};

function renderDashboard() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <OperationsDashboard />
    </SWRConfig>,
  );
}

/** All endpoints healthy. Individual tests override one. */
function happyPath() {
  fleetHealth.mockResolvedValue(FLEET);
  deadLetters.mockResolvedValue(DEAD_LETTERS);
  alertStats.mockResolvedValue(ALERT_STATS);
  costDashboard.mockResolvedValue(COSTS);
  listApprovals.mockResolvedValue(APPROVALS);
  coverage.mockResolvedValue(COVERAGE);
  getFunnel.mockResolvedValue(FUNNEL);
  getPipelineHealth.mockResolvedValue(PIPELINE);
}

beforeEach(() => {
  for (const m of [
    fleetHealth, deadLetters, alertStats, costDashboard, listApprovals, coverage,
    getFunnel, getPipelineHealth,
  ]) {
    m.mockReset();
  }
  happyPath();
});

afterEach(() => cleanup());

describe('panels render real API values', () => {
  it('reports connector staleness against each connector\u2019s own cadence', async () => {
    renderDashboard();

    expect(await screen.findByText('Corp Okta')).toBeTruthy();
    // Cadence-relative, not wall-clock: 960s is only late because the
    // interval is 300s.
    expect(screen.getByText('3.2 intervals behind')).toBeTruthy();
    expect(screen.getByText(/No successful sync for 3.2 poll intervals/)).toBeTruthy();
    expect(screen.getByText('1 need attention')).toBeTruthy();
  });

  it('groups rejected events by the reason the pipeline gave', async () => {
    renderDashboard();

    expect(await screen.findByText('schema_validation_failed')).toBeTruthy();
    const panel = within(
      screen.getByRole('region', { name: /Rejected events/i }),
    );
    expect(panel.getByText('unknown_tenant')).toBeTruthy();
    expect(panel.getByText('17')).toBeTruthy();
    expect(panel.getByText('12')).toBeTruthy();
  });

  it('shows alert posture with the two counters worth acting on', async () => {
    renderDashboard();

    expect(await screen.findByText('128')).toBeTruthy();
    expect(screen.getByText(/By disposition/i)).toBeTruthy();
    expect(screen.getByText('False positive')).toBeTruthy();
  });

  it('labels agent throughput as runs, which is what the endpoint measures', async () => {
    renderDashboard();

    expect(await screen.findByText('Runs')).toBeTruthy();
    expect(screen.getByText('96')).toBeTruthy();
    expect(screen.getByText('$4.21')).toBeTruthy();
    // `total_runs` is investigation runs, not alerts triaged. Calling it the
    // latter would be a different measurement than the one taken.
    expect(screen.queryByText(/alerts triaged/i)).toBeNull();
  });

  it('surfaces pending containment with its age and links to where it is decided', async () => {
    renderDashboard();

    expect(await screen.findByText('Isolate WIN-DC01')).toBeTruthy();
    expect(screen.getByText('waiting 45m')).toBeTruthy();
    expect(
      screen.getAllByRole('link').some((a) => a.getAttribute('href') === '/responder/approvals'),
    ).toBe(true);
  });

  it('counts disabled rules against coverage rather than folding them into a total', async () => {
    renderDashboard();

    expect(await screen.findByText('3 / 4')).toBeTruthy();
    expect(screen.getByText('3 disabled')).toBeTruthy();
  });
});

describe('one dead endpoint does not degrade the rest', () => {
  it('blanks only the failing panel and names the failure', async () => {
    fleetHealth.mockRejectedValue(new Error('API 503 Service Unavailable'));
    renderDashboard();

    // The failing panel says so.
    expect(await screen.findByText(/Fleet health unavailable/i)).toBeTruthy();
    expect(screen.getByText(/API 503 Service Unavailable/)).toBeTruthy();
    // And invents nothing in its place.
    expect(screen.queryByText('Corp Okta')).toBeNull();

    // Neighbouring panels still show their real values.
    expect(screen.getByText('schema_validation_failed')).toBeTruthy();
    expect(screen.getByText('Isolate WIN-DC01')).toBeTruthy();
  });

  it('shows no figures at all when every endpoint is down', async () => {
    const down = new Error('network unreachable');
    for (const m of [
      fleetHealth, deadLetters, alertStats, costDashboard, listApprovals, coverage,
      getFunnel, getPipelineHealth,
    ]) {
      m.mockRejectedValue(down);
    }
    renderDashboard();

    await screen.findByText(/Fleet health unavailable/i);
    // Every figure that would otherwise render is sourced from a payload that
    // never arrived, so none of them may appear.
    for (const fabricated of ['128', '96', '$4.21', '3 / 4', '17']) {
      expect(screen.queryByText(fabricated), fabricated).toBeNull();
    }
  });
});

describe('first paint shows nothing rather than something plausible', () => {
  // The bug this repo shipped twice was not in the error branch — error was
  // handled — it was that `data` is also undefined on first paint, so a
  // `data ?? MOCK` expression rendered the mock silently, with no banner,
  // for as long as the request took. On a deployment whose API is slow or
  // unreachable that is the whole session. A test that only fails the
  // endpoint never reaches this state, so it has to be asserted directly.
  it('renders a skeleton, not sample data, while requests are in flight', async () => {
    for (const m of [
      fleetHealth, deadLetters, alertStats, costDashboard, listApprovals, coverage,
      getFunnel, getPipelineHealth,
    ]) {
      m.mockReturnValue(new Promise(() => {})); // never settles
    }

    renderDashboard();
    // Let SWR flush its initial render.
    await new Promise((r) => setTimeout(r, 0));

    for (const value of ['Corp Okta', 'Prod CloudTrail', 'schema_validation_failed', '128', '96', '$4.21']) {
      expect(screen.queryByText(value), value).toBeNull();
    }
  });
});

describe('honest empty states', () => {
  it('distinguishes "nothing rejected" from "the panel failed"', async () => {
    deadLetters.mockResolvedValue({ ...DEAD_LETTERS, total: 0, by_reason: [] });
    renderDashboard();

    expect(await screen.findByText(/Nothing rejected/i)).toBeTruthy();
    expect(screen.queryByText(/Dead-letter counts unavailable/i)).toBeNull();
  });

  it('explains an empty alert queue when no connector is configured', async () => {
    fleetHealth.mockResolvedValue({ ...FLEET, connectors: [], counts: {} });
    alertStats.mockResolvedValue({ ...ALERT_STATS, total: 0, by_severity: {}, by_status: {} });
    renderDashboard();

    expect(await screen.findByText(/No connectors configured/i)).toBeTruthy();
    expect(screen.getByText(/No alerts recorded/i)).toBeTruthy();
  });

  it('claims no fleet is reporting when there is no fleet', async () => {
    // The badge rendered whenever the endpoint answered, and with zero
    // connectors `failed + degraded` is zero — so it printed a green "All
    // sources reporting" directly above "No connectors configured". Zero
    // sources reporting is not the same statement as all of them reporting,
    // and green is the part an operator scans for.
    fleetHealth.mockResolvedValue({ ...FLEET, connectors: [], counts: {} });
    renderDashboard();

    expect(await screen.findByText(/No connectors configured/i)).toBeTruthy();
    expect(screen.queryByText(/All sources reporting/i)).toBeNull();
    expect(screen.queryByText(/sources reporting/i)).toBeNull();
  });

  it('counts the fleet it is vouching for when every connector is healthy', async () => {
    const healthy = FLEET.connectors.map((c) => ({
      ...c,
      state: 'healthy' as const,
      last_sync: new Date().toISOString(),
      missed_intervals: 0,
      seconds_since_sync: 30,
    }));
    fleetHealth.mockResolvedValue({
      ...FLEET,
      connectors: healthy,
      counts: { healthy: healthy.length },
    });
    renderDashboard();

    expect(await screen.findByText(`All ${healthy.length} sources reporting`)).toBeTruthy();
  });

  it('says nothing is waiting rather than rendering an empty list', async () => {
    listApprovals.mockResolvedValue({ ...APPROVALS, items: [], total: 0 });
    renderDashboard();

    expect(await screen.findByText(/Nothing waiting on a human/i)).toBeTruthy();
  });
});

describe('derived helpers', () => {
  it('formatStaleness prefers cadence-relative wording once a poll is missed', () => {
    const base = FLEET.connectors[0];
    expect(formatStaleness({ ...base, missed_intervals: 3.24 })).toBe('3.2 intervals behind');
    // Under one interval, wall-clock is the more useful reading.
    expect(formatStaleness({ ...base, missed_intervals: 0.2, seconds_since_sync: 60 })).toBe(
      'synced just now',
    );
    expect(formatStaleness({ ...base, missed_intervals: 0.2, seconds_since_sync: 7200 })).toBe(
      'synced 2h ago',
    );
    expect(formatStaleness({ ...base, last_sync: null })).toBe('never synced');
    expect(
      formatStaleness({ ...base, missed_intervals: null, seconds_since_sync: null }),
    ).toBe('sync time unknown');
  });

  it('formatWaitingFor reads an approval age without inventing precision', () => {
    const now = Date.parse('2026-05-06T12:00:00Z');
    expect(formatWaitingFor('2026-05-06T11:59:40Z', now)).toBe('waiting <1m');
    expect(formatWaitingFor('2026-05-06T11:15:00Z', now)).toBe('waiting 45m');
    expect(formatWaitingFor('2026-05-06T09:00:00Z', now)).toBe('waiting 3h');
    expect(formatWaitingFor('not-a-date', now)).toBe('waiting');
  });

  it('thinnestTactics ranks by active coverage and skips untagged techniques', () => {
    const ranked = thinnestTactics(COVERAGE);
    // Persistence is 1/2 covered, Execution 1/1. The `tactic: null` cell is
    // counted in the summary but cannot be attributed to a tactic here.
    expect(ranked[0]).toEqual({ tactic: 'Persistence', covered: 1, total: 2 });
    expect(ranked.some((t) => t.tactic === null || t.tactic === 'Unknown')).toBe(false);
  });
});

describe('accessibility (WCAG 2.1 AA)', () => {
  const axeOptions = { rules: { 'color-contrast': { enabled: false } } };

  it('has no violations with every panel populated', async () => {
    const { container } = renderDashboard();
    await screen.findByText('Corp Okta');

    expect(await axe(container, axeOptions)).toHaveNoViolations();
  });
});
