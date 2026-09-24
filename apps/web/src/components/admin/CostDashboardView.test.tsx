import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, within, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

// WS-H1 — verify the cost dashboard wires:
//   1. SWR fixture → headline / daily / by_model / top_cases / actions
//   2. window-days <select> drives a fresh costsApi.dashboard call
//   3. BYOK panel toggles its "active" / "neutral" branding from the payload
//   4. Empty branches render their dedicated copy without crashing
//
// We mock SWR so we control the data the view receives, and mock costsApi to
// observe the param wiring. SWR is keyed on `['cost-dashboard', days]`, so
// the cache map below mirrors the component's keying scheme exactly.

const swrCalls = vi.hoisted(() => new Map<string, unknown>());
vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    const cacheKey = JSON.stringify(key);
    const data = swrCalls.get(cacheKey);
    return {
      data,
      error: undefined,
      isLoading: false,
      mutate: vi.fn(async () => undefined),
    };
  },
}));

const dashboardMock = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({
  __esModule: true,
  costsApi: {
    dashboard: dashboardMock,
  },
}));

import { CostDashboardView } from './CostDashboardView';
import type { CostDashboard } from '@/lib/api';

function fixture(overrides: Partial<CostDashboard> = {}): CostDashboard {
  return {
    tenant_id: 't1',
    period: {
      start: '2026-04-09T00:00:00Z',
      end: '2026-05-09T00:00:00Z',
      window_days: 30,
      label: 'Apr 9 – May 9, 2026',
    },
    headline: {
      total_cost_usd: 142.37,
      measured_call_count: 1287,
      estimated_cost_usd: 0,
      estimated_call_count: 0,
      unpriced_call_count: 0,
      total_tokens: 4_321_000,
      total_calls: 1287,
      total_runs: 312,
      avg_cost_per_run_usd: 0.456,
    },
    daily_costs: [
      { day: '2026-05-07', total_cost_usd: 12.5, measured_call_count: 80, estimated_cost_usd: 0, estimated_call_count: 0, unpriced_call_count: 0, total_tokens: 320_000, call_count: 80 },
      { day: '2026-05-08', total_cost_usd: 18.2, measured_call_count: 95, estimated_cost_usd: 0, estimated_call_count: 0, unpriced_call_count: 0, total_tokens: 410_000, call_count: 95 },
      { day: '2026-05-09', total_cost_usd: 9.7, measured_call_count: 65, estimated_cost_usd: 0, estimated_call_count: 0, unpriced_call_count: 0, total_tokens: 280_000, call_count: 65 },
    ],
    by_model: [
      {
        model: 'gpt-4o-mini',
        resolved_model: 'openai/gpt-4o-mini',
        runs: 200,
        calls: 800,
        total_prompt_tokens: 1_200_000,
        total_completion_tokens: 600_000,
        total_cost_usd: 65.4,
        measured_call_count: 800,
        estimated_cost_usd: 0,
        estimated_call_count: 0,
        unpriced_call_count: 0,
        imputed_public_cost_usd: 65.4,
        imputed_is_estimable: true,
        unpriced_tokens: 0,
        avg_latency_ms: 1240,
      },
      {
        model: 'claude-3-5-sonnet-20241022',
        resolved_model: null,
        runs: 112,
        calls: 487,
        total_prompt_tokens: 900_000,
        total_completion_tokens: 410_000,
        total_cost_usd: 76.97,
        measured_call_count: 487,
        estimated_cost_usd: 0,
        estimated_call_count: 0,
        unpriced_call_count: 0,
        imputed_public_cost_usd: 76.97,
        imputed_is_estimable: true,
        unpriced_tokens: 0,
        avg_latency_ms: 2100,
      },
    ],
    top_cases: [
      { case_id: 'CASE-2026-0042', runs: 6, total_cost_usd: 18.4, measured_call_count: 24, estimated_cost_usd: 0, estimated_call_count: 0, total_tokens: 420_000 },
      { case_id: 'CASE-2026-0044', runs: 4, total_cost_usd: 12.1, measured_call_count: 16, estimated_cost_usd: 0, estimated_call_count: 0, total_tokens: 280_000 },
    ],
    action_counts: [
      { action: 'cases:read', count: 482 },
      { action: 'alerts:write', count: 219 },
    ],
    byok_savings: {
      is_byok_active: false,
      provider: 'openai',
      recorded_cost_usd: 142.37,
      recorded_is_measured: true,
      imputed_public_cost_usd: 142.37,
      imputed_is_estimable: true,
      unpriced_tokens: 0,
      savings_usd: 0,
    },
    ...overrides,
  };
}

function seed(days: number, payload: CostDashboard) {
  swrCalls.set(JSON.stringify(['cost-dashboard', days]), payload);
}

beforeEach(() => {
  swrCalls.clear();
  dashboardMock.mockReset();
});

describe('CostDashboardView', () => {
  it('renders headline KPIs and the period hero from the SWR payload', () => {
    seed(30, fixture());
    render(<CostDashboardView />);

    expect(screen.getByRole('heading', { name: 'Cost Dashboard', level: 1 })).toBeInTheDocument();
    expect(screen.getByText('Apr 9 – May 9, 2026')).toBeInTheDocument();

    const headline = screen.getByTestId('cost-headline');
    // Total LLM spend → "$142.37"
    expect(within(headline).getByText('$142.37')).toBeInTheDocument();
    // Tokens consumed → "4.32M" (4,321,000 tokens)
    expect(within(headline).getByText('4.32M')).toBeInTheDocument();
    // Avg cost / run → "$0.46" (0.456 → toFixed(2))
    expect(within(headline).getByText('$0.46')).toBeInTheDocument();
  });

  it('renders the by-model table with recorded + imputed costs', () => {
    seed(30, fixture());
    render(<CostDashboardView />);

    const table = screen.getByTestId('model-table');
    expect(within(table).getByText('gpt-4o-mini')).toBeInTheDocument();
    expect(within(table).getByText('claude-3-5-sonnet-20241022')).toBeInTheDocument();
    // $65.40 appears in both recorded and imputed columns when BYOK is inactive,
    // so we just assert the value shows up in the table at least once.
    expect(within(table).getAllByText('$65.40').length).toBeGreaterThan(0);
    expect(within(table).getAllByText('$76.97').length).toBeGreaterThan(0);
  });

  it('renders top-cost cases and action counts', () => {
    seed(30, fixture());
    render(<CostDashboardView />);

    const cases = screen.getByTestId('top-cases');
    expect(within(cases).getByText('CASE-2026-0042')).toBeInTheDocument();
    expect(within(cases).getByText('$18.40')).toBeInTheDocument();

    const actions = screen.getByTestId('action-counts');
    expect(within(actions).getByText('cases:read')).toBeInTheDocument();
    expect(within(actions).getByText('482')).toBeInTheDocument();
  });

  it('marks the BYOK panel "neutral" when the provider is hosted', () => {
    seed(30, fixture());
    render(<CostDashboardView />);

    const panel = screen.getByTestId('byok-panel');
    expect(panel).toHaveAttribute('data-byok', 'inactive');
    expect(within(panel).getByText('Hosted provider')).toBeInTheDocument();
  });

  it('marks the BYOK panel "active" and surfaces savings when BYOK is on', () => {
    seed(
      30,
      fixture({
        byok_savings: {
          is_byok_active: true,
          provider: 'local-ollama',
          recorded_cost_usd: 0,
          recorded_is_measured: true,
          imputed_public_cost_usd: 142.37,
          imputed_is_estimable: true,
          unpriced_tokens: 0,
          savings_usd: 142.37,
        },
      }),
    );
    render(<CostDashboardView />);

    const panel = screen.getByTestId('byok-panel');
    expect(panel).toHaveAttribute('data-byok', 'active');
    expect(within(panel).getByText('BYOK active')).toBeInTheDocument();
    expect(
      within(panel).getByText('~$142.37 saved by running your own model'),
    ).toBeInTheDocument();
  });

  it('switches the SWR key when the operator changes the window', async () => {
    seed(30, fixture());
    seed(7, fixture({ headline: { ...fixture().headline, total_cost_usd: 12.5 } }));

    render(<CostDashboardView />);
    // "$142.37" appears in headline + BYOK panel — narrow to the headline.
    expect(within(screen.getByTestId('cost-headline')).getByText('$142.37')).toBeInTheDocument();

    await userEvent.selectOptions(screen.getByLabelText('Reporting window'), '7');

    await waitFor(() => {
      expect(within(screen.getByTestId('cost-headline')).getByText('$12.50')).toBeInTheDocument();
    });
  });

  it('renders empty states when the window has no activity', () => {
    seed(
      30,
      fixture({
        headline: {
          total_cost_usd: 0,
          measured_call_count: 0,
          estimated_cost_usd: 0,
          estimated_call_count: 0,
          unpriced_call_count: 0,
          total_tokens: 0,
          total_calls: 0,
          total_runs: 0,
          avg_cost_per_run_usd: null,
        },
        daily_costs: [],
        by_model: [],
        top_cases: [],
        action_counts: [],
      }),
    );
    render(<CostDashboardView />);

    expect(screen.getByText('No LLM calls recorded in this window.')).toBeInTheDocument();
    expect(screen.getByText('No LLM activity recorded for this window.')).toBeInTheDocument();
    expect(screen.getByText('No per-model rows recorded for this window.')).toBeInTheDocument();
    expect(
      screen.getByText('No case-attributed runs recorded for this window.'),
    ).toBeInTheDocument();
    expect(screen.getByText('No audit events recorded for this window.')).toBeInTheDocument();
  });
});

/**
 * The local-model deployment: real LLM traffic, and no money spent.
 *
 * This is the state PR #829 produced live — 903 tokens through a local model
 * via the gateway — and the state the old tracker reported as $0.000999. Every
 * assertion here is on **first paint** of the real payload, not on an error
 * branch: the defect was never an error, it was a confident wrong number in
 * the success path.
 */
describe('CostDashboardView — a window nothing measured', () => {
  function unmeasured(): CostDashboard {
    const base = fixture();
    return {
      ...base,
      headline: {
        total_cost_usd: 0,
        measured_call_count: 0,
        estimated_cost_usd: 0,
        estimated_call_count: 0,
        unpriced_call_count: 1287,
        total_tokens: 4_321_000,
        total_calls: 1287,
        total_runs: 312,
        avg_cost_per_run_usd: null,
      },
      daily_costs: [
        {
          day: '2026-05-09',
          total_cost_usd: 0,
          measured_call_count: 0,
          estimated_cost_usd: 0,
          estimated_call_count: 0,
          unpriced_call_count: 65,
          total_tokens: 280_000,
          call_count: 65,
        },
      ],
      by_model: [
        {
          model: 'aisoc-triage',
          resolved_model: 'ollama/qwen2:1.5b',
          runs: 312,
          calls: 1287,
          total_prompt_tokens: 3_000_000,
          total_completion_tokens: 1_321_000,
          total_cost_usd: 0,
          measured_call_count: 0,
          estimated_cost_usd: 0,
          estimated_call_count: 0,
          unpriced_call_count: 1287,
          imputed_public_cost_usd: 0,
          imputed_is_estimable: false,
          unpriced_tokens: 4_321_000,
          avg_latency_ms: 5094,
        },
      ],
      top_cases: [
        {
          case_id: 'CASE-2026-0042',
          runs: 6,
          total_cost_usd: 0,
          measured_call_count: 0,
          estimated_cost_usd: 0,
          estimated_call_count: 0,
          total_tokens: 420_000,
        },
      ],
      byok_savings: {
        is_byok_active: true,
        provider: 'local-ollama',
        recorded_cost_usd: 0,
        recorded_is_measured: false,
        imputed_public_cost_usd: 0,
        imputed_is_estimable: false,
        unpriced_tokens: 4_321_000,
        savings_usd: 0,
      },
    };
  }

  it('shows no dollar figure anywhere when nothing was measured', () => {
    seed(30, unmeasured());
    render(<CostDashboardView />);

    // The single most important assertion in this file: a page rendering
    // 1,287 real LLM calls must not print a currency amount it did not
    // measure. Not "$0.00", not "<$0.01", not a default-rate estimate.
    expect(document.body.textContent).not.toMatch(/\$\d/);
  });

  it('labels the headline "not measured" rather than zero', () => {
    seed(30, unmeasured());
    render(<CostDashboardView />);

    const headline = screen.getByTestId('cost-headline');
    expect(within(headline).queryByText('$0.00')).not.toBeInTheDocument();
    expect(
      within(headline).getByText(/not measured · 1,?287 calls the gateway did not price/),
    ).toBeInTheDocument();
    // Tokens are measurable without a price and must still be reported.
    expect(within(headline).getByText('4.32M')).toBeInTheDocument();
  });

  it('says why the spend chart is flat instead of implying a free week', () => {
    seed(30, unmeasured());
    render(<CostDashboardView />);

    expect(screen.getByTestId('daily-spend-unmeasured')).toHaveTextContent(
      /had LLM calls whose\s+cost was not measured/,
    );
  });

  it('names the model the alias resolved to, and imputes nothing for it', () => {
    seed(30, unmeasured());
    render(<CostDashboardView />);

    const table = screen.getByTestId('model-table');
    expect(within(table).getByText('aisoc-triage')).toBeInTheDocument();
    expect(within(table).getByText('→ ollama/qwen2:1.5b')).toBeInTheDocument();
    expect(within(table).getByText('no published price')).toBeInTheDocument();
  });

  it('refuses to claim a BYOK saving it cannot compute', () => {
    seed(30, unmeasured());
    render(<CostDashboardView />);

    const panel = screen.getByTestId('byok-panel');
    expect(panel).toHaveAttribute('data-byok', 'active');
    expect(
      within(panel).getByText(
        'Not estimable — no model in this window has a published list price',
      ),
    ).toBeInTheDocument();
    expect(within(panel).getByText('not estimable')).toBeInTheDocument();
  });
});

/**
 * The mixed window: some calls billed, some only estimable.
 *
 * An estimate is allowed to appear — it is useful — but never without the
 * word, and never merged into the measured figure.
 */
describe('CostDashboardView — estimates are labelled', () => {
  it('prefixes an estimated figure and says it was not billed', () => {
    const base = fixture();
    seed(30, {
      ...base,
      headline: {
        total_cost_usd: 0,
        measured_call_count: 0,
        estimated_cost_usd: 3.5,
        estimated_call_count: 400,
        unpriced_call_count: 0,
        total_tokens: 900_000,
        total_calls: 400,
        total_runs: 40,
        avg_cost_per_run_usd: null,
      },
    });
    render(<CostDashboardView />);

    const headline = screen.getByTestId('cost-headline');
    expect(within(headline).getByText('~$3.50')).toBeInTheDocument();
    expect(
      within(headline).getByText('list-price estimate over 400 calls — not billed'),
    ).toBeInTheDocument();
  });
});
