/**
 * Smoke tests for the SOC Insights dashboard (T3.1).
 *
 * Three things must hold for the dashboard to be useful:
 *   1. It renders the 7 expected tile labels once data arrives.
 *   2. It shows a skeleton (not an empty grid) while data is loading.
 *   3. It renders a graceful error state when the API fails.
 *
 * The Sparkline math is unit-tested separately so we can keep these
 * tests fast and DOM-focused.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { SWRConfig } from 'swr';
import type { ReactElement } from 'react';

vi.mock('@/lib/api', () => ({
  insightsApi: {
    getSOC: vi.fn(),
  },
}));

vi.mock('@/lib/realtime', () => ({
  useRealtimeChannel: vi.fn(() => ({
    status: 'open',
    last: null,
    history: [],
    send: vi.fn(),
    reset: vi.fn(),
  })),
}));

import { insightsApi, type SOCInsightsResponse } from '@/lib/api';
import { SOCInsightsView } from './SOCInsightsView';
import { pointsToPath } from './Sparkline';

/**
 * SWR keeps a process-global cache by default. When one test parks a never-
 * resolving promise on the key (skeleton case), the next test inherits that
 * pending state and the new `mockResolvedValue` is ignored — the cache says
 * "we're already loading, don't re-fetch". Wrapping each render in a fresh
 * `SWRConfig` provider gives every test its own Map, so the cache cannot
 * leak across `describe` siblings. This is the standard pattern from the
 * SWR docs (https://swr.vercel.app/docs/advanced/cache).
 */
function renderIsolated(node: ReactElement) {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      {node}
    </SWRConfig>,
  );
}

const sampleResponse: SOCInsightsResponse = {
  window: '24h',
  generated_at: '2026-05-13T12:00:00Z',
  tenant_id: '00000000-0000-0000-0000-000000000001',
  manual_investigation_minutes: 45,
  tiles: [
    {
      key: 'mtta',
      label: 'MTTA',
      value: 1.2,
      unit: 'hours',
      previous_value: 1.5,
      delta_pct: -20.0,
      sparkline: { points: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24] },
    },
    {
      key: 'mttr',
      label: 'MTTR',
      value: 6.0,
      unit: 'hours',
      previous_value: 5.0,
      delta_pct: 20.0,
      sparkline: { points: [] },
    },
    {
      key: 'fp_rate',
      label: 'FP Rate',
      value: 0.12,
      unit: 'pct',
      previous_value: 0.18,
      delta_pct: -33.3,
      sparkline: { points: [] },
    },
    {
      key: 'alerts_per_day',
      label: 'Alerts / day',
      value: 42,
      unit: 'count',
      previous_value: 30,
      delta_pct: 40.0,
      sparkline: { points: [] },
    },
    {
      key: 'cases_per_day',
      label: 'Cases / day',
      value: 8,
      unit: 'count',
      previous_value: 6,
      delta_pct: 33.3,
      sparkline: { points: [] },
    },
    {
      key: 'agent_cost_per_investigation',
      label: 'Agent cost / investigation',
      value: 0.12,
      unit: 'usd',
      previous_value: 0.15,
      delta_pct: -20.0,
      sparkline: { points: [] },
    },
    {
      key: 'analyst_hours_saved',
      label: 'Analyst hours saved',
      value: 6,
      unit: 'hours_saved',
      previous_value: 4,
      delta_pct: 50.0,
      sparkline: { points: [] },
    },
  ],
};

describe('SOCInsightsView', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders a skeleton placeholder before data resolves', () => {
    // Hold the fetch open so the loading state stays visible.
    (insightsApi.getSOC as ReturnType<typeof vi.fn>).mockReturnValue(
      new Promise(() => {}),
    );

    renderIsolated(<SOCInsightsView />);

    expect(screen.getByLabelText(/loading soc insights/i)).toBeInTheDocument();
  });

  it('renders all seven tile labels once data arrives', async () => {
    (insightsApi.getSOC as ReturnType<typeof vi.fn>).mockResolvedValue(
      sampleResponse,
    );

    renderIsolated(<SOCInsightsView />);

    // Wait for at least one tile to land — proves the SWR cycle
    // completed without re-rendering into the error/loading branch.
    await waitFor(() =>
      expect(screen.getByText('MTTA')).toBeInTheDocument(),
    );

    for (const tile of sampleResponse.tiles) {
      expect(screen.getByText(tile.label)).toBeInTheDocument();
    }

    // The tile grid should contain exactly the 7 tiles — guards
    // against accidental duplication if SWR reshuffles a re-fetch
    // mid-render.
    const grid = screen.getByTestId('soc-insights-tiles');
    expect(grid.children.length).toBe(7);
  });

  it('renders an error state when the API call fails', async () => {
    (insightsApi.getSOC as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error('500 boom'),
    );

    renderIsolated(<SOCInsightsView />);

    await waitFor(() =>
      expect(screen.getByRole('alert')).toBeInTheDocument(),
    );
    expect(screen.getByText(/500 boom/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Sparkline math
// ---------------------------------------------------------------------------

describe('pointsToPath', () => {
  it('renders a flat midline for empty input', () => {
    // 0 → midpoint of viewbox so the tile reads "no data" instead of
    // looking broken.
    const path = pointsToPath([]);
    expect(path).toBe('0,15 100,15');
  });

  it('renders a flat midline for a single point', () => {
    const path = pointsToPath([7]);
    expect(path).toBe('0,15 100,15');
  });

  it('renders monotonic input as a left-to-right line', () => {
    const path = pointsToPath([0, 10]);
    // Two points → x = 0 then 100. Values map into the 10–90% band so
    // the second point ends at y = 30 - (24 + 3) = 3.00.
    expect(path.startsWith('0.00,')).toBe(true);
    expect(path.endsWith(' 100.00,3.00')).toBe(true);
  });

  it('emits one coordinate pair per point', () => {
    const points = [1, 2, 3, 4, 5, 6, 7, 8];
    const path = pointsToPath(points);
    expect(path.split(' ').length).toBe(points.length);
  });
});
