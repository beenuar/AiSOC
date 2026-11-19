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

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { SWRConfig } from 'swr';
import type { ReactElement, ReactNode } from 'react';

vi.mock('@/lib/api', () => ({
  getActiveTenantId: vi.fn(() => '00000000-0000-0000-0000-000000000001'),
  insightsApi: {
    getSOC: vi.fn(),
  },
  tenantsApi: { me: vi.fn() },
  // Needed because the view now binds to the real `TimeWindowProvider`, which
  // reconciles the window with the signed-in user's stored preference. Stubbed
  // rather than omitted: an absent export makes the provider throw during
  // render, which reads as a component failure rather than a missing mock.
  authApi: {
    currentUser: vi.fn(() => null),
    isAuthenticated: vi.fn(() => false),
    updateUserPreferences: vi.fn(() => Promise.resolve()),
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

import { authApi, getActiveTenantId, insightsApi, tenantsApi, type SOCInsightsResponse } from '@/lib/api';
import { useRealtimeChannel } from '@/lib/realtime';
import { TenantProvider, useTenant } from '@/components/layout/TenantProvider';
import { TimeWindowProvider } from '@/components/layout/TimeWindowProvider';
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
  const cache = new Map();
  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <SWRConfig value={{ provider: () => cache, revalidateOnMount: true, shouldRetryOnError: false }}>
        <TimeWindowProvider>
          <TenantProvider>{children}</TenantProvider>
        </TimeWindowProvider>
      </SWRConfig>
    );
  }
  return render(node, { wrapper: Wrapper });
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function realtimeEvent(type: string) {
  vi.mocked(useRealtimeChannel).mockReturnValue({
    status: 'open',
    last: { type },
    history: [],
    send: vi.fn(),
    reset: vi.fn(),
  });
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
    vi.mocked(insightsApi.getSOC).mockReset();
    vi.mocked(authApi.currentUser).mockReturnValue(null);
    vi.mocked(authApi.isAuthenticated).mockReturnValue(false);
    vi.mocked(tenantsApi.me).mockReset();
    window.localStorage.clear();
    vi.mocked(getActiveTenantId).mockReturnValue(sampleResponse.tenant_id);
    vi.mocked(useRealtimeChannel).mockReturnValue({
      status: 'open', last: null, history: [], send: vi.fn(), reset: vi.fn(),
    });
  });

  afterEach(() => {
    vi.useRealTimers();
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

  it('keeps the current tiles visible while a realtime refresh is pending', async () => {
    vi.useFakeTimers();
    const next = deferred<SOCInsightsResponse>();
    vi.mocked(insightsApi.getSOC)
      .mockResolvedValueOnce(sampleResponse)
      .mockReturnValueOnce(next.promise);
    const view = renderIsolated(<SOCInsightsView />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(screen.getByText('1.2h')).toBeInTheDocument();

    realtimeEvent('insights_updated');
    view.rerender(<SOCInsightsView />);
    await act(async () => { await vi.advanceTimersByTimeAsync(250); });

    expect(insightsApi.getSOC).toHaveBeenCalledTimes(2);
    expect(screen.getByText('1.2h')).toBeInTheDocument();
    expect(screen.queryByLabelText(/loading soc insights/i)).not.toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent(/refreshing/i);

    await act(async () => {
      next.resolve({ ...sampleResponse, tiles: [{ ...sampleResponse.tiles[0], value: 2.5 }] });
    });
    expect(screen.getByText('2.5h')).toBeInTheDocument();
    expect(screen.queryByText('1.2h')).not.toBeInTheDocument();
  });

  it('retains the last snapshot on refresh failure and retries without blanking it', async () => {
    vi.useFakeTimers();
    vi.mocked(insightsApi.getSOC)
      .mockResolvedValueOnce(sampleResponse)
      .mockRejectedValueOnce(new Error('Refresh failed'))
      .mockResolvedValueOnce({ ...sampleResponse, tiles: [{ ...sampleResponse.tiles[0], value: 2.5 }] });
    const view = renderIsolated(<SOCInsightsView />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });

    realtimeEvent('case.updated');
    view.rerender(<SOCInsightsView />);
    await act(async () => { await vi.advanceTimersByTimeAsync(250); });

    expect(screen.getByText('1.2h')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent(/showing the last successful update/i);
    expect(screen.getByRole('alert')).toHaveTextContent('Refresh failed');

    await act(async () => { fireEvent.click(screen.getByRole('button', { name: /retry/i })); });
    expect(screen.getByText('2.5h')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('coalesces a burst and waits for an in-flight refresh before requesting again', async () => {
    vi.useFakeTimers();
    const next = deferred<SOCInsightsResponse>();
    vi.mocked(insightsApi.getSOC)
      .mockResolvedValueOnce(sampleResponse)
      .mockReturnValueOnce(next.promise)
      .mockResolvedValueOnce(sampleResponse);
    const view = renderIsolated(<SOCInsightsView />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });

    for (let i = 0; i < 3; i++) {
      realtimeEvent('case.updated');
      view.rerender(<SOCInsightsView />);
      await act(async () => { await vi.advanceTimersByTimeAsync(100); });
    }
    expect(insightsApi.getSOC).toHaveBeenCalledTimes(2);

    for (let i = 0; i < 3; i++) {
      realtimeEvent('case.updated');
      view.rerender(<SOCInsightsView />);
      await act(async () => { await vi.advanceTimersByTimeAsync(500); });
    }
    expect(insightsApi.getSOC).toHaveBeenCalledTimes(2);

    await act(async () => { next.resolve(sampleResponse); });
    await act(async () => { await vi.advanceTimersByTimeAsync(250); });
    expect(insightsApi.getSOC).toHaveBeenCalledTimes(3);
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(insightsApi.getSOC).toHaveBeenCalledTimes(3);
  });

  it('does not refetch for unrelated realtime messages', async () => {
    vi.useFakeTimers();
    vi.mocked(insightsApi.getSOC).mockResolvedValue(sampleResponse);
    const view = renderIsolated(<SOCInsightsView />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    realtimeEvent('pong');
    view.rerender(<SOCInsightsView />);
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(insightsApi.getSOC).toHaveBeenCalledTimes(1);
  });

  it('deduplicates a quick remount of the same tenant and window', async () => {
    vi.useFakeTimers();
    vi.mocked(insightsApi.getSOC).mockResolvedValue(sampleResponse);
    const view = renderIsolated(<SOCInsightsView key="first" />);
    await act(async () => { await vi.advanceTimersByTimeAsync(100); });
    view.rerender(<SOCInsightsView key="second" />);
    await act(async () => { await vi.advanceTimersByTimeAsync(100); });
    expect(screen.getByText('1.2h')).toBeInTheDocument();
    expect(insightsApi.getSOC).toHaveBeenCalledTimes(1);
  });

  it('does not display the old window under the new selection while loading', async () => {
    const next = deferred<SOCInsightsResponse>();
    vi.mocked(insightsApi.getSOC)
      .mockResolvedValueOnce(sampleResponse)
      .mockReturnValueOnce(next.promise);
    renderIsolated(<SOCInsightsView />);
    await screen.findByText('1.2h');

    fireEvent.click(screen.getByRole('radio', { name: '7d' }));
    expect(insightsApi.getSOC).toHaveBeenLastCalledWith('7d');
    expect(screen.queryByText('1.2h')).not.toBeInTheDocument();
    expect(screen.getByLabelText(/loading soc insights/i)).toBeInTheDocument();

    await act(async () => {
      next.resolve({ ...sampleResponse, window: '7d', tiles: [{ ...sampleResponse.tiles[0], value: 2.5 }] });
    });
    expect(screen.getByText('2.5h')).toBeInTheDocument();
  });

  it('hides cached tiles immediately when the active tenant changes', async () => {
    const next = deferred<SOCInsightsResponse>();
    vi.mocked(insightsApi.getSOC)
      .mockResolvedValueOnce(sampleResponse)
      .mockReturnValueOnce(next.promise);
    const view = renderIsolated(<SOCInsightsView />);
    await screen.findByText('1.2h');

    vi.mocked(getActiveTenantId).mockReturnValue('00000000-0000-0000-0000-000000000002');
    view.rerender(<SOCInsightsView />);
    expect(insightsApi.getSOC).toHaveBeenCalledTimes(2);
    expect(screen.queryByText('1.2h')).not.toBeInTheDocument();
    expect(screen.getByLabelText(/loading soc insights/i)).toBeInTheDocument();
  });

  it('does not reuse another tenant snapshot or a pending response after a tenant change', async () => {
    const previous = deferred<SOCInsightsResponse>();
    const next = deferred<SOCInsightsResponse>();
    vi.mocked(insightsApi.getSOC)
      .mockReturnValueOnce(previous.promise)
      .mockReturnValueOnce(next.promise);
    const view = renderIsolated(<SOCInsightsView />);

    const nextTenant = '00000000-0000-0000-0000-000000000002';
    vi.mocked(getActiveTenantId).mockReturnValue(nextTenant);
    view.rerender(<SOCInsightsView />);
    expect(insightsApi.getSOC).toHaveBeenCalledTimes(2);

    await act(async () => { previous.resolve(sampleResponse); });
    expect(screen.queryByText('1.2h')).not.toBeInTheDocument();
    expect(screen.getByLabelText(/loading soc insights/i)).toBeInTheDocument();

    await act(async () => {
      next.resolve({ ...sampleResponse, tenant_id: nextTenant, tiles: [{ ...sampleResponse.tiles[0], value: 2.5 }] });
    });
    expect(screen.getByText('2.5h')).toBeInTheDocument();
  });

  it('uses the transport tenant when the tenant picker falls back to the home tenant', async () => {
    const childTenant = '00000000-0000-0000-0000-000000000002';
    vi.mocked(getActiveTenantId).mockReturnValue(childTenant);
    vi.mocked(authApi.isAuthenticated).mockReturnValue(true);
    vi.mocked(authApi.currentUser).mockReturnValue({
      id: 'operator', email: 'operator@example.test', role: 'mssp-admin',
      tenant_id: sampleResponse.tenant_id,
    });
    vi.mocked(tenantsApi.me).mockRejectedValue(new Error('Tenant picker unavailable'));
    vi.mocked(insightsApi.getSOC).mockResolvedValue({ ...sampleResponse, tenant_id: childTenant });

    function TenantContextState() {
      const { current } = useTenant();
      return <span data-testid="tenant-context">{current?.id}</span>;
    }
    renderIsolated(<><TenantContextState /><SOCInsightsView /></>);
    await waitFor(() => expect(screen.getByTestId('tenant-context')).toHaveTextContent(sampleResponse.tenant_id));
    await screen.findByText('1.2h');
    expect(insightsApi.getSOC).toHaveBeenCalledTimes(1);
  });

  it.each([
    [{ tenant_id: '00000000-0000-0000-0000-000000000002' }, /selected tenant/i],
    [{ window: '7d' as const }, /selected time window/i],
  ])('rejects a snapshot for the wrong scope: %j', async (scope, message) => {
    vi.mocked(insightsApi.getSOC).mockResolvedValue({ ...sampleResponse, ...scope });
    renderIsolated(<SOCInsightsView />);
    expect(await screen.findByRole('alert')).toHaveTextContent(message);
    expect(screen.queryByText('1.2h')).not.toBeInTheDocument();
    expect(screen.queryByTestId('soc-insights-tiles')).not.toBeInTheDocument();
  });

  it('keeps only the validated snapshot when a refresh returns another tenant', async () => {
    vi.useFakeTimers();
    vi.mocked(insightsApi.getSOC)
      .mockResolvedValueOnce(sampleResponse)
      .mockResolvedValueOnce({
        ...sampleResponse,
        tenant_id: '00000000-0000-0000-0000-000000000002',
        tiles: [{ ...sampleResponse.tiles[0], value: 99 }],
      });
    const view = renderIsolated(<SOCInsightsView />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    realtimeEvent('case.updated');
    view.rerender(<SOCInsightsView />);
    await act(async () => { await vi.advanceTimersByTimeAsync(250); });

    expect(screen.getByRole('alert')).toHaveTextContent(/selected tenant/i);
    expect(screen.getByText('1.2h')).toBeInTheDocument();
    expect(screen.queryByText('99.0h')).not.toBeInTheDocument();
  });

  it('cancels a scheduled refresh when the page unmounts', async () => {
    vi.useFakeTimers();
    vi.mocked(insightsApi.getSOC).mockResolvedValue(sampleResponse);
    const view = renderIsolated(<SOCInsightsView />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    realtimeEvent('case.updated');
    view.rerender(<SOCInsightsView />);
    view.unmount();
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(insightsApi.getSOC).toHaveBeenCalledTimes(1);
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
