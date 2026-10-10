/**
 * Two surfaces showing the same alert must show the same risk number.
 *
 * Reported as "one alert shows two different risk numbers". Both surfaces
 * read `alert.riskScore`, but the field arrived unnormalised — the live API
 * populates it from `ai_score`, a [0,1] float — and the two rendered it
 * differently: `InvestigationRail` wrapped it in `Math.round`, so 0.85 became
 * **1**, while `AlertDetailView` printed the raw **0.85**.
 *
 * This asserts against *one* API payload driven through the real
 * `normalizeAlert` boundary, because that is where the ambiguity lives.
 * Asserting on each component with its own hand-built `Alert` is what let the
 * contradiction survive: each view's fixture used the scale that view assumed.
 *
 * Against the pre-change tree, both agreement tests fail.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';

const swrState = vi.hoisted(() => ({ data: undefined as unknown, isLoading: false }));

vi.mock('swr', () => ({
  __esModule: true,
  default: () => ({ data: swrState.data, error: undefined, isLoading: swrState.isLoading, mutate: vi.fn() }),
}));

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn(), back: vi.fn() }),
  usePathname: () => '/alerts/a1',
  useSearchParams: () => new URLSearchParams(),
}));

import { alertsApi } from '@/lib/api';
import { AlertDetailView } from './AlertDetailView';
import { InvestigationRail } from './InvestigationRail';

/** Exactly what `AlertResponse` serialises for a model-scored alert. */
const API_PAYLOAD = {
  id: 'a1',
  title: 'Credential dumping on WIN-DC01',
  description: 'LSASS memory access from an unsigned binary.',
  severity: 'critical',
  status: 'new',
  source: 'crowdstrike',
  tenant_id: 't1',
  ai_score: 0.85,
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-01T00:00:00Z',
};

/**
 * Run the payload through the real boundary rather than hand-building an
 * `Alert`. `normalizeAlert` is module-private on purpose, so reach it the way
 * the console does — through a stubbed `fetch`.
 */
async function loadAlert(payload: Record<string, unknown>) {
  vi.stubGlobal(
    'fetch',
    vi.fn(
      async () =>
        new Response(JSON.stringify(payload), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
    ),
  );
  try {
    swrState.data = await alertsApi.get('a1');
  } finally {
    vi.unstubAllGlobals();
  }
}

beforeEach(async () => {
  swrState.isLoading = false;
  await loadAlert(API_PAYLOAD);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('the rail and the detail view agree about one alert', () => {
  it('the rail shows the normalised 0-100 score, not a rounded fraction', () => {
    render(<InvestigationRail alertId="a1" onClose={vi.fn()} />);

    const summary = within(screen.getByRole('region', { name: /alert summary/i }));
    expect(summary.getByText(/^risk 85$/)).toBeInTheDocument();
    // `Math.round(0.85)` — the number the rail used to print.
    expect(summary.queryByText(/^risk 1$/)).toBeNull();
  });

  it('the detail view shows the same number', () => {
    render(<AlertDetailView alertId="a1" />);

    expect(screen.getByText('85')).toBeInTheDocument();
    expect(screen.queryByText('0.85')).toBeNull();
  });
});

describe('an unscored alert is not reported as zero risk', () => {
  it('the detail view omits the figure rather than printing 0', async () => {
    const { ai_score: _dropped, ...unscored } = API_PAYLOAD;
    await loadAlert(unscored);

    render(<AlertDetailView alertId="a1" />);

    expect(screen.queryByText(/risk score/i)).toBeNull();
  });
});
