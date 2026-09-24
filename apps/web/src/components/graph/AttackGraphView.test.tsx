/**
 * The Attack Graph must not invent a graph, and must say so when it cannot
 * load one.
 *
 * `GET /api/v1/graph` did not exist — the console called it, got 404, and
 * rendered its error state. The error state was the *correct* behaviour and
 * the temptation on fixing the route is to soften it; these tests pin the two
 * halves that make it correct.
 *
 * Asserted at **first paint**, not only on the error branch. SWR v2 disables
 * `revalidateOnMount` whenever `fallbackData` is supplied, so a component
 * handed a mock there may never fetch at all: the sample data is not a
 * placeholder that a real response replaces, it is what the view shows for
 * good. A test that only drives the error branch passes happily against a
 * component that renders a fabricated graph forever and never errors,
 * because the error never happens.
 *
 * The header's "Generated …" timestamp is the signal, because it renders if
 * and only if `graphState.data` is already populated. Present on the very
 * first render means data arrived without a fetch.
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { SWRConfig } from 'swr';

const getOverview = vi.hoisted(() => vi.fn());
const getMitreCoverage = vi.hoisted(() => vi.fn());
const canUseDemoData = vi.hoisted(() => vi.fn());

vi.mock('@/lib/api', () => ({
  __esModule: true,
  graphApi: { getOverview, getMitreCoverage },
}));

vi.mock('@/lib/demoFallback', () => ({
  __esModule: true,
  canUseDemoData,
}));

vi.mock('next/navigation', () => ({
  __esModule: true,
  useSearchParams: () => new URLSearchParams(''),
}));

// cytoscape renders onto a real canvas, which jsdom does not provide. The
// stub keeps `GraphCanvas` mountable so "did the view decide it has a graph
// to draw?" stays observable; node labels are painted, not DOM, so the
// assertions below key on the surrounding chrome instead.
vi.mock('cytoscape', () => {
  const cy = () => ({ on: vi.fn(), destroy: vi.fn() });
  cy.use = vi.fn();
  return { __esModule: true, default: cy };
});
vi.mock('cytoscape-fcose', () => ({ __esModule: true, default: {} }));

import { AttackGraphView } from './AttackGraphView';

/** The message shape `request()` throws: status and path, never a guess. */
class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

function renderView() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <AttackGraphView />
    </SWRConfig>,
  );
}

const GENERATED = /Generated /;

beforeEach(() => {
  vi.clearAllMocks();
  canUseDemoData.mockReturnValue(false);
  getMitreCoverage.mockResolvedValue({ tactics: [], cells: [], generatedAt: '' });
});

afterEach(cleanup);

describe('AttackGraphView, demo mode off', () => {
  it('holds no graph at first paint — it has not fetched one yet', () => {
    getOverview.mockImplementation(() => new Promise(() => {}));
    renderView();
    // If `fallbackData` were ever supplied, `graphState.data` would be
    // populated on the first render and this timestamp would be present.
    expect(screen.queryByText(GENERATED)).toBeNull();
  });

  it('names the endpoint and the status rather than inventing a graph', async () => {
    getOverview.mockRejectedValue(
      new ApiError('API 503 Service Unavailable — /api/v1/graph', 503),
    );
    renderView();

    expect(screen.queryByText(GENERATED)).toBeNull();

    await waitFor(() => {
      expect(screen.getByText("Couldn't load graph")).toBeInTheDocument();
    });
    expect(
      screen.getByText('API 503 Service Unavailable — /api/v1/graph'),
    ).toBeInTheDocument();
    // Still nothing fabricated standing in for the estate.
    expect(screen.queryByText(GENERATED)).toBeNull();
  });

  it('reads a tenant with no graph as empty, not as broken', async () => {
    getOverview.mockResolvedValue({
      nodes: [],
      edges: [],
      generatedAt: '2026-09-24T12:00:00Z',
    });
    renderView();

    await waitFor(() => {
      expect(screen.getByText('No graph yet')).toBeInTheDocument();
    });
    expect(screen.queryByText("Couldn't load graph")).toBeNull();
  });

  it('draws the graph the backend returned', async () => {
    getOverview.mockResolvedValue({
      nodes: [{ id: 'host:WIN-DB01', label: 'WIN-DB01', kind: 'host', riskScore: 92 }],
      edges: [],
      generatedAt: '2026-09-24T12:00:00Z',
    });
    renderView();

    await waitFor(() => {
      expect(screen.queryByText('No graph yet')).toBeNull();
    });
    expect(screen.queryByText("Couldn't load graph")).toBeNull();
    expect(getOverview).toHaveBeenCalledWith({ depth: 3 });
  });
});

describe('AttackGraphView, hosted demo', () => {
  it('substitutes sample topology only when demo mode allows it', async () => {
    // The same failure as the second test above, with the gate open. If this
    // rendered the error state too, the gate would be dead code; if the test
    // above rendered a graph, the gate would not be a gate.
    canUseDemoData.mockReturnValue(true);
    getOverview.mockRejectedValue(new ApiError('API 503 — /api/v1/graph', 503));
    renderView();

    await waitFor(() => {
      expect(screen.queryByText(GENERATED)).not.toBeNull();
    });
    expect(screen.queryByText("Couldn't load graph")).toBeNull();
  });
});
