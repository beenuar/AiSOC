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
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
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

/**
 * `GET /api/v1/graph` bounds itself and reports `truncated`. For a while
 * nothing rendered it, which put both halves of one defect on either side of
 * a single request: the API stopped presenting a partial graph as complete,
 * and the canvas carried on doing it.
 *
 * Asserted at first paint for the same reason as the block above — a view
 * handed `fallbackData` never fetches, so a truncation flag it reads out of a
 * mock proves nothing about a real response.
 */
describe('AttackGraphView, truncated response', () => {
  /**
   * The notice is named, because `EmptyState` is a `role="status"` too.
   * `getByRole('status')` would match whichever of the two happened to be
   * mounted — so "no truncation notice" and "the empty state is showing"
   * would assert the same thing, and a test for one would pass on the other.
   */
  const NOTICE = { name: 'Truncated graph' } as const;
  const findNotice = () => screen.findByRole('status', NOTICE);
  const queryNotice = () => screen.queryByRole('status', NOTICE);

  const TRUNCATED = {
    nodes: [{ id: 'host:WIN-DB01', label: 'WIN-DB01', kind: 'host', riskScore: 92 }],
    edges: [{ id: 'e1', source: 'host:WIN-DB01', target: 'host:WIN-DB01', label: 'self' }],
    generatedAt: '2026-09-24T12:00:00Z',
    truncated: true,
    nodeLimit: 400,
    edgeLimit: 900,
  };

  it('holds no truncation claim at first paint — nothing has been fetched', () => {
    getOverview.mockImplementation(() => new Promise(() => {}));
    renderView();
    // Were `fallbackData` ever supplied, `graphState.data` would be populated
    // on the first render and this notice would already be on screen — for
    // good, because supplying it also disables revalidation.
    expect(screen.queryByText(/This graph is incomplete/)).toBeNull();
    expect(queryNotice()).toBeNull();
  });

  it('says the graph is incomplete, and reports the counts and the depth', async () => {
    getOverview.mockResolvedValue(TRUNCATED);
    renderView();

    const notice = await findNotice();
    expect(notice).toHaveTextContent('This graph is incomplete.');
    expect(notice).toHaveTextContent('1 nodes and 1 edges at depth 3');
    // The limits come from the response, so the number shown is the number
    // the service applied rather than a copy the console keeps.
    expect(notice).toHaveTextContent("this view's ceiling of 400 nodes and 900 edges");
    // And it must not read as a load failure or an empty tenant.
    expect(screen.queryByText("Couldn't load graph")).toBeNull();
    expect(screen.queryByText('No graph yet')).toBeNull();
  });

  it('names the node ceiling when the returned counts reach it', async () => {
    getOverview.mockResolvedValue({ ...TRUNCATED, nodeLimit: 1, edgeLimit: 900 });
    renderView();
    expect(await findNotice()).toHaveTextContent('cut at the 1-node ceiling');
  });

  it('names the edge ceiling when that is the one that bit', async () => {
    getOverview.mockResolvedValue({ ...TRUNCATED, nodeLimit: 400, edgeLimit: 1 });
    renderView();
    expect(await findNotice()).toHaveTextContent('cut at the 1-edge ceiling');
  });

  it('names both when both were reached', async () => {
    getOverview.mockResolvedValue({ ...TRUNCATED, nodeLimit: 1, edgeLimit: 1 });
    renderView();
    expect(await findNotice()).toHaveTextContent('cut at the 1-node and 1-edge ceiling');
  });

  it('claims no ceiling the response did not report', async () => {
    getOverview.mockResolvedValue({ ...TRUNCATED, nodeLimit: undefined, edgeLimit: undefined });
    renderView();
    const notice = await findNotice();
    expect(notice).toHaveTextContent('a ceiling this response did not report');
    expect(notice).not.toHaveTextContent('400');
  });

  it('narrowing the depth issues a new query rather than re-showing the cache', async () => {
    getOverview.mockResolvedValue(TRUNCATED);
    renderView();

    await findNotice();
    expect(getOverview).toHaveBeenCalledWith({ depth: 3 });

    // A control that moved a number and refetched nothing would be worse than
    // no control: it would report a narrower, still-truncated graph as the
    // result of narrowing.
    fireEvent.change(screen.getByRole('combobox'), { target: { value: '1' } });
    await waitFor(() => {
      expect(getOverview).toHaveBeenCalledWith({ depth: 1 });
    });
  });

  it('says nothing when the backend reports a complete graph', async () => {
    getOverview.mockResolvedValue({ ...TRUNCATED, truncated: false });
    renderView();

    await waitFor(() => {
      expect(screen.queryByText('No graph yet')).toBeNull();
    });
    expect(queryNotice()).toBeNull();
  });

  it('says nothing when the endpoint omits the flag entirely', async () => {
    // `undefined` means "this endpoint does not report bounding", which is
    // not the same as "complete" — but it is not grounds for a claim either.
    getOverview.mockResolvedValue({ ...TRUNCATED, truncated: undefined });
    renderView();

    await waitFor(() => {
      expect(screen.queryByText('No graph yet')).toBeNull();
    });
    expect(queryNotice()).toBeNull();
  });

  it('does not claim truncation for a graph that failed to load', async () => {
    // A graph that could not be retrieved has no size to report, and saying
    // "incomplete" about it would soften an error state that is correct.
    getOverview.mockRejectedValue(new ApiError('API 503 — /api/v1/graph', 503));
    renderView();

    await waitFor(() => {
      expect(screen.getByText("Couldn't load graph")).toBeInTheDocument();
    });
    expect(queryNotice()).toBeNull();
  });

  it('does not claim truncation for a tenant with no graph', async () => {
    getOverview.mockResolvedValue({ nodes: [], edges: [], generatedAt: '2026-09-24T12:00:00Z' });
    renderView();

    await waitFor(() => {
      expect(screen.getByText('No graph yet')).toBeInTheDocument();
    });
    expect(queryNotice()).toBeNull();
  });

  it('introduces no heading, so the page heading order is unchanged', async () => {
    getOverview.mockResolvedValue(TRUNCATED);
    renderView();
    const notice = await findNotice();

    // The page already runs h1 -> h2 -> the h3 inside EmptyState/ErrorState.
    // A heading in the notice would land between the h2 panels and those,
    // which the axe-core WCAG AA gate reads as a broken order. Asserted on
    // the notice itself rather than on the page's heading set, because the
    // set changes with whichever panel states happen to be showing.
    expect(notice.querySelector('h1, h2, h3, h4, h5, h6')).toBeNull();
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
