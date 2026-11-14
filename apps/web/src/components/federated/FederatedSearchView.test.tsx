/**
 * Federated search surface.
 *
 * The property these tests exist to protect is per-backend isolation. The API
 * deliberately never fails the whole call because one SIEM is slow, 401s or
 * 5xxs — it returns a `sources[]` verdict per backend instead. A UI that
 * renders only the merged rows discards that, and the analyst cannot tell
 * "Sentinel has nothing" from "Sentinel did not answer", which are opposite
 * conclusions mid-incident.
 *
 * So: a partial failure must stay visible, and must never be allowed to look
 * like a clean empty result.
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { SWRConfig } from 'swr';
import { axe } from 'vitest-axe';

const listBackends = vi.hoisted(() => vi.fn());
const search = vi.hoisted(() => vi.fn());

// Hoisted with the mock factory, which vitest lifts above the imports.
const FakeDisabledError = vi.hoisted(
  () =>
    class FederatedSearchDisabledError extends Error {
      constructor() {
        super('Federated search is disabled on this deployment (AISOC_FEATURE_FED_SEARCH).');
        this.name = 'FederatedSearchDisabledError';
      }
    },
);

vi.mock('@/lib/api', () => ({
  __esModule: true,
  federatedApi: { listBackends, search },
  FederatedSearchDisabledError: FakeDisabledError,
  FEDERATED_OPERATORS: [
    'eq', 'ne', 'contains', 'starts_with', 'ends_with', 'gt', 'gte', 'lt', 'lte', 'in',
  ],
}));

vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ children, href }: { children: React.ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}));

// Real SWR against a mocked fetcher: the loading -> resolved transition is
// part of what is under test, and stubbing SWR would skip it.
import { FederatedSearchView } from './FederatedSearchView';

const BACKENDS = {
  backends: [
    {
      connector_id: 'aaaaaaaa-0000-4000-8000-000000000001',
      connector_type: 'splunk',
      name: 'Prod Splunk',
      health_status: 'healthy',
      is_enabled: true,
    },
    {
      connector_id: 'bbbbbbbb-0000-4000-8000-000000000002',
      connector_type: 'microsoft_sentinel',
      name: 'Corp Sentinel',
      health_status: 'degraded',
      is_enabled: true,
    },
  ],
};

/** One backend answered with a row, the other timed out. */
const PARTIAL_FAILURE = {
  rows: [
    {
      _time: '2026-05-06T12:00:00Z',
      host: 'WIN-DC01',
      user: 'svc_backup',
      _aisoc_source: {
        connector_id: 'aaaaaaaa-0000-4000-8000-000000000001',
        connector_name: 'Prod Splunk',
        connector_type: 'splunk',
      },
    },
  ],
  row_count: 1,
  sources: [
    {
      connector_id: 'aaaaaaaa-0000-4000-8000-000000000001',
      connector_name: 'Prod Splunk',
      connector_type: 'splunk',
      status: 'ok' as const,
      row_count: 1,
      duration_ms: 812,
      error: null,
    },
    {
      connector_id: 'bbbbbbbb-0000-4000-8000-000000000002',
      connector_name: 'Corp Sentinel',
      connector_type: 'microsoft_sentinel',
      status: 'error' as const,
      row_count: 0,
      duration_ms: 30_000,
      error: 'connectors service unreachable: ReadTimeout',
    },
  ],
  truncated: false,
};

/**
 * Render with a private SWR cache.
 *
 * SWR's cache is module-global, so without this the second test in a file
 * reads the first test's `federated-backends` entry and never calls the
 * mocked fetcher — every later assertion then measures the wrong render.
 */
function renderView() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <FederatedSearchView />
    </SWRConfig>,
  );
}

async function runSearch(text = 'failed logon') {
  const input = await screen.findByLabelText(/search text/i);
  fireEvent.change(input, { target: { value: text } });
  fireEvent.click(screen.getByRole('button', { name: /run federated search/i }));
}

beforeEach(() => {
  listBackends.mockReset();
  search.mockReset();
  listBackends.mockResolvedValue(BACKENDS);
});

afterEach(() => cleanup());

describe('backend inventory', () => {
  it('lists the tenant\u2019s connected SIEMs with their recorded health', async () => {
    renderView();

    expect(await screen.findByText('Prod Splunk')).toBeTruthy();
    expect(screen.getByText('Corp Sentinel')).toBeTruthy();
    expect(screen.getByText('Reachable')).toBeTruthy();
    expect(screen.getByText('Degraded')).toBeTruthy();
  });

  it('says so, and offers no query box, when no SIEM is connected', async () => {
    listBackends.mockResolvedValue({ backends: [] });
    renderView();

    expect(await screen.findByText(/No SIEM connectors are connected/i)).toBeTruthy();
    expect(screen.queryByRole('button', { name: /run federated search/i })).toBeNull();
  });

  it('names the feature flag rather than showing a bare not-found', async () => {
    listBackends.mockRejectedValue(new FakeDisabledError());
    renderView();

    expect(await screen.findByText(/Federated search is turned off/i)).toBeTruthy();
    expect(screen.getByText(/AISOC_FEATURE_FED_SEARCH/)).toBeTruthy();
  });

  it('surfaces a backend-list failure instead of rendering an empty picker', async () => {
    listBackends.mockRejectedValue(new Error('API 500 Internal Server Error'));
    renderView();

    expect(await screen.findByText(/Could not list federated backends/i)).toBeTruthy();
    expect(screen.getByText(/API 500 Internal Server Error/)).toBeTruthy();
  });
});

describe('per-backend isolation', () => {
  it('shows one SIEM timing out without blanking the other SIEM\u2019s rows', async () => {
    search.mockResolvedValue(PARTIAL_FAILURE);
    renderView();
    await runSearch();

    // The failure is named, with its own message and its own latency.
    await waitFor(() => expect(screen.getByText(/2 backends did not/i)).toBeTruthy());
    expect(screen.getByText(/connectors service unreachable: ReadTimeout/)).toBeTruthy();
    expect(screen.getByText('30000 ms')).toBeTruthy();

    // And the backend that did answer still shows its row.
    expect(screen.getByText('812 ms')).toBeTruthy();
    expect(screen.getAllByText(/WIN-DC01/).length).toBeGreaterThan(0);
  });

  it('does not print a row count for a backend that failed', async () => {
    search.mockResolvedValue(PARTIAL_FAILURE);
    renderView();
    await runSearch();

    const failed = await screen.findByTestId(
      'source-verdict-bbbbbbbb-0000-4000-8000-000000000002',
    );
    // "0 rows" beside a failure reads as "nothing matched", which is the one
    // conclusion the analyst must not draw from a timeout.
    expect(failed.textContent).not.toMatch(/\b0 rows?\b/);
    expect(failed.textContent).toMatch(/Failed/);
  });

  it('distinguishes "every backend failed" from "nothing matched"', async () => {
    search.mockResolvedValue({
      rows: [],
      row_count: 0,
      sources: [
        { ...PARTIAL_FAILURE.sources[1], status: 'error' as const },
      ],
      truncated: false,
    });
    renderView();
    await runSearch();

    expect(await screen.findByText(/No backend returned results/i)).toBeTruthy();
    expect(screen.queryByText(/No matching events/i)).toBeNull();
  });

  it('says "no matching events" when a backend genuinely answered empty', async () => {
    search.mockResolvedValue({
      rows: [],
      row_count: 0,
      sources: [{ ...PARTIAL_FAILURE.sources[0], row_count: 0 }],
      truncated: false,
    });
    renderView();
    await runSearch();

    expect(await screen.findByText(/No matching events/i)).toBeTruthy();
  });

  it('flags a merged result that was capped', async () => {
    search.mockResolvedValue({ ...PARTIAL_FAILURE, truncated: true });
    renderView();
    await runSearch();

    expect(await screen.findByText(/Capped at 100 rows after merging/i)).toBeTruthy();
  });
});

describe('query construction', () => {
  it('refuses to send a query the server would reject as empty', async () => {
    renderView();
    await screen.findByText('Prod Splunk');

    const button = screen.getByRole('button', { name: /run federated search/i });
    expect(button.hasAttribute('disabled')).toBe(true);
    fireEvent.click(button);
    expect(search).not.toHaveBeenCalled();
  });

  it('omits connector_ids when every backend is selected, rather than listing them', async () => {
    search.mockResolvedValue(PARTIAL_FAILURE);
    renderView();
    await runSearch();

    await waitFor(() => expect(search).toHaveBeenCalledTimes(1));
    // `null` means "every enabled backend" server-side. Enumerating them
    // instead would silently pin the search to whatever was connected at the
    // moment the page loaded.
    expect(search.mock.calls[0][0].connector_ids).toBeNull();
  });

  it('scopes to the chosen backend when one is unticked', async () => {
    search.mockResolvedValue(PARTIAL_FAILURE);
    renderView();
    await screen.findByText('Prod Splunk');

    fireEvent.click(screen.getAllByRole('checkbox')[1]); // untick Sentinel
    await runSearch();

    await waitFor(() => expect(search).toHaveBeenCalledTimes(1));
    expect(search.mock.calls[0][0].connector_ids).toEqual([
      'aaaaaaaa-0000-4000-8000-000000000001',
    ]);
  });

  it('splits a comma list for the `in` operator and sends a real array', async () => {
    search.mockResolvedValue(PARTIAL_FAILURE);
    renderView();
    await screen.findByText('Prod Splunk');

    fireEvent.click(screen.getByRole('button', { name: /add filter/i }));
    fireEvent.change(screen.getByLabelText(/filter 1 field/i), {
      target: { value: 'user' },
    });
    fireEvent.change(screen.getByLabelText(/filter 1 operator/i), {
      target: { value: 'in' },
    });
    fireEvent.change(screen.getByLabelText(/filter 1 value/i), {
      target: { value: 'alice, bob ,carol' },
    });
    fireEvent.click(screen.getByRole('button', { name: /run federated search/i }));

    await waitFor(() => expect(search).toHaveBeenCalledTimes(1));
    expect(search.mock.calls[0][0].indicators).toEqual([
      { field: 'user', operator: 'in', value: ['alice', 'bob', 'carol'] },
    ]);
  });

  it('drops half-typed filter rows instead of sending an invalid indicator', async () => {
    search.mockResolvedValue(PARTIAL_FAILURE);
    renderView();
    await screen.findByText('Prod Splunk');

    fireEvent.click(screen.getByRole('button', { name: /add filter/i }));
    fireEvent.change(screen.getByLabelText(/filter 1 field/i), {
      target: { value: 'host' },
    });
    // value left blank
    await runSearch();

    await waitFor(() => expect(search).toHaveBeenCalledTimes(1));
    expect(search.mock.calls[0][0].indicators).toEqual([]);
  });
});

describe('pivots', () => {
  it('deep-links recognised entities into the attack graph', async () => {
    search.mockResolvedValue(PARTIAL_FAILURE);
    renderView();
    await runSearch();

    const hostPivot = await screen.findByRole('link', { name: /Pivot host: WIN-DC01/i });
    expect(hostPivot.getAttribute('href')).toBe('/graph?entity=host%3AWIN-DC01');

    const userPivot = screen.getByRole('link', { name: /Pivot user: svc_backup/i });
    expect(userPivot.getAttribute('href')).toBe('/graph?entity=user%3Asvc_backup');
  });
});

describe('accessibility (WCAG 2.1 AA)', () => {
  // jsdom cannot compute styles from CSS variables, so axe's color-contrast
  // rule only ever returns "incomplete" here. Same exemption the shared
  // sweep in `src/test/a11y.test.tsx` takes.
  const axeOptions = { rules: { 'color-contrast': { enabled: false } } };

  it('has no violations with the query form and backend picker rendered', async () => {
    const { container } = renderView();
    await screen.findByText('Prod Splunk');

    expect(await axe(container, axeOptions)).toHaveNoViolations();
  });

  it('has no violations with results and a partial failure on screen', async () => {
    search.mockResolvedValue(PARTIAL_FAILURE);
    const { container } = renderView();
    await runSearch();
    await screen.findByText(/connectors service unreachable/);

    expect(await axe(container, axeOptions)).toHaveNoViolations();
  });
});

describe('request failure', () => {
  it('shows the error and no partial rows when the search call itself fails', async () => {
    search.mockRejectedValue(new Error('API 502 Bad Gateway'));
    renderView();
    await runSearch();

    expect(await screen.findByText(/Federated search failed/i)).toBeTruthy();
    expect(screen.getByText(/API 502 Bad Gateway/)).toBeTruthy();
    expect(screen.queryByText(/Merged rows/i)).toBeNull();
  });
});
