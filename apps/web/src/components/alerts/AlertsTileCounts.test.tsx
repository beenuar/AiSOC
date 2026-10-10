/**
 * The Alerts stat strip describes the result set, not the loaded page.
 *
 * The defect: `AlertsView` computed three of its four tiles in the browser
 * from `data?.alerts`, which is one page of 25, and rendered them beside a
 * **Total** read from the server-side `total`. With 522 alerts in the tenant
 * the tiles were arithmetically capped at 25, and clicking "next page"
 * changed them.
 *
 * `GET /api/v1/alerts` now returns `facets` — severity and status counts over
 * the same `WHERE` clause that produces `total` — so all four numbers on the
 * strip describe one set of rows.
 *
 * The last test is the honesty half. A server that sends no facets has told
 * us nothing about the result set, and falling back to the page-derived count
 * would be the original defect wearing a fallback. The strip says so instead.
 * Note what it does *not* do: a facet map that omits `critical` means zero
 * criticals matched, and that renders as a real `0`.
 *
 * Against the pre-change tree, every test here fails.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

// `swr` is mocked rather than the fetcher: its cache is module-scoped and
// every test here renders the same `['alerts', filters]` key, so the second
// render in a file is served from the cache inside the 2s dedupe window and
// never calls the fetcher at all.
const swrState = vi.hoisted(() => ({ data: undefined as unknown }));

vi.mock('swr', () => ({
  __esModule: true,
  // Key-aware: the page also mounts `SavedViewsBar`, which calls `useSWR` on
  // its own key and expects an array. Answering every key with the alert
  // payload crashes it.
  default: (key: unknown) => {
    const isAlertList = Array.isArray(key) && key[0] === 'alerts';
    return {
      data: isAlertList ? swrState.data : undefined,
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    };
  },
}));

// The RBA entity queue is the default tab and fetches on its own; stub it so
// this file only exercises the alert grid.
vi.mock('@/components/alerts/EntityRiskQueue', () => ({
  EntityRiskQueue: () => <div data-testid="entity-queue" />,
}));

import { AlertsView } from './AlertsView';

/** 25 rows, 3 of them critical — a page that under-represents the queue. */
const PAGE = Array.from({ length: 25 }, (_, i) => ({
  id: `a${i}`,
  title: `Alert ${i}`,
  description: '',
  severity: i < 3 ? 'critical' : 'low',
  status: i < 2 ? 'new' : 'resolved',
  source: 'crowdstrike',
  tenantId: 't1',
  createdAt: '2026-10-01T00:00:00Z',
  updatedAt: '2026-10-01T00:00:00Z',
}));

async function openTheAlertGrid() {
  render(<AlertsView />);
  await userEvent.click(await screen.findByRole('tab', { name: /^alerts$/i }));
}

/** The strip renders `<p>label</p><p>value</p>` per tile inside one group. */
function tile(label: string) {
  const strip = screen.getByRole('group', { name: /alert counts/i });
  const heading = within(strip).getByText(label);
  return within(heading.parentElement as HTMLElement);
}

beforeEach(() => {
  swrState.data = undefined;
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('the stat strip is not capped by the page size', () => {
  beforeEach(() => {
    swrState.data = {
      alerts: PAGE,
      total: 522,
      page: 1,
      pageSize: 25,
      facets: {
        bySeverity: { critical: 118, high: 64, low: 340 },
        byStatus: { new: 200, triaging: 90, resolved: 232 },
        unresolved: 290,
      },
    };
  });

  it('shows the whole-result-set critical count, not the three on this page', async () => {
    await openTheAlertGrid();

    expect(tile('Critical').getByText('118')).toBeInTheDocument();
    expect(tile('Critical').queryByText('3')).toBeNull();
  });

  it('shows the whole-result-set high count', async () => {
    await openTheAlertGrid();

    // Zero highs are on this page at all, so the page-derived count was 0.
    expect(tile('High').getByText('64')).toBeInTheDocument();
  });

  it('counts every unresolved status, not just `new`', async () => {
    await openTheAlertGrid();

    expect(tile('Unresolved').getByText('290')).toBeInTheDocument();
  });
});

describe('an absent facet is distinguished from a zero one', () => {
  it('renders a real zero when the server says zero', async () => {
    swrState.data = {
      alerts: PAGE,
      total: 522,
      page: 1,
      pageSize: 25,
      // No `critical` key — the server counted and found none.
      facets: { bySeverity: { low: 522 }, byStatus: { resolved: 522 }, unresolved: 0 },
    };

    await openTheAlertGrid();

    expect(tile('Critical').getByText('0')).toBeInTheDocument();
  });

  it('does not fall back to the page-derived count when the server sends none', async () => {
    swrState.data = { alerts: PAGE, total: 522, page: 1, pageSize: 25 };

    await openTheAlertGrid();

    // 3 criticals are visible on the page; publishing that as the tenant's
    // critical count is the defect this file exists to stop.
    expect(tile('Critical').queryByText('3')).toBeNull();
    expect(tile('Critical').queryByText('0')).toBeNull();
    expect(tile('Critical').getByText('—')).toBeInTheDocument();
  });
});
