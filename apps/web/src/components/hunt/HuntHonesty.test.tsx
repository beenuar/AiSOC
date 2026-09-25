/**
 * Data-honesty gate for the hunt workspace.
 *
 * `HuntView` had no demo gate at all. Its `demoMode` was a local
 * `useState(false)` flipped by **fetch failure**, so the page fabricated
 * precisely when the backend was unhealthy — the moment a user is least able
 * to tell invented telemetry from real telemetry.
 *
 * Two fabrications rendered that way: `DEMO_SAVED`, three invented saved
 * hunts, whenever `listSaved()` failed; and `DEMO_RESULTS`, three detections
 * on named hosts with encoded-PowerShell command lines and a routable C2 IP,
 * whenever `search()` failed. The results path also published `took: 42` — a
 * query latency for a query that never ran, rendered in the same "N hits ·
 * Nms" line as a real measurement.
 *
 * Both paths did disclose, which is better than silence. Disclosure is not
 * the property under test: fabricated telemetry must not render outside the
 * hosted demo at all.
 *
 * SWR is mocked rather than driven through a rejecting fetcher because the
 * saved-search key is module-scoped and its error survives `cleanup()`, which
 * leaks the first test's failure into every later one in this file.
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { __setDemoModeForTests } from '@/lib/demoMode';

const swrData = vi.hoisted(() => new Map<string, unknown>());
const swrErrors = vi.hoisted(() => new Map<string, unknown>());

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    const k = typeof key === 'string' ? key : JSON.stringify(key);
    return {
      data: swrData.get(k),
      error: swrErrors.get(k),
      isLoading: false,
      mutate: vi.fn(),
    };
  },
}));

const huntApi = vi.hoisted(() => ({
  listSaved: vi.fn(),
  search: vi.fn(),
  saveSearch: vi.fn(),
  deleteSaved: vi.fn(),
}));

const savedHuntsApi = vi.hoisted(() => ({
  list: vi.fn(),
  create: vi.fn(),
  run: vi.fn(),
  remove: vi.fn(),
}));

const nlQueryApi = vi.hoisted(() => ({ translate: vi.fn() }));

vi.mock('@/lib/api', () => ({
  __esModule: true,
  huntApi,
  savedHuntsApi,
  nlQueryApi,
}));

// Monaco is loaded through `next/dynamic` and needs a real browser.
vi.mock('next/dynamic', () => ({
  __esModule: true,
  default: () => function EditorStub() {
    return null;
  },
}));

import { HuntView } from './HuntView';

const SAVED_SEARCHES_KEY = 'hunt.saved';

/** Every string `DEMO_RESULTS` would put on screen. */
const FABRICATED_RESULTS = [
  'WORKSTATION-042',
  'SERVER-DC01',
  'WORKSTATION-019',
  'svc_admin',
  '185.220.101.45',
  'maria.lin',
];

/** Every string `DEMO_SAVED` would put on screen. */
const FABRICATED_SAVED = [
  'Encoded PowerShell',
  'LSASS access attempts',
  'Outbound connections to TOR exits',
];

function expectNoFabrication(names: string[]) {
  for (const name of names) {
    expect(
      document.body.textContent ?? '',
      `"${name}" is fabricated telemetry and must not render outside demo mode`,
    ).not.toContain(name);
  }
}

/** Clicking an example pill translates the question and runs the hunt. */
function runAHunt() {
  return userEvent.click(
    screen.getByRole('button', { name: /Did we get any new attacks from Iran\?/i }),
  );
}

beforeEach(() => {
  swrData.clear();
  swrErrors.clear();
  huntApi.listSaved.mockReset();
  huntApi.search.mockReset();
  savedHuntsApi.list.mockReset().mockResolvedValue([]);
  nlQueryApi.translate.mockReset().mockResolvedValue({
    esql: 'FROM events | LIMIT 10',
    explanation: 'Filters events by source geography.',
  });
  __setDemoModeForTests(false);
});

afterEach(() => {
  cleanup();
  __setDemoModeForTests(null);
});

describe('a failed saved-search load does not invent saved hunts', () => {
  it('shows the error rather than three hunts nobody saved', () => {
    swrErrors.set(SAVED_SEARCHES_KEY, new Error('502 Bad Gateway'));

    render(<HuntView />);

    expect(screen.getByText(/Couldn't load saved searches/i)).toBeTruthy();
    expectNoFabrication(FABRICATED_SAVED);
  });

  it('reads an empty list as empty', () => {
    swrData.set(SAVED_SEARCHES_KEY, []);

    render(<HuntView />);

    expect(screen.getByText(/No saved searches yet/i)).toBeTruthy();
    expectNoFabrication(FABRICATED_SAVED);
  });

  it('publishes nothing before the request has answered', () => {
    render(<HuntView />);

    expectNoFabrication(FABRICATED_SAVED);
  });
});

describe('a failed hunt does not invent results', () => {
  it('surfaces the failure instead of three fabricated detections', async () => {
    huntApi.search.mockRejectedValue(new Error('lake unreachable'));

    render(<HuntView />);
    await runAHunt();

    await waitFor(() => {
      expect(huntApi.search).toHaveBeenCalled();
    });
    await waitFor(() => {
      expect(screen.getByText(/lake unreachable/i)).toBeTruthy();
    });
    expectNoFabrication(FABRICATED_RESULTS);
  });

  it('publishes no query latency for a query that never ran', async () => {
    huntApi.search.mockRejectedValue(new Error('lake unreachable'));

    render(<HuntView />);
    await runAHunt();

    await waitFor(() => {
      expect(huntApi.search).toHaveBeenCalled();
    });
    // `took: 42` was a fabricated measurement rendered beside a hit count.
    await waitFor(() => {
      expect(screen.queryByText(/42ms/)).toBeNull();
      expect(screen.queryByText(/3 hits/)).toBeNull();
    });
  });

  it('renders the real results the backend returned', async () => {
    huntApi.search.mockResolvedValue({
      total: 1,
      took: 7,
      hits: [
        {
          id: 'real-1',
          timestamp: '2026-05-06T11:48:00Z',
          source: 'lake',
          severity: 'low',
          fields: { host: 'build-agent-3' },
        },
      ],
    });

    render(<HuntView />);
    await runAHunt();

    await waitFor(() => {
      expect(screen.getByText(/build-agent-3/)).toBeTruthy();
    });
    expectNoFabrication(FABRICATED_RESULTS);
  });
});

describe('the hosted demo is still populated', () => {
  it('shows the sample hunts when the build is the demo', () => {
    __setDemoModeForTests(true);
    swrErrors.set(SAVED_SEARCHES_KEY, new Error('no backend in the demo'));

    render(<HuntView />);

    expect(screen.getByText('LSASS access attempts')).toBeTruthy();
  });

  it('shows the sample results when the build is the demo', async () => {
    __setDemoModeForTests(true);
    huntApi.search.mockRejectedValue(new Error('no backend in the demo'));

    render(<HuntView />);
    await runAHunt();

    await waitFor(() => {
      expect(screen.getByText(/WORKSTATION-042/)).toBeTruthy();
    });
  });
});
