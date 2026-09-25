/**
 * The server fetch in `cases/page.tsx` must survive into the first paint.
 *
 * `initialCases` is documented as server-rendered data that avoids a flash of
 * mock content. It was folded into the same `fallback` object as `MOCK_CASES`
 * and the whole thing passed through `demoFallback(fallback)` — which returns
 * `undefined` outside the hosted demo *regardless of whether real SSR data
 * was supplied*. So on every non-demo deployment the server round-trip was
 * made, awaited, and then discarded.
 *
 * Real SSR data is not sample data, and the gate that withholds one must not
 * withhold the other.
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { __setDemoModeForTests } from '@/lib/demoMode';
import type { CasesResponse } from '@/lib/api';

const swrData = vi.hoisted(() => new Map<string, unknown>());
const swrFallbacks = vi.hoisted(() => new Map<string, unknown>());

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown, _fetcher: unknown, options?: { fallbackData?: unknown }) => {
    const k = typeof key === 'string' ? key : JSON.stringify(key);
    swrFallbacks.set(k, options?.fallbackData);
    return {
      data: swrData.get(k) ?? options?.fallbackData,
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    };
  },
}));

vi.mock('@/lib/api', () => ({
  __esModule: true,
  casesApi: { list: vi.fn() },
}));

vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ children, href }: { children: React.ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}));

vi.mock('@/components/saved-views/SavedViewsBar', () => ({
  __esModule: true,
  SavedViewsBar: () => null,
}));

import { CasesView } from './CasesView';

const SSR_CASES: CasesResponse = {
  cases: [
    {
      id: 'case-ssr-1',
      title: 'Server-rendered case from the API',
      status: 'open',
      severity: 'high',
      alertCount: 2,
      createdAt: '2026-05-06T09:00:00Z',
      updatedAt: '2026-05-06T09:30:00Z',
      tags: [],
    },
  ],
  total: 1,
  page: 1,
  pageSize: 1,
} as CasesResponse;

/** Titles only `MOCK_CASES` carries. */
const FABRICATED_TITLES = [
  'Ransomware incident on finance workstations',
  'Suspected APT lateral movement campaign',
  'Cryptominer on dev server cluster',
];

beforeEach(() => {
  swrData.clear();
  swrFallbacks.clear();
  __setDemoModeForTests(false);
});

afterEach(() => {
  cleanup();
  __setDemoModeForTests(null);
});

describe('server-rendered cases are not discarded outside demo mode', () => {
  it('renders the SSR payload on first paint', () => {
    render(<CasesView initialCases={SSR_CASES} />);

    expect(screen.getByText('Server-rendered case from the API')).toBeTruthy();
  });

  it('still withholds the fabricated list when no SSR data was supplied', () => {
    render(<CasesView />);

    for (const title of FABRICATED_TITLES) {
      expect(
        screen.queryByText(title),
        `"${title}" is sample data and must not render outside demo mode`,
      ).toBeNull();
    }
  });

  it('never hands the fabricated list to SWR as real SSR data', () => {
    render(<CasesView initialCases={SSR_CASES} />);

    const supplied = [...swrFallbacks.values()].find(Boolean) as CasesResponse | undefined;
    expect(supplied?.cases?.[0]?.title).toBe('Server-rendered case from the API');
  });
});

describe('the hosted demo is still populated', () => {
  it('shows the sample list when the build is the demo and there is no SSR data', () => {
    __setDemoModeForTests(true);

    render(<CasesView />);

    // The sample list cycles ten titles across eighteen rows, so each one
    // appears more than once.
    expect(
      screen.getAllByText('Ransomware incident on finance workstations').length,
    ).toBeGreaterThan(0);
  });
});
