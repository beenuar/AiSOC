/**
 * The counter beside the filters must know what the stat cards above it know.
 *
 * `CasesView` already computes `countsUnknown` and honours it in the five
 * status stat cards, which render an em-dash when the case service has not
 * answered. The small counter in the filter row did not: it printed
 * `0 cases`, so the page gave two different answers about the same unread
 * list — five honest em-dashes and one confident zero, a few pixels apart.
 *
 * Two surfaces disagreeing about the same data is the tell, and the
 * confident one is always the wrong one: a zero reads as
 * measured-and-there-are-none, which is a different claim from
 * not-measured.
 */
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { __setDemoModeForTests } from '@/lib/demoMode';

const swrData = vi.hoisted(() => ({ value: undefined as unknown }));
const swrError = vi.hoisted(() => ({ value: undefined as unknown }));

// Keyed, not blanket: `SavedViewsBar` uses SWR too, and handing it the cases
// payload makes it throw on a shape it never asked for.
vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    const isCases = Array.isArray(key) && key[0] === 'cases';
    return {
      data: isCases ? swrData.value : undefined,
      error: isCases ? swrError.value : undefined,
      isLoading: false,
      mutate: vi.fn(),
    };
  },
}));

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/api')>();
  return { ...actual, casesApi: { ...actual.casesApi, list: vi.fn() } };
});

vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ children, href }: { children: React.ReactNode; href: string }) => <a href={href}>{children}</a>,
}));

vi.mock('next/navigation', () => ({
  __esModule: true,
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/cases',
  useSearchParams: () => new URLSearchParams(),
}));

import { CasesView } from './CasesView';

beforeEach(() => {
  swrData.value = undefined;
  swrError.value = undefined;
  __setDemoModeForTests(false);
});

afterEach(() => {
  cleanup();
  __setDemoModeForTests(null);
});

describe('an unread case list is not a count of zero', () => {
  it('does not print a zero when the service has not answered', () => {
    render(<CasesView />);

    expect(screen.queryByText(/^0 cases$/)).toBeNull();
    expect(screen.getByText(/^— cases$/)).toBeInTheDocument();
  });

  it('agrees with the stat cards beside it', () => {
    render(<CasesView />);

    // The five status cards already render an em-dash here. The counter must
    // be the sixth, not the one surface that disagrees.
    const dashes = screen.getAllByText('—');
    expect(dashes.length).toBeGreaterThanOrEqual(5);
    expect(screen.getByText(/^— cases$/)).toBeInTheDocument();
  });

  it('does not print a zero when the read failed', () => {
    swrError.value = new Error('503 Service Unavailable');

    render(<CasesView />);

    expect(screen.queryByText(/^0 cases$/)).toBeNull();
    expect(screen.getByText(/^— cases$/)).toBeInTheDocument();
  });

  it('still counts a genuinely empty list as zero', () => {
    // The other direction. An em-dash forever would pass every assertion
    // above and hide a real, informative zero.
    swrData.value = { cases: [], total: 0 };

    render(<CasesView />);

    expect(screen.getByText(/^0 cases$/)).toBeInTheDocument();
    expect(screen.queryByText(/^— cases$/)).toBeNull();
  });

  it('counts a populated list', () => {
    swrData.value = {
      cases: [
        { id: 'c1', title: 'Ransomware on FIN-WS-04', status: 'open', severity: 'critical', createdAt: '2026-09-27T10:00:00Z', updatedAt: '2026-09-27T10:00:00Z' },
        { id: 'c2', title: 'Impossible travel for j.doe', status: 'open', severity: 'high', createdAt: '2026-09-27T11:00:00Z', updatedAt: '2026-09-27T11:00:00Z' },
      ],
      total: 2,
    };

    render(<CasesView />);

    expect(screen.getByText(/^2 cases$/)).toBeInTheDocument();
  });
});
