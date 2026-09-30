/**
 * The fabricated case list stays withheld outside the hosted demo.
 *
 * This file used to assert that an `initialCases` prop, fed by a server-side
 * fetch in `cases/page.tsx`, survived into the first paint. That fetch sent
 * no credential and a build-time tenant id, so it served one fixed tenant's
 * cases to whoever loaded the page and only returned anything because an
 * uncredentialed request resolved to a demo administrator. It was removed,
 * and with it the prop: a server render has no session to borrow, so there
 * was no authenticated version of that call to keep.
 *
 * What still matters, and is what this file now covers, is the direction that
 * has a production path: `demoFallback` must hand SWR the sample list inside
 * the hosted demo and nothing at all outside it. Folding real data and sample
 * data into one object and passing the pair through `demoFallback` is how
 * that gate got confused once already.
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

const FABRICATED_TITLES = [
  'Ransomware incident on finance workstations',
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

describe('the fabricated case list is withheld outside demo mode', () => {
  it('renders none of the sample titles', () => {
    render(<CasesView />);

    for (const title of FABRICATED_TITLES) {
      expect(
        screen.queryByText(title),
        `"${title}" is sample data and must not render outside demo mode`,
      ).toBeNull();
    }
  });

  it('hands SWR no fallback at all, rather than a fabricated one', () => {
    render(<CasesView />);

    const supplied = [...swrFallbacks.values()] as (CasesResponse | undefined)[];
    expect(supplied.every((value) => value === undefined)).toBe(true);
  });
});

describe('the hosted demo is still populated', () => {
  it('shows the sample list when the build is the demo', () => {
    __setDemoModeForTests(true);

    render(<CasesView />);

    // The sample list cycles ten titles across eighteen rows, so each one
    // appears more than once.
    expect(
      screen.getAllByText('Ransomware incident on finance workstations').length,
    ).toBeGreaterThan(0);
  });
});
