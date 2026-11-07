/**
 * A real surface rendering through the catalogue, not just the provider.
 *
 * Issue #1729. The provider's own test proves the plumbing; this proves a
 * page. The distinction matters here more than usual, because the defect
 * being fixed was *exactly* a working mechanism with no caller — a test
 * that only exercises `translate()` is the shape that let the catalogue
 * ship unread for its whole life.
 *
 * So these assertions fail if a hardcoded English string comes back: the
 * page heading, the error title and the retry control are read in Arabic
 * and the English literals are asserted absent. Reverting any of them to a
 * literal reds this file.
 *
 * The per-key equivalent, across all 52 keys rather than the handful a DOM
 * test can reach, is `scripts/check_i18n_keys.py` — which fails when a key
 * stops being rendered anywhere.
 */

import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { LOCALE_STORAGE_KEY } from '@/lib/i18n';

const swrData = vi.hoisted(() => new Map<string, unknown>());
const swrErrors = vi.hoisted(() => new Map<string, unknown>());

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown, _fetcher: unknown, options?: { fallbackData?: unknown }) => {
    const k = typeof key === 'string' ? key : JSON.stringify(key);
    return {
      data: swrErrors.has(k) ? undefined : (swrData.get(k) ?? options?.fallbackData),
      error: swrErrors.get(k),
      isLoading: false,
      mutate: vi.fn(),
    };
  },
}));

vi.mock('@/lib/api', () => ({
  __esModule: true,
  casesApi: { list: vi.fn() },
  // The provider reads the cached profile so the choice roams; without
  // this the module mock would leave `authApi` undefined.
  authApi: { currentUser: () => null, updateUserPreferences: () => Promise.resolve({}) },
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

import { CasesView } from '@/components/cases/CasesView';
import { ErrorState } from '@/components/ui/ErrorState';
import { LocaleProvider } from './LocaleProvider';

/** Mount with Arabic already chosen, as a returning operator would have it. */
function renderInArabic(ui: React.ReactElement) {
  window.localStorage.setItem(LOCALE_STORAGE_KEY, 'ar');
  return render(<LocaleProvider>{ui}</LocaleProvider>);
}

beforeEach(() => {
  swrData.clear();
  swrErrors.clear();
  window.localStorage.clear();
  document.documentElement.setAttribute('dir', 'ltr');
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('the Cases surface renders through the catalogue', () => {
  it('reads its heading from the catalogue, not from a literal', () => {
    renderInArabic(<CasesView />);

    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('الحالات');
    // The literal that used to be there. If someone puts it back, this
    // fails — which is the whole point of asserting the absence too.
    expect(screen.queryByText('Cases')).toBeNull();
  });

  it('puts the page into right-to-left, not just into Arabic glyphs', () => {
    renderInArabic(<CasesView />);

    expect(document.documentElement.getAttribute('dir')).toBe('rtl');
  });

  it('reads the unreadable-queue title from the catalogue', () => {
    swrErrors.set(JSON.stringify(['cases', 'all', 'all']), new Error('boom'));
    renderInArabic(<CasesView />);

    // "we could not read the list" and "the list is empty" are different
    // facts about a SOC, and the translated copy has to keep them apart.
    expect(screen.getByText('تعذّر تحميل الحالات')).toBeTruthy();
    expect(screen.queryByText('Could not load cases')).toBeNull();
  });
});

describe('the shared error primitive renders through the catalogue', () => {
  it('translates the retry control everywhere the console reports a failure', () => {
    renderInArabic(<ErrorState onRetry={() => {}} />);

    expect(screen.getByRole('button').textContent).toBe('إعادة المحاولة');
    expect(screen.queryByText('Retry')).toBeNull();
  });

  it('still renders English with no provider in the tree', () => {
    // Many tests mount this component bare. `useLocale()` falls back
    // rather than throwing, so they keep working.
    render(<ErrorState onRetry={() => {}} />);

    expect(screen.getByRole('button').textContent).toBe('Retry');
  });
});
