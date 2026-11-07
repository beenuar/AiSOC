/**
 * The language switcher, and the honesty of what it claims to translate.
 *
 * Issue #1729. The switcher is the easy half; the hard half is that the
 * catalogue covers the analyst surfaces and not the console, so a switcher
 * that silently translates a sliver reads as *more* broken than a page that
 * was never translated. What is asserted here is therefore as much about
 * the disclosure as about the control:
 *
 * * **switching works end to end** — picking a language changes the strings
 *   and the document's reading direction;
 * * **languages are offered under their own names** — somebody looking for
 *   Arabic scans for العربية, not for the English word;
 * * **the scope table tells the truth per surface** — translated, falling
 *   back, or not covered at all, each derived from the catalogue rather
 *   than from a sentence that goes stale the first time a surface is
 *   added. A surface the catalogue has never heard of must read "not
 *   translated" and never 100%, because zero of zero is not full coverage;
 * * **the counts are catalogue strings, not a share of the console** — the
 *   note that says so has to be on screen, or "46 of 52" reads as "most of
 *   the product is in Arabic", which is wildly untrue.
 */

import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const currentUser = vi.hoisted(() => vi.fn<() => unknown>(() => null));
const updateUserPreferences = vi.hoisted(() =>
  vi.fn<(p: Record<string, unknown>) => Promise<unknown>>(() => Promise.resolve({})),
);

vi.mock('@/lib/api', () => ({
  __esModule: true,
  authApi: { currentUser, updateUserPreferences },
}));

import { LanguagePanel } from './LanguagePanel';
import { LocaleProvider } from '@/components/i18n/LocaleProvider';
import { en } from '@/lib/i18n/messages/en';
import { ar } from '@/lib/i18n/messages/ar';

function renderPanel() {
  return render(
    <LocaleProvider>
      <LanguagePanel />
    </LocaleProvider>,
  );
}

/** The scope row for a destination, found by its visible label. */
function scopeRow(label: string): HTMLElement {
  const row = screen.getByText(label).closest('li');
  if (!row) throw new Error(`no scope row for ${label}`);
  return row;
}

beforeEach(() => {
  window.localStorage.clear();
  currentUser.mockReturnValue(null);
  document.documentElement.setAttribute('dir', 'ltr');
});

afterEach(() => {
  vi.clearAllMocks();
});

describe('LanguagePanel', () => {
  it('offers each language under its own name', () => {
    renderPanel();

    expect(screen.getByRole('button', { name: /English/ })).toBeTruthy();
    expect(screen.getByRole('button', { name: /العربية/ })).toBeTruthy();
  });

  it('switches the console and the document direction', async () => {
    const user = userEvent.setup();
    renderPanel();

    await user.click(screen.getByRole('button', { name: /العربية/ }));

    expect(document.documentElement.getAttribute('dir')).toBe('rtl');
    // The panel's own copy is translated, so the scope note is readable by
    // the person who just chose Arabic — which is the only person who needs
    // to be told that the rest of the console is not.
    expect(screen.getByText('ما الذي تشمله الترجمة')).toBeTruthy();
    expect(screen.queryByText(en.language.scopeTitle)).toBeNull();
  });

  it('marks the pressed language, so the current choice is visible', async () => {
    const user = userEvent.setup();
    renderPanel();

    expect(screen.getByRole('button', { name: /English/ }).getAttribute('aria-pressed')).toBe('true');

    await user.click(screen.getByRole('button', { name: /العربية/ }));

    expect(screen.getByRole('button', { name: /العربية/ }).getAttribute('aria-pressed')).toBe('true');
    expect(screen.getByRole('button', { name: /English/ }).getAttribute('aria-pressed')).toBe('false');
  });

  it('states the scope rather than leaving the reader to discover it', () => {
    renderPanel();

    // The sentence that stops "46 of 52" being read as a share of the
    // product. Without it the counts are actively misleading.
    expect(screen.getByText(en.language.scopeNote)).toBeTruthy();
    expect(screen.getByText(en.language.contribute)).toBeTruthy();
  });

  it('reports a covered surface as translated', async () => {
    const user = userEvent.setup();
    renderPanel();
    await user.click(screen.getByRole('button', { name: /العربية/ }));

    // `alerts.*` is fully translated in the pilot locale.
    expect(within(scopeRow('التنبيهات')).getByText('مُترجَم')).toBeTruthy();
  });

  it('reports a surface the locale leaves untranslated as falling back', async () => {
    const user = userEvent.setup();
    renderPanel();
    await user.click(screen.getByRole('button', { name: /العربية/ }));

    // `settings.*` is deliberately untranslated in the pilot locale so the
    // fallback is exercised on a real screen. The switcher says so instead
    // of letting the operator wonder why this page stayed English.
    expect(within(scopeRow('الإعدادات')).getByText('يعود إلى الإنجليزية')).toBeTruthy();
  });

  it('reports a surface with no keys as not translated, never as complete', () => {
    renderPanel();

    // Explore has no catalogue surface at all. The tempting bug is to
    // compute 0/0 and render 100%.
    const row = scopeRow('Explore');
    expect(within(row).getByText(en.language.absent)).toBeTruthy();
    expect(within(row).queryByText(/of \d+ strings/)).toBeNull();
  });

  it('counts the strings the catalogues actually carry', () => {
    // Counted here from the catalogue modules rather than by asking the
    // same function the component asks. A meter compared against a second
    // call to the thing being measured agrees with itself whatever it does.
    const flatten = (node: unknown, prefix = ''): string[] =>
      typeof node === 'object' && node !== null
        ? Object.entries(node).flatMap(([k, v]) =>
            typeof v === 'string' ? [prefix ? `${prefix}.${k}` : k] : flatten(v, prefix ? `${prefix}.${k}` : k),
          )
        : [];

    const total = flatten(en).length;
    const translated = flatten(ar).length;
    expect(total).toBeGreaterThan(translated); // the pilot locale is a deep partial

    renderPanel();

    const arabic = screen.getByRole('button', { name: /العربية/ });
    expect(within(arabic).getByText(`${translated} of ${total} strings`)).toBeTruthy();
  });
});
