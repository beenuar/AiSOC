/**
 * The reader the catalogue never had.
 *
 * `apps/web/src/lib/i18n/` shipped a translator, a direction helper and two
 * catalogues that **no component imported**, so the console was English-only
 * while the parity gate stayed green — it compared the locales with each
 * other and never asked whether anything rendered them. Issue #1729.
 *
 * Asserted by name below:
 *
 * * **direction reaches the document, not just the strings** — the whole
 *   point of a right-to-left pilot locale. Arabic glyphs laid out
 *   left-to-right is the failure this is here to prevent, and it is
 *   invisible to any assertion that only reads text content;
 * * **the choice survives a reload** — written to localStorage and read
 *   back on mount, which is what "persists" has to mean;
 * * **the server's preference wins over this device's** — so the choice
 *   follows an operator to a new browser;
 * * **a tree with no provider still renders English** — `useLocale()`
 *   falls back rather than throwing, because a component that crashes
 *   outside a provider makes adding a translated string a risk.
 */

import { render, screen } from '@testing-library/react';
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

import { LocaleProvider, useLocale } from './LocaleProvider';
import { LOCALE_STORAGE_KEY } from '@/lib/i18n';

/** Shows the active locale, the direction, and a string from the catalogue. */
function Probe() {
  const { locale, dir, t, setLocale } = useLocale();
  return (
    <div>
      <p data-testid="locale">{locale}</p>
      <p data-testid="dir">{dir}</p>
      <p data-testid="nav-alerts">{t('nav.alerts')}</p>
      <button type="button" onClick={() => setLocale('ar')}>
        to arabic
      </button>
    </div>
  );
}

beforeEach(() => {
  window.localStorage.clear();
  currentUser.mockReturnValue(null);
  updateUserPreferences.mockClear();
  document.documentElement.setAttribute('lang', 'en');
  document.documentElement.setAttribute('dir', 'ltr');
});

afterEach(() => {
  vi.clearAllMocks();
});

describe('LocaleProvider', () => {
  it('renders the base locale when nothing has been chosen', () => {
    render(
      <LocaleProvider>
        <Probe />
      </LocaleProvider>,
    );

    expect(screen.getByTestId('locale').textContent).toBe('en');
    expect(screen.getByTestId('nav-alerts').textContent).toBe('Alerts');
  });

  it('puts the chosen language and its direction on the document', async () => {
    const user = userEvent.setup();
    render(
      <LocaleProvider>
        <Probe />
      </LocaleProvider>,
    );

    await user.click(screen.getByRole('button', { name: 'to arabic' }));

    // The strings.
    expect(screen.getByTestId('locale').textContent).toBe('ar');
    expect(screen.getByTestId('nav-alerts').textContent).toBe('التنبيهات');
    // And the layout. Without this the catalogue renders Arabic glyphs in a
    // left-to-right page, which is the one outcome that looks translated
    // and reads wrong.
    expect(document.documentElement.getAttribute('dir')).toBe('rtl');
    expect(document.documentElement.getAttribute('lang')).toBe('ar');
  });

  it('persists the choice to this device and to the profile', async () => {
    const user = userEvent.setup();
    render(
      <LocaleProvider>
        <Probe />
      </LocaleProvider>,
    );

    await user.click(screen.getByRole('button', { name: 'to arabic' }));

    expect(window.localStorage.getItem(LOCALE_STORAGE_KEY)).toBe('ar');
    expect(updateUserPreferences).toHaveBeenCalledWith({ locale: 'ar' });
  });

  it('reads the stored choice back on mount', () => {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, 'ar');

    render(
      <LocaleProvider>
        <Probe />
      </LocaleProvider>,
    );

    expect(screen.getByTestId('locale').textContent).toBe('ar');
    expect(document.documentElement.getAttribute('dir')).toBe('rtl');
  });

  it('ignores a stored value that is not a locale', () => {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, 'klingon');

    render(
      <LocaleProvider>
        <Probe />
      </LocaleProvider>,
    );

    expect(screen.getByTestId('locale').textContent).toBe('en');
  });

  it('prefers the profile over this device, so the choice roams', () => {
    currentUser.mockReturnValue({ preferences: { locale: 'ar' } });

    render(
      <LocaleProvider>
        <Probe />
      </LocaleProvider>,
    );

    expect(screen.getByTestId('locale').textContent).toBe('ar');
    expect(window.localStorage.getItem(LOCALE_STORAGE_KEY)).toBe('ar');
  });

  it('survives a profile that names a language the console does not ship', () => {
    currentUser.mockReturnValue({ preferences: { locale: 'klingon' } });

    render(
      <LocaleProvider>
        <Probe />
      </LocaleProvider>,
    );

    expect(screen.getByTestId('locale').textContent).toBe('en');
  });

  it('renders English outside a provider instead of throwing', () => {
    // `useTheme()` throws here because a themeless tree has no sensible
    // default. An untranslated one does — it is what the console was.
    render(<Probe />);

    expect(screen.getByTestId('locale').textContent).toBe('en');
    expect(screen.getByTestId('nav-alerts').textContent).toBe('Alerts');
  });

  it('does not undo the operator\'s choice when the profile write fails', async () => {
    updateUserPreferences.mockRejectedValueOnce(new Error('offline'));
    const user = userEvent.setup();
    render(
      <LocaleProvider>
        <Probe />
      </LocaleProvider>,
    );

    await user.click(screen.getByRole('button', { name: 'to arabic' }));

    expect(screen.getByTestId('locale').textContent).toBe('ar');
    expect(document.documentElement.getAttribute('dir')).toBe('rtl');
  });
});
