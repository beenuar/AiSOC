'use client';

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { authApi } from '@/lib/api';
import {
  BASE_LOCALE,
  LOCALE_STORAGE_KEY,
  direction,
  isLocaleCode,
  translate,
  type LocaleCode,
} from '@/lib/i18n';

/**
 * The component tree's access to the translation catalogue.
 *
 * `apps/web/src/lib/i18n/` shipped a working `translate()`, a `direction()`
 * and two catalogues, and **nothing imported any of it** — so the console
 * was English-only with a green parity gate, because that gate compared the
 * locales with each other and never asked whether anything rendered them.
 * This is the reader. `scripts/check_i18n_keys.py` now fails when it is
 * missing, per key rather than per import.
 *
 * Deliberately shaped like `ThemeProvider`: the same storage-then-server
 * reconciliation, the same pre-paint bootstrap script, the same default in
 * `useState` so the first React render matches the markup the server sent.
 * A second pattern for the same problem is a second thing to keep right.
 *
 * **No automatic negotiation from `navigator.languages`.** The catalogue
 * covers a fraction of the console, so resolving an Arabic browser into a
 * partly-Arabic page nobody asked for is a worse first impression than
 * English. The choice is explicit, in Settings, and `negotiateLocale()`
 * stays available for the day coverage justifies it.
 */

type LocaleContextValue = {
  locale: LocaleCode;
  /** `translate()` bound to the active locale. */
  t: (key: string, values?: Record<string, string | number>) => string;
  /** Reading direction of the active locale. */
  dir: 'ltr' | 'rtl';
  setLocale: (next: LocaleCode) => void;
};

const LocaleContext = createContext<LocaleContextValue | null>(null);

function readStoredLocale(): LocaleCode {
  if (typeof window === 'undefined') return BASE_LOCALE;
  try {
    const value = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    if (value && isLocaleCode(value)) return value;
  } catch {
    // localStorage throws in iOS private browsing; fall back silently.
  }
  return BASE_LOCALE;
}

/**
 * Language and direction both live on `<html>`.
 *
 * `dir` is the half that matters and the half a string-only
 * implementation forgets: without it the Arabic catalogue renders
 * left-to-right in Arabic glyphs, with punctuation and numbers in the
 * wrong places. `lang` is not decoration either — it is what a screen
 * reader switches voice on, and what `:lang()` and hyphenation read.
 */
function applyLocale(locale: LocaleCode) {
  if (typeof document === 'undefined') return;
  const root = document.documentElement;
  root.setAttribute('lang', locale);
  root.setAttribute('dir', direction(locale));
}

export function LocaleProvider({ children }: { children: ReactNode }) {
  // Same default as the bootstrap script and the server-rendered `<html>`,
  // so the first client render cannot disagree with the markup. The effect
  // below corrects it from storage on mount.
  const [locale, setLocaleState] = useState<LocaleCode>(BASE_LOCALE);

  useEffect(() => {
    const stored = readStoredLocale();
    setLocaleState(stored);
    applyLocale(stored);

    // Reconcile with the profile the last `/me` call cached, so the choice
    // follows the operator to a new browser. Local storage wins only when
    // the server has no opinion.
    const serverLocale = authApi.currentUser()?.preferences?.locale;
    if (typeof serverLocale === 'string' && isLocaleCode(serverLocale) && serverLocale !== stored) {
      setLocaleState(serverLocale);
      applyLocale(serverLocale);
      try {
        window.localStorage.setItem(LOCALE_STORAGE_KEY, serverLocale);
      } catch {
        /* ignore */
      }
    }
  }, []);

  const setLocale = useCallback((next: LocaleCode) => {
    setLocaleState(next);
    applyLocale(next);
    try {
      window.localStorage.setItem(LOCALE_STORAGE_KEY, next);
    } catch {
      // private mode / quota — accept that the choice doesn't persist.
    }
    // Fire-and-forget, exactly as the theme does: the local value is the
    // source of truth and a failed network call must not undo a choice the
    // operator can already see on screen.
    authApi.updateUserPreferences({ locale: next }).catch(() => {
      /* ignore */
    });
  }, []);

  const t = useCallback(
    (key: string, values?: Record<string, string | number>) => translate(locale, key, values),
    [locale],
  );

  const value = useMemo<LocaleContextValue>(
    () => ({ locale, t, dir: direction(locale), setLocale }),
    [locale, t, setLocale],
  );

  return <LocaleContext.Provider value={value}>{children}</LocaleContext.Provider>;
}

/**
 * Read the active locale and its bound translator.
 *
 * Falls back to the base locale outside a provider rather than throwing.
 * `useTheme()` throws because a themeless tree is a wiring bug with no
 * sensible default; an untranslated tree has one — English, which is what
 * the console rendered before any of this existed. A component that throws
 * here would make adding a translated string to a page a crash risk, which
 * is how a catalogue stops being adopted.
 */
export function useLocale(): LocaleContextValue {
  const ctx = useContext(LocaleContext);
  return (
    ctx ?? {
      locale: BASE_LOCALE,
      t: (key, values) => translate(BASE_LOCALE, key, values),
      dir: direction(BASE_LOCALE),
      setLocale: () => {},
    }
  );
}
