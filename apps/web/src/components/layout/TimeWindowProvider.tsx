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
  DEFAULT_TIME_WINDOW,
  TIME_WINDOW_STORAGE_KEY,
  isTimeWindow,
  type TimeWindow,
} from '@/lib/timeWindow';

interface TimeWindowContextValue {
  /** Currently-active window — every dashboard should bind to this. */
  window: TimeWindow;
  /** Update the window and persist (localStorage + user preferences). */
  setWindow: (next: TimeWindow) => void;
}

const TimeWindowContext = createContext<TimeWindowContextValue | null>(null);

function readStored(): TimeWindow {
  if (typeof window === 'undefined') return DEFAULT_TIME_WINDOW;
  try {
    const raw = window.localStorage.getItem(TIME_WINDOW_STORAGE_KEY);
    if (isTimeWindow(raw)) return raw;
  } catch {
    /* localStorage can be unavailable (iOS private mode); ignore */
  }
  return DEFAULT_TIME_WINDOW;
}

/**
 * Provides the global TimeWindow (W4).
 *
 * Initial render uses the default window so SSR and the first client paint
 * match exactly — there's no inline bootstrap script for this (unlike the
 * theme, where the wrong colour for one paint is visually jarring). Right
 * after mount we reconcile with localStorage *and* the user's server-side
 * preference so the choice roams across browsers.
 *
 * Writes are local-first: we update React state + localStorage
 * synchronously, then fire-and-forget the PATCH to /auth/me/preferences.
 * A failed network call must not throw away the user's selection.
 */
export function TimeWindowProvider({ children }: { children: ReactNode }) {
  const [timeWindow, setTimeWindowState] = useState<TimeWindow>(DEFAULT_TIME_WINDOW);

  // Mount: reconcile with localStorage, then with the server-stored user
  // preference (cached from /me). Same pattern as ThemeProvider so the two
  // behave identically — once we hydrate, the user's last-chosen window
  // wins, and if that disagrees with the server, the server value takes
  // precedence (i.e. "I logged in from a new machine — my preference comes
  // with me").
  useEffect(() => {
    const stored = readStored();
    if (stored !== DEFAULT_TIME_WINDOW) {
      setTimeWindowState(stored);
    }

    const user = authApi.currentUser();
    const serverWindow = user?.preferences?.timeWindow;
    if (isTimeWindow(serverWindow) && serverWindow !== stored) {
      setTimeWindowState(serverWindow);
      try {
        window.localStorage.setItem(TIME_WINDOW_STORAGE_KEY, serverWindow);
      } catch {
        /* ignore */
      }
    }
  }, []);

  const setWindow = useCallback((next: TimeWindow) => {
    setTimeWindowState(next);
    try {
      window.localStorage.setItem(TIME_WINDOW_STORAGE_KEY, next);
    } catch {
      /* private mode — accept that this doesn't persist */
    }
    // Fire-and-forget; the local value is the source of truth.
    authApi.updateUserPreferences({ timeWindow: next }).catch(() => {
      /* ignore — server preference is a nice-to-have, not a guarantee */
    });
  }, []);

  const value = useMemo<TimeWindowContextValue>(
    () => ({ window: timeWindow, setWindow }),
    [timeWindow, setWindow],
  );

  return <TimeWindowContext.Provider value={value}>{children}</TimeWindowContext.Provider>;
}

export function useTimeWindow(): TimeWindowContextValue {
  const ctx = useContext(TimeWindowContext);
  if (!ctx) {
    throw new Error('useTimeWindow() must be used inside <TimeWindowProvider>');
  }
  return ctx;
}
