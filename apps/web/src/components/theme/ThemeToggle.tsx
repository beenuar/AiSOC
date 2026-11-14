'use client';

import { useTheme, type ThemePreference } from './ThemeProvider';

type ThemeToggleProps = {
  className?: string;
};

const PREFERENCE_LABELS: Record<ThemePreference, string> = {
  dark: 'Dark theme',
  light: 'Light theme',
  system: 'Match system theme',
};

const PREFERENCE_ORDER: ThemePreference[] = ['dark', 'light', 'system'];

function preferenceIcon(preference: ThemePreference) {
  switch (preference) {
    case 'light':
      return (
        <svg
          xmlns="http://www.w3.org/2000/svg"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={1.6}
          strokeLinecap="round"
          strokeLinejoin="round"
          className="h-4 w-4"
          aria-hidden
        >
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
        </svg>
      );
    case 'system':
      return (
        <svg
          xmlns="http://www.w3.org/2000/svg"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={1.6}
          strokeLinecap="round"
          strokeLinejoin="round"
          className="h-4 w-4"
          aria-hidden
        >
          <rect x="3" y="4" width="18" height="12" rx="2" />
          <path d="M8 20h8M12 16v4" />
        </svg>
      );
    case 'dark':
    default:
      return (
        <svg
          xmlns="http://www.w3.org/2000/svg"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={1.6}
          strokeLinecap="round"
          strokeLinejoin="round"
          className="h-4 w-4"
          aria-hidden
        >
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79Z" />
        </svg>
      );
  }
}

/**
 * Compact tri-state toggle (dark → light → system → dark). Lives in the
 * TopBar so a buyer can flip themes without leaving whatever screen they
 * landed on. Keyboard-accessible (renders as a real `<button>`) and
 * announces the next state to screen readers via `aria-label`.
 */
export function ThemeToggle({ className }: ThemeToggleProps) {
  const { preference, toggle } = useTheme();

  // The button advertises the *next* state because that's what activating
  // it will do — clearer than describing the current one.
  const idx = PREFERENCE_ORDER.indexOf(preference);
  const next = PREFERENCE_ORDER[(idx + 1) % PREFERENCE_ORDER.length];
  const label = `Switch to ${PREFERENCE_LABELS[next].toLowerCase()}`;

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={label}
      title={label}
      className={
        'rounded-md p-1.5 text-fg-muted transition-colors hover:bg-surface-hover hover:text-fg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/50 ' +
        (className ?? '')
      }
    >
      {preferenceIcon(preference)}
      <span className="sr-only">{PREFERENCE_LABELS[preference]}</span>
    </button>
  );
}
