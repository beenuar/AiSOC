import { describe, it, expect, beforeEach, beforeAll, vi } from 'vitest';
import { act, render, renderHook } from '@testing-library/react';
import { ThemeProvider, useTheme } from './ThemeProvider';
import { THEME_STORAGE_KEY } from './themeScript';

/**
 * The theme system is the buyer's first interaction with personalisation:
 * if the toggle doesn't persist, doesn't survive remounts, or paints the
 * wrong default, the rest of WS-F1 is academic. These tests cover the
 * surface contract — they intentionally don't pin the visual output.
 */

// Node 24+ ships a partial built-in `localStorage` (only `removeItem`).
// Replace it with a complete in-memory store so the suite can write *and*
// read keys reliably. Scoped to this file so we don't change behaviour for
// any other test that might be intentionally exercising the partial shim.
beforeAll(() => {
  const store = new Map<string, string>();
  const memoryStorage: Storage = {
    get length() {
      return store.size;
    },
    clear: () => store.clear(),
    getItem: (key) => (store.has(key) ? (store.get(key) as string) : null),
    key: (index) => Array.from(store.keys())[index] ?? null,
    removeItem: (key) => {
      store.delete(key);
    },
    setItem: (key, value) => {
      store.set(key, String(value));
    },
  };
  Object.defineProperty(window, 'localStorage', {
    configurable: true,
    value: memoryStorage,
  });
});

function setSystemPrefersLight(prefersLight: boolean) {
  // Override the matchMedia stub from setup.ts so we can swap the OS theme.
  window.matchMedia = (query: string) =>
    ({
      matches: query.includes('light') ? prefersLight : !prefersLight,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(() => false),
    }) as MediaQueryList;
}

describe('ThemeProvider', () => {
  beforeEach(() => {
    window.localStorage.clear();
    document.documentElement.removeAttribute('data-theme');
    document.documentElement.removeAttribute('data-theme-preference');
    document.documentElement.style.colorScheme = '';
    setSystemPrefersLight(false);
  });

  it('defaults to dark when localStorage is empty', () => {
    const { result } = renderHook(() => useTheme(), {
      wrapper: ({ children }) => <ThemeProvider>{children}</ThemeProvider>,
    });
    expect(result.current.preference).toBe('dark');
    expect(result.current.resolved).toBe('dark');
  });

  it('hydrates from localStorage when set', () => {
    window.localStorage.setItem(THEME_STORAGE_KEY, 'light');
    const { result } = renderHook(() => useTheme(), {
      wrapper: ({ children }) => <ThemeProvider>{children}</ThemeProvider>,
    });
    expect(result.current.preference).toBe('light');
    expect(result.current.resolved).toBe('light');
  });

  it('resolves "system" against prefers-color-scheme', () => {
    window.localStorage.setItem(THEME_STORAGE_KEY, 'system');
    setSystemPrefersLight(true);
    const { result } = renderHook(() => useTheme(), {
      wrapper: ({ children }) => <ThemeProvider>{children}</ThemeProvider>,
    });
    expect(result.current.preference).toBe('system');
    expect(result.current.resolved).toBe('light');
  });

  it('toggle cycles dark → light → system → dark', () => {
    const { result } = renderHook(() => useTheme(), {
      wrapper: ({ children }) => <ThemeProvider>{children}</ThemeProvider>,
    });

    expect(result.current.preference).toBe('dark');
    act(() => result.current.toggle());
    expect(result.current.preference).toBe('light');
    act(() => result.current.toggle());
    expect(result.current.preference).toBe('system');
    act(() => result.current.toggle());
    expect(result.current.preference).toBe('dark');
  });

  it('persists the choice to localStorage and writes data-theme onto <html>', () => {
    const { result } = renderHook(() => useTheme(), {
      wrapper: ({ children }) => <ThemeProvider>{children}</ThemeProvider>,
    });

    act(() => result.current.setPreference('light'));

    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe('light');
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    expect(document.documentElement.getAttribute('data-theme-preference')).toBe(
      'light',
    );
  });

  it('renders children inside the provider boundary', () => {
    const { getByTestId } = render(
      <ThemeProvider>
        <div data-testid="probe">probe</div>
      </ThemeProvider>,
    );
    expect(getByTestId('probe')).toBeInTheDocument();
  });
});
