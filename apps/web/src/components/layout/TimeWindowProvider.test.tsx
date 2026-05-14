import { describe, expect, it, beforeEach, vi } from 'vitest';
import { act, render, renderHook, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { TimeWindowProvider, useTimeWindow } from './TimeWindowProvider';
import { TIME_WINDOW_STORAGE_KEY, type TimeWindow } from '@/lib/timeWindow';

// Minimal `authApi` mock — TimeWindowProvider reads `currentUser()?.preferences`
// at mount and fires `updateUserPreferences` on writes. The provider must work
// when the user is logged out (currentUser → null) and must not crash if the
// preferences PATCH rejects.
const currentUserMock = vi.fn(() => null as { preferences?: Record<string, unknown> } | null);
const updateUserPreferencesMock = vi.fn(
  (_p: Record<string, unknown>) => Promise.resolve() as Promise<unknown>,
);

vi.mock('@/lib/api', () => ({
  authApi: {
    currentUser: () => currentUserMock(),
    updateUserPreferences: (p: Record<string, unknown>) => updateUserPreferencesMock(p),
  },
}));

function clearStorage() {
  try {
    window.localStorage.removeItem(TIME_WINDOW_STORAGE_KEY);
  } catch {
    /* ignore */
  }
}

describe('TimeWindowProvider', () => {
  beforeEach(() => {
    clearStorage();
    currentUserMock.mockReset();
    currentUserMock.mockReturnValue(null);
    updateUserPreferencesMock.mockReset();
    updateUserPreferencesMock.mockResolvedValue(undefined as never);
  });

  it('defaults to "24h" when nothing is stored and the user has no preference', () => {
    const { result } = renderHook(() => useTimeWindow(), {
      wrapper: ({ children }) => <TimeWindowProvider>{children}</TimeWindowProvider>,
    });
    expect(result.current.window).toBe<TimeWindow>('24h');
  });

  it('reconciles to a stored value on mount', async () => {
    window.localStorage.setItem(TIME_WINDOW_STORAGE_KEY, '7d');
    const { result } = renderHook(() => useTimeWindow(), {
      wrapper: ({ children }) => <TimeWindowProvider>{children}</TimeWindowProvider>,
    });
    // useEffect runs after the initial render; tick the React tree once.
    await act(async () => {});
    expect(result.current.window).toBe<TimeWindow>('7d');
  });

  it('persists writes to localStorage and the server', async () => {
    const { result } = renderHook(() => useTimeWindow(), {
      wrapper: ({ children }) => <TimeWindowProvider>{children}</TimeWindowProvider>,
    });
    await act(async () => {
      result.current.setWindow('30d');
    });
    expect(result.current.window).toBe<TimeWindow>('30d');
    expect(window.localStorage.getItem(TIME_WINDOW_STORAGE_KEY)).toBe('30d');
    expect(updateUserPreferencesMock).toHaveBeenCalledWith({ timeWindow: '30d' });
  });

  it('prefers the server preference over a stale localStorage value', async () => {
    window.localStorage.setItem(TIME_WINDOW_STORAGE_KEY, '24h');
    currentUserMock.mockReturnValue({ preferences: { timeWindow: '7d' } });
    const { result } = renderHook(() => useTimeWindow(), {
      wrapper: ({ children }) => <TimeWindowProvider>{children}</TimeWindowProvider>,
    });
    await act(async () => {});
    expect(result.current.window).toBe<TimeWindow>('7d');
    // The provider should also rewrite localStorage so the next paint matches.
    expect(window.localStorage.getItem(TIME_WINDOW_STORAGE_KEY)).toBe('7d');
  });

  it('throws when useTimeWindow() is called outside the provider', () => {
    // Silence the React error boundary noise.
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => renderHook(() => useTimeWindow())).toThrow(
      /useTimeWindow\(\) must be used inside <TimeWindowProvider>/,
    );
    err.mockRestore();
  });

  it('does not crash when localStorage is unavailable', async () => {
    // Simulate iOS Private Mode: getItem/setItem throw. The test setup installs
    // a custom Storage shim on `window`, so we patch the shim's own methods
    // rather than `Storage.prototype` (which the shim doesn't inherit from).
    const original = window.localStorage;
    const broken = {
      ...original,
      getItem: () => {
        throw new Error('QuotaExceededError');
      },
      setItem: () => {
        throw new Error('QuotaExceededError');
      },
    } as Storage;
    Object.defineProperty(window, 'localStorage', { configurable: true, value: broken });

    try {
      const { result } = renderHook(() => useTimeWindow(), {
        wrapper: ({ children }) => <TimeWindowProvider>{children}</TimeWindowProvider>,
      });
      await act(async () => {
        // Should not throw even though localStorage is broken.
        result.current.setWindow('1h');
      });
      expect(result.current.window).toBe<TimeWindow>('1h');
    } finally {
      Object.defineProperty(window, 'localStorage', {
        configurable: true,
        value: original,
      });
    }
  });
});

describe('TimeWindowProvider integration with consumers', () => {
  beforeEach(() => {
    clearStorage();
    currentUserMock.mockReset();
    currentUserMock.mockReturnValue(null);
    updateUserPreferencesMock.mockReset();
    updateUserPreferencesMock.mockResolvedValue(undefined as never);
  });

  it('exposes the current window to nested consumers', async () => {
    function Probe() {
      const { window: w, setWindow } = useTimeWindow();
      return (
        <div>
          <span data-testid="window">{w}</span>
          <button onClick={() => setWindow('1h')}>shrink</button>
        </div>
      );
    }
    render(
      <TimeWindowProvider>
        <Probe />
      </TimeWindowProvider>,
    );
    expect(screen.getByTestId('window')).toHaveTextContent('24h');
    await userEvent.click(screen.getByRole('button', { name: /shrink/i }));
    expect(screen.getByTestId('window')).toHaveTextContent('1h');
  });
});
