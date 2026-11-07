/**
 * The console had two version surfaces reading two different things.
 *
 * `Sidebar.tsx` imported `package.json` and rendered `packageJson.version`;
 * `SettingsView.tsx` rendered `process.env.NEXT_PUBLIC_APP_VERSION || '0.0.0'`.
 * Both are frozen when the bundle is compiled, by two separate mechanisms, so
 * a pulled image could disagree with itself — and the `'0.0.0'` fallback is
 * the same defect the API's `0.1.0` was: a plausible-looking number standing
 * in for "nobody told me".
 *
 * Both now read `consoleVersion` from `GET /api/runtime-config`, which is the
 * one route whose whole purpose is answering "what does this deployment
 * believe about itself" at request time.
 *
 * The unknown case has its own test because it was previously unreachable:
 * `next.config.js` substituted `'0.0.0'` before the route could ever see an
 * absent value, so the route's own `'unknown'` branch was dead code.
 */
import { renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { UNKNOWN_CONSOLE_VERSION, useConsoleVersion } from './useConsoleVersion';

function mockRuntimeConfig(body: unknown, ok = true) {
  const fetchMock = vi.fn().mockResolvedValue({
    ok,
    json: async () => body,
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('useConsoleVersion', () => {
  it('reports the version the deployment serves at runtime', async () => {
    const fetchMock = mockRuntimeConfig({ consoleVersion: '22.2.0' });

    const { result } = renderHook(() => useConsoleVersion());

    await waitFor(() => expect(result.current.version).toBe('22.2.0'), { timeout: 3000 });
    expect(fetchMock).toHaveBeenCalledWith('/api/runtime-config', expect.anything());
  });

  it('renders an explicit unknown rather than a version-shaped placeholder', async () => {
    mockRuntimeConfig({ consoleVersion: 'unknown' });

    const { result } = renderHook(() => useConsoleVersion());

    await waitFor(() => expect(result.current.version).toBe('unknown'), { timeout: 3000 });
    expect(UNKNOWN_CONSOLE_VERSION).toBe('unknown');
    // The point of the constant: it must never be mistaken for a release.
    expect(UNKNOWN_CONSOLE_VERSION).not.toMatch(/^\d/);
  });

  it('is unknown when the route is unreachable, never a number', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network down')));

    const { result } = renderHook(() => useConsoleVersion());

    await waitFor(() => expect(result.current.isLoading).toBe(false), { timeout: 3000 });
    expect(result.current.version).toBe(UNKNOWN_CONSOLE_VERSION);
  });

  it('is unknown when the route answers without a version', async () => {
    mockRuntimeConfig({ demoMode: false });

    const { result } = renderHook(() => useConsoleVersion());

    await waitFor(() => expect(result.current.isLoading).toBe(false), { timeout: 3000 });
    expect(result.current.version).toBe(UNKNOWN_CONSOLE_VERSION);
  });

  it('does not report a version while the answer is still in flight', () => {
    mockRuntimeConfig({ consoleVersion: '22.2.0' });

    const { result } = renderHook(() => useConsoleVersion());

    expect(result.current.isLoading).toBe(true);
    expect(result.current.version).toBeNull();
  });
});
