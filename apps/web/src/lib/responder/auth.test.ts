import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { AUTH_REFRESH_KEY, AUTH_TOKEN_KEY, AUTH_USER_KEY, apiFetch } from '../api';
import {
  clearSession,
  getAccessToken,
  getProfile,
  getRefreshToken,
  isAuthenticated,
  saveSession,
} from './auth';

const NOW = new Date('2026-11-11T08:00:00Z');
const NOW_SECONDS = Math.floor(NOW.getTime() / 1000);
const EXPIRES_KEY = 'aisoc.responder.expiresAt';
const PROFILE_KEY = 'aisoc.responder.profile';
const PROFILE = { user_id: 'responder-1', email: 'responder@example.test', name: 'Responder' };

function token(type: 'access' | 'refresh', expiresIn: number, subject = PROFILE.user_id): string {
  const payload = btoa(JSON.stringify({ sub: subject, type, exp: NOW_SECONDS + expiresIn }))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `eyJhbGciOiJIUzI1NiJ9.${payload}.signature`;
}

beforeEach(() => {
  window.localStorage.clear();
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
});

afterEach(() => {
  window.localStorage.clear();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('responder session recovery', () => {
  it('keeps an expired access session eligible for silent renewal', () => {
    const refresh = token('refresh', 3600);
    saveSession({ access_token: token('access', -60), refresh_token: refresh, expires_in: -60 });

    expect(getAccessToken()).toBeNull();
    expect(getRefreshToken()).toBe(refresh);
    expect(isAuthenticated()).toBe(true);
  });

  it('allows renewal when only a live refresh token remains', () => {
    window.localStorage.setItem(AUTH_REFRESH_KEY, token('refresh', 3600));

    expect(getAccessToken()).toBeNull();
    expect(isAuthenticated()).toBe(true);
  });

  it('does not accept a session whose access and refresh tokens have expired', () => {
    saveSession({
      access_token: token('access', -60),
      refresh_token: token('refresh', -60),
      expires_in: -60,
    });

    expect(getAccessToken()).toBeNull();
    expect(isAuthenticated()).toBe(false);
  });

  it('uses the renewed JWT even when the original passkey expiry is stale', () => {
    saveSession({
      access_token: token('access', -60),
      refresh_token: token('refresh', 3600),
      expires_in: -60,
    });
    const renewedAccess = token('access', 1800);
    window.localStorage.setItem(AUTH_TOKEN_KEY, renewedAccess);

    expect(Number(window.localStorage.getItem(EXPIRES_KEY))).toBeLessThan(Date.now());
    expect(getAccessToken()).toBe(renewedAccess);
    expect(isAuthenticated()).toBe(true);
  });

  it('rejects expired or unreadable access tokens even with a future legacy expiry', () => {
    window.localStorage.setItem(EXPIRES_KEY, String(Date.now() + 3_600_000));
    for (const access of [token('access', -60), 'not-a-jwt']) {
      window.localStorage.setItem(AUTH_TOKEN_KEY, access);
      expect(getAccessToken()).toBeNull();
    }
    expect(isAuthenticated()).toBe(false);
  });

  it('removes the prior desktop user when adopting a passkey session', () => {
    window.localStorage.setItem(AUTH_USER_KEY, JSON.stringify({ id: 'previous-user' }));

    saveSession({
      access_token: token('access', 1800),
      refresh_token: token('refresh', 3600),
      expires_in: 1800,
      profile: PROFILE,
    });

    expect(window.localStorage.getItem(AUTH_USER_KEY)).toBeNull();
    expect(getProfile()).toEqual(PROFILE);
    expect(getAccessToken()).toBe(token('access', 1800));
  });

  it('does not replay a previous user action after a passkey sign-in', async () => {
    saveSession({
      access_token: token('access', 1800),
      refresh_token: token('refresh', 3600),
      expires_in: 1800,
    });
    window.localStorage.setItem(AUTH_USER_KEY, JSON.stringify({ id: PROFILE.user_id }));
    let release!: (response: Response) => void;
    const fetchMock = vi.fn()
      .mockImplementationOnce(() => new Promise<Response>((resolve) => { release = resolve; }))
      .mockResolvedValue(new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const pending = apiFetch('/api/v1/playbooks/example/run', { method: 'POST', body: '{}' });

    const nextAccess = token('access', 1800, 'next-user');
    saveSession({
      access_token: nextAccess,
      refresh_token: token('refresh', 3600, 'next-user'),
      expires_in: 1800,
    });
    release(new Response('{}', { status: 401 }));

    await expect(pending).rejects.toThrow('Session changed');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(getAccessToken()).toBe(nextAccess);
  });

  it('clears both the shared user session and the responder profile on logout', () => {
    saveSession({
      access_token: token('access', 1800),
      refresh_token: token('refresh', 3600),
      expires_in: 1800,
      profile: PROFILE,
    });
    window.localStorage.setItem(AUTH_USER_KEY, JSON.stringify({ id: PROFILE.user_id }));
    expect(getProfile()).toEqual(PROFILE);

    clearSession();

    for (const key of [AUTH_TOKEN_KEY, AUTH_REFRESH_KEY, AUTH_USER_KEY, EXPIRES_KEY, PROFILE_KEY]) {
      expect(window.localStorage.getItem(key)).toBeNull();
    }
    expect(getAccessToken()).toBeNull();
    expect(getRefreshToken()).toBeNull();
    expect(getProfile()).toBeNull();
    expect(isAuthenticated()).toBe(false);
  });
});
