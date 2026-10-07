/**
 * The console's end of an SSO round trip.
 *
 * Fix pass 4.1 names three defects. Two of them — "no console code reads
 * the fragment" and "the login page offers only email and password" —
 * were fixed in v17.1.0 and were covered by no test, which is how a
 * handler whose only caller is one `useEffect` quietly stops being called.
 *
 * These assertions exist so that stays true, and they are written against
 * the real `completeSsoHandoff` rather than a mock of it: the behaviour
 * under test is "what this function does to `window`", and a double
 * cannot have that.
 *
 * Why the fragment at all: a query string reaches the server, the access
 * log and the `Referer` header. A fragment does not. The cost is that the
 * only copy of the token lives in `window.location.hash` until this runs,
 * which is why `handleUnauthorized` — which rebuilds its redirect from
 * `pathname + search` — must never be allowed to fire first. Both SSO
 * callbacks therefore land on `/login`, where this consumer lives.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { AUTH_REFRESH_KEY, AUTH_TOKEN_KEY, AUTH_USER_KEY, authApi } from './api';

const USER = {
  id: 'cf0a5e32-3d7a-4f54-9f4a-6f6b6a4f6d21',
  email: 'alice@example.com',
  role: 'infosec',
  tenant_id: '2a2f1a7c-5a3f-4c37-9f35-1d6b6fbb9c41',
};

function landOn(hash: string): void {
  window.history.replaceState(null, '', `/login?next=%2Falerts${hash}`);
}

beforeEach(() => {
  window.localStorage.clear();
  landOn('');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('completeSsoHandoff', () => {
  it('reads the session out of the fragment and stores it', async () => {
    landOn('#access_token=at-123&refresh_token=rt-456');
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify(USER), { status: 200 })),
    );

    await expect(authApi.completeSsoHandoff()).resolves.toBe(true);

    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBe('at-123');
    expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBe('rt-456');
    expect(JSON.parse(window.localStorage.getItem(AUTH_USER_KEY) ?? '{}').email).toBe(USER.email);
  });

  it('clears the fragment, so the token is not left in the address bar', async () => {
    landOn('#access_token=at-123&refresh_token=rt-456');
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify(USER), { status: 200 })),
    );

    await authApi.completeSsoHandoff();

    expect(window.location.hash).toBe('');
    // The `?next=` the callback set has to survive: it is where the page
    // routes to once the session is stored.
    expect(window.location.search).toBe('?next=%2Falerts');
  });

  it('presents the token as a bearer credential to /auth/me', async () => {
    landOn('#access_token=at-123&refresh_token=rt-456');
    const fetchMock = vi.fn(async (_url: string, _init: RequestInit) =>
      new Response(JSON.stringify(USER), { status: 200 }),
    );
    vi.stubGlobal('fetch', fetchMock);

    await authApi.completeSsoHandoff();

    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain('/api/v1/auth/me');
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer at-123');
  });

  it('stores nothing when the API rejects the token', async () => {
    landOn('#access_token=forged&refresh_token=forged');
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('{}', { status: 401 })),
    );

    await expect(authApi.completeSsoHandoff()).resolves.toBe(false);
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBeNull();
  });

  it('does nothing at all when there is no fragment', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    await expect(authApi.completeSsoHandoff()).resolves.toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('ssoStatus', () => {
  it('reads as "no SSO" when the endpoint is unreachable', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('connection refused');
      }),
    );

    // A status outage must not take the password form down with it, and
    // it must not render an SSO button that cannot work.
    await expect(authApi.ssoStatus()).resolves.toMatchObject({
      sso_enabled: false,
      local_login_enabled: true,
    });
  });
});
