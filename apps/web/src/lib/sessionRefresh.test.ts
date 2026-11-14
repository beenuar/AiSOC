import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  ACTIVE_TENANT_KEY,
  AUTH_REFRESH_KEY,
  AUTH_TOKEN_KEY,
  AUTH_USER_KEY,
  apiFetch,
  apiRequest,
  authApi,
} from './api';

const USER = {
  id: 'session-user',
  email: 'analyst@example.com',
  role: 'infosec',
  tenant_id: 'session-tenant',
};

function token(id: string, expiresIn = 600, subject = USER.id): string {
  const encode = (value: unknown) =>
    btoa(JSON.stringify(value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode({
    sub: subject,
    jti: id,
    exp: Math.floor(Date.now() / 1000) + expiresIn,
  })}.signature`;
}

function pair(id: string, subject = USER.id) {
  return {
    access_token: token(`${id}-access`, 600, subject),
    refresh_token: token(`${id}-refresh`, 86_400, subject),
    token_type: 'bearer',
    expires_in: 600,
  };
}

function storeSession(tokens = pair('original'), user = USER) {
  window.localStorage.setItem(AUTH_TOKEN_KEY, tokens.access_token);
  window.localStorage.setItem(AUTH_REFRESH_KEY, tokens.refresh_token);
  window.localStorage.setItem(AUTH_USER_KEY, JSON.stringify(user));
  return tokens;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

function isRefresh(url: RequestInfo | URL): boolean {
  return String(url).endsWith('/api/v1/auth/refresh');
}

function bearer(init?: RequestInit): string | null {
  return new Headers(init?.headers).get('Authorization');
}

beforeEach(() => {
  window.localStorage.clear();
  // A terminal 401 may clear credentials here without jsdom navigation.
  window.history.replaceState(null, '', '/login');
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe('session refresh through the JSON client', () => {
  it('exchanges a stored refresh token and retries a server-rejected access token', async () => {
    const original = storeSession();
    const renewed = pair('renewed');
    const calls: Array<{ url: string; init?: RequestInit; authorization: string | null }> = [];
    vi.stubGlobal('fetch', vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init, authorization: bearer(init) });
      if (isRefresh(url)) return json(renewed);
      return bearer(init) === `Bearer ${renewed.access_token}`
        ? json({ alerts: ['alert-1'] })
        : json({ detail: 'Access token expired' }, 401);
    }));

    await expect(apiRequest('/api/v1/alerts')).resolves.toEqual({ alerts: ['alert-1'] });

    expect(calls).toHaveLength(3);
    expect(calls[0].authorization).toBe(`Bearer ${original.access_token}`);
    expect(calls[1].url).toContain('/api/v1/auth/refresh');
    expect(calls[1].init?.method).toBe('POST');
    expect(JSON.parse(String(calls[1].init?.body))).toEqual({ refresh_token: original.refresh_token });
    expect(calls[2].authorization).toBe(`Bearer ${renewed.access_token}`);
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBe(renewed.access_token);
    expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBe(renewed.refresh_token);
    expect(authApi.currentUser()).toEqual(USER);
  });

  it('renews an already-expired access token before sending the protected request', async () => {
    const original = pair('expired');
    original.access_token = token('expired-access', -60);
    storeSession(original);
    const renewed = pair('renewed');
    const calls: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push(String(url));
      if (isRefresh(url)) return json(renewed);
      expect(bearer(init)).toBe(`Bearer ${renewed.access_token}`);
      return json({ ready: true });
    }));

    await expect(apiRequest('/api/v1/alerts')).resolves.toEqual({ ready: true });
    expect(calls).toHaveLength(2);
    expect(calls[0]).toContain('/api/v1/auth/refresh');
    expect(calls[1]).toContain('/api/v1/alerts');
  });

  it('shares one refresh attempt across concurrent unauthorized requests', async () => {
    storeSession();
    const renewed = pair('renewed');
    const refresh = deferred<Response>();
    let refreshCalls = 0;
    vi.stubGlobal('fetch', vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      if (isRefresh(url)) {
        refreshCalls += 1;
        return refresh.promise;
      }
      return bearer(init) === `Bearer ${renewed.access_token}`
        ? json({ path: String(url) })
        : json({}, 401);
    }));

    const pending = Promise.allSettled([
      apiRequest('/api/v1/alerts'),
      apiRequest('/api/v1/cases'),
      apiRequest('/api/v1/connectors'),
    ]);
    await vi.waitFor(() => expect(refreshCalls).toBeGreaterThan(0));
    refresh.resolve(json(renewed));

    expect((await pending).map((result) => result.status)).toEqual([
      'fulfilled', 'fulfilled', 'fulfilled',
    ]);
    expect(refreshCalls).toBe(1);
  });

  it('cancels one waiting caller promptly while its peer completes the shared refresh', async () => {
    storeSession();
    const renewed = pair('renewed');
    const refresh = deferred<Response>();
    const controller = new AbortController();
    const cancelledCalls: string[] = [];
    let refreshCalls = 0;
    let refreshSignal: AbortSignal | null | undefined;
    let cancelledResult: PromiseSettledResult<unknown> | undefined;
    let peerFinished = false;
    vi.stubGlobal('fetch', vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      if (isRefresh(url)) {
        refreshCalls += 1;
        refreshSignal = init?.signal;
        return refresh.promise;
      }
      if (String(url).endsWith('/cancelled')) cancelledCalls.push(String(url));
      return bearer(init) === `Bearer ${renewed.access_token}` ? json({ ok: true }) : json({}, 401);
    }));

    const cancelled = Promise.allSettled([
      apiRequest('/api/v1/cancelled', { signal: controller.signal }),
    ]).then(([result]) => { cancelledResult = result; });
    const peer = Promise.allSettled([apiRequest('/api/v1/peer')]).then((result) => {
      peerFinished = true;
      return result;
    });
    try {
      await vi.waitFor(() => expect(refreshCalls).toBe(1));
      controller.abort();
      // This must settle before the refresh is released, not only when the
      // server finally responds to the unrelated caller's shared request.
      await vi.waitFor(() => expect(cancelledResult).toMatchObject({
        status: 'rejected',
        reason: { name: 'AbortError' },
      }));
      expect(refreshSignal).toBeDefined();
      expect(refreshSignal?.aborted).toBe(false);
      expect(peerFinished).toBe(false);
    } finally {
      refresh.resolve(json(renewed));
    }

    await cancelled;
    expect(await peer).toEqual([{ status: 'fulfilled', value: { ok: true } }]);
    expect(cancelledCalls).toHaveLength(1);
    expect(refreshCalls).toBe(1);
  });

  it('reuses the renewed access token when an earlier request returns a late 401', async () => {
    const original = storeSession();
    const renewed = pair('renewed');
    const lateResponse = deferred<Response>();
    let refreshCalls = 0;
    vi.stubGlobal('fetch', vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      if (isRefresh(url)) {
        refreshCalls += 1;
        return json(renewed);
      }
      if (String(url).endsWith('/slow') && bearer(init) === `Bearer ${original.access_token}`) {
        return lateResponse.promise;
      }
      return bearer(init) === `Bearer ${renewed.access_token}` ? json({ ok: true }) : json({}, 401);
    }));

    const late = Promise.allSettled([apiRequest('/api/v1/slow')]);
    await expect(apiRequest('/api/v1/fast')).resolves.toEqual({ ok: true });
    lateResponse.resolve(json({}, 401));

    expect(await late).toEqual([{ status: 'fulfilled', value: { ok: true } }]);
    expect(refreshCalls).toBe(1);
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBe(renewed.access_token);
  });

  it('does not restore credentials after logout while refresh is outstanding', async () => {
    storeSession();
    const refresh = deferred<Response>();
    let refreshCalls = 0;
    let protectedCalls = 0;
    vi.stubGlobal('fetch', vi.fn(async (url: RequestInfo | URL) => {
      if (isRefresh(url)) {
        refreshCalls += 1;
        return refresh.promise;
      }
      protectedCalls += 1;
      return json({}, 401);
    }));

    const pending = Promise.allSettled([apiRequest('/api/v1/alerts')]);
    await vi.waitFor(() => expect(refreshCalls).toBe(1));
    authApi.logout();
    refresh.resolve(json(pair('old-session-renewed')));

    expect((await pending)[0].status).toBe('rejected');
    expect(protectedCalls).toBe(1);
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBeNull();
    expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBeNull();
    expect(authApi.currentUser()).toBeNull();
  });

  it.each([200, 401])('does not overwrite a different login when the old refresh returns %i', async (status) => {
    storeSession();
    const refresh = deferred<Response>();
    let refreshCalls = 0;
    let protectedCalls = 0;
    vi.stubGlobal('fetch', vi.fn(async (url: RequestInfo | URL) => {
      if (isRefresh(url)) {
        refreshCalls += 1;
        return refresh.promise;
      }
      protectedCalls += 1;
      return json({}, 401);
    }));

    const pending = Promise.allSettled([apiRequest('/api/v1/alerts')]);
    await vi.waitFor(() => expect(refreshCalls).toBe(1));
    const otherUser = { ...USER, id: 'other-user', email: 'other@example.com' };
    const otherTokens = storeSession(pair('different-login', otherUser.id), otherUser);
    refresh.resolve(json(status === 200 ? pair('old-session-renewed') : {}, status));

    expect((await pending)[0].status).toBe('rejected');
    expect(protectedCalls).toBe(1);
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBe(otherTokens.access_token);
    expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBe(otherTokens.refresh_token);
    expect(authApi.currentUser()).toEqual(otherUser);
  });

  it.each(['logout', 'different login', 'same-user login'])(
    'does not send a waiting POST after %s between refresh persistence and continuation',
    async (change) => {
      const original = pair('expired');
      original.access_token = token('expired-access', -60);
      storeSession(original);
      const renewed = pair('renewed');
      const nextUser = change === 'different login'
        ? { ...USER, id: 'another-user', email: 'another@example.com' }
        : USER;
      const nextTokens = pair('next-login', nextUser.id);
      const sentPosts: string[] = [];
      let changed = false;
      let adopted: Promise<unknown> | undefined;
      const setItem = window.localStorage.setItem.bind(window.localStorage);
      vi.spyOn(window.localStorage, 'setItem').mockImplementation((key, value) => {
        setItem(key, value);
        if (key === AUTH_REFRESH_KEY && value === renewed.refresh_token) {
          // The refresh response was accepted and stored. Change the session
          // before the request waiting on that refresh resumes its POST.
          queueMicrotask(() => {
            changed = true;
            if (change === 'logout') {
              authApi.logout();
            } else {
              adopted = authApi.adoptSession(nextTokens.access_token, nextTokens.refresh_token);
              void adopted.catch(() => undefined);
            }
          });
        }
      });
      vi.stubGlobal('fetch', vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
        if (isRefresh(url)) return json(renewed);
        if (String(url).endsWith('/api/v1/auth/me')) return json(nextUser);
        if (init?.method === 'POST') sentPosts.push(String(url));
        return json({ created: true });
      }));

      await expect(apiRequest('/api/v1/cases', {
        method: 'POST',
        body: JSON.stringify({ title: 'Original session operation' }),
      })).rejects.toMatchObject({ status: 0 });

      expect(changed).toBe(true);
      expect(sentPosts).toEqual([]);
      if (change === 'logout') {
        expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBeNull();
        expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBeNull();
        expect(authApi.currentUser()).toBeNull();
      } else {
        await expect(adopted).resolves.toEqual(nextUser);
        expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBe(nextTokens.access_token);
        expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBe(nextTokens.refresh_token);
        expect(authApi.currentUser()).toEqual(nextUser);
      }
    },
  );

  it('ends the session when the refresh credential is rejected', async () => {
    storeSession();
    const fetchMock = vi.fn(async () => json({ detail: 'Invalid refresh token' }, 401));
    vi.stubGlobal('fetch', fetchMock);

    await expect(apiRequest('/api/v1/alerts')).rejects.toMatchObject({ status: 401 });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBeNull();
    expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBeNull();
    expect(authApi.currentUser()).toBeNull();
  });

  it.each([429, 500])('preserves the session when refresh temporarily returns %i', async (status) => {
    const original = storeSession();
    let refreshCalls = 0;
    vi.stubGlobal('fetch', vi.fn(async (url: RequestInfo | URL) => {
      if (isRefresh(url)) {
        refreshCalls += 1;
        return json({ detail: 'Try again later' }, status);
      }
      return json({}, 401);
    }));

    await expect(apiRequest('/api/v1/alerts')).rejects.toMatchObject({ status });

    expect(refreshCalls).toBe(1);
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBe(original.access_token);
    expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBe(original.refresh_token);
    expect(authApi.currentUser()).toEqual(USER);
  });

  it('preserves credentials after a refresh network error and allows a later retry', async () => {
    const original = storeSession();
    const renewed = pair('renewed');
    let refreshCalls = 0;
    vi.stubGlobal('fetch', vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      if (isRefresh(url)) {
        refreshCalls += 1;
        if (refreshCalls === 1) throw new TypeError('Network unavailable');
        return json(renewed);
      }
      return bearer(init) === `Bearer ${renewed.access_token}` ? json({ ok: true }) : json({}, 401);
    }));

    await expect(apiRequest('/api/v1/alerts')).rejects.toMatchObject({ status: 0 });
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBe(original.access_token);
    expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBe(original.refresh_token);
    expect(authApi.currentUser()).toEqual(USER);

    await expect(apiRequest('/api/v1/alerts')).resolves.toEqual({ ok: true });
    expect(refreshCalls).toBe(2);
  });

  it.each([
    ['invalid JSON', '{"access_token":'],
    ['missing refresh token', JSON.stringify({ access_token: 'incomplete-response' })],
    ['invalid token types', JSON.stringify({ access_token: 42, refresh_token: {} })],
  ])('preserves credentials after refresh returns %s and permits a later retry', async (_description, body) => {
    const original = storeSession();
    const renewed = pair('renewed');
    let refreshCalls = 0;
    let protectedCalls = 0;
    vi.stubGlobal('fetch', vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      if (isRefresh(url)) {
        refreshCalls += 1;
        return refreshCalls === 1
          ? new Response(body, { status: 200, headers: { 'Content-Type': 'application/json' } })
          : json(renewed);
      }
      protectedCalls += 1;
      return bearer(init) === `Bearer ${renewed.access_token}` ? json({ ok: true }) : json({}, 401);
    }));

    await expect(apiRequest('/api/v1/alerts')).rejects.toMatchObject({ status: 502 });
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBe(original.access_token);
    expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBe(original.refresh_token);
    expect(authApi.currentUser()).toEqual(USER);
    expect(protectedCalls).toBe(1);

    await expect(apiRequest('/api/v1/alerts')).resolves.toEqual({ ok: true });
    expect(refreshCalls).toBe(2);
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBe(renewed.access_token);
    expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBe(renewed.refresh_token);
  });

  it('retries a protected request only once when the new access token is also rejected', async () => {
    storeSession();
    let refreshCalls = 0;
    let protectedCalls = 0;
    vi.stubGlobal('fetch', vi.fn(async (url: RequestInfo | URL) => {
      if (isRefresh(url)) {
        refreshCalls += 1;
        return json(pair('renewed'));
      }
      protectedCalls += 1;
      return json({}, 401);
    }));

    await expect(apiRequest('/api/v1/alerts')).rejects.toMatchObject({ status: 401 });

    expect(refreshCalls).toBe(1);
    expect(protectedCalls).toBe(2);
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBeNull();
  });

  it('does not refresh or clear a session for a forbidden operation', async () => {
    const original = storeSession();
    const fetchMock = vi.fn(async () => json({ detail: 'Insufficient permission' }, 403));
    vi.stubGlobal('fetch', fetchMock);

    await expect(apiRequest('/api/v1/alerts')).rejects.toMatchObject({ status: 403 });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBe(original.access_token);
    expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBe(original.refresh_token);
  });

  it('does not replace or clear the browser session when an explicit credential is rejected', async () => {
    const original = storeSession();
    const fetchMock = vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) => json({}, 401));
    vi.stubGlobal('fetch', fetchMock);

    await expect(apiRequest('/api/v1/auth/me', {
      headers: { Authorization: 'Bearer another-credential' },
    })).rejects.toMatchObject({ status: 401 });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(bearer(fetchMock.mock.calls[0]?.[1])).toBe('Bearer another-credential');
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBe(original.access_token);
    expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBe(original.refresh_token);
    expect(authApi.currentUser()).toEqual(USER);
  });

  it.each(['/api/v1/auth/login', '/api/v1/auth/refresh', '/api/v1/auth/mfa/verify'])(
    'keeps sign-in errors from %s separate from session expiry',
    async (path) => {
      const original = storeSession();
      const fetchMock = vi.fn(async () => json({ detail: 'Invalid credential' }, 401));
      vi.stubGlobal('fetch', fetchMock);

      await expect(apiRequest(path, { method: 'POST', body: '{}' })).rejects.toMatchObject({ status: 401 });

      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBe(original.access_token);
      expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBe(original.refresh_token);
      expect(authApi.currentUser()).toEqual(USER);
    },
  );
});

describe('session refresh through the raw response client', () => {
  it('preserves the request context and leaves the retried response body unread', async () => {
    storeSession();
    window.localStorage.setItem(ACTIVE_TENANT_KEY, 'request-tenant');
    const renewed = pair('renewed');
    const controller = new AbortController();
    const body = JSON.stringify({ query: 'show alerts' });
    const calls: Array<{ url: string; init?: RequestInit; headers: Headers }> = [];
    vi.stubGlobal('fetch', vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      if (isRefresh(url)) {
        // A user may change the active tenant while the earlier request waits.
        window.localStorage.setItem(ACTIVE_TENANT_KEY, 'new-active-tenant');
        return json(renewed);
      }
      calls.push({ url: String(url), init, headers: new Headers(init?.headers) });
      return bearer(init) === `Bearer ${renewed.access_token}`
        ? new Response('event: message\ndata: ready\n\n', { headers: { 'Content-Type': 'text/event-stream' } })
        : json({}, 401);
    }));

    const response = await apiFetch('/api/v1/stream', {
      baseUrl: 'https://agents.example.test',
      params: { stream: true, limit: 10 },
      method: 'POST',
      body,
      headers: new Headers({ 'X-Request-Id': 'original-request', 'Content-Type': 'application/json' }),
      signal: controller.signal,
    });

    expect(response.status).toBe(200);
    expect(response.bodyUsed).toBe(false);
    expect(await response.text()).toBe('event: message\ndata: ready\n\n');
    expect(calls).toHaveLength(2);
    for (const call of calls) {
      expect(call.url).toBe('https://agents.example.test/api/v1/stream?stream=true&limit=10');
      expect(call.init?.method).toBe('POST');
      expect(call.init?.body).toBe(body);
      expect(call.init?.signal).toBe(controller.signal);
      expect(call.headers.get('X-Tenant-Id')).toBe('request-tenant');
      expect(call.headers.get('X-Request-Id')).toBe('original-request');
      expect(call.headers.get('Content-Type')).toBe('application/json');
    }
    expect(calls[1].headers.get('Authorization')).toBe(`Bearer ${renewed.access_token}`);
  });
});

describe('recoverable stored sessions', () => {
  it('keeps an expired access token recoverable while its refresh token is live', () => {
    const original = pair('expired');
    original.access_token = token('expired-access', -60);
    storeSession(original);

    expect(authApi.isAuthenticated()).toBe(true);
  });

  it('does not treat two expired credentials as recoverable', () => {
    storeSession({
      ...pair('expired'),
      access_token: token('expired-access', -60),
      refresh_token: token('expired-refresh', -60),
    });

    expect(authApi.isAuthenticated()).toBe(false);
  });
});
