import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ACTIVE_TENANT_KEY, AUTH_REFRESH_KEY, AUTH_TOKEN_KEY, AUTH_USER_KEY } from './api';
import { getFimEvents, getFimSummary } from './osquery-api';

function token(expiresIn: number): string {
  const payload = btoa(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + expiresIn }));
  return `header.${payload}.signature`;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

beforeEach(() => {
  window.localStorage.clear();
  window.localStorage.setItem(ACTIVE_TENANT_KEY, 'selected-tenant');
  window.localStorage.setItem(AUTH_TOKEN_KEY, token(600));
});

afterEach(() => {
  window.localStorage.clear();
  vi.unstubAllGlobals();
});

describe('osquery session requests', () => {
  it('preserves pagination and bearer auth without declaring a tenant', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ total: 51, offset: 25, limit: 25, items: [] }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(getFimEvents({ page: 2, page_size: 25, hostname: 'workstation' })).resolves.toEqual({
      events: [], total: 51, page: 2, page_size: 25,
    });

    const [url, init] = fetchMock.mock.calls[0];
    const target = new URL(String(url));
    expect(target.pathname).toBe('/api/v1/osquery/fim/events');
    expect(target.searchParams.get('offset')).toBe('25');
    expect(target.searchParams.get('limit')).toBe('25');
    expect(target.searchParams.get('hostname')).toBe('workstation');
    const headers = new Headers((init as RequestInit).headers);
    expect(headers.get('Authorization')).toBe(`Bearer ${window.localStorage.getItem(AUTH_TOKEN_KEY)}`);
    expect(headers.has('X-Tenant-Id')).toBe(false);
  });

  it('renews an expired session before querying osquery and still omits the tenant header', async () => {
    const renewedAccess = token(1200);
    const refresh = token(86_400);
    window.localStorage.setItem(AUTH_TOKEN_KEY, token(-60));
    window.localStorage.setItem(AUTH_REFRESH_KEY, refresh);
    window.localStorage.setItem(AUTH_USER_KEY, JSON.stringify({ id: 'analyst', tenant_id: 'session-tenant' }));
    const calls: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push(String(url));
      if (String(url).endsWith('/api/v1/auth/refresh')) {
        expect(JSON.parse(String(init?.body))).toEqual({ refresh_token: refresh });
        return json({ access_token: renewedAccess, refresh_token: token(172_800) });
      }
      const headers = new Headers(init?.headers);
      expect(headers.get('Authorization')).toBe(`Bearer ${renewedAccess}`);
      expect(headers.has('X-Tenant-Id')).toBe(false);
      return json({ total_events: 0, by_action: [], top_paths: [], active_nodes: 0 });
    }));

    await expect(getFimSummary()).resolves.toMatchObject({ total_events: 0 });
    expect(calls).toHaveLength(2);
    expect(calls[0]).toContain('/api/v1/auth/refresh');
    expect(calls[1]).toBe(`${window.location.origin}/api/v1/osquery/fim/summary`);
  });

  it('keeps the service-unavailable status available to the FIM page', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('osquery is not deployed', { status: 503 })));

    await expect(getFimSummary()).rejects.toMatchObject({
      status: 503,
      body: 'osquery is not deployed',
    });
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).not.toBeNull();
  });
});
