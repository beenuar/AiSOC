/**
 * The Install button must not report a success it did not achieve.
 *
 * Measured against a real API — the published `aisoc-core-api` image, a real
 * account, a real session — clicking Install produced:
 *
 *     POST /api/v1/marketplace/install -> HTTP 401 {"detail":"Not authenticated"}
 *     GET  /api/v1/marketplace/installed -> {"total":0,"items":[]}
 *
 * and the card flipped to **Installed** with the page header counting
 * "1 installed". Nothing had been installed.
 *
 * Two faults stacked. The three marketplace calls sent `credentials:
 * 'include'` and no `Authorization` header, while the API authenticates a
 * bearer JWT held in localStorage — so every one of them was anonymous. And
 * the handler listed 401 and 404 as statuses to ignore, so the optimistic
 * flag set before the request was never rolled back: the one status the
 * missing header produced was the one status that could not fail the call.
 *
 * Both directions. A button that never reports success would pass the
 * assertions about lying and be just as useless.
 */
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AUTH_TOKEN_KEY } from '@/lib/api';
import type { MarketplaceItem } from './MarketplaceView';

const swrCalls = vi.hoisted(() => new Map<string, unknown>());
const swrFetchers = vi.hoisted(() => new Map<string, (url: string) => Promise<unknown>>());
vi.mock('swr', () => ({
  __esModule: true,
  default: (key: string, fetcher: (url: string) => Promise<unknown>) => {
    swrFetchers.set(key, fetcher);
    return {
      data: swrCalls.get(key),
      error: undefined,
      isLoading: false,
      mutate: vi.fn(async () => undefined),
    };
  },
}));

import { MarketplaceView } from './MarketplaceView';

const RULE: MarketplaceItem = {
  id: 'det-application-005',
  type: 'detection',
  name: 'Log4Shell JNDI Pattern in HTTP Header',
  description: 'Triggers on the application signal.',
  version: '1.0.0',
  author: 'AiSOC',
  tags: ['application'],
  tier: 'stable',
  source: 'core',
  verified: true,
  executable: true,
  category: 'application',
};

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  swrCalls.clear();
  swrFetchers.clear();
  swrCalls.set('/marketplace/index.json', { version: '1', generated: '2026-09-28T00:00:00Z', items: [RULE] });
  swrCalls.set('/api/v1/marketplace/installed', { total: 0, items: [] });
  window.localStorage.setItem(AUTH_TOKEN_KEY, 'a.real.session');
  fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  vi.unstubAllGlobals();
});

function card() {
  const heading = screen.getByText(RULE.name);
  return within(heading.closest('div.flex-col') as HTMLElement);
}

describe('the Install control', () => {
  it('treats an anonymous installed-set 401 as the static preview', async () => {
    window.localStorage.clear();
    const currentPath = window.location.pathname;
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ detail: 'Not authenticated' }), { status: 401 }));
    render(<MarketplaceView />);

    const url = '/api/v1/marketplace/installed';
    await expect(swrFetchers.get(url)!(url)).resolves.toBeNull();
    expect(window.location.pathname).toBe(currentPath);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('does not turn a rejected saved session into an empty installed-set', async () => {
    // Clearing the terminally rejected credential must not make this
    // response look like the anonymous static-preview case after awaiting it.
    window.history.replaceState(null, '', '/login');
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ detail: 'Not authenticated' }), { status: 401 }));
    render(<MarketplaceView />);

    const url = '/api/v1/marketplace/installed';
    await expect(swrFetchers.get(url)!(url)).rejects.toThrow('installed: Not authenticated');
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBeNull();
  });

  it('does not claim to have installed anything when the API refuses', async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ detail: 'Not authenticated' }),
    });
    const user = userEvent.setup();
    render(<MarketplaceView />);

    await user.click(card().getByRole('button', { name: /^Install$/ }));

    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument());
    expect(screen.getByRole('alert')).toHaveTextContent(/Not authenticated/);
    // The optimistic flag has to come back off, on the card and in the header.
    expect(card().getByRole('button', { name: /^Install$/ })).toBeInTheDocument();
    expect(card().queryByText(/^Installed$/)).toBeNull();
    expect(screen.queryByText(/\d+ installed/)).toBeNull();
  });

  it('does not claim to have installed a reference-only rule the API refused', async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 409,
      json: async () => ({ detail: 'det-x is reference-only — the detection engine does not load it.' }),
    });
    const user = userEvent.setup();
    render(<MarketplaceView />);

    await user.click(card().getByRole('button', { name: /^Install$/ }));

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/reference-only/));
    expect(card().getByRole('button', { name: /^Install$/ })).toBeInTheDocument();
  });

  it('sends the session the rest of the console authenticates with', async () => {
    fetchMock.mockResolvedValue({ ok: true, status: 200, json: async () => ({ id: RULE.id }) });
    const user = userEvent.setup();
    render(<MarketplaceView />);

    await user.click(card().getByRole('button', { name: /^Install$/ }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    const [url, init] = fetchMock.mock.calls.find(([u]) => String(u).includes('/marketplace/install'))!;
    expect(String(url)).toContain('/api/v1/marketplace/install');
    expect((init as RequestInit).headers).toMatchObject({ Authorization: 'Bearer a.real.session' });
  });

  it('reports success when the install actually succeeded', async () => {
    // The other direction: a control that always refuses would pass the two
    // assertions above and install nothing, forever.
    fetchMock.mockResolvedValue({ ok: true, status: 200, json: async () => ({ id: RULE.id }) });
    const user = userEvent.setup();
    render(<MarketplaceView />);

    await user.click(card().getByRole('button', { name: /^Install$/ }));

    await waitFor(() => expect(card().getByText(/^Installed$/)).toBeInTheDocument());
    expect(screen.queryByRole('alert')).toBeNull();
  });
});
