import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { MarketplaceItem } from './MarketplaceView';

// We mock SWR rather than the global fetch for the index, because the
// component uses two SWR keys with different fetchers and we want a single
// source of truth for "what data does the grid see today".
const swrCalls = vi.hoisted(() => new Map<string, unknown>());
vi.mock('swr', () => ({
  __esModule: true,
  default: (key: string) => {
    const data = swrCalls.get(key);
    return {
      data,
      error: undefined,
      isLoading: false,
      mutate: vi.fn(async () => undefined),
    };
  },
}));

import { MarketplaceView } from './MarketplaceView';

const baseItem: MarketplaceItem = {
  id: 'cloudflare-waf',
  type: 'plugin',
  name: 'Cloudflare WAF',
  description: 'Block IPs at the edge.',
  version: '1.0.0',
  author: 'AiSOC Core',
  tags: ['edge', 'waf'],
  source: 'core',
  verified: true,
  plugin_type: 'action',
  sdks: ['python'],
};

beforeEach(() => {
  swrCalls.clear();
  swrCalls.set('/marketplace/index.json', {
    version: '1',
    generated: '2026-05-04T00:00:00Z',
    items: [baseItem],
    stats: {
      total: 1,
      playbooks: 0,
      detections: 0,
      plugins: 1,
      verified: 1,
      community: 0,
    },
  });
  swrCalls.set('/api/v1/marketplace/installed', {
    total: 0,
    items: [],
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('MarketplaceView install flow', () => {
  it('renders the marketplace catalog and the install affordance for a known item', () => {
    render(<MarketplaceView />);

    expect(screen.getByRole('heading', { level: 1, name: /marketplace/i })).toBeInTheDocument();
    expect(screen.getByText('Cloudflare WAF')).toBeInTheDocument();
    // Anchor on the exact label so we don't collide with the "Installs" sort
    // button or any other text containing the substring "install".
    expect(screen.getByRole('button', { name: /^install$/i })).toBeInTheDocument();
  });

  it('POSTs to /api/v1/marketplace/install when the user clicks Install', async () => {
    const fetchMock = vi.fn(
      async (): Promise<Response> =>
        new Response(JSON.stringify({ ok: true }), { status: 200 }),
    );
    vi.stubGlobal('fetch', fetchMock);

    render(<MarketplaceView />);

    await userEvent.click(screen.getByRole('button', { name: /^install$/i }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/v1/marketplace/install',
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
        }),
      );
    });

    // Body must include the item type+id, not arbitrary data.
    const calls = fetchMock.mock.calls as unknown as [string, RequestInit][];
    const call = calls.find((c) => c[0] === '/api/v1/marketplace/install');
    expect(call).toBeTruthy();
    const body = JSON.parse(String(call![1]?.body));
    expect(body).toEqual({ type: 'plugin', id: 'cloudflare-waf' });

    // After a successful POST the optimistic toggle flips to the per-card
    // "Installed" badge. We anchor on its title rather than text because the
    // header also renders an "<n> installed" count for the tenant.
    expect(await screen.findByTitle('Enabled for this tenant')).toBeInTheDocument();
  });

  it('rolls back the optimistic install toggle when the API returns 500', async () => {
    const fetchMock = vi.fn(
      async (): Promise<Response> =>
        new Response(JSON.stringify({ detail: 'boom' }), { status: 500 }),
    );
    vi.stubGlobal('fetch', fetchMock);

    render(<MarketplaceView />);

    await userEvent.click(screen.getByRole('button', { name: /^install$/i }));

    // Toast should appear, and the install button should come back.
    expect(await screen.findByRole('alert')).toHaveTextContent(/could not install cloudflare-waf/i);
    expect(screen.getByRole('button', { name: /^install$/i })).toBeInTheDocument();
  });
});

describe('MarketplaceView tier filter', () => {
  // The plan's central UX requirement: a working `cloudflare-waf` and a
  // 5,937-rule pile of imported Sigma content must not look identical. The
  // default-on `stable` tier is the mechanism. These tests pin that.
  const stableItem: MarketplaceItem = {
    ...baseItem,
    id: 'cloudflare-waf',
    name: 'Cloudflare WAF',
    tier: 'stable',
  };
  const importedItem: MarketplaceItem = {
    id: 'sigma-imp-1',
    type: 'detection',
    name: 'Suspicious LSASS Access (Sigma)',
    description: 'Imported from SigmaHQ.',
    version: '0.0.0',
    author: 'SigmaHQ',
    tags: ['sigma'],
    source: 'sigmahq',
    tier: 'imported',
  };
  const untaggedItem: MarketplaceItem = {
    id: 'aws-root-account-login',
    type: 'detection',
    name: 'AWS root account login',
    description: 'Native rule with no explicit tier.',
    version: '1.0.0',
    author: 'AiSOC Core',
    tags: ['aws'],
    source: 'core',
    verified: true,
    // No `tier` set on purpose — must surface under `stable` by default.
  };

  beforeEach(() => {
    swrCalls.clear();
    swrCalls.set('/marketplace/index.json', {
      version: '1',
      generated: '2026-05-04T00:00:00Z',
      items: [stableItem, importedItem, untaggedItem],
      stats: {
        total: 3,
        playbooks: 0,
        detections: 2,
        plugins: 1,
        verified: 2,
        community: 0,
      },
    });
    swrCalls.set('/api/v1/marketplace/installed', { total: 0, items: [] });
  });

  it("hides imported content by default and shows it after the user opts in", async () => {
    render(<MarketplaceView />);

    // Default tier filter is `stable`: native + untagged rules are visible,
    // imported Sigma rules are hidden.
    expect(screen.getByText('Cloudflare WAF')).toBeInTheDocument();
    expect(screen.getByText('AWS root account login')).toBeInTheDocument();
    expect(screen.queryByText('Suspicious LSASS Access (Sigma)')).not.toBeInTheDocument();

    // Opt into the imported tier — the Sigma item appears, stable items disappear.
    await userEvent.click(screen.getByRole('button', { name: /^Imported/i }));

    expect(await screen.findByText('Suspicious LSASS Access (Sigma)')).toBeInTheDocument();
    expect(screen.queryByText('Cloudflare WAF')).not.toBeInTheDocument();
    expect(screen.queryByText('AWS root account login')).not.toBeInTheDocument();
  });

  it('shows everything when the user picks "All tiers"', async () => {
    render(<MarketplaceView />);

    await userEvent.click(screen.getByRole('button', { name: /^All tiers/i }));

    expect(await screen.findByText('Cloudflare WAF')).toBeInTheDocument();
    expect(screen.getByText('Suspicious LSASS Access (Sigma)')).toBeInTheDocument();
    expect(screen.getByText('AWS root account login')).toBeInTheDocument();
  });

  it('renders a count next to each tier chip', () => {
    render(<MarketplaceView />);

    // Stable count = 2 (cloudflare-waf + untagged native rule).
    expect(screen.getByRole('button', { name: /^Stable\s*\(2\)/ })).toBeInTheDocument();
    // Imported count = 1 (sigma-imp-1).
    expect(screen.getByRole('button', { name: /^Imported\s*\(1\)/ })).toBeInTheDocument();
    // All tiers count = 3.
    expect(screen.getByRole('button', { name: /^All tiers\s*\(3\)/ })).toBeInTheDocument();
  });
});
