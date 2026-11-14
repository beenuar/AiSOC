/**
 * Five banners claimed to be showing data they were not showing.
 *
 * `ConnectorsView` said "showing demo instances so you can explore the
 * interface" above a list that is `data?.connectors ?? []` — empty outside the
 * hosted demo. `RBACView` said "showing demo roles" while `roles` was
 * `undefined`, which suppressed both the skeleton and the empty state, so the
 * banner was the only thing on the page. `PlaybooksView` said "showing demo
 * playbooks" and a truthy `error` suppressed its empty state too.
 * `EffectivePermissionsView` said "falling back to demo data" when
 * `demoFallback(DEMO_RESULT)` is `undefined` and there is no fallback. And
 * `CopilotView` labelled *any* error "Demo mode" on deployments that are not
 * the demo, beside a green "Connected" that asserted connectivity before a
 * single request had been made.
 *
 * **Every test here asserts on first paint as well as on the error branch.**
 * SWR v2 disables revalidation when `fallbackData` is supplied, so a mock is
 * what the view *shows* rather than a first paint — and `data` is `undefined`
 * on first paint *and* after a failure, so a suite that only drives the error
 * branch never exercises the state a self-hoster spends every page load in.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'vitest-axe';
import { __setDemoModeForTests } from '@/lib/demoMode';

const swrData = vi.hoisted(() => new Map<string, unknown>());
const swrErrors = vi.hoisted(() => new Map<string, unknown>());
const swrMutations = vi.hoisted(() => [] as string[]);

vi.mock('swr', () => {
  const useSWR = (key: unknown) => {
    const k = typeof key === 'string' ? key : JSON.stringify(key);
    return {
      data: swrData.get(k),
      error: swrErrors.get(k),
      isLoading: false,
      mutate: vi.fn(async () => {
        swrMutations.push(k);
      }),
    };
  };
  return { __esModule: true, default: useSWR, mutate: vi.fn(), useSWRConfig: () => ({ mutate: vi.fn() }) };
});

vi.mock('react-hot-toast', () => ({
  __esModule: true,
  default: Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }),
}));

import { ApiError } from '@/lib/api';
import { ConnectorsView } from '@/components/connectors/ConnectorsView';
import { RBACView } from '@/components/settings/RBACView';

/** Verbatim from the `DEMO_*` / `MOCK_*` arrays in the views under test. */
const FABRICATED = ['CrowdStrike Falcon', 'Microsoft Sentinel', 'AWS Security Hub', 'Okta SSO'];

const axeOptions = { rules: { 'color-contrast': { enabled: false } } };

beforeEach(() => {
  swrData.clear();
  swrErrors.clear();
  swrMutations.length = 0;
  __setDemoModeForTests(false);
});

afterEach(() => {
  cleanup();
  __setDemoModeForTests(null);
});

// ─── ConnectorsView ──────────────────────────────────────────────────────────

describe('ConnectorsView — the banner describes what is on screen', () => {
  it('shows no banner on first paint, because nothing has failed yet', () => {
    render(<ConnectorsView />);

    expect(screen.queryByText(/unavailable/i)).toBeNull();
    expect(screen.queryByText(/unreachable/i)).toBeNull();
  });

  it('publishes no fabricated connectors on first paint', () => {
    render(<ConnectorsView />);

    for (const name of FABRICATED) {
      expect(screen.queryByText(name), `${name} is sample data`).toBeNull();
    }
  });

  it('does not claim to be showing demo instances when it is showing none', () => {
    swrErrors.set('connectors', new ApiError('API 503', 503, ''));

    render(<ConnectorsView />);

    expect(screen.queryByText(/showing demo instances/i)).toBeNull();
    expect(screen.getByText(/could not be loaded/i)).toBeTruthy();
    for (const name of FABRICATED) {
      expect(screen.queryByText(name)).toBeNull();
    }
  });

  it('calls a 422 a console bug instead of blaming the connectors service', () => {
    swrErrors.set('connectors', new ApiError('API 422', 422, ''));

    render(<ConnectorsView />);

    expect(screen.getByText(/console bug rather than an outage/i)).toBeTruthy();
    expect(screen.queryByText(/connectors service returned/i)).toBeNull();
  });

  it('reports the tiles as not measured rather than a confident zero', () => {
    // "Total Connectors 0 · Active 0 · Errors 0" on a tenant whose connectors
    // could not be read is four wrong numbers above a banner disclosing one.
    swrErrors.set('connectors', new ApiError('API 503', 503, ''));

    render(<ConnectorsView />);

    expect(screen.getAllByText('not measured').length).toBeGreaterThanOrEqual(4);
  });

  it('shows measured zeros when an empty estate really arrives', () => {
    swrData.set('connectors', { connectors: [], total: 0 });

    render(<ConnectorsView />);

    expect(screen.queryByText('not measured')).toBeNull();
    expect(screen.getByText(/No connectors yet/i)).toBeTruthy();
  });

  it('does not tell a tenant with connectors to add their first one', () => {
    // The onboarding empty state rendered over a working estate during any
    // outage, because a failed list and an empty list are both `[]`.
    swrErrors.set('connectors', new ApiError('API 503', 503, ''));

    render(<ConnectorsView />);

    expect(screen.queryByText(/No connectors yet/i)).toBeNull();
  });

  it('offers a retry that re-issues the request that failed', async () => {
    swrErrors.set('connectors', new ApiError('API 503', 503, ''));
    render(<ConnectorsView />);

    await userEvent.click(screen.getByRole('button', { name: /retry/i }));

    expect(swrMutations).toContain('connectors');
  });

  it('has no axe violations on first paint or in the degraded state', async () => {
    const first = render(<ConnectorsView />);
    expect(await axe(first.container, axeOptions)).toHaveNoViolations();
    cleanup();

    swrErrors.set('connectors', new ApiError('API 503', 503, ''));
    const degraded = render(<ConnectorsView />);
    expect(await axe(degraded.container, axeOptions)).toHaveNoViolations();
  });
});

// ─── RBACView ────────────────────────────────────────────────────────────────

describe('RBACView — the banner is no longer the only thing on the page', () => {
  it('shows the skeleton and no banner on first paint', () => {
    render(<RBACView />);

    expect(screen.queryByText(/unavailable/i)).toBeNull();
    expect(screen.queryByText(/demo roles/i)).toBeNull();
  });

  it('does not claim to be showing demo roles when it is showing none', () => {
    swrErrors.set('/api/v1/rbac/roles', new ApiError('API 500', 500, ''));

    render(<RBACView />);

    expect(screen.queryByText(/showing demo roles/i)).toBeNull();
    expect(screen.getByText(/could not be loaded/i)).toBeTruthy();
  });

  it('says the roles are unknown rather than that none are defined', () => {
    swrErrors.set('/api/v1/rbac/roles', new ApiError('API 500', 500, ''));

    render(<RBACView />);

    expect(screen.getByText(/unknown rather than as a tenant with no roles/i)).toBeTruthy();
    expect(screen.queryByText(/No roles defined yet/i)).toBeNull();
  });

  it('distinguishes a permission refusal from an outage', () => {
    // A 403 here is routine — plenty of roles cannot read RBAC — and calling
    // it "RBAC API unreachable" sends somebody to check a healthy service.
    swrErrors.set('/api/v1/rbac/roles', new ApiError('API 403', 403, ''));

    render(<RBACView />);

    expect(screen.getByText(/not authorised/i)).toBeTruthy();
    expect(screen.queryByText(/unreachable/i)).toBeNull();
  });

  it('offers a retry that re-issues the request that failed', async () => {
    swrErrors.set('/api/v1/rbac/roles', new ApiError('API 500', 500, ''));
    render(<RBACView />);

    await userEvent.click(screen.getByRole('button', { name: /retry/i }));

    expect(swrMutations).toContain('/api/v1/rbac/roles');
  });

  it('renders the empty state when a tenant really has no roles', () => {
    swrData.set('/api/v1/rbac/roles', []);

    render(<RBACView />);

    expect(screen.getByText(/No roles defined yet/i)).toBeTruthy();
  });

  it('has no axe violations on first paint or in the degraded state', async () => {
    const first = render(<RBACView />);
    expect(await axe(first.container, axeOptions)).toHaveNoViolations();
    cleanup();

    swrErrors.set('/api/v1/rbac/roles', new ApiError('API 500', 500, ''));
    const degraded = render(<RBACView />);
    expect(await axe(degraded.container, axeOptions)).toHaveNoViolations();
  });
});
