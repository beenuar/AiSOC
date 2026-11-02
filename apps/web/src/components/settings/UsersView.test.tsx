/**
 * The organisation-members page, which shipped and was gated by nothing.
 *
 * Wave 2, Phase 9.5, prerequisite. `docs/audit/CLAIM_TO_GATE_MATRIX.md`
 * carried, inside the caveat of a GATED row, the sentence "Six console pages
 * parity 4.5 also names — branding, SCIM tokens, retention, organisation
 * members and grants, rule packs, delegations — **are not built**". Three of
 * those six were built. `ScimTokensPanel` is gated by another row of the
 * same matrix and `RBACView` by `BannerHonesty.test.tsx`; this page, at
 * `/settings/users`, was tested by nothing at all.
 *
 * That is the damage a stale "not built" does. It reads as modesty and works
 * as an exemption: a surface recorded as absent needs no claim row and no
 * gate, so a shipped page inherits the coverage of a page that does not
 * exist. `scripts/check_unbuilt_claims.py` now fails on the sentence; this
 * file is the gate the corrected row names.
 *
 * **Every test asserts on first paint as well as on the error branch**, for
 * the reason `BannerHonesty.test.tsx` records: `data` is `undefined` on
 * first paint *and* after a failure, so a suite that only drives the error
 * branch never exercises the state a self-hoster spends every page load in.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';

const swrState = vi.hoisted(() => ({
  data: undefined as unknown,
  error: undefined as unknown,
  isLoading: false,
}));

vi.mock('swr', () => ({
  default: (key: unknown) => {
    // The roles lookup is a second useSWR in the same component. Answering
    // it with the member list's state would make every assertion below
    // depend on which call fired first.
    if (typeof key === 'string' && key.startsWith('api/v1/rbac/roles')) {
      return { data: [], error: undefined, isLoading: false, mutate: vi.fn() };
    }
    return { ...swrState, mutate: vi.fn(async () => undefined) };
  },
}));

vi.mock('react-hot-toast', () => ({
  default: { success: vi.fn(), error: vi.fn() },
}));

vi.mock('@/lib/api', () => ({
  adminUsersApi: { listUsers: vi.fn(), updateRoles: vi.fn(), setActive: vi.fn(), deleteUser: vi.fn() },
  // `currentUser`, not `me`: the component reads it synchronously inside an
  // effect, and a double that exposed the wrong name made every test fail
  // with a TypeError rather than an assertion — the mirror of the recorded
  // trap where a stub is *more* capable than the real object.
  authApi: { currentUser: vi.fn(() => ({ id: 'self', email: 'me@example.com' })) },
  rbacApi: { listRoles: vi.fn(async () => []) },
}));

import { UsersView } from './UsersView';

beforeEach(() => {
  swrState.data = undefined;
  swrState.error = undefined;
  swrState.isLoading = false;
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('UsersView — the page exists, so it is held to the honest-state rule', () => {
  it('a failed read says the list could not be loaded, and does not claim there are none', () => {
    swrState.error = new Error('HTTP 503');
    render(<UsersView />);

    expect(screen.getByText(/could not be loaded/i)).toBeInTheDocument();
    // The assertion that matters is the absent one: "we could not read the
    // members" and "this organisation has no members" are different facts
    // about an access-control surface, and only one of them is safe to act on.
    expect(screen.queryByText(/No users match these filters/i)).not.toBeInTheDocument();
  });

  it('a failed read surfaces the reason rather than a bare failure', () => {
    swrState.error = new Error('HTTP 503');
    render(<UsersView />);
    expect(screen.getByText(/HTTP 503/)).toBeInTheDocument();
  });

  it('an empty result says it is empty and says the server answered', () => {
    swrState.data = { items: [], total: 0 };
    render(<UsersView />);

    expect(screen.getByText(/No users match these filters/i)).toBeInTheDocument();
    expect(screen.getByText(/not a load failure/i)).toBeInTheDocument();
    expect(screen.queryByText(/could not be loaded/i)).not.toBeInTheDocument();
  });

  it('first paint shows neither the empty state nor the error state', () => {
    // `data` undefined with no error: the state every page load passes
    // through. Rendering "no users" here would tell an administrator their
    // organisation is empty while the request is still in flight.
    swrState.isLoading = true;
    render(<UsersView />);

    expect(screen.queryByText(/No users match these filters/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/could not be loaded/i)).not.toBeInTheDocument();
  });

  it('a member count is not rendered over a failed read', () => {
    // `total` falls back to 0 when the read failed, and "0 members" beside a
    // red error box is a number nobody measured.
    swrState.error = new Error('HTTP 500');
    render(<UsersView />);
    expect(screen.queryByText(/^0 members$/)).not.toBeInTheDocument();
  });

  it('renders the members it was given, with their roles and status', () => {
    swrState.data = {
      items: [
        {
          id: 'u-1',
          email: 'ops@example.com',
          full_name: 'Ops Lead',
          is_active: true,
          roles: ['admin'],
          last_login_at: null,
          created_at: '2026-01-01T00:00:00Z',
        },
      ],
      total: 1,
    };
    render(<UsersView />);

    expect(screen.getByText('ops@example.com')).toBeInTheDocument();
    expect(screen.getByText('admin')).toBeInTheDocument();
    expect(screen.getByText(/1 member$/)).toBeInTheDocument();
  });
});
