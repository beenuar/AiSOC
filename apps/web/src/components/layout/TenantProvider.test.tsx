import { describe, expect, it, beforeEach, vi } from 'vitest';
import { act, render, renderHook, screen, waitFor } from '@testing-library/react';
import { TenantProvider, useTenant } from './TenantProvider';

// `@/lib/api` is mocked end-to-end so the provider can be exercised in isolation
// from the real network + localStorage helpers. Each mocked function is a
// `vi.fn` we can program per test.
const currentUserMock = vi.fn();
const isAuthenticatedMock = vi.fn();
const tenantsMeMock = vi.fn();
const msspChildrenMock = vi.fn();
const getActiveTenantIdMock = vi.fn(() => '');
const setActiveTenantIdMock = vi.fn();

vi.mock('@/lib/api', () => ({
  authApi: {
    currentUser: () => currentUserMock(),
    isAuthenticated: () => isAuthenticatedMock(),
  },
  tenantsApi: {
    me: () => tenantsMeMock(),
  },
  msspApi: {
    listChildren: () => msspChildrenMock(),
  },
  getActiveTenantId: () => getActiveTenantIdMock(),
  setActiveTenantId: (id: string | null) => setActiveTenantIdMock(id),
}));

function wrapper({ children }: { children: React.ReactNode }) {
  return <TenantProvider>{children}</TenantProvider>;
}

beforeEach(() => {
  currentUserMock.mockReset();
  isAuthenticatedMock.mockReset();
  tenantsMeMock.mockReset();
  msspChildrenMock.mockReset();
  getActiveTenantIdMock.mockReset();
  getActiveTenantIdMock.mockReturnValue('');
  setActiveTenantIdMock.mockReset();
});

describe('TenantProvider', () => {
  it('exits loading=false when the user is not authenticated', async () => {
    currentUserMock.mockReturnValue(null);
    isAuthenticatedMock.mockReturnValue(false);

    const { result } = renderHook(() => useTenant(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.current).toBeNull();
    expect(result.current.available).toEqual([]);
    expect(tenantsMeMock).not.toHaveBeenCalled();
  });

  it('loads the current tenant for a standalone (non-MSSP) user', async () => {
    currentUserMock.mockReturnValue({
      id: 'u1',
      email: 'a@b.com',
      role: 'analyst',
      tenant_id: 't1',
    });
    isAuthenticatedMock.mockReturnValue(true);
    tenantsMeMock.mockResolvedValue({
      id: 't1',
      name: 'Acme Corp',
      mssp_role: null,
      parent_tenant_id: null,
    });

    const { result } = renderHook(() => useTenant(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.userRole).toBe('analyst');
    expect(result.current.current).toEqual({
      id: 't1',
      name: 'Acme Corp',
      role: 'standalone',
    });
    expect(result.current.available).toHaveLength(1);
    // Standalone users should never trigger the /mssp/children call.
    expect(msspChildrenMock).not.toHaveBeenCalled();
  });

  it('lists [parent, ...children] for an MSSP parent operator', async () => {
    currentUserMock.mockReturnValue({
      id: 'u1',
      email: 'a@mssp.com',
      role: 'mssp-admin',
      tenant_id: 'parent-t',
    });
    isAuthenticatedMock.mockReturnValue(true);
    tenantsMeMock.mockResolvedValue({
      id: 'parent-t',
      name: 'MSSP Holdings',
      mssp_role: 'parent',
      parent_tenant_id: null,
    });
    msspChildrenMock.mockResolvedValue([
      { id: 'c1', name: 'Customer A', mssp_role: 'child' },
      { id: 'c2', name: 'Customer B', mssp_role: 'child' },
    ]);

    const { result } = renderHook(() => useTenant(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.available.map((t) => t.id)).toEqual(['parent-t', 'c1', 'c2']);
    expect(result.current.available[0].role).toBe('parent');
    expect(result.current.available[1].role).toBe('child');
    expect(result.current.current?.id).toBe('parent-t');
  });

  it('honours an active tenant ID from storage when it resolves', async () => {
    currentUserMock.mockReturnValue({
      id: 'u1',
      email: 'a@mssp.com',
      role: 'mssp-admin',
      tenant_id: 'parent-t',
    });
    isAuthenticatedMock.mockReturnValue(true);
    getActiveTenantIdMock.mockReturnValue('c2'); // stale-but-valid
    tenantsMeMock.mockResolvedValue({
      id: 'parent-t',
      name: 'MSSP Holdings',
      mssp_role: 'parent',
      parent_tenant_id: null,
    });
    msspChildrenMock.mockResolvedValue([
      { id: 'c1', name: 'Customer A', mssp_role: 'child' },
      { id: 'c2', name: 'Customer B', mssp_role: 'child' },
    ]);

    const { result } = renderHook(() => useTenant(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.current?.id).toBe('c2');
    expect(result.current.current?.name).toBe('Customer B');
  });

  it('falls back to "me" if the stored active tenant is not in the list', async () => {
    currentUserMock.mockReturnValue({
      id: 'u1',
      email: 'a@mssp.com',
      role: 'mssp-admin',
      tenant_id: 'parent-t',
    });
    isAuthenticatedMock.mockReturnValue(true);
    getActiveTenantIdMock.mockReturnValue('deleted-child');
    tenantsMeMock.mockResolvedValue({
      id: 'parent-t',
      name: 'MSSP Holdings',
      mssp_role: 'parent',
      parent_tenant_id: null,
    });
    msspChildrenMock.mockResolvedValue([]);

    const { result } = renderHook(() => useTenant(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.current?.id).toBe('parent-t');
  });

  it('still renders a fallback tenant when /tenants/me errors', async () => {
    currentUserMock.mockReturnValue({
      id: 'u1',
      email: 'a@b.com',
      role: 'analyst',
      tenant_id: 't1',
    });
    isAuthenticatedMock.mockReturnValue(true);
    tenantsMeMock.mockRejectedValue(new Error('boom'));

    const { result } = renderHook(() => useTenant(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.error).toBe('boom');
    expect(result.current.current).toEqual({
      id: 't1',
      name: 'My tenant',
      role: 'standalone',
    });
    expect(result.current.available).toHaveLength(1);
  });

  it('tolerates /mssp/children failing for an otherwise-healthy parent', async () => {
    currentUserMock.mockReturnValue({
      id: 'u1',
      email: 'a@mssp.com',
      role: 'mssp-admin',
      tenant_id: 'parent-t',
    });
    isAuthenticatedMock.mockReturnValue(true);
    tenantsMeMock.mockResolvedValue({
      id: 'parent-t',
      name: 'MSSP Holdings',
      mssp_role: 'parent',
      parent_tenant_id: null,
    });
    msspChildrenMock.mockRejectedValue(new Error('403'));

    const { result } = renderHook(() => useTenant(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.error).toBeNull();
    expect(result.current.current?.id).toBe('parent-t');
    // No children → switcher will render as a read-only badge upstream.
    expect(result.current.available).toHaveLength(1);
  });

  it('throws when useTenant() is called outside the provider', () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => renderHook(() => useTenant())).toThrow(
      /useTenant\(\) must be used inside <TenantProvider>/,
    );
    err.mockRestore();
  });

  it('setTenant() persists the choice via setActiveTenantId and dispatches an event', async () => {
    currentUserMock.mockReturnValue({
      id: 'u1',
      email: 'a@mssp.com',
      role: 'mssp-admin',
      tenant_id: 'parent-t',
    });
    isAuthenticatedMock.mockReturnValue(true);
    tenantsMeMock.mockResolvedValue({
      id: 'parent-t',
      name: 'MSSP Holdings',
      mssp_role: 'parent',
      parent_tenant_id: null,
    });
    msspChildrenMock.mockResolvedValue([
      { id: 'c1', name: 'Customer A', mssp_role: 'child' },
    ]);

    // Suppress JSDOM's "not implemented: navigation" noise from
    // `window.location.reload()` — the call is intentional and we just
    // need it to no-op.
    const reloadSpy = vi.fn();
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...window.location, reload: reloadSpy },
    });

    const switchedEvents: CustomEvent[] = [];
    const handler = (e: Event) => switchedEvents.push(e as CustomEvent);
    window.addEventListener('aisoc:tenant-switched', handler as EventListener);

    const { result } = renderHook(() => useTenant(), { wrapper });
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      result.current.setTenant('c1');
    });

    expect(setActiveTenantIdMock).toHaveBeenCalledWith('c1');
    expect(reloadSpy).toHaveBeenCalledTimes(1);
    expect(switchedEvents).toHaveLength(1);
    expect((switchedEvents[0].detail as { tenantId: string }).tenantId).toBe('c1');
    expect(result.current.current?.id).toBe('c1');

    window.removeEventListener('aisoc:tenant-switched', handler as EventListener);
  });
});

describe('TenantProvider integration with consumers', () => {
  it('exposes current/available/userRole to nested consumers', async () => {
    currentUserMock.mockReturnValue({
      id: 'u1',
      email: 'a@b.com',
      role: 'analyst-lead',
      tenant_id: 't1',
    });
    isAuthenticatedMock.mockReturnValue(true);
    tenantsMeMock.mockResolvedValue({
      id: 't1',
      name: 'Acme',
      mssp_role: null,
      parent_tenant_id: null,
    });

    function Probe() {
      const { current, available, userRole } = useTenant();
      return (
        <ul>
          <li data-testid="role">{userRole ?? ''}</li>
          <li data-testid="current">{current?.name ?? ''}</li>
          <li data-testid="count">{available.length}</li>
        </ul>
      );
    }

    render(
      <TenantProvider>
        <Probe />
      </TenantProvider>,
    );

    expect(screen.getByTestId('role')).toHaveTextContent('analyst-lead');
    await waitFor(() => {
      expect(screen.getByTestId('current')).toHaveTextContent('Acme');
      expect(screen.getByTestId('count')).toHaveTextContent('1');
    });
  });
});
