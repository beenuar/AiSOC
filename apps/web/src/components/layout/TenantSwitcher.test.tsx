import { describe, expect, it, beforeEach, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { TenantSwitcher } from './TenantSwitcher';
import { TenantProvider } from './TenantProvider';

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

beforeEach(() => {
  currentUserMock.mockReset();
  isAuthenticatedMock.mockReset();
  tenantsMeMock.mockReset();
  msspChildrenMock.mockReset();
  getActiveTenantIdMock.mockReset();
  getActiveTenantIdMock.mockReturnValue('');
  setActiveTenantIdMock.mockReset();
});

function renderSwitcher() {
  return render(
    <TenantProvider>
      <TenantSwitcher />
    </TenantProvider>,
  );
}

describe('TenantSwitcher', () => {
  it('renders nothing when the user is not authenticated', async () => {
    currentUserMock.mockReturnValue(null);
    isAuthenticatedMock.mockReturnValue(false);

    const { container } = renderSwitcher();
    // First paint shows the loading pill; once loading resolves, the unauth
    // branch returns null.
    await waitFor(() => {
      expect(container.querySelector('button')).toBeNull();
    });
  });

  it('renders a read-only pill for a standalone tenant', async () => {
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

    renderSwitcher();

    await waitFor(() => {
      expect(screen.getByText('Acme Corp')).toBeInTheDocument();
    });
    // The read-only pill has no aria-haspopup trigger.
    expect(screen.queryByRole('button', { name: /Active tenant/i })).toBeNull();
  });

  it('renders a switcher button for an MSSP parent', async () => {
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

    renderSwitcher();

    const trigger = await screen.findByRole('button', { name: /Active tenant/i });
    expect(trigger).toHaveTextContent('MSSP Holdings');

    await userEvent.click(trigger);

    // Dropdown opens with all 3 tenants visible.
    const list = screen.getByRole('listbox', { name: /Tenants/i });
    const options = await screen.findAllByRole('option');
    expect(options).toHaveLength(3);
    expect(list).toHaveTextContent('MSSP Holdings');
    expect(list).toHaveTextContent('Customer A');
    expect(list).toHaveTextContent('Customer B');
  });

  it('switches tenants on click', async () => {
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

    // Stub out window.location.reload so the test runner doesn't bomb out.
    const reloadSpy = vi.fn();
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...window.location, reload: reloadSpy },
    });

    renderSwitcher();

    const trigger = await screen.findByRole('button', { name: /Active tenant/i });
    await userEvent.click(trigger);

    const customer = await screen.findByRole('option', { name: /Customer A/i });
    await userEvent.click(customer);

    expect(setActiveTenantIdMock).toHaveBeenCalledWith('c1');
    expect(reloadSpy).toHaveBeenCalledTimes(1);
  });

  it('disables the active tenant in the dropdown', async () => {
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

    renderSwitcher();

    const trigger = await screen.findByRole('button', { name: /Active tenant/i });
    await userEvent.click(trigger);

    const active = await screen.findByRole('option', { name: /MSSP Holdings/i });
    expect(active).toBeDisabled();
    expect(active).toHaveAttribute('aria-selected', 'true');
  });

  it('closes on Escape', async () => {
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

    renderSwitcher();

    const trigger = await screen.findByRole('button', { name: /Active tenant/i });
    await userEvent.click(trigger);
    expect(screen.getByRole('dialog', { name: /Switch tenant/i })).toBeInTheDocument();
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('dialog', { name: /Switch tenant/i })).not.toBeInTheDocument();
  });
});
