import { cloneElement } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SearchParamsContext } from 'next/dist/shared/lib/hooks-client-context.shared-runtime';
import { NavigationTestProvider } from '@/test/NavigationTestProvider';

const state = vi.hoisted(() => ({
  filters: {} as Record<string, unknown>,
  savedViews: [] as unknown[],
}));
vi.mock('swr', () => ({
  useSWRConfig: () => ({ mutate: vi.fn() }),
  default: (key: unknown) => {
    if (Array.isArray(key) && key[0] === 'alerts') state.filters = key[1];
    return {
      data: Array.isArray(key) && key[0] === 'saved-views' ? state.savedViews : undefined,
      isLoading: false,
      error: undefined,
      mutate: vi.fn(),
    };
  },
}));
vi.mock('./EntityRiskQueue', () => ({ EntityRiskQueue: () => <div>Entity queue fixture</div> }));

import AlertsPage from '@/app/(app)/alerts/page';

async function renderUrl() {
  return render(await AlertsPage({
    searchParams: Promise.resolve(Object.fromEntries(new URLSearchParams(window.location.search))),
  }), { wrapper: NavigationTestProvider });
}

beforeEach(() => {
  state.filters = {};
  state.savedViews = [];
  window.history.replaceState(null, '', '/alerts?view=alerts');
});
afterEach(cleanup);

describe('Alerts entity filter', () => {
  it('applies a trimmed exact value on Enter, resets pagination, and preserves other filters', async () => {
    window.history.replaceState(null, '', '/alerts?view=alerts&page=3&pageSize=50&severity=high&search=login&keep=a&keep=b#queue');
    await renderUrl();
    const user = userEvent.setup();
    await user.selectOptions(screen.getByLabelText('Entity type'), 'user');
    await user.type(screen.getByLabelText('Entity value'), '  Finance & Legal+ops@example.com  ');
    expect(state.filters.entityValue).toBeUndefined();
    expect(state.filters.page).toBe(3);
    await user.keyboard('{Enter}');

    expect(state.filters).toMatchObject({
      entityType: 'user', entityValue: 'Finance & Legal+ops@example.com',
      severity: 'high', search: 'login', page: 1, pageSize: 50,
    });
    const url = new URL(window.location.href);
    expect(url.searchParams.get('entity_value')).toBe('Finance & Legal+ops@example.com');
    expect(url.searchParams.get('entity_type')).toBe('user');
    expect(url.searchParams.has('page')).toBe(false);
    expect(url.searchParams.getAll('keep')).toEqual(['a', 'b']);
    expect(url.hash).toBe('#queue');
  });

  it('removes the pair and resets the form without dropping the other filters', async () => {
    window.history.replaceState(null, '', '/alerts?view=alerts&entity_type=host&entity_value=WIN-01&severity=critical&page=2');
    const { unmount } = await renderUrl();
    expect(screen.getByLabelText('Entity value')).toHaveValue('WIN-01');
    await userEvent.click(screen.getByRole('button', { name: 'Remove entity filter' }));

    expect(state.filters.entityType).toBeUndefined();
    expect(state.filters.entityValue).toBeUndefined();
    expect(state.filters.severity).toBe('critical');
    expect(state.filters.page).toBe(1);
    expect(screen.getByLabelText('Entity value')).toHaveValue('');
    expect(screen.getByLabelText('Entity type')).toHaveValue('');
    unmount();
    await renderUrl();
    expect(screen.queryByRole('button', { name: 'Remove entity filter' })).not.toBeInTheDocument();
    expect(state.filters.entityValue).toBeUndefined();
  });

  it('accepts all types and prevents a blank entity from being submitted', async () => {
    await renderUrl();
    const apply = screen.getByRole('button', { name: 'Apply entity filter' });
    expect(apply).toBeDisabled();
    await userEvent.type(screen.getByLabelText('Entity value'), '   ');
    expect(apply).toBeDisabled();
    await userEvent.type(screen.getByLabelText('Entity value'), '192.0.2.19');
    await userEvent.click(apply);
    expect(state.filters.entityValue).toBe('192.0.2.19');
    expect(state.filters.entityType).toBeUndefined();
    expect(new URLSearchParams(window.location.search).has('entity_type')).toBe(false);
    expect(screen.getByText('No alerts match these filters')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(state.filters.entityValue).toBeUndefined();
    expect(window.location.search).toBe('?view=alerts');
  });

  it('opens a same-route entity link in Alerts without applying a conflicting saved default', async () => {
    state.savedViews = [{
      id: 'default', name: 'Low severity fixture', view_type: 'alerts',
      is_default: true, filters: { severity: 'low' },
    }];
    window.history.replaceState(null, '', '/alerts');
    await renderUrl();
    expect(screen.getByRole('tab', { name: 'Entities' })).toHaveAttribute('aria-selected', 'true');

    act(() => window.history.pushState(null, '', '/alerts?view=alerts&page=1&entity_type=host&entity_value=WIN-01'));
    await waitFor(() => expect(screen.getByRole('tab', { name: 'Alerts' })).toHaveAttribute('aria-selected', 'true'));
    expect(state.filters.entityValue).toBe('WIN-01');
    expect(state.filters.severity).toBeUndefined();
    expect(screen.getByRole('button', { name: /Low severity fixture/, pressed: false })).toBeInTheDocument();
  });

  it('keeps an applied entity while the router is still reporting the previous URL', async () => {
    window.history.replaceState(null, '', '/alerts');
    const routerParams = new URLSearchParams();
    const page = await AlertsPage({ searchParams: Promise.resolve({}) });
    const tree = () => <SearchParamsContext.Provider value={routerParams}>{cloneElement(page)}</SearchParamsContext.Provider>;
    const { rerender } = render(tree());
    const user = userEvent.setup();
    await user.click(screen.getByRole('tab', { name: 'Alerts' }));
    await user.selectOptions(screen.getByLabelText('Entity type'), 'host');
    await user.type(screen.getByLabelText('Entity value'), 'WIN-01');
    await user.click(screen.getByRole('button', { name: 'Apply entity filter' }));
    expect(state.filters.entityValue).toBe('WIN-01');
    expect(new URLSearchParams(window.location.search).get('entity_value')).toBe('WIN-01');

    state.savedViews = [{
      id: 'late-default', name: 'Low severity fixture', view_type: 'alerts',
      is_default: true, filters: { severity: 'low' },
    }];
    rerender(tree());

    expect(new URLSearchParams(window.location.search).get('entity_value')).toBe('WIN-01');
    expect(state.filters).toMatchObject({ entityType: 'host', entityValue: 'WIN-01', page: 1 });
    expect(state.filters.severity).toBeUndefined();
    const defaultChip = screen.getByRole('button', { name: /Low severity fixture/, pressed: false });
    await user.click(defaultChip);
    expect(state.filters.severity).toBe('low');
    expect(state.filters.entityValue).toBeUndefined();
  });

  it('still applies the saved default on an untouched queue', async () => {
    state.savedViews = [{
      id: 'default', name: 'Low severity fixture', view_type: 'alerts',
      is_default: true, filters: { severity: 'low' },
    }];
    window.history.replaceState(null, '', '/alerts');
    await renderUrl();
    await userEvent.click(screen.getByRole('tab', { name: 'Alerts' }));
    expect(state.filters.severity).toBe('low');
    expect(new URLSearchParams(window.location.search).get('severity')).toBe('low');
    expect(screen.getByRole('button', { name: /Low severity fixture/, pressed: true })).toBeInTheDocument();
  });

  it('updates the applied form on saved-view selection and browser history changes', async () => {
    state.savedViews = [{
      id: 'entity-preset', name: 'Domain fixture', view_type: 'alerts',
      is_default: false, filters: { entityType: 'domain', entityValue: 'example.test' },
    }];
    window.history.replaceState(null, '', '/alerts?view=alerts&entity_type=host&entity_value=WIN-01');
    await renderUrl();
    await userEvent.click(screen.getByRole('button', { name: 'Domain fixture' }));
    expect(state.filters.entityType).toBe('domain');
    expect(screen.getByLabelText('Entity value')).toHaveValue('example.test');
    expect(screen.getByLabelText('Entity type')).toHaveValue('domain');

    act(() => window.history.pushState(null, '', '/alerts?view=alerts&entity_type=ip&entity_value=2001%3Adb8%3A%3A1'));
    expect(screen.getByLabelText('Entity value')).toHaveValue('2001:db8::1');
    act(() => window.history.back());
    await waitFor(() => expect(screen.getByLabelText('Entity value')).toHaveValue('example.test'));
    expect(state.filters.entityType).toBe('domain');
  });
});
