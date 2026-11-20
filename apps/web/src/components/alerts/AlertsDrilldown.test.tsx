/**
 * Exercises the real /alerts page → AlertsView boundary, not just a query
 * parser. A posture link must open the alert grid and send its filters to the
 * SWR key that the actual alertsApi.list fetcher consumes.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { NavigationTestProvider } from '@/test/NavigationTestProvider';

const requestedKeys = vi.hoisted(() => [] as unknown[]);
const alertState = vi.hoisted(() => ({ data: undefined as unknown }));
const savedViewsState = vi.hoisted(() => ({ data: undefined as unknown }));

vi.mock('swr', () => ({
  __esModule: true,
  useSWRConfig: () => ({ mutate: vi.fn() }),
  default: (key: unknown) => {
    requestedKeys.push(key);
    const data = Array.isArray(key) && key[0] === 'alerts'
      ? alertState.data
      : Array.isArray(key) && key[0] === 'saved-views' ? savedViewsState.data : undefined;
    return { data, error: undefined, isLoading: false, mutate: vi.fn() };
  },
}));

vi.mock('@/components/alerts/EntityRiskQueue', () => ({
  EntityRiskQueue: () => <div data-testid="entity-queue" />,
}));

import AlertsPage from '@/app/(app)/alerts/page';

function requestedFilters() {
  const keys = requestedKeys.filter(
    (key): key is [string, Record<string, unknown>] =>
      Array.isArray(key) && key[0] === 'alerts',
  );
  return keys[keys.length - 1]?.[1];
}

async function renderCurrentUrl() {
  const searchParams = Object.fromEntries(new URLSearchParams(window.location.search));
  return render(await AlertsPage({ searchParams: Promise.resolve(searchParams) }), {
    wrapper: NavigationTestProvider,
  });
}

beforeEach(() => {
  requestedKeys.length = 0;
  alertState.data = undefined;
  savedViewsState.data = undefined;
  window.history.replaceState(null, '', '/alerts');
});
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('operations posture links open the filtered alert grid', () => {
  const defaultSavedView = {
    id: 'default-alerts',
    view_type: 'alerts',
    name: 'Low resolved alerts',
    is_default: true,
    filters: { severity: 'low', status: 'resolved' },
  };

  it('shows the unresolved critical queue, including non-new open statuses', async () => {
    const page = await AlertsPage({
      searchParams: Promise.resolve({
        view: 'alerts',
        severity: 'critical',
        unresolved_only: 'true',
      }),
    });
    render(page);

    expect(screen.getByRole('tab', { name: 'Alerts' }).getAttribute('aria-selected')).toBe('true');
    expect(screen.getByRole('button', { name: 'Remove unresolved-only filter' })).toBeTruthy();
    expect(requestedFilters()).toMatchObject({
      severity: 'critical',
      unresolvedOnly: true,
      page: 1,
      sort: 'priority',
    });
  });

  it('uses creation time for the 24h filter and allows removing it', async () => {
    const page = await AlertsPage({
      searchParams: Promise.resolve({ view: 'alerts', created_within_hours: '24' }),
    });
    render(page);

    expect(requestedFilters()?.createdWithinHours).toBe(24);
    await userEvent.click(screen.getByRole('button', { name: 'Remove created-within-hours filter' }));
    await waitFor(() => expect(requestedFilters()?.createdWithinHours).toBeUndefined());
    expect(requestedFilters()?.sort).toBe('priority');
  });

  it.each([
    ['unresolved_only', 'true', 'Remove unresolved-only filter', 'unresolvedOnly'],
    ['created_within_hours', '24', 'Remove created-within-hours filter', 'createdWithinHours'],
    ['status', 'escalated', 'Remove status filter', 'status'],
  ])('removes %s from the URL so reloading does not restore it', async (param, value, label, filter) => {
    window.history.replaceState(null, '', `/alerts?${param}=${value}&tag=one&tag=two#queue`);
    const { unmount } = await renderCurrentUrl();
    const historyLength = window.history.length;

    await userEvent.click(screen.getByRole('button', { name: label }));

    const url = new URL(window.location.href);
    expect(url.searchParams.has(param)).toBe(false);
    expect(url.searchParams.get('view')).toBe('alerts');
    expect(url.searchParams.getAll('tag')).toEqual(['one', 'two']);
    expect(url.hash).toBe('#queue');
    expect(window.history.length).toBe(historyLength);
    expect(requestedFilters()?.[filter]).toBeUndefined();
    expect(requestedFilters()?.sort).toBe('priority');

    unmount();
    await renderCurrentUrl();
    expect(screen.queryByRole('button', { name: label })).toBeNull();
    expect(screen.getByRole('tab', { name: 'Alerts' })).toHaveAttribute('aria-selected', 'true');
    expect(requestedFilters()?.[filter]).toBeUndefined();
  });

  it('keeps the remaining drilldown filters when removing one chip', async () => {
    window.history.replaceState(null, '', '/alerts?view=alerts&severity=critical&status=escalated&unresolved_only=true&created_within_hours=24');
    await renderCurrentUrl();

    await userEvent.click(screen.getByRole('button', { name: 'Remove unresolved-only filter' }));

    expect(Object.fromEntries(new URLSearchParams(window.location.search))).toEqual({
      view: 'alerts', severity: 'critical', status: 'escalated', created_within_hours: '24',
    });
    expect(requestedFilters()).toMatchObject({
      severity: 'critical', status: 'escalated', createdWithinHours: 24, page: 1, sort: 'priority',
    });
  });

  it('updates the URL when changing the severity and status quick filters', async () => {
    window.history.replaceState(null, '', '/alerts?view=alerts&severity=critical&status=new&unresolved_only=true');
    await renderCurrentUrl();

    await userEvent.click(screen.getByRole('button', { name: 'High' }));
    await userEvent.click(screen.getByRole('button', { name: 'Investigating' }));
    expect(Object.fromEntries(new URLSearchParams(window.location.search))).toEqual({
      view: 'alerts', severity: 'high', status: 'investigating', unresolved_only: 'true',
    });

    await userEvent.click(screen.getByRole('button', { name: 'All severities' }));
    await userEvent.click(screen.getByRole('button', { name: 'All statuses' }));
    expect(Object.fromEntries(new URLSearchParams(window.location.search))).toEqual({
      view: 'alerts', unresolved_only: 'true',
    });
  });

  it('explains the new filters in the empty state and clears them from the URL', async () => {
    window.history.replaceState(null, '', '/alerts?severity=critical&status=escalated&unresolved_only=true&created_within_hours=24');
    const { unmount } = await renderCurrentUrl();

    expect(screen.getByText(/severity, status, unresolved-only, or creation-time filters/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(window.location.search).toBe('?view=alerts');
    expect(requestedFilters()).toEqual({ page: 1, pageSize: 25, sort: 'priority' });

    unmount();
    await renderCurrentUrl();
    expect(screen.queryByRole('button', { name: 'Clear filters' })).toBeNull();
    expect(screen.getByRole('tab', { name: 'Alerts' })).toHaveAttribute('aria-selected', 'true');
  });

  it('keeps the drilldown instead of automatically applying a saved default, while allowing manual selection', async () => {
    savedViewsState.data = [defaultSavedView];
    window.history.replaceState(null, '', '/alerts?view=alerts&severity=critical&unresolved_only=true');
    await renderCurrentUrl();

    expect(requestedFilters()).toMatchObject({ severity: 'critical', unresolvedOnly: true, sort: 'priority' });
    expect(new URLSearchParams(window.location.search).get('severity')).toBe('critical');
    const preset = screen.getByRole('button', { name: /Low resolved alerts/, pressed: false });
    expect(preset).toHaveAttribute('aria-pressed', 'false');

    await userEvent.click(preset);
    expect(requestedFilters()).toMatchObject({ severity: 'low', status: 'resolved' });
    expect(requestedFilters()?.unresolvedOnly).toBeUndefined();
    expect(Object.fromEntries(new URLSearchParams(window.location.search))).toEqual({
      view: 'alerts', severity: 'low', status: 'resolved',
    });
    expect(preset).toHaveAttribute('aria-pressed', 'true');
  });

  it('shows all alerts from the Total link even when a default saved view exists', async () => {
    savedViewsState.data = [defaultSavedView];
    window.history.replaceState(null, '', '/alerts?view=alerts');
    await renderCurrentUrl();

    expect(requestedFilters()).toEqual({ page: 1, pageSize: 25, sort: 'priority' });
    expect(window.location.search).toBe('?view=alerts');
  });

  it('still applies the saved default when opening alerts without an explicit drilldown', async () => {
    savedViewsState.data = [defaultSavedView];
    await renderCurrentUrl();
    await userEvent.click(screen.getByRole('tab', { name: 'Alerts' }));

    expect(requestedFilters()).toMatchObject({ severity: 'low', status: 'resolved' });
    expect(screen.getByRole('button', { name: /Low resolved alerts/, pressed: true })).toBeInTheDocument();
  });

  it('reads the current URL when history remounts cached server props', async () => {
    const cachedPage = await AlertsPage({
      searchParams: Promise.resolve({ severity: 'critical', unresolved_only: 'true' }),
    });
    window.history.replaceState(null, '', '/alerts?view=alerts');
    render(cachedPage, { wrapper: NavigationTestProvider });

    expect(requestedFilters()?.severity).toBeUndefined();
    expect(requestedFilters()?.unresolvedOnly).toBeUndefined();
    expect(screen.queryByRole('button', { name: 'Remove unresolved-only filter' })).toBeNull();
    expect(screen.getByRole('tab', { name: 'Alerts' })).toHaveAttribute('aria-selected', 'true');
  });

  it('follows Back and Forward query changes without requiring fresh server props', async () => {
    window.history.replaceState(null, '', '/alerts?view=alerts&severity=critical&unresolved_only=true');
    await renderCurrentUrl();

    act(() => window.history.pushState(null, '', '/alerts?view=alerts&severity=high&created_within_hours=24'));
    expect(requestedFilters()).toMatchObject({ severity: 'high', createdWithinHours: 24 });
    expect(requestedFilters()?.unresolvedOnly).toBeUndefined();

    act(() => window.history.back());
    await waitFor(() => expect(requestedFilters()).toMatchObject({ severity: 'critical', unresolvedOnly: true }));
    expect(requestedFilters()?.createdWithinHours).toBeUndefined();

    act(() => window.history.forward());
    await waitFor(() => expect(requestedFilters()).toMatchObject({ severity: 'high', createdWithinHours: 24 }));
    expect(requestedFilters()?.unresolvedOnly).toBeUndefined();
  });

  it('opens the status breakdown in the alert grid, not the entity queue', async () => {
    const page = await AlertsPage({
      searchParams: Promise.resolve({ view: 'alerts', status: 'false_positive' }),
    });
    render(page);

    expect(screen.getByRole('tab', { name: 'Alerts' }).getAttribute('aria-selected')).toBe('true');
    expect(requestedFilters()?.status).toBe('false_positive');
    expect(screen.queryByTestId('entity-queue')).toBeNull();
  });

  it('shows the real status for a breakdown that is not in the quick-filter buttons', async () => {
    alertState.data = {
      alerts: [{
        id: 'a1',
        title: 'Escalated endpoint alert',
        description: '',
        severity: 'critical',
        status: 'escalated',
        source: 'connector',
        tenantId: 'default',
        createdAt: '2026-11-18T10:00:00Z',
        updatedAt: '2026-11-18T10:00:00Z',
        tags: [],
        iocs: [],
        mitreAttack: [],
      }],
      total: 1,
      page: 1,
      pageSize: 25,
      facets: { bySeverity: { critical: 1 }, byStatus: { escalated: 1 }, unresolved: 1 },
    };
    const page = await AlertsPage({
      searchParams: Promise.resolve({ view: 'alerts', status: 'escalated' }),
    });
    render(page);

    expect(screen.getByText('Escalated')).toBeTruthy();
    expect(requestedFilters()?.status).toBe('escalated');
  });

  it('preserves the default entities tab when no drilldown is supplied', async () => {
    const page = await AlertsPage({ searchParams: Promise.resolve({}) });
    render(page);

    expect(screen.getByRole('tab', { name: 'Entities' }).getAttribute('aria-selected')).toBe('true');
    expect(screen.getByTestId('entity-queue')).toBeTruthy();
  });

  it('restores page size, search, and disposition from the URL after a reload-shaped remount', async () => {
    const cachedPage = await AlertsPage({
      searchParams: Promise.resolve({ view: 'alerts' }),
    });
    window.history.replaceState(
      null,
      '',
      '/alerts?view=alerts&page=2&pageSize=50&search=powershell&disposition=needs_review',
    );
    const { unmount } = render(cachedPage, { wrapper: NavigationTestProvider });

    expect(requestedFilters()).toMatchObject({
      page: 2,
      pageSize: 50,
      search: 'powershell',
      disposition: 'needs_review',
      sort: 'priority',
    });

    unmount();
    await renderCurrentUrl();
    expect(requestedFilters()).toMatchObject({
      page: 2,
      pageSize: 50,
      search: 'powershell',
      disposition: 'needs_review',
    });
  });

  it('does not thrash list requests when the URL carries pagination params', async () => {
    window.history.replaceState(null, '', '/alerts?view=alerts&pageSize=50');
    await renderCurrentUrl();
    await new Promise((resolve) => setTimeout(resolve, 50));
    const alertKeys = requestedKeys.filter(
      (key): key is [string, Record<string, unknown>] => Array.isArray(key) && key[0] === 'alerts',
    );
    expect(alertKeys.length).toBeLessThanOrEqual(2);
    expect(requestedFilters()?.pageSize).toBe(50);
  });

  it('does not send invalid time windows or unexpected status strings to the API', async () => {
    const page = await AlertsPage({
      searchParams: Promise.resolve({
        view: 'alerts',
        created_within_hours: '-50',
        status: 'new%26tenant_id%3Dother',
      }),
    });
    render(page);

    expect(requestedFilters()?.createdWithinHours).toBeUndefined();
    expect(requestedFilters()?.status).toBeUndefined();
  });
});
