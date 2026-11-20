/**
 * Exercises the real /alerts page → AlertsView boundary, not just a query
 * parser. A posture link must open the alert grid and send its filters to the
 * SWR key that the actual alertsApi.list fetcher consumes.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const requestedKeys = vi.hoisted(() => [] as unknown[]);
const alertState = vi.hoisted(() => ({ data: undefined as unknown }));

vi.mock('swr', () => ({
  __esModule: true,
  useSWRConfig: () => ({ mutate: vi.fn() }),
  default: (key: unknown) => {
    requestedKeys.push(key);
    const data = Array.isArray(key) && key[0] === 'alerts' ? alertState.data : undefined;
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

beforeEach(() => {
  requestedKeys.length = 0;
  alertState.data = undefined;
});
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('operations posture links open the filtered alert grid', () => {
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
