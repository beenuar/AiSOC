/**
 * The entity queue says WHERE an entity was seen (#1950).
 *
 * `root` with 40 points could be a brute force on one internet-facing box or
 * one failed login on each of ten servers; without hosts on the row the list
 * cannot be triaged from the list. These pins drive the real component with
 * API-shaped fixtures: top-3 chips with a +N overflow on the row, the full
 * ranked list in the detail drawer, the contribution's own host beside its
 * timestamp — and nothing rendered at all when no contributing alert named a
 * host, because an invented sighting is worse than none.
 */
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import type { EntityRiskRecord } from '@/lib/api';

import { EntityRiskQueue } from './EntityRiskQueue';

const swrState = vi.hoisted(() => ({
  queue: undefined as { entities: EntityRiskRecord[] } | undefined,
  detail: undefined as EntityRiskRecord | undefined,
}));

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    const name = Array.isArray(key) ? key[0] : key;
    if (String(name).includes('detail')) {
      return { data: swrState.detail, error: undefined, isLoading: false, mutate: vi.fn() };
    }
    if (String(name).includes('stats')) {
      return { data: undefined, error: undefined, isLoading: false, mutate: vi.fn() };
    }
    return { data: swrState.queue, error: undefined, isLoading: false, mutate: vi.fn() };
  },
}));

vi.mock('@/lib/demoFallback', () => ({
  __esModule: true,
  canUseDemoData: () => false,
  demoFallback: () => undefined,
}));

function entity(overrides: Partial<EntityRiskRecord> = {}): EntityRiskRecord {
  return {
    tenant_id: 't-1',
    entity_type: 'user',
    entity_value: 'root',
    score: 61.2,
    display_score: 61,
    threshold: 80,
    promoted: false,
    promoted_incident_id: null,
    first_seen: '2026-11-17T08:00:00Z',
    last_seen: '2026-11-17T10:00:00Z',
    alert_count: 7,
    severity_histogram: { critical: 0, high: 3, medium: 4, low: 0, info: 0 },
    contributions: [
      {
        alert_id: 'a-1',
        severity: 'high',
        raw_points: 12,
        observed_at: '2026-11-17T10:00:00Z',
        title: 'Repeated authentication failures',
        source: null,
        host: 'edge-01',
      },
    ],
    hosts: [
      { name: 'edge-01', alert_count: 4, last_seen: '2026-11-17T10:00:00Z' },
      { name: 'db-02', alert_count: 2, last_seen: '2026-11-17T09:00:00Z' },
      { name: 'app-03', alert_count: 1, last_seen: '2026-11-17T08:30:00Z' },
      { name: 'app-04', alert_count: 1, last_seen: '2026-11-17T08:10:00Z' },
      { name: 'app-05', alert_count: 1, last_seen: '2026-11-17T08:05:00Z' },
    ],
    ...overrides,
  };
}

describe('entity hosts on the queue (#1950)', () => {
  it('shows the top three hosts and an honest overflow count on the row', () => {
    swrState.queue = { entities: [entity()] };
    swrState.detail = undefined;
    render(<EntityRiskQueue />);

    const chips = screen.getByTestId('entity-hosts');
    expect(within(chips).getByText('edge-01')).toBeInTheDocument();
    expect(within(chips).getByText('db-02')).toBeInTheDocument();
    expect(within(chips).getByText('app-03')).toBeInTheDocument();
    expect(within(chips).queryByText('app-04')).not.toBeInTheDocument();
    expect(within(chips).getByText('+2')).toBeInTheDocument();
  });

  it('renders no host line when no contributing alert named one', () => {
    swrState.queue = { entities: [entity({ hosts: [] })] };
    render(<EntityRiskQueue />);
    expect(screen.queryByTestId('entity-hosts')).not.toBeInTheDocument();
  });

  it('tolerates responses cached before the field shipped', () => {
    swrState.queue = { entities: [entity({ hosts: undefined })] };
    render(<EntityRiskQueue />);
    expect(screen.queryByTestId('entity-hosts')).not.toBeInTheDocument();
    expect(screen.getByText('root')).toBeInTheDocument();
  });

  it('lists every ranked host and the contribution host in the detail drawer', async () => {
    const record = entity();
    swrState.queue = { entities: [record] };
    swrState.detail = record;
    render(<EntityRiskQueue />);

    await userEvent.click(screen.getByText('root'));
    const detail = await screen.findByTestId('entity-hosts-detail');
    for (const name of ['edge-01', 'db-02', 'app-03', 'app-04', 'app-05']) {
      expect(within(detail).getByText(name)).toBeInTheDocument();
    }
    expect(within(detail).getByText(/4 alerts/)).toBeInTheDocument();
  });
});
