/**
 * The alert grid asks for the prioritising order.
 *
 * `GET /api/v1/alerts` orders by `created_at` descending and keeps that as
 * its default, because it has generated SDK clients built against "page one
 * is the newest rows" and changing the order silently would alter what they
 * read without altering the schema.
 *
 * So the console has to opt in, and this is the only thing that proves it
 * does. Without it, the server-side `sort=priority` is a parameter nothing
 * sends — the "exists but nothing calls it" shape — and an analyst watching
 * a low-severity flood still never sees the critical underneath it.
 *
 * Against the pre-change tree this fails: the console sent no `sort` at all.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const swrKeys = vi.hoisted(() => [] as unknown[]);

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    swrKeys.push(key);
    return { data: undefined, error: undefined, isLoading: false, mutate: vi.fn() };
  },
}));

vi.mock('@/components/alerts/EntityRiskQueue', () => ({
  EntityRiskQueue: () => <div data-testid="entity-queue" />,
}));

import { AlertsView } from './AlertsView';

/** The filter object the grid hands to `alertsApi.list`. */
function requestedFilters(): Record<string, unknown> | undefined {
  const key = swrKeys.find((k) => Array.isArray(k) && k[0] === 'alerts') as unknown[] | undefined;
  return key?.[1] as Record<string, unknown> | undefined;
}

beforeEach(() => {
  swrKeys.length = 0;
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('the alert grid does not let a flood bury a critical', () => {
  it('requests severity-first ordering', async () => {
    render(<AlertsView />);
    await userEvent.click(await screen.findByRole('tab', { name: /^alerts$/i }));

    expect(requestedFilters()?.sort).toBe('priority');
  });

  it('sends a value the API accepts', async () => {
    // `list_alerts` answers 400 for anything outside this set, so a typo
    // here would 400 the whole grid rather than degrade its ordering.
    render(<AlertsView />);

    expect(['newest', 'priority']).toContain(requestedFilters()?.sort);
  });
});
