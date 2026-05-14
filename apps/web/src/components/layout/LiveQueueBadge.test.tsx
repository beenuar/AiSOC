/**
 * Tests for the sidebar `LiveQueueBadge`.
 *
 * The badge fetches `GET /api/v1/alerts/queue?owner=me` on a low-rate poll
 * and surfaces the `counts.mine` value as a pill on the Investigation
 * Queue nav item. We assert the three states that matter for sidebar UX:
 *
 *   1. Zero count   → component renders nothing (don't draw attention to
 *                      an empty queue).
 *   2. Small count  → numeric label and aria-label match the count.
 *   3. >99 count    → clamped to "99+" so the pill never overflows the
 *                      sidebar slot.
 *
 * @author Beenu Arora <beenu@cyble.com>
 */

import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { LiveQueueBadge } from './LiveQueueBadge';
import type { QueueResponse } from '@/lib/api';

// ---------------------------------------------------------------------------
// Mock infrastructure
// ---------------------------------------------------------------------------
//
// We treat SWR as a thin pass-through: the test owns the data shape and the
// component just reads `data?.counts?.mine`. We also mock the API client so
// SWR never tries to hit a real fetch.

const swrState: { data: QueueResponse | undefined } = { data: undefined };

vi.mock('swr', () => ({
  __esModule: true,
  default: () => ({
    data: swrState.data,
    error: undefined,
    isLoading: false,
    isValidating: false,
    mutate: vi.fn(),
  }),
}));

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    queueApi: {
      list: vi.fn(),
      claim: vi.fn(),
      assign: vi.fn(),
      snooze: vi.fn(),
    },
  };
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a minimal QueueResponse shaped just enough for the badge.
 *
 * The badge only reads `counts.mine`; the rest is here to satisfy the
 * type contract so we catch upstream shape regressions at typecheck time.
 */
function makeResponse(mineCount: number): QueueResponse {
  return {
    items: [],
    total: mineCount,
    counts: { mine: mineCount, unassigned: 0, all: mineCount },
    period: 'all',
    owner: 'me',
    page: 1,
    page_size: 1,
    pages: 1,
    generated_at: new Date().toISOString(),
  };
}

afterEach(() => {
  swrState.data = undefined;
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('LiveQueueBadge', () => {
  it('renders nothing when SWR has no data yet', () => {
    swrState.data = undefined;

    const { container } = render(<LiveQueueBadge />);

    // An undefined SWR result resolves to `count = 0`, which we hide.
    expect(container.firstChild).toBeNull();
  });

  it('renders nothing when the mine count is zero', () => {
    swrState.data = makeResponse(0);

    const { container } = render(<LiveQueueBadge />);

    expect(container.firstChild).toBeNull();
    expect(screen.queryByTestId('sidebar-queue-badge')).not.toBeInTheDocument();
  });

  it('renders the numeric count when the user has open alerts', () => {
    swrState.data = makeResponse(5);

    render(<LiveQueueBadge />);

    const pill = screen.getByTestId('sidebar-queue-badge');
    expect(pill).toHaveTextContent('5');
    expect(pill).toHaveAttribute('aria-label', '5 items in your queue');
    // Title mirrors the aria-label for sighted users on hover.
    expect(pill).toHaveAttribute('title', '5 items in your queue');
  });

  it('uses the singular noun when the count is exactly one', () => {
    swrState.data = makeResponse(1);

    render(<LiveQueueBadge />);

    const pill = screen.getByTestId('sidebar-queue-badge');
    expect(pill).toHaveTextContent('1');
    expect(pill).toHaveAttribute('aria-label', '1 item in your queue');
  });

  it('clamps the display label to "99+" past one hundred', () => {
    swrState.data = makeResponse(247);

    render(<LiveQueueBadge />);

    const pill = screen.getByTestId('sidebar-queue-badge');
    // Display is clamped so the pill stays inside the sidebar gutter…
    expect(pill).toHaveTextContent('99+');
    // …but the accessible label keeps the real number so screen readers get
    // the truth.
    expect(pill).toHaveAttribute('aria-label', '247 items in your queue');
  });
});
