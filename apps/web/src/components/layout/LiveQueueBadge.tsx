'use client';

import useSWR from 'swr';
import { queueApi, type QueueResponse } from '@/lib/api';

const POLL_INTERVAL_MS = 30_000;

/**
 * Sidebar pill that surfaces the current user's open Investigation Queue
 * count. It polls `GET /api/v1/alerts/queue?owner=me` on a low-rate timer so
 * the sidebar stays current without paying for a full page render.
 *
 * Rendered as the right-slot of the Investigation Queue nav item. Hidden when
 * the count is zero so we don't draw attention to an empty queue.
 *
 * @author Beenu Arora <beenu@cyble.com>
 */
export function LiveQueueBadge() {
  const { data, error } = useSWR<QueueResponse>(
    ['sidebar:queue:mine'],
    () => queueApi.list({ owner: 'me', period: 'all', page: 1, page_size: 1 }),
    {
      refreshInterval: POLL_INTERVAL_MS,
      revalidateOnFocus: true,
      revalidateOnReconnect: true,
      shouldRetryOnError: false,
      dedupingInterval: 10_000,
    },
  );

  // `?? 0` then `if (count <= 0) return null` made a failed read
  // indistinguishable from an empty queue: the analyst's sidebar simply
  // showed no pending work. Unknown is its own state.
  const count = data?.counts?.mine ?? null;

  if (count === null) {
    // Hiding on error is the same pixel as an empty queue. A muted dash says
    // the number is unknown without claiming there is nothing to do.
    if (!error) return null;
    return (
      <span
        className="ml-auto inline-flex items-center justify-center min-w-[1.25rem] h-5 px-1.5 rounded-full text-xs font-bold tabular-nums bg-gray-700 text-gray-300"
        role="status"
        aria-label="Queue size unknown — the queue service did not answer"
        title="Queue size unknown — the queue service did not answer"
        data-testid="sidebar-queue-badge-unknown"
      >
        —
      </span>
    );
  }

  if (count <= 0) {
    return null;
  }

  const display = count > 99 ? '99+' : String(count);
  const label = `${count} item${count === 1 ? '' : 's'} in your queue`;

  return (
    <span
      className="ml-auto inline-flex items-center justify-center min-w-[1.25rem] h-5 px-1.5 rounded-full text-xs font-bold text-white tabular-nums bg-brand-600"
      aria-label={label}
      title={label}
      data-testid="sidebar-queue-badge"
    >
      {display}
    </span>
  );
}
