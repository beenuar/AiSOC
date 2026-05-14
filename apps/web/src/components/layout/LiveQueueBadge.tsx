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
  const { data } = useSWR<QueueResponse>(
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

  const count = data?.counts?.mine ?? 0;

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
