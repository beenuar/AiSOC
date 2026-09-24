'use client';

/**
 * Events the pipeline refused, grouped by why.
 *
 * The companion to connector fleet health. A connector can be polling happily
 * while every event it produces is rejected downstream for a schema mismatch,
 * and the symptom is identical from the alert queue: nothing arrives.
 *
 * `GET /api/v1/health/dead-letters` returns `by_reason` even when it is empty,
 * deliberately, so "no dead letters" reads as a real answer rather than a
 * panel that failed to load. This component preserves that distinction.
 */

import useSWR from 'swr';
import { operationsApi } from '@/lib/api';
import { EmptyState } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';

const WINDOW_HOURS = 24;

export function RejectedEventsPanel() {
  const { data, error, isLoading, mutate } = useSWR(
    `ops-dead-letters:${WINDOW_HOURS}`,
    () => operationsApi.deadLetters({ hours: WINDOW_HOURS, limit: 50 }),
    { refreshInterval: 60_000, revalidateOnFocus: false },
  );

  const byReason = data?.by_reason ?? [];
  const maxCount = Math.max(...byReason.map((r) => r.count), 1);

  return (
    <section
      aria-labelledby="ops-dlq-heading"
      className="rounded-xl border border-gray-800/60 bg-gray-900/40"
    >
      <div className="flex items-baseline justify-between px-4 py-3">
        <div>
          <h2 id="ops-dlq-heading" className="text-sm font-medium text-gray-300">
            Rejected events
          </h2>
          <p className="mt-0.5 text-[11px] text-gray-500">
            Last {WINDOW_HOURS} hours, grouped by reason.
          </p>
        </div>
        {data && (
          <span className="shrink-0 text-sm font-medium text-gray-200">
            {data.total.toLocaleString()}
          </span>
        )}
      </div>

      {isLoading && !data ? (
        <div className="m-4 h-20 animate-pulse rounded bg-gray-800/40" />
      ) : error ? (
        <ErrorState
          title="Dead-letter counts unavailable"
          error={error}
          onRetry={() => {
            void mutate();
          }}
          className="m-4"
        />
      ) : data && data.total === 0 ? (
        <EmptyState
          title="Nothing rejected"
          description={`Every event the pipeline received in the last ${WINDOW_HOURS} hours was accepted.`}
          className="m-4"
        />
      ) : (
        <ul className="space-y-2 px-4 pb-4">
          {byReason.map((row) => (
            <li key={row.reason}>
              <div className="mb-1 flex items-baseline justify-between gap-3">
                <span className="truncate text-xs text-gray-300">{row.reason}</span>
                <span className="shrink-0 text-xs text-gray-500">
                  {row.count.toLocaleString()}
                </span>
              </div>
              <div className="h-1 rounded-full bg-gray-800">
                <div
                  className="h-1 rounded-full bg-amber-500/60"
                  style={{ width: `${Math.round((row.count / maxCount) * 100)}%` }}
                />
              </div>
            </li>
          ))}
          {data?.truncated && (
            <li className="pt-1 text-[11px] text-gray-600">
              Sample capped; counts above are complete for the window.
            </li>
          )}
        </ul>
      )}
    </section>
  );
}
