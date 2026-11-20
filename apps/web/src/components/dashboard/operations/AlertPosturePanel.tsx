'use client';

/**
 * Where the alert backlog actually sits.
 *
 * `GET /api/v1/alerts/stats` returns the severity and status distributions
 * plus the two counters worth acting on: what arrived in the last 24 hours,
 * and how many critical alerts are still open.
 *
 * The status distribution is the disposition picture. It is a point-in-time
 * snapshot rather than a series — no endpoint in the tree buckets disposition
 * over time — and the panel says so instead of implying a trend it cannot
 * source. `/metrics/funnel` publishes real period-over-period deltas for the
 * funnel stages and is rendered by `FunnelKpiBar`; nothing here duplicates it
 * with invented arrows.
 */

import useSWR from 'swr';
import Link from 'next/link';
import { clsx } from 'clsx';
import { operationsApi } from '@/lib/api';
import { EmptyState } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;

type BreakdownFilter = 'severity' | 'status';

function breakdownHref(filter: BreakdownFilter, key: string): string {
  return `/alerts?view=alerts&${filter}=${encodeURIComponent(key)}`;
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  info: 'bg-slate-500',
};

/** Statuses the API is known to emit, in workflow order. Unknown keys append. */
const STATUS_ORDER = [
  'new',
  'triaged',
  'investigating',
  'escalated',
  'resolved',
  'false_positive',
  'suppressed',
] as const;

function orderedEntries(
  counts: Record<string, number>,
  preferred: readonly string[],
): Array<[string, number]> {
  const known = preferred.filter((k) => k in counts).map<[string, number]>((k) => [k, counts[k]]);
  const rest = Object.entries(counts)
    .filter(([k]) => !preferred.includes(k))
    .sort((a, b) => b[1] - a[1]);
  return [...known, ...rest];
}

function humanise(key: string): string {
  return key.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase());
}

export function AlertPosturePanel() {
  const { data, error, isLoading, mutate } = useSWR(
    'ops-alert-stats',
    () => operationsApi.alertStats(),
    { refreshInterval: 60_000, revalidateOnFocus: false },
  );

  const severities = data ? orderedEntries(data.by_severity ?? {}, SEVERITY_ORDER) : [];
  const statuses = data ? orderedEntries(data.by_status ?? {}, STATUS_ORDER) : [];
  const severityTotal = severities.reduce((sum, [, n]) => sum + n, 0);
  const statusTotal = statuses.reduce((sum, [, n]) => sum + n, 0);

  return (
    <section
      aria-labelledby="ops-posture-heading"
      className="rounded-xl border border-gray-800/60 bg-gray-900/40"
    >
      <div className="px-4 py-3">
        <h2 id="ops-posture-heading" className="text-sm font-medium text-gray-300">
          Alert posture
        </h2>
        <p className="mt-0.5 text-[11px] text-gray-500">
          Current distribution. A snapshot, not a trend — no endpoint buckets
          disposition over time.
        </p>
      </div>

      {isLoading && !data ? (
        <div className="m-4 h-28 animate-pulse rounded bg-gray-800/40" />
      ) : error ? (
        <ErrorState
          title="Alert statistics unavailable"
          error={error}
          onRetry={() => {
            void mutate();
          }}
          className="m-4"
        />
      ) : !data || data.total === 0 ? (
        <EmptyState
          title="No alerts recorded"
          description="Severity and disposition counts populate once the pipeline promotes its first alert."
          className="m-4"
        />
      ) : (
        <div className="space-y-4 px-4 pb-4">
          <div className="grid grid-cols-3 gap-3">
            <Link
              href="/alerts?view=alerts"
              aria-label={`View all ${data.total.toLocaleString()} alerts`}
              className="group -m-1 rounded-md p-1 transition-colors hover:bg-gray-800/40 focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-400"
            >
              <span className="block text-[11px] uppercase tracking-wider text-gray-500">Total</span>
              <span className="block text-2xl font-semibold text-gray-100 group-hover:underline">
                {data.total.toLocaleString()}
              </span>
            </Link>
            <Link
              href="/alerts?view=alerts&created_within_hours=24"
              aria-label={`View ${data.new_last_24h.toLocaleString()} alerts created in the last 24 hours`}
              className="group -m-1 rounded-md p-1 transition-colors hover:bg-gray-800/40 focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-400"
            >
              <span className="block text-[11px] uppercase tracking-wider text-gray-500">New (24h)</span>
              <span className="block text-2xl font-semibold text-blue-300 group-hover:underline">
                {data.new_last_24h.toLocaleString()}
              </span>
            </Link>
            <Link
              href="/alerts?view=alerts&severity=critical&unresolved_only=true"
              aria-label={`View ${data.critical_open.toLocaleString()} critical open alerts`}
              className="group -m-1 rounded-md p-1 transition-colors hover:bg-gray-800/40 focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-400"
            >
              <span className="block text-[11px] uppercase tracking-wider text-gray-500">Critical open</span>
              <span
                className={clsx(
                  'block text-2xl font-semibold group-hover:underline',
                  data.critical_open > 0 ? 'text-red-300' : 'text-gray-100',
                )}
              >
                {data.critical_open.toLocaleString()}
              </span>
            </Link>
          </div>

          <StackedBar
            label="By severity"
            filter="severity"
            entries={severities}
            total={severityTotal}
            colorFor={(k) => SEVERITY_COLOR[k] ?? 'bg-slate-600'}
          />
          <StackedBar
            label="By disposition"
            filter="status"
            entries={statuses}
            total={statusTotal}
            colorFor={(k) => (k === 'false_positive' ? 'bg-violet-500' : 'bg-teal-500')}
          />
        </div>
      )}
    </section>
  );
}

function StackedBar({
  label,
  filter,
  entries,
  total,
  colorFor,
}: {
  label: string;
  filter: BreakdownFilter;
  entries: Array<[string, number]>;
  total: number;
  colorFor: (key: string) => string;
}) {
  if (entries.length === 0 || total === 0) {
    return (
      <div>
        <p className="mb-1.5 text-[11px] uppercase tracking-wider text-gray-500">{label}</p>
        <p className="text-xs text-gray-600">No breakdown reported.</p>
      </div>
    );
  }

  return (
    <div>
      <p className="mb-1.5 text-[11px] uppercase tracking-wider text-gray-500">{label}</p>
      <div className="flex h-2 rounded-full bg-gray-800">
        {entries.map(([key, n]) => (
          <Link
            key={key}
            href={breakdownHref(filter, key)}
            aria-label={`View ${n.toLocaleString()} ${humanise(key)} alerts`}
            className={clsx(colorFor(key), 'block first:rounded-l-full last:rounded-r-full transition-[filter] hover:brightness-125 focus-visible:z-10 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-400')}
            style={{ width: `${(n / total) * 100}%` }}
            title={`${humanise(key)}: ${n}`}
          >
            <span className="sr-only">{`${humanise(key)}: ${n}`}</span>
          </Link>
        ))}
      </div>
      <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
        {entries.map(([key, n]) => (
          <li key={key} className="text-[11px]">
            <Link
              href={breakdownHref(filter, key)}
              aria-label={`View ${n.toLocaleString()} ${humanise(key)} alerts`}
              className="group flex items-center gap-1.5 rounded focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-400"
            >
              <span className={clsx('h-1.5 w-1.5 rounded-full', colorFor(key))} aria-hidden="true" />
              <span className="text-gray-400 group-hover:text-white group-hover:underline">{humanise(key)}</span>
              <span className="text-gray-300 group-hover:text-white group-hover:underline">{n.toLocaleString()}</span>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
