'use client';

/**
 * Connector fleet health.
 *
 * This is the panel the alert-centric dashboards structurally cannot provide.
 * When a connector stops polling, alerts from that source stop arriving, and
 * every alert-shaped widget in the console gets *quieter*. An absence of
 * alerts is indistinguishable from an absence of threats unless something is
 * watching the sources themselves.
 *
 * `GET /api/v1/health/fleet` has been writing that answer for a while with
 * nothing reading it. It judges staleness per connector against that
 * connector's own configured cadence, which is why this panel reports
 * "3.2 intervals missed" rather than an absolute age: a daily connector and a
 * five-minute connector are not late at the same wall-clock time.
 */

import useSWR from 'swr';
import Link from 'next/link';
import { clsx } from 'clsx';
import { operationsApi, type FleetConnectorHealth, type FleetHealthState } from '@/lib/api';
import { EmptyState } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';

const STATE_STYLE: Record<FleetHealthState, { dot: string; text: string; label: string }> = {
  healthy: { dot: 'bg-green-500', text: 'text-green-300', label: 'Healthy' },
  degraded: { dot: 'bg-yellow-500', text: 'text-yellow-300', label: 'Degraded' },
  failed: { dot: 'bg-red-500', text: 'text-red-300', label: 'Failed' },
  unproven: { dot: 'bg-blue-500', text: 'text-blue-300', label: 'Never synced' },
  disabled: { dot: 'bg-gray-600', text: 'text-gray-400', label: 'Disabled' },
};

/** Order worst-first so the answer is the first thing read. */
const STATE_ORDER: FleetHealthState[] = ['failed', 'degraded', 'unproven', 'healthy', 'disabled'];

export function formatStaleness(row: FleetConnectorHealth): string {
  if (row.last_sync === null) return 'never synced';

  const missed = row.missed_intervals;
  if (missed !== null && missed >= 1) {
    // Cadence-relative is the actionable framing: "two intervals late" tells
    // an operator it is genuinely behind, where "22 minutes" does not unless
    // they also remember the interval.
    return `${missed.toFixed(1)} intervals behind`;
  }

  const secs = row.seconds_since_sync;
  if (secs === null) return 'sync time unknown';
  if (secs < 90) return 'synced just now';
  if (secs < 3600) return `synced ${Math.round(secs / 60)}m ago`;
  if (secs < 86_400) return `synced ${Math.round(secs / 3600)}h ago`;
  return `synced ${Math.round(secs / 86_400)}d ago`;
}

function ConnectorRow({ row }: { row: FleetConnectorHealth }) {
  const style = STATE_STYLE[row.state] ?? STATE_STYLE.unproven;
  return (
    <li
      className="flex items-start gap-3 border-t border-gray-800/40 px-4 py-2.5 first:border-t-0"
      data-testid={`fleet-row-${row.connector_id}`}
    >
      <span className={clsx('mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full', style.dot)} aria-hidden="true" />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-2">
          <span className="truncate text-sm text-gray-200">{row.name}</span>
          <span className="text-[11px] text-gray-500">{row.connector_type}</span>
          <span className={clsx('text-[11px]', style.text)}>{style.label}</span>
        </div>
        {/* The server writes operator-actionable wording; render it verbatim
            rather than re-deriving a status string from the same fields. */}
        <p className="mt-0.5 text-[11px] text-gray-500">{row.reason}</p>
      </div>
      <div className="shrink-0 text-right text-[11px] text-gray-500">
        <div>{formatStaleness(row)}</div>
        <div className="mt-0.5">
          {row.events_ingested.toLocaleString()} events
          {row.error_count > 0 ? ` · ${row.error_count} errors` : ''}
        </div>
      </div>
    </li>
  );
}

export function ConnectorFleetPanel() {
  const { data, error, isLoading, mutate } = useSWR(
    'ops-fleet-health',
    () => operationsApi.fleetHealth(),
    { refreshInterval: 60_000, revalidateOnFocus: false },
  );

  const connectors = data?.connectors ?? [];
  const sorted = [...connectors].sort(
    (a, b) => STATE_ORDER.indexOf(a.state) - STATE_ORDER.indexOf(b.state),
  );
  const counts = data?.counts;
  const needsAttention = (counts?.failed ?? 0) + (counts?.degraded ?? 0);

  return (
    <section
      aria-labelledby="ops-fleet-heading"
      className="rounded-xl border border-gray-800/60 bg-gray-900/40"
    >
      <div className="flex items-baseline justify-between px-4 py-3">
        <div>
          <h2 id="ops-fleet-heading" className="text-sm font-medium text-gray-300">
            Connector fleet
          </h2>
          <p className="mt-0.5 text-[11px] text-gray-500">
            Staleness measured against each connector&apos;s own poll cadence.
          </p>
        </div>
        {data && (
          <span
            className={clsx(
              'shrink-0 rounded-full px-2 py-0.5 text-[11px] font-medium',
              needsAttention > 0
                ? 'bg-red-500/10 text-red-300'
                : 'bg-green-500/10 text-green-300',
            )}
          >
            {needsAttention > 0
              ? `${needsAttention} need attention`
              : 'All sources reporting'}
          </span>
        )}
      </div>

      {isLoading && !data ? (
        <div className="m-4 h-24 animate-pulse rounded bg-gray-800/40" />
      ) : error ? (
        <ErrorState
          title="Fleet health unavailable"
          description="Connector staleness is unknown right now. Treat a quiet alert queue as unexplained until this recovers."
          error={error}
          onRetry={() => {
            void mutate();
          }}
          className="m-4"
        />
      ) : connectors.length === 0 ? (
        <EmptyState
          title="No connectors configured"
          description="Nothing is feeding the pipeline yet, so an empty alert queue is expected."
          action={
            <Link
              href="/connectors"
              className="text-sm text-blue-400 underline underline-offset-2 hover:text-blue-300"
            >
              Connect a source
            </Link>
          }
          className="m-4"
        />
      ) : (
        <ul>
          {sorted.map((row) => (
            <ConnectorRow key={row.connector_id} row={row} />
          ))}
        </ul>
      )}
    </section>
  );
}
