'use client';

/**
 * Mobile-first triage queue.
 *
 * The on-call responder lands here from the home screen / push tap and
 * needs to grok the queue in under five seconds:
 *   • severity bar on the left (color-coded glance)
 *   • title + source above the fold of the card
 *   • age + status pill on the right
 *   • severity chips at the top to filter the queue
 *   • auto-refresh every 30s so you never need to pull-to-refresh
 *   • tap a card to drill into the detail page
 */

import Link from 'next/link';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { clsx } from 'clsx';
import { alertsApi, type Alert, type AlertSeverity } from '@/lib/api';
import {
  formatRelative,
  severityTone,
  alertStatusTone,
} from '@/lib/responder/format';

type SeverityFilter = AlertSeverity | 'all';

const SEVERITY_FILTERS: Array<{ id: SeverityFilter; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'critical', label: 'Critical' },
  { id: 'high', label: 'High' },
  { id: 'medium', label: 'Medium' },
];

const REFRESH_INTERVAL_MS = 30_000;

export default function ResponderTriagePage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [showResolved, setShowResolved] = useState(false);

  const load = useCallback(async (mode: 'initial' | 'refresh') => {
    if (mode === 'initial') setLoading(true);
    else setRefreshing(true);
    setError(null);
    try {
      const data = await alertsApi.list({
        pageSize: 100,
        // The mobile responder is interested in things that need attention,
        // so we pull a generous page and let the client filter.
      });
      setAlerts(data.alerts ?? []);
    } catch (err) {
      console.error('[responder] failed to load alerts', err);
      setError(
        err instanceof Error ? err.message : 'Failed to load alert queue.',
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void load('initial');
  }, [load]);

  // Quiet auto-refresh so the queue stays fresh without the responder
  // having to pull-to-refresh. Cancels cleanly on unmount.
  useEffect(() => {
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        void load('refresh');
      }
    }, REFRESH_INTERVAL_MS);
    return () => window.clearInterval(id);
  }, [load]);

  const visibleAlerts = useMemo(() => {
    let list = alerts;
    if (!showResolved) {
      list = list.filter(
        (a) => a.status !== 'resolved' && a.status !== 'false_positive',
      );
    }
    if (severityFilter !== 'all') {
      list = list.filter((a) => a.severity === severityFilter);
    }
    // Sort: severity desc, then age asc (oldest unresolved first feels
    // wrong on mobile — newest first is what responders expect).
    return [...list].sort((a, b) => {
      const rs = severityTone(b.severity).rank - severityTone(a.severity).rank;
      if (rs !== 0) return rs;
      return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
    });
  }, [alerts, severityFilter, showResolved]);

  const counts = useMemo(() => {
    return {
      critical: alerts.filter((a) => a.severity === 'critical').length,
      high: alerts.filter((a) => a.severity === 'high').length,
      open: alerts.filter(
        (a) => a.status !== 'resolved' && a.status !== 'false_positive',
      ).length,
    };
  }, [alerts]);

  return (
    <div className="px-4 pt-4 pb-2">
      {/* Heading + counts strip */}
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Triage queue</h1>
          <p className="text-xs text-zinc-500 mt-0.5">
            {counts.open} open ·{' '}
            <span className="text-red-400">{counts.critical} critical</span> ·{' '}
            <span className="text-orange-400">{counts.high} high</span>
          </p>
        </div>
        <button
          type="button"
          onClick={() => void load('refresh')}
          disabled={refreshing}
          aria-label="Refresh queue"
          className="w-9 h-9 rounded-full border border-zinc-800 hover:border-zinc-700 disabled:opacity-60 flex items-center justify-center text-zinc-300"
        >
          <svg
            className={clsx('w-4 h-4', refreshing && 'animate-spin')}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.75}
              d="M16.023 9.348h4.992V4.356m0 0L17.66 1m3.355 3.355L17.66 8.71M3.355 19.644l3.355-3.355M3.355 19.644h4.992v-4.992M3.355 19.644a9 9 0 0114.456-3.355M2.985 14.64H7.977m12.038-5.293a9 9 0 00-14.456 3.355"
            />
          </svg>
        </button>
      </div>

      {/* Severity filter chips */}
      <div className="-mx-4 px-4 overflow-x-auto mb-3">
        <div className="flex gap-2 pr-4">
          {SEVERITY_FILTERS.map((filter) => {
            const active = severityFilter === filter.id;
            const tone =
              filter.id === 'all'
                ? null
                : severityTone(filter.id as AlertSeverity);
            return (
              <button
                key={filter.id}
                type="button"
                onClick={() => setSeverityFilter(filter.id)}
                className={clsx(
                  'shrink-0 text-xs px-3 py-1.5 rounded-full border transition',
                  active
                    ? tone
                      ? `${tone.bg} ${tone.fg} border-transparent`
                      : 'bg-indigo-500/15 text-indigo-300 border-transparent'
                    : 'bg-transparent text-zinc-400 border-zinc-800 hover:border-zinc-700',
                )}
              >
                {filter.label}
              </button>
            );
          })}
          <button
            type="button"
            onClick={() => setShowResolved((v) => !v)}
            className={clsx(
              'shrink-0 text-xs px-3 py-1.5 rounded-full border transition ml-1',
              showResolved
                ? 'bg-zinc-800 text-zinc-200 border-transparent'
                : 'bg-transparent text-zinc-500 border-zinc-800 hover:border-zinc-700',
            )}
          >
            {showResolved ? 'Showing resolved' : 'Show resolved'}
          </button>
        </div>
      </div>

      {/* Body */}
      {error ? (
        <div className="rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300 mb-3">
          {error}
        </div>
      ) : null}

      {loading ? (
        <SkeletonList />
      ) : visibleAlerts.length === 0 ? (
        <EmptyState filter={severityFilter} showResolved={showResolved} />
      ) : (
        <ul className="space-y-2">
          {visibleAlerts.map((alert) => (
            <li key={alert.id}>
              <AlertCard alert={alert} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function AlertCard({ alert }: { alert: Alert }) {
  const tone = severityTone(alert.severity);
  const status = alertStatusTone(alert.status);
  const mitre = alert.mitreAttack?.[0];

  return (
    <Link
      href={`/responder/triage/${alert.id}`}
      className={clsx(
        'block rounded-xl bg-zinc-900/70 hover:bg-zinc-900 border border-zinc-800/80 hover:border-zinc-700 transition active:scale-[0.99] border-l-4',
        tone.border,
      )}
    >
      <div className="px-4 py-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <h2 className="text-sm font-medium text-zinc-100 leading-snug line-clamp-2">
              {alert.title}
            </h2>
            <div className="mt-1.5 flex items-center gap-2 text-[11px] text-zinc-500">
              <span className="truncate">{alert.source}</span>
              {mitre ? (
                <>
                  <span aria-hidden>·</span>
                  <span className="truncate">{mitre.techniqueId}</span>
                </>
              ) : null}
            </div>
          </div>
          <div className="flex flex-col items-end gap-1.5 shrink-0">
            <span
              className={clsx(
                'text-[10px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded',
                tone.bg,
                tone.fg,
              )}
            >
              {alert.severity}
            </span>
            <span
              className={clsx(
                'text-[10px] uppercase tracking-wider px-2 py-0.5 rounded',
                status.bg,
                status.fg,
              )}
            >
              {status.label}
            </span>
          </div>
        </div>
        <div className="mt-2 flex items-center justify-between text-[11px] text-zinc-500">
          <span>{formatRelative(alert.createdAt)}</span>
          {alert.assignee ? (
            <span className="truncate max-w-[120px]">@{alert.assignee}</span>
          ) : (
            <span className="text-zinc-600">unassigned</span>
          )}
        </div>
      </div>
    </Link>
  );
}

function SkeletonList() {
  return (
    <ul className="space-y-2" aria-hidden>
      {Array.from({ length: 5 }).map((_, i) => (
        <li
          key={i}
          className="rounded-xl bg-zinc-900/40 border border-zinc-800/60 border-l-4 border-l-zinc-800 px-4 py-3"
        >
          <div className="h-3.5 w-2/3 bg-zinc-800/80 rounded animate-pulse" />
          <div className="h-3 w-1/3 bg-zinc-800/60 rounded mt-2.5 animate-pulse" />
          <div className="h-2.5 w-1/4 bg-zinc-800/60 rounded mt-3 animate-pulse" />
        </li>
      ))}
    </ul>
  );
}

function EmptyState({
  filter,
  showResolved,
}: {
  filter: SeverityFilter;
  showResolved: boolean;
}) {
  const message =
    filter === 'all' && !showResolved
      ? 'Queue is clear. Time for coffee.'
      : 'No alerts match this filter.';
  return (
    <div className="rounded-xl border border-zinc-800/80 bg-zinc-900/30 px-6 py-12 text-center">
      <div className="w-10 h-10 mx-auto rounded-full bg-zinc-800/60 flex items-center justify-center mb-3">
        <svg
          className="w-5 h-5 text-zinc-500"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={1.75}
            d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
      </div>
      <p className="text-sm text-zinc-300">{message}</p>
      <p className="text-xs text-zinc-500 mt-1">
        Auto-refreshes every 30 seconds.
      </p>
    </div>
  );
}
