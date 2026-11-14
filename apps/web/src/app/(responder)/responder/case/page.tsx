'use client';

/**
 * Mobile case list — the responder's case backlog when they're away from
 * their desk. Mirrors the triage queue's information density:
 *   • severity bar on the left
 *   • title + assignee
 *   • status pill on the right
 *   • severity chips at the top
 *   • "mine only" toggle (the on-call usually wants their own first)
 */

import Link from 'next/link';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { clsx } from 'clsx';
import { casesApi, type Case, type CaseSeverity } from '@/lib/api';
import {
  formatRelative,
  severityTone,
  caseStatusTone,
} from '@/lib/responder/format';
import { getProfile } from '@/lib/responder/auth';

type SeverityFilter = CaseSeverity | 'all';

const SEVERITY_FILTERS: Array<{ id: SeverityFilter; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'critical', label: 'Critical' },
  { id: 'high', label: 'High' },
  { id: 'medium', label: 'Medium' },
];

const REFRESH_INTERVAL_MS = 60_000;

export default function ResponderCasesPage() {
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [showClosed, setShowClosed] = useState(false);
  const [mineOnly, setMineOnly] = useState(false);

  const profile = getProfile();
  const myEmail = profile?.email;

  const load = useCallback(async (mode: 'initial' | 'refresh') => {
    if (mode === 'initial') setLoading(true);
    else setRefreshing(true);
    setError(null);
    try {
      const data = await casesApi.list({ pageSize: 100 });
      setCases(data.cases ?? []);
    } catch (err) {
      console.error('[responder] failed to load cases', err);
      setError(err instanceof Error ? err.message : 'Failed to load cases.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void load('initial');
  }, [load]);

  useEffect(() => {
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible') void load('refresh');
    }, REFRESH_INTERVAL_MS);
    return () => window.clearInterval(id);
  }, [load]);

  const visible = useMemo(() => {
    let list = cases;
    if (!showClosed) {
      list = list.filter((c) => c.status !== 'closed' && c.status !== 'resolved');
    }
    if (severityFilter !== 'all') {
      list = list.filter((c) => c.severity === severityFilter);
    }
    if (mineOnly && myEmail) {
      list = list.filter((c) => c.assignee === myEmail);
    }
    return [...list].sort((a, b) => {
      const rs = severityTone(b.severity).rank - severityTone(a.severity).rank;
      if (rs !== 0) return rs;
      return new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime();
    });
  }, [cases, showClosed, severityFilter, mineOnly, myEmail]);

  const counts = useMemo(
    () => ({
      open: cases.filter(
        (c) => c.status !== 'closed' && c.status !== 'resolved',
      ).length,
      mine: cases.filter((c) => c.assignee === myEmail).length,
    }),
    [cases, myEmail],
  );

  return (
    <div className="px-4 pt-4 pb-2">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Cases</h1>
          <p className="text-xs text-zinc-500 mt-0.5">
            {counts.open} open
            {myEmail ? ` · ${counts.mine} mine` : ''}
          </p>
        </div>
        <button
          type="button"
          onClick={() => void load('refresh')}
          disabled={refreshing}
          aria-label="Refresh cases"
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

      <div className="-mx-4 px-4 overflow-x-auto mb-3">
        <div className="flex gap-2 pr-4">
          {SEVERITY_FILTERS.map((filter) => {
            const active = severityFilter === filter.id;
            const tone =
              filter.id === 'all'
                ? null
                : severityTone(filter.id as CaseSeverity);
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
          {myEmail ? (
            <button
              type="button"
              onClick={() => setMineOnly((v) => !v)}
              className={clsx(
                'shrink-0 text-xs px-3 py-1.5 rounded-full border transition ml-1',
                mineOnly
                  ? 'bg-indigo-500/15 text-indigo-300 border-transparent'
                  : 'bg-transparent text-zinc-500 border-zinc-800 hover:border-zinc-700',
              )}
            >
              {mineOnly ? 'Mine (on)' : 'Mine'}
            </button>
          ) : null}
          <button
            type="button"
            onClick={() => setShowClosed((v) => !v)}
            className={clsx(
              'shrink-0 text-xs px-3 py-1.5 rounded-full border transition',
              showClosed
                ? 'bg-zinc-800 text-zinc-200 border-transparent'
                : 'bg-transparent text-zinc-500 border-zinc-800 hover:border-zinc-700',
            )}
          >
            {showClosed ? 'Closed (on)' : 'Closed'}
          </button>
        </div>
      </div>

      {error ? (
        <div className="rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300 mb-3">
          {error}
        </div>
      ) : null}

      {loading ? (
        <SkeletonList />
      ) : visible.length === 0 ? (
        <EmptyState mineOnly={mineOnly} />
      ) : (
        <ul className="space-y-2">
          {visible.map((c) => (
            <li key={c.id}>
              <CaseCard caseRecord={c} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function CaseCard({ caseRecord }: { caseRecord: Case }) {
  const tone = severityTone(caseRecord.severity);
  const status = caseStatusTone(caseRecord.status);
  return (
    <Link
      href={`/responder/case/${caseRecord.id}`}
      className={clsx(
        'block rounded-xl bg-zinc-900/70 hover:bg-zinc-900 border border-zinc-800/80 hover:border-zinc-700 transition active:scale-[0.99] border-l-4',
        tone.border,
      )}
    >
      <div className="px-4 py-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <h2 className="text-sm font-medium text-zinc-100 leading-snug line-clamp-2">
              {caseRecord.title}
            </h2>
            <div className="mt-1.5 flex items-center gap-2 text-[11px] text-zinc-500">
              <span className="font-mono">{caseRecord.id}</span>
              {caseRecord.alertCount ? (
                <>
                  <span aria-hidden>·</span>
                  <span>
                    {caseRecord.alertCount} alert
                    {caseRecord.alertCount === 1 ? '' : 's'}
                  </span>
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
              {caseRecord.severity}
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
          <span>updated {formatRelative(caseRecord.updatedAt)}</span>
          {caseRecord.assignee ? (
            <span className="truncate max-w-[120px]">@{caseRecord.assignee}</span>
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
      {Array.from({ length: 4 }).map((_, i) => (
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

function EmptyState({ mineOnly }: { mineOnly: boolean }) {
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
            d="M3.75 9.776c.112-.017.227-.026.344-.026h15.812c.117 0 .232.009.344.026m-16.5 0a2.25 2.25 0 00-1.883 2.542l.857 6a2.25 2.25 0 002.227 1.932H19.05a2.25 2.25 0 002.227-1.932l.857-6a2.25 2.25 0 00-1.883-2.542m-16.5 0V6A2.25 2.25 0 016 3.75h3.879a1.5 1.5 0 011.06.44l2.122 2.12a1.5 1.5 0 001.06.44H18A2.25 2.25 0 0120.25 9v.776"
          />
        </svg>
      </div>
      <p className="text-sm text-zinc-300">
        {mineOnly ? 'No cases assigned to you.' : 'No cases match this filter.'}
      </p>
    </div>
  );
}
