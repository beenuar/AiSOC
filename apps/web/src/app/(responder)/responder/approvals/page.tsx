'use client';

/**
 * Mobile approvals queue.
 *
 * The agent stops and waits when it wants to take a high-risk action
 * (isolate a host, disable an account, revoke a session). On-call sees
 * the request here, taps Approve or Deny, and the agent resumes. The
 * desktop console has a richer review surface; this view is optimized
 * for phone-in-pocket-at-2am.
 */

import Link from 'next/link';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { clsx } from 'clsx';
import {
  responderApi,
  type ApprovalRequest,
  type ApprovalStatus,
} from '@/lib/api';
import { formatRelative, formatUntil, severityTone } from '@/lib/responder/format';

type ScopeFilter = 'mine' | 'all';

const REFRESH_INTERVAL_MS = 30_000;

export default function ResponderApprovalsPage() {
  const [items, setItems] = useState<ApprovalRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scope, setScope] = useState<ScopeFilter>('mine');

  const load = useCallback(
    async (mode: 'initial' | 'refresh') => {
      if (mode === 'initial') setLoading(true);
      else setRefreshing(true);
      setError(null);
      try {
        const data = await responderApi.listApprovals({
          status: 'pending',
          mine: scope === 'mine',
          page_size: 50,
        });
        setItems(data.items ?? []);
      } catch (err) {
        console.error('[responder] failed to load approvals', err);
        setError(
          err instanceof Error ? err.message : 'Failed to load approvals.',
        );
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [scope],
  );

  useEffect(() => {
    void load('initial');
  }, [load]);

  // Approvals are time-sensitive — refresh more aggressively than cases.
  useEffect(() => {
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible') void load('refresh');
    }, REFRESH_INTERVAL_MS);
    return () => window.clearInterval(id);
  }, [load]);

  const sorted = useMemo(() => {
    return [...items].sort((a, b) => {
      // Highest risk first, then oldest (longest pending) first.
      const ra = riskRank(a.risk_level);
      const rb = riskRank(b.risk_level);
      if (ra !== rb) return rb - ra;
      return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
    });
  }, [items]);

  return (
    <div className="px-4 pt-4 pb-2">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Approvals</h1>
          <p className="text-xs text-zinc-500 mt-0.5">
            {sorted.length} pending
          </p>
        </div>
        <button
          type="button"
          onClick={() => void load('refresh')}
          disabled={refreshing}
          aria-label="Refresh approvals"
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

      {/* Scope toggle: mine vs everyone. Defaults to "mine" since most of the
          time the on-call cares about their own queue. */}
      <div className="mb-3 inline-flex rounded-full bg-zinc-900/70 border border-zinc-800 p-0.5 text-xs">
        {(['mine', 'all'] as ScopeFilter[]).map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => setScope(s)}
            className={clsx(
              'px-3 py-1.5 rounded-full transition',
              scope === s
                ? 'bg-zinc-100 text-zinc-900 font-medium'
                : 'text-zinc-400 hover:text-zinc-200',
            )}
          >
            {s === 'mine' ? 'Mine' : 'All'}
          </button>
        ))}
      </div>

      {error ? (
        <div className="rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300 mb-3">
          {error}
        </div>
      ) : null}

      {loading ? (
        <SkeletonList />
      ) : sorted.length === 0 ? (
        <EmptyState />
      ) : (
        <ul className="space-y-2">
          {sorted.map((req) => (
            <li key={req.id}>
              <ApprovalCard req={req} onChanged={() => void load('refresh')} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function riskRank(level: ApprovalRequest['risk_level']): number {
  switch (level) {
    case 'critical':
      return 4;
    case 'high':
      return 3;
    case 'medium':
      return 2;
    case 'low':
      return 1;
    default:
      return 0;
  }
}

function ApprovalCard({
  req,
  onChanged,
}: {
  req: ApprovalRequest;
  onChanged: () => void;
}) {
  const tone = severityTone(req.risk_level);
  const [busy, setBusy] = useState<'approve' | 'deny' | null>(null);
  const [error, setError] = useState<string | null>(null);

  const expiresIn = formatUntil(req.expires_at);
  const expired = req.expires_at
    ? new Date(req.expires_at).getTime() < Date.now()
    : false;

  const approve = useCallback(async () => {
    setBusy('approve');
    setError(null);
    try {
      await responderApi.approve(req.id);
      onChanged();
    } catch (err) {
      console.error('[responder] approve failed', err);
      setError(err instanceof Error ? err.message : 'Approve failed');
    } finally {
      setBusy(null);
    }
  }, [req.id, onChanged]);

  const deny = useCallback(async () => {
    // Backend requires a reason — the desktop console takes a free-text
    // input; on mobile we use a sensible default and let the user open the
    // detail page if they want a richer reason.
    setBusy('deny');
    setError(null);
    try {
      await responderApi.deny(req.id, 'Denied from mobile responder.');
      onChanged();
    } catch (err) {
      console.error('[responder] deny failed', err);
      setError(err instanceof Error ? err.message : 'Deny failed');
    } finally {
      setBusy(null);
    }
  }, [req.id, onChanged]);

  return (
    <div
      className={clsx(
        'rounded-xl bg-zinc-900/70 border border-zinc-800/80 border-l-4 px-4 py-3',
        tone.border,
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <h2 className="text-sm font-medium text-zinc-100 leading-snug line-clamp-2">
            {req.title}
          </h2>
          <p className="mt-1 text-xs text-zinc-400 leading-relaxed line-clamp-3">
            {req.summary}
          </p>
        </div>
        <span
          className={clsx(
            'shrink-0 text-[10px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded',
            tone.bg,
            tone.fg,
          )}
        >
          {req.risk_level}
        </span>
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-zinc-500">
        <span>requested by {req.requested_by}</span>
        <span aria-hidden>·</span>
        <span>opened {formatRelative(req.created_at)}</span>
        {req.expires_at ? (
          <>
            <span aria-hidden>·</span>
            <span className={expired ? 'text-red-400' : 'text-amber-400'}>
              {expired ? 'expired' : `expires in ${expiresIn ?? 'soon'}`}
            </span>
          </>
        ) : null}
      </div>

      {error ? (
        <div className="mt-2 text-xs text-red-300">{error}</div>
      ) : null}

      <div className="mt-3 grid grid-cols-3 gap-2">
        <button
          type="button"
          onClick={() => void approve()}
          disabled={busy !== null || expired}
          className="h-10 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-200 text-xs font-medium transition active:scale-[0.97] disabled:opacity-50 disabled:active:scale-100"
        >
          {busy === 'approve' ? '…' : 'Approve'}
        </button>
        <button
          type="button"
          onClick={() => void deny()}
          disabled={busy !== null || expired}
          className="h-10 rounded-lg bg-red-500/15 hover:bg-red-500/25 border border-red-500/30 text-red-200 text-xs font-medium transition active:scale-[0.97] disabled:opacity-50 disabled:active:scale-100"
        >
          {busy === 'deny' ? '…' : 'Deny'}
        </button>
        {/* Deep-link to alert/case if linked, otherwise to a (future) detail page */}
        <Link
          href={
            req.case_id
              ? `/responder/case/${req.case_id}`
              : req.alert_id
                ? `/responder/triage/${req.alert_id}`
                : '#'
          }
          className={clsx(
            'h-10 rounded-lg border border-zinc-800 hover:border-zinc-700 bg-zinc-900/60 text-zinc-300 text-xs font-medium transition active:scale-[0.97] flex items-center justify-center',
            !req.case_id && !req.alert_id && 'opacity-40 pointer-events-none',
          )}
        >
          Context
        </Link>
      </div>
    </div>
  );
}

function SkeletonList() {
  return (
    <ul className="space-y-2" aria-hidden>
      {Array.from({ length: 3 }).map((_, i) => (
        <li
          key={i}
          className="rounded-xl bg-zinc-900/40 border border-zinc-800/60 border-l-4 border-l-zinc-800 px-4 py-3"
        >
          <div className="h-3.5 w-2/3 bg-zinc-800/80 rounded animate-pulse" />
          <div className="h-3 w-full bg-zinc-800/60 rounded mt-2 animate-pulse" />
          <div className="h-2.5 w-1/2 bg-zinc-800/60 rounded mt-3 animate-pulse" />
          <div className="mt-3 grid grid-cols-3 gap-2">
            {Array.from({ length: 3 }).map((__, j) => (
              <div
                key={j}
                className="h-10 rounded-lg bg-zinc-800/40 animate-pulse"
              />
            ))}
          </div>
        </li>
      ))}
    </ul>
  );
}

function EmptyState() {
  return (
    <div className="rounded-xl border border-zinc-800/80 bg-zinc-900/30 px-6 py-12 text-center">
      <div className="w-10 h-10 mx-auto rounded-full bg-emerald-500/15 flex items-center justify-center mb-3">
        <svg
          className="w-5 h-5 text-emerald-400"
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
      <p className="text-sm text-zinc-300">Nothing to approve.</p>
      <p className="text-xs text-zinc-500 mt-1">
        Agent isn&apos;t blocked on you. Nice.
      </p>
    </div>
  );
}
