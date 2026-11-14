'use client';

/**
 * Mobile on-call control.
 *
 * Two jobs:
 *  1. Let the on-call flip their own status — available / busy / snoozed
 *     for a window / offline. This is the equivalent of the "page on-call"
 *     toggle the plan calls out.
 *  2. Show who else is on-call right now so handoffs aren't a guessing
 *     game in the middle of an incident.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { clsx } from 'clsx';
import {
  responderApi,
  type OnCallSnapshot,
  type OnCallStatus,
} from '@/lib/api';
import { formatRelative, formatUntil } from '@/lib/responder/format';

const STATUSES: { value: OnCallStatus; label: string; tone: string }[] = [
  {
    value: 'available',
    label: 'Available',
    tone: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  },
  {
    value: 'busy',
    label: 'Busy',
    tone: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  },
  {
    value: 'snoozed',
    label: 'Snoozed',
    tone: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30',
  },
  {
    value: 'offline',
    label: 'Offline',
    tone: 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30',
  },
];

const SNOOZE_PRESETS: { label: string; minutes: number }[] = [
  { label: '15m', minutes: 15 },
  { label: '1h', minutes: 60 },
  { label: '4h', minutes: 240 },
  { label: '8h', minutes: 480 },
];

export default function ResponderOnCallPage() {
  const [me, setMe] = useState<OnCallSnapshot | null>(null);
  const [team, setTeam] = useState<OnCallSnapshot[]>([]);
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState<OnCallStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [mine, all] = await Promise.all([
        responderApi.getOnCall(),
        responderApi.listOnCall(),
      ]);
      setMe(mine);
      setTeam(all.items ?? []);
    } catch (err) {
      console.error('[responder] failed to load on-call', err);
      setError(err instanceof Error ? err.message : 'Failed to load on-call.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const showToast = useCallback((message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(null), 2400);
  }, []);

  const setStatus = useCallback(
    async (status: OnCallStatus, snoozeMinutes?: number) => {
      setUpdating(status);
      try {
        const next = await responderApi.setOnCall(status, {
          snooze_minutes: snoozeMinutes ?? null,
        });
        setMe(next);
        // Refresh the team view so my own row reflects the change too.
        const all = await responderApi.listOnCall();
        setTeam(all.items ?? []);
        showToast(`Set to ${status}`);
      } catch (err) {
        console.error('[responder] failed to set on-call', err);
        showToast(err instanceof Error ? err.message : 'Update failed');
      } finally {
        setUpdating(null);
      }
    },
    [showToast],
  );

  // Sort team: available first, then busy, then snoozed, then offline. Within
  // a status, alphabetical by display name so the list is stable.
  const sortedTeam = useMemo(() => {
    const rank: Record<OnCallStatus, number> = {
      available: 0,
      busy: 1,
      snoozed: 2,
      offline: 3,
    };
    return [...team].sort((a, b) => {
      const ra = rank[a.status] ?? 99;
      const rb = rank[b.status] ?? 99;
      if (ra !== rb) return ra - rb;
      const an = a.user_name ?? a.user_email ?? a.user_id;
      const bn = b.user_name ?? b.user_email ?? b.user_id;
      return an.localeCompare(bn);
    });
  }, [team]);

  return (
    <div className="px-4 pt-4 pb-2">
      <h1 className="text-xl font-semibold tracking-tight">On-call</h1>
      <p className="text-xs text-zinc-500 mt-0.5">Your status and the rotation.</p>

      {error ? (
        <div className="mt-3 rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : null}

      {/* My status card */}
      <section className="mt-4 rounded-xl border border-zinc-800/80 bg-zinc-900/50 px-4 py-3">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0">
            <div className="text-xs uppercase tracking-wider text-zinc-500">
              You
            </div>
            <div className="text-sm font-medium text-zinc-100 truncate">
              {me?.user_name ?? me?.user_email ?? '—'}
            </div>
          </div>
          {me ? <StatusPill status={me.status} /> : null}
        </div>
        {me?.until ? (
          <div className="mt-1 text-[11px] text-zinc-500">
            until {formatUntil(me.until) ?? '—'}
          </div>
        ) : null}

        {/* Status grid — 2x2 thumb-reachable. */}
        <div className="mt-3 grid grid-cols-2 gap-2">
          {STATUSES.map((s) => {
            const active = me?.status === s.value;
            const isUpdating = updating === s.value;
            return (
              <button
                key={s.value}
                type="button"
                disabled={loading || updating !== null}
                onClick={() =>
                  s.value === 'snoozed' ? undefined : void setStatus(s.value)
                }
                className={clsx(
                  'h-12 rounded-lg border text-xs font-medium transition active:scale-[0.97]',
                  active
                    ? s.tone
                    : 'bg-zinc-900/40 hover:bg-zinc-900/80 border-zinc-800 hover:border-zinc-700 text-zinc-300',
                  (loading || updating !== null) && 'opacity-60 active:scale-100',
                )}
              >
                {isUpdating ? '…' : s.label}
              </button>
            );
          })}
        </div>

        {/* Snooze presets — only relevant when picking a snooze window. */}
        <div className="mt-2">
          <div className="text-[11px] uppercase tracking-wider text-zinc-500 mb-1.5">
            Snooze for
          </div>
          <div className="grid grid-cols-4 gap-2">
            {SNOOZE_PRESETS.map((p) => (
              <button
                key={p.minutes}
                type="button"
                disabled={loading || updating !== null}
                onClick={() => void setStatus('snoozed', p.minutes)}
                className="h-10 rounded-lg bg-zinc-900/40 hover:bg-zinc-900/80 border border-zinc-800 hover:border-zinc-700 text-xs text-zinc-300 transition active:scale-[0.97] disabled:opacity-60 disabled:active:scale-100"
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* Rotation roster */}
      <section className="mt-4">
        <h2 className="text-xs uppercase tracking-wider text-zinc-500 mb-2 px-1">
          Team
        </h2>
        {loading ? (
          <SkeletonList />
        ) : sortedTeam.length === 0 ? (
          <p className="text-xs text-zinc-500 px-1 py-3">
            No one configured for the rotation.
          </p>
        ) : (
          <ul className="rounded-xl border border-zinc-800/80 bg-zinc-900/30 divide-y divide-zinc-800/80 overflow-hidden">
            {sortedTeam.map((m) => (
              <li
                key={m.user_id}
                className="px-4 py-2.5 flex items-center gap-3"
              >
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-zinc-200 truncate">
                    {m.user_name ?? m.user_email ?? m.user_id}
                  </div>
                  <div className="mt-0.5 flex items-center gap-2 text-[11px] text-zinc-500">
                    {m.rotation ? <span>{m.rotation}</span> : null}
                    {m.until && m.status === 'snoozed' ? (
                      <span>back {formatUntil(m.until) ?? 'soon'}</span>
                    ) : (
                      <span>updated {formatRelative(m.updated_at)}</span>
                    )}
                  </div>
                </div>
                <StatusPill status={m.status} />
              </li>
            ))}
          </ul>
        )}
      </section>

      {toast ? (
        <div
          role="status"
          className="fixed left-1/2 -translate-x-1/2 bottom-[calc(5rem+env(safe-area-inset-bottom))] z-40 px-4 py-2 rounded-lg bg-zinc-100 text-zinc-900 text-sm shadow-lg"
        >
          {toast}
        </div>
      ) : null}
    </div>
  );
}

function StatusPill({ status }: { status: OnCallStatus }) {
  const meta = STATUSES.find((s) => s.value === status);
  return (
    <span
      className={clsx(
        'shrink-0 text-[10px] uppercase tracking-wider px-2 py-0.5 rounded border',
        meta?.tone ?? 'bg-zinc-800 text-zinc-400 border-zinc-700',
      )}
    >
      {meta?.label ?? status}
    </span>
  );
}

function SkeletonList() {
  return (
    <ul
      className="rounded-xl border border-zinc-800/60 bg-zinc-900/20 divide-y divide-zinc-800/60 overflow-hidden"
      aria-hidden
    >
      {Array.from({ length: 4 }).map((_, i) => (
        <li key={i} className="px-4 py-3 flex items-center gap-3">
          <div className="flex-1">
            <div className="h-3 w-1/2 bg-zinc-800/80 rounded animate-pulse" />
            <div className="h-2.5 w-1/3 bg-zinc-800/60 rounded mt-2 animate-pulse" />
          </div>
          <div className="h-5 w-16 bg-zinc-800/60 rounded animate-pulse" />
        </li>
      ))}
    </ul>
  );
}
