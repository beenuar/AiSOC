'use client';

/**
 * Mobile alert detail.
 *
 * The on-call's single most-used surface after the queue. The job here is:
 *   • Surface the *what* and *why* fast (severity, MITRE, source, top IOCs)
 *   • Give the four actions the on-call ever does at 2am from a phone:
 *       - Acknowledge (mark triaged, claim it)
 *       - Snooze (1h / 4h / morning) so it leaves the queue
 *       - Resolve (it's fine, close it)
 *       - Mark false positive
 *   • Drill into the parent case if one exists.
 *
 * Everything else (raw event JSON, full timeline, agent decisions) is in the
 * desktop console; the phone doesn't need it.
 */

import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { clsx } from 'clsx';
import {
  alertsApi,
  responderApi,
  type Alert,
  type AlertStatus,
} from '@/lib/api';
import {
  formatRelative,
  alertStatusTone,
  severityTone,
} from '@/lib/responder/format';
import { getProfile } from '@/lib/responder/auth';

type SnoozeWindow = {
  label: string;
  minutes?: number;
  /** "morning" = next 7am local */
  preset?: 'morning';
};

const SNOOZE_WINDOWS: SnoozeWindow[] = [
  { label: '1h', minutes: 60 },
  { label: '4h', minutes: 240 },
  { label: 'Morning', preset: 'morning' },
];

function nextMorningISO(): string {
  const d = new Date();
  d.setHours(7, 0, 0, 0);
  if (d.getTime() <= Date.now()) {
    d.setDate(d.getDate() + 1);
  }
  return d.toISOString();
}

export default function ResponderAlertDetailPage() {
  const params = useParams<{ alertId: string }>();
  const alertId = params?.alertId;
  const router = useRouter();

  const [alert, setAlert] = useState<Alert | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!alertId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await alertsApi.get(alertId);
      setAlert(data);
    } catch (err) {
      console.error('[responder] failed to load alert', err);
      setError(err instanceof Error ? err.message : 'Failed to load alert.');
    } finally {
      setLoading(false);
    }
  }, [alertId]);

  useEffect(() => {
    void load();
  }, [load]);

  const showToast = useCallback((message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(null), 2400);
  }, []);

  const updateStatus = useCallback(
    async (status: AlertStatus, label: string) => {
      if (!alertId) return;
      setBusyAction(label);
      try {
        const profile = getProfile();
        const updates: Partial<Alert> = { status };
        if (status === 'triaged' && !alert?.assignee && profile?.email) {
          // Acknowledging implicitly claims the alert for the responder.
          updates.assignee = profile.email;
        }
        const next = await alertsApi.update(alertId, updates);
        setAlert(next);
        showToast(`${label} ✓`);
      } catch (err) {
        console.error('[responder] failed to update alert', err);
        showToast(err instanceof Error ? err.message : 'Action failed');
      } finally {
        setBusyAction(null);
      }
    },
    [alertId, alert?.assignee, showToast],
  );

  const snooze = useCallback(
    async (window: SnoozeWindow) => {
      if (!alertId) return;
      setBusyAction(`snooze-${window.label}`);
      try {
        const next = await responderApi.snoozeAlert(alertId, {
          durationMinutes: window.minutes,
          until: window.preset === 'morning' ? nextMorningISO() : undefined,
        });
        setAlert(next);
        showToast(`Snoozed for ${window.label.toLowerCase()} ✓`);
      } catch (err) {
        console.error('[responder] failed to snooze alert', err);
        showToast(err instanceof Error ? err.message : 'Snooze failed');
      } finally {
        setBusyAction(null);
      }
    },
    [alertId, showToast],
  );

  const tone = useMemo(
    () => severityTone(alert?.severity),
    [alert?.severity],
  );
  const status = useMemo(
    () => alertStatusTone(alert?.status),
    [alert?.status],
  );
  const mitre = alert?.mitreAttack ?? [];
  const topIocs = (alert?.iocs ?? []).slice(0, 5);

  return (
    <div className="px-4 pt-3 pb-2">
      {/* Back nav */}
      <button
        type="button"
        onClick={() => router.back()}
        className="-ml-2 mb-2 inline-flex items-center gap-1 text-sm text-zinc-400 hover:text-zinc-200"
      >
        <svg
          className="w-4 h-4"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={1.75}
            d="M15.75 19.5L8.25 12l7.5-7.5"
          />
        </svg>
        Queue
      </button>

      {error ? (
        <div className="rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : null}

      {loading || !alert ? (
        <DetailSkeleton />
      ) : (
        <>
          {/* Header card */}
          <div
            className={clsx(
              'rounded-xl bg-zinc-900/70 border border-zinc-800/80 border-l-4 px-4 py-3',
              tone.border,
            )}
          >
            <div className="flex items-start justify-between gap-3">
              <h1 className="text-base font-semibold leading-snug text-zinc-100">
                {alert.title}
              </h1>
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
            <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-zinc-500">
              <span>{alert.source}</span>
              <span aria-hidden>·</span>
              <span>{formatRelative(alert.createdAt)}</span>
              {alert.assignee ? (
                <>
                  <span aria-hidden>·</span>
                  <span>@{alert.assignee}</span>
                </>
              ) : null}
            </div>
            {alert.description ? (
              <p className="mt-2 text-sm text-zinc-300 leading-relaxed whitespace-pre-wrap">
                {alert.description}
              </p>
            ) : null}
          </div>

          {/* Quick actions — one row, thumb-reachable */}
          <ActionGrid>
            <ActionButton
              label="Acknowledge"
              busy={busyAction === 'Acknowledge'}
              disabled={alert.status === 'triaged'}
              tone="primary"
              onClick={() => void updateStatus('triaged', 'Acknowledge')}
              icon={
                <svg
                  className="w-5 h-5"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={1.75}
                    d="M4.5 12.75l6 6 9-13.5"
                  />
                </svg>
              }
            />
            <ActionButton
              label="Resolve"
              busy={busyAction === 'Resolve'}
              disabled={alert.status === 'resolved'}
              onClick={() => void updateStatus('resolved', 'Resolve')}
              icon={
                <svg
                  className="w-5 h-5"
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
              }
            />
            <ActionButton
              label="False positive"
              busy={busyAction === 'False positive'}
              disabled={alert.status === 'false_positive'}
              onClick={() =>
                void updateStatus('false_positive', 'False positive')
              }
              icon={
                <svg
                  className="w-5 h-5"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={1.75}
                    d="M9.75 9.75l4.5 4.5m0-4.5l-4.5 4.5M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                  />
                </svg>
              }
            />
          </ActionGrid>

          {/* Snooze row — three preset windows that match how on-calls actually use it */}
          <div className="mt-3 rounded-xl border border-zinc-800/80 bg-zinc-900/40 px-4 py-3">
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-xs uppercase tracking-wider text-zinc-500">
                Snooze
              </h2>
              <span className="text-[10px] text-zinc-600">
                returns to queue when window ends
              </span>
            </div>
            <div className="grid grid-cols-3 gap-2">
              {SNOOZE_WINDOWS.map((w) => (
                <button
                  key={w.label}
                  type="button"
                  disabled={busyAction === `snooze-${w.label}`}
                  onClick={() => void snooze(w)}
                  className={clsx(
                    'h-10 rounded-lg text-sm font-medium border transition active:scale-[0.97]',
                    'bg-zinc-900/60 hover:bg-zinc-900 border-zinc-800 hover:border-zinc-700 text-zinc-200',
                    busyAction === `snooze-${w.label}` && 'opacity-60',
                  )}
                >
                  {w.label}
                </button>
              ))}
            </div>
          </div>

          {/* MITRE techniques */}
          {mitre.length > 0 ? (
            <Section title="MITRE ATT&CK">
              <ul className="space-y-1.5">
                {mitre.map((m) => (
                  <li
                    key={m.techniqueId}
                    className="flex items-center justify-between text-sm"
                  >
                    <span className="text-zinc-300 truncate">{m.technique}</span>
                    <span className="ml-2 text-[11px] font-mono text-indigo-300">
                      {m.techniqueId}
                    </span>
                  </li>
                ))}
              </ul>
            </Section>
          ) : null}

          {/* Indicators */}
          {topIocs.length > 0 ? (
            <Section
              title={`Indicators (${alert.iocs?.length ?? topIocs.length})`}
            >
              <ul className="divide-y divide-zinc-800/80">
                {topIocs.map((ioc, i) => (
                  <li
                    key={`${ioc.type}:${ioc.value}:${i}`}
                    className="py-2 flex items-center justify-between gap-3"
                  >
                    <div className="min-w-0">
                      <div className="text-[10px] uppercase tracking-wider text-zinc-500">
                        {ioc.type}
                      </div>
                      <div className="text-sm font-mono text-zinc-200 truncate">
                        {ioc.value}
                      </div>
                    </div>
                    {ioc.malicious ? (
                      <span className="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded bg-red-500/15 text-red-300">
                        Malicious
                      </span>
                    ) : null}
                  </li>
                ))}
              </ul>
            </Section>
          ) : null}

          {/* Linked case shortcut */}
          {alert.caseId ? (
            <Link
              href={`/responder/case/${alert.caseId}`}
              className="mt-3 flex items-center justify-between rounded-xl border border-zinc-800/80 bg-zinc-900/40 px-4 py-3 hover:bg-zinc-900 active:scale-[0.99] transition"
            >
              <div>
                <div className="text-[10px] uppercase tracking-wider text-zinc-500">
                  Linked case
                </div>
                <div className="text-sm font-medium text-indigo-300">
                  {alert.caseId}
                </div>
              </div>
              <svg
                className="w-4 h-4 text-zinc-500"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={1.75}
                  d="M8.25 4.5l7.5 7.5-7.5 7.5"
                />
              </svg>
            </Link>
          ) : null}
        </>
      )}

      {/* Toast */}
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

function ActionGrid({ children }: { children: React.ReactNode }) {
  return (
    <div className="mt-3 grid grid-cols-3 gap-2">{children}</div>
  );
}

function ActionButton({
  label,
  icon,
  onClick,
  busy,
  disabled,
  tone = 'default',
}: {
  label: string;
  icon: React.ReactNode;
  onClick: () => void;
  busy?: boolean;
  disabled?: boolean;
  tone?: 'default' | 'primary';
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled || busy}
      className={clsx(
        'h-16 rounded-xl border text-xs font-medium flex flex-col items-center justify-center gap-1 transition active:scale-[0.97]',
        tone === 'primary'
          ? 'bg-indigo-500/15 hover:bg-indigo-500/25 border-indigo-500/30 text-indigo-200'
          : 'bg-zinc-900/60 hover:bg-zinc-900 border-zinc-800 hover:border-zinc-700 text-zinc-200',
        (disabled || busy) && 'opacity-50 active:scale-100',
      )}
    >
      <span>{icon}</span>
      <span>{label}</span>
    </button>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="mt-3 rounded-xl border border-zinc-800/80 bg-zinc-900/40 px-4 py-3">
      <h2 className="text-xs uppercase tracking-wider text-zinc-500 mb-2">
        {title}
      </h2>
      {children}
    </section>
  );
}

function DetailSkeleton() {
  return (
    <div aria-hidden>
      <div className="rounded-xl bg-zinc-900/40 border border-zinc-800/60 border-l-4 border-l-zinc-800 px-4 py-3">
        <div className="h-4 w-3/4 bg-zinc-800/80 rounded animate-pulse" />
        <div className="h-3 w-1/2 bg-zinc-800/60 rounded mt-3 animate-pulse" />
        <div className="h-12 bg-zinc-800/40 rounded mt-3 animate-pulse" />
      </div>
      <div className="mt-3 grid grid-cols-3 gap-2">
        {Array.from({ length: 3 }).map((_, i) => (
          <div
            key={i}
            className="h-16 rounded-xl bg-zinc-900/40 border border-zinc-800/60 animate-pulse"
          />
        ))}
      </div>
    </div>
  );
}
