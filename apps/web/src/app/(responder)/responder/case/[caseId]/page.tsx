'use client';

/**
 * Mobile case detail.
 *
 * The on-call needs to: read the case, claim it, mark it active, close it
 * out, and jump into the linked alerts. That's it. Everything else (full
 * timeline, tasks editor, comments thread, ATT&CK matrix) lives on the
 * desktop console — touching them on a phone at 2am is a mistake.
 */

import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { clsx } from 'clsx';
import {
  alertsApi,
  casesApi,
  type Alert,
  type Case,
  type CaseStatus,
} from '@/lib/api';
import {
  formatRelative,
  caseStatusTone,
  severityTone,
  alertStatusTone,
} from '@/lib/responder/format';
import { getProfile } from '@/lib/responder/auth';

const MAX_ALERTS_VISIBLE = 8;

export default function ResponderCaseDetailPage() {
  const params = useParams<{ caseId: string }>();
  const caseId = params?.caseId;
  const router = useRouter();

  const [caseRecord, setCaseRecord] = useState<Case | null>(null);
  const [linkedAlerts, setLinkedAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!caseId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await casesApi.get(caseId);
      setCaseRecord(data);
      const alertIds = (data.alertIds ?? []).slice(0, MAX_ALERTS_VISIBLE);
      if (alertIds.length > 0) {
        // Best-effort hydration of the alert summaries; tolerate per-id
        // failures so a single missing alert doesn't blank the screen.
        const settled = await Promise.allSettled(
          alertIds.map((id) => alertsApi.get(id)),
        );
        setLinkedAlerts(
          settled
            .filter(
              (r): r is PromiseFulfilledResult<Alert> =>
                r.status === 'fulfilled',
            )
            .map((r) => r.value),
        );
      } else {
        setLinkedAlerts([]);
      }
    } catch (err) {
      console.error('[responder] failed to load case', err);
      setError(err instanceof Error ? err.message : 'Failed to load case.');
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    void load();
  }, [load]);

  const showToast = useCallback((message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(null), 2400);
  }, []);

  const updateStatus = useCallback(
    async (status: CaseStatus, label: string) => {
      if (!caseId) return;
      setBusyAction(label);
      try {
        const profile = getProfile();
        const updates: Partial<Case> = { status };
        // Claim the case if we're moving it to "active" and nobody owns it.
        if (
          status === 'in_progress' &&
          !caseRecord?.assignee &&
          profile?.email
        ) {
          updates.assignee = profile.email;
        }
        const next = await casesApi.update(caseId, updates);
        setCaseRecord(next);
        showToast(`${label} — done`);
      } catch (err) {
        console.error('[responder] failed to update case', err);
        showToast(err instanceof Error ? err.message : 'Action failed');
      } finally {
        setBusyAction(null);
      }
    },
    [caseId, caseRecord?.assignee, showToast],
  );

  const claim = useCallback(async () => {
    if (!caseId) return;
    const profile = getProfile();
    if (!profile?.email) {
      showToast('No profile — sign in again');
      return;
    }
    setBusyAction('Claim');
    try {
      const next = await casesApi.update(caseId, { assignee: profile.email });
      setCaseRecord(next);
      showToast('Claimed');
    } catch (err) {
      console.error('[responder] failed to claim case', err);
      showToast(err instanceof Error ? err.message : 'Claim failed');
    } finally {
      setBusyAction(null);
    }
  }, [caseId, showToast]);

  const tone = useMemo(
    () => severityTone(caseRecord?.severity),
    [caseRecord?.severity],
  );
  const status = useMemo(
    () => caseStatusTone(caseRecord?.status),
    [caseRecord?.status],
  );
  const profile = getProfile();
  const isMine = profile?.email && caseRecord?.assignee === profile.email;
  const tags = caseRecord?.tags ?? [];
  const mitre = caseRecord?.mitre ?? [];

  return (
    <div className="px-4 pt-3 pb-2">
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
        Cases
      </button>

      {error ? (
        <div className="rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : null}

      {loading || !caseRecord ? (
        <DetailSkeleton />
      ) : (
        <>
          <div
            className={clsx(
              'rounded-xl bg-zinc-900/70 border border-zinc-800/80 border-l-4 px-4 py-3',
              tone.border,
            )}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <h1 className="text-base font-semibold leading-snug text-zinc-100">
                  {caseRecord.title}
                </h1>
                <div className="mt-1 text-[11px] font-mono text-zinc-500">
                  {caseRecord.id}
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
            <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-zinc-500">
              <span>opened {formatRelative(caseRecord.createdAt)}</span>
              {caseRecord.assignee ? (
                <>
                  <span aria-hidden>·</span>
                  <span>
                    {isMine ? 'mine' : `@${caseRecord.assignee}`}
                  </span>
                </>
              ) : (
                <>
                  <span aria-hidden>·</span>
                  <span className="text-zinc-600">unassigned</span>
                </>
              )}
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
            {caseRecord.description ? (
              <p className="mt-2 text-sm text-zinc-300 leading-relaxed whitespace-pre-wrap">
                {caseRecord.description}
              </p>
            ) : null}
          </div>

          {/* Action row — three thumb-reachable buttons */}
          <ActionGrid>
            <ActionButton
              label={isMine ? 'Claimed' : 'Claim'}
              busy={busyAction === 'Claim'}
              disabled={!!isMine}
              tone="primary"
              onClick={claim}
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
                    d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0A17.933 17.933 0 0112 21.75c-2.676 0-5.216-.584-7.499-1.632z"
                  />
                </svg>
              }
            />
            <ActionButton
              label="Active"
              busy={busyAction === 'Active'}
              disabled={caseRecord.status === 'in_progress'}
              onClick={() => void updateStatus('in_progress', 'Active')}
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
                    d="M5.25 5.653c0-.856.917-1.398 1.667-.986l11.54 6.348a1.125 1.125 0 010 1.971l-11.54 6.347a1.125 1.125 0 01-1.667-.985V5.653z"
                  />
                </svg>
              }
            />
            <ActionButton
              label="Resolve"
              busy={busyAction === 'Resolve'}
              disabled={
                caseRecord.status === 'resolved' ||
                caseRecord.status === 'closed'
              }
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
          </ActionGrid>

          {/* Tags + MITRE */}
          {(tags.length > 0 || mitre.length > 0) && (
            <Section title="Context">
              <div className="flex flex-wrap gap-1.5">
                {mitre.map((m) => (
                  <span
                    key={`mitre-${m}`}
                    className="text-[11px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20"
                  >
                    {m}
                  </span>
                ))}
                {tags.map((t) => (
                  <span
                    key={`tag-${t}`}
                    className="text-[11px] px-2 py-0.5 rounded bg-zinc-800/80 text-zinc-300"
                  >
                    {t}
                  </span>
                ))}
              </div>
            </Section>
          )}

          {/* Linked alerts — drill into the alert detail surface we already built */}
          <Section
            title={`Alerts${
              caseRecord.alertCount ? ` (${caseRecord.alertCount})` : ''
            }`}
          >
            {linkedAlerts.length === 0 ? (
              <p className="text-xs text-zinc-500 py-2">
                No alerts linked yet.
              </p>
            ) : (
              <ul className="divide-y divide-zinc-800/80 -mx-1">
                {linkedAlerts.map((a) => (
                  <li key={a.id}>
                    <Link
                      href={`/responder/triage/${a.id}`}
                      className="flex items-center gap-3 px-1 py-2.5 hover:bg-zinc-900/40 active:scale-[0.99] transition rounded"
                    >
                      <AlertSeverityDot severity={a.severity} />
                      <div className="flex-1 min-w-0">
                        <div className="text-sm text-zinc-200 truncate">
                          {a.title}
                        </div>
                        <div className="mt-0.5 flex items-center gap-2 text-[11px] text-zinc-500">
                          <span>{a.source}</span>
                          <span aria-hidden>·</span>
                          <span>{formatRelative(a.createdAt)}</span>
                        </div>
                      </div>
                      <AlertStatusPill status={a.status} />
                      <svg
                        className="w-3.5 h-3.5 text-zinc-600 shrink-0"
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
                  </li>
                ))}
                {(caseRecord.alertCount ?? 0) > linkedAlerts.length ? (
                  <li className="px-1 py-2 text-[11px] text-zinc-500">
                    {(caseRecord.alertCount ?? 0) - linkedAlerts.length} more on
                    desktop
                  </li>
                ) : null}
              </ul>
            )}
          </Section>

          {caseRecord.resolution ? (
            <Section title="Resolution">
              <p className="text-sm text-zinc-300 whitespace-pre-wrap">
                {caseRecord.resolution}
              </p>
            </Section>
          ) : null}
        </>
      )}

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

function AlertSeverityDot({ severity }: { severity: Alert['severity'] }) {
  const tone = severityTone(severity);
  return (
    <span
      aria-label={severity}
      className={clsx('w-1.5 h-8 rounded-full shrink-0 self-stretch', {
        'bg-red-500': tone.glyph === 'C',
        'bg-orange-500': tone.glyph === 'H',
        'bg-yellow-500': tone.glyph === 'M',
        'bg-blue-500': tone.glyph === 'L',
        'bg-slate-500': tone.glyph === 'I',
      })}
    />
  );
}

function AlertStatusPill({ status }: { status: Alert['status'] }) {
  const t = alertStatusTone(status);
  return (
    <span
      className={clsx(
        'shrink-0 text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded',
        t.bg,
        t.fg,
      )}
    >
      {t.label}
    </span>
  );
}

function ActionGrid({ children }: { children: React.ReactNode }) {
  return <div className="mt-3 grid grid-cols-3 gap-2">{children}</div>;
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
        <div className="h-3 w-1/3 bg-zinc-800/60 rounded mt-3 animate-pulse" />
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
