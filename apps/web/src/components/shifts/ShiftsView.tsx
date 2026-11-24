'use client';

/**
 * Shift handoffs, from real rows.
 *
 * This view used to render fabricated domain data unconditionally and made
 * no API call; then it rendered an honest "not yet wired" state. The
 * backend now exists (`/api/v1/operating-model/*`): shifts are tenant
 * configuration, and a handoff is a SNAPSHOT of the tenant's real open
 * work generated at shift end — open alerts by severity, attention cases,
 * pending approvals, running investigations — acknowledged by the shift
 * coming on. Nothing here is invented: an empty tenant shows an empty
 * state, an unreachable API shows the error, and a snapshot section whose
 * store could not answer renders its `could_not_check` reason.
 */

import { useCallback, useEffect, useState } from 'react';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';
import { apiFetch } from '@/lib/api';

interface Shift {
  id: string;
  name: string;
  timezone: string;
  start_minute: number;
  end_minute: number;
  weekdays: number[];
  enabled: boolean;
}

interface AttentionCase {
  case_number?: string;
  title?: string;
  severity?: string;
  unowned?: boolean;
  overdue?: boolean;
  could_not_check?: string;
}

interface Snapshot {
  window?: { start: string; end: string };
  open_alerts_by_severity?: Record<string, number | string>;
  attention_cases?: AttentionCase[];
  pending_approvals?: number | { could_not_check: string };
  running_investigations?: number | { could_not_check: string };
  this_shift?: { alerts_in?: number; alerts_closed?: number; could_not_check?: string; note?: string };
}

interface Handoff {
  id: string;
  shift_id: string;
  window_start: string;
  window_end: string;
  snapshot: Snapshot;
  notes: string;
  acked_by: string | null;
  acked_at: string | null;
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_CLASS: Record<string, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/20',
  high: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  low: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
  info: 'text-slate-400 bg-slate-500/10 border-slate-500/20',
};

function minuteLabel(minute: number): string {
  const h = String(Math.floor(minute / 60)).padStart(2, '0');
  const m = String(minute % 60).padStart(2, '0');
  return `${h}:${m}`;
}

export function ShiftsView() {
  const [shifts, setShifts] = useState<Shift[]>([]);
  const [handoffs, setHandoffs] = useState<Handoff[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notesDraft, setNotesDraft] = useState<Record<string, string>>({});

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [shiftsResp, handoffsResp] = await Promise.all([
        apiFetch('/api/v1/operating-model/shifts'),
        apiFetch('/api/v1/operating-model/handoffs'),
      ]);
      if (!shiftsResp.ok || !handoffsResp.ok) {
        throw new Error(`shifts ${shiftsResp.status}, handoffs ${handoffsResp.status}`);
      }
      setShifts(await shiftsResp.json());
      setHandoffs(await handoffsResp.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'request failed');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const generateNow = async () => {
    try {
      const resp = await apiFetch('/api/v1/operating-model/handoffs/generate', { method: 'POST' });
      if (!resp.ok) throw new Error(`generate ${resp.status}`);
      setHandoffs(await resp.json());
      toast.success('Due handoffs generated');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'generation failed');
    }
  };

  const ack = async (handoffId: string) => {
    try {
      const resp = await apiFetch(`/api/v1/operating-model/handoffs/${handoffId}/ack`, { method: 'POST' });
      if (!resp.ok) throw new Error(`ack ${resp.status}`);
      const updated: Handoff = await resp.json();
      setHandoffs((prev) => prev.map((h) => (h.id === updated.id ? updated : h)));
      toast.success('Handoff acknowledged');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'ack failed');
    }
  };

  const saveNotes = async (handoffId: string) => {
    try {
      const resp = await apiFetch(`/api/v1/operating-model/handoffs/${handoffId}/notes`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ notes: notesDraft[handoffId] ?? '' }),
      });
      if (!resp.ok) throw new Error(`notes ${resp.status}`);
      const updated: Handoff = await resp.json();
      setHandoffs((prev) => prev.map((h) => (h.id === updated.id ? updated : h)));
      toast.success('Notes saved');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'saving notes failed');
    }
  };

  if (loading) {
    return <div className="p-8 text-sm text-slate-400">Loading shift handoffs…</div>;
  }

  if (error) {
    return (
      <EmptyState
        icon={EmptyStateIcons.alert}
        title="Shift board unavailable"
        description={`The operating-model API could not be reached: ${error}. Nothing is shown rather than something invented.`}
      />
    );
  }

  if (shifts.length === 0) {
    return (
      <EmptyState
        icon={EmptyStateIcons.case}
        title="No shifts defined"
        description="Define your SOC shifts (name, timezone, hours) under Settings → Operating model. Handoffs are generated from your real open work at each shift end — nothing is invented."
      />
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">Shift handoffs</h2>
          <p className="text-sm text-slate-400">
            Snapshots of real open work at each shift end. Sections that could not be measured say so.
          </p>
        </div>
        <button
          type="button"
          onClick={generateNow}
          className="rounded-md border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-700"
        >
          Generate due handoffs
        </button>
      </div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {shifts.map((shift) => (
          <div key={shift.id} className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
            <div className="flex items-center justify-between">
              <span className="font-medium text-slate-100">{shift.name}</span>
              <span
                className={clsx(
                  'rounded px-2 py-0.5 text-xs',
                  shift.enabled ? 'bg-emerald-500/10 text-emerald-400' : 'bg-slate-600/20 text-slate-400',
                )}
              >
                {shift.enabled ? 'enabled' : 'disabled'}
              </span>
            </div>
            <p className="mt-1 text-sm text-slate-400">
              {minuteLabel(shift.start_minute)}–{minuteLabel(shift.end_minute)} · {shift.timezone}
            </p>
          </div>
        ))}
      </div>

      {handoffs.length === 0 ? (
        <EmptyState
          icon={EmptyStateIcons.search}
          title="No handoffs yet"
          description="A handoff appears when a shift occurrence ends (the sweep runs every few minutes), or generate due handoffs now."
        />
      ) : (
        <div className="space-y-4">
          {handoffs.map((handoff) => {
            const snapshot = handoff.snapshot ?? {};
            const severities = snapshot.open_alerts_by_severity ?? {};
            return (
              <div key={handoff.id} className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="text-sm text-slate-300">
                    <span className="font-medium text-slate-100">
                      {new Date(handoff.window_start).toLocaleString()} → {new Date(handoff.window_end).toLocaleString()}
                    </span>
                  </div>
                  {handoff.acked_at ? (
                    <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-xs text-emerald-400">
                      acknowledged {new Date(handoff.acked_at).toLocaleString()}
                    </span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => void ack(handoff.id)}
                      className="rounded-md bg-emerald-600 px-3 py-1 text-sm text-white hover:bg-emerald-500"
                    >
                      Acknowledge handoff
                    </button>
                  )}
                </div>

                <div className="mt-3 flex flex-wrap gap-2">
                  {SEVERITY_ORDER.map((sev) => {
                    const count = severities[sev];
                    if (count === undefined) return null;
                    return (
                      <span
                        key={sev}
                        className={clsx('rounded border px-2 py-0.5 text-xs', SEVERITY_CLASS[sev])}
                      >
                        {sev}: {String(count)} open
                      </span>
                    );
                  })}
                  {'could_not_check' in severities && (
                    <span className="rounded border border-slate-600 px-2 py-0.5 text-xs text-slate-400">
                      open alerts: could not check ({String(severities.could_not_check)})
                    </span>
                  )}
                  <span className="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-300">
                    pending approvals: {typeof snapshot.pending_approvals === 'number' ? snapshot.pending_approvals : 'could not check'}
                  </span>
                  <span className="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-300">
                    running investigations: {typeof snapshot.running_investigations === 'number' ? snapshot.running_investigations : 'could not check'}
                  </span>
                </div>

                {(snapshot.attention_cases?.length ?? 0) > 0 && (
                  <div className="mt-3">
                    <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-400">
                      Needs attention ({snapshot.attention_cases!.length})
                    </h4>
                    <ul className="mt-1 space-y-1">
                      {snapshot.attention_cases!.slice(0, 8).map((item, index) => (
                        <li key={item.case_number ?? index} className="text-sm text-slate-300">
                          {item.could_not_check ? (
                            <span className="text-slate-400">could not check ({item.could_not_check})</span>
                          ) : (
                            <>
                              <span className="font-mono text-slate-200">{item.case_number}</span> {item.title}
                              {item.unowned && <span className="ml-2 text-xs text-orange-400">unowned</span>}
                              {item.overdue && <span className="ml-2 text-xs text-red-400">overdue</span>}
                            </>
                          )}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                <div className="mt-3">
                  <label className="text-xs font-semibold uppercase tracking-wide text-slate-400" htmlFor={`notes-${handoff.id}`}>
                    Outgoing notes
                  </label>
                  <textarea
                    id={`notes-${handoff.id}`}
                    defaultValue={handoff.notes}
                    onChange={(event) => setNotesDraft((prev) => ({ ...prev, [handoff.id]: event.target.value }))}
                    rows={2}
                    className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 p-2 text-sm text-slate-200"
                    placeholder="What the next shift needs to know — the one human-authored field."
                  />
                  <button
                    type="button"
                    onClick={() => void saveNotes(handoff.id)}
                    className="mt-1 rounded-md border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:bg-slate-800"
                  >
                    Save notes
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default ShiftsView;
