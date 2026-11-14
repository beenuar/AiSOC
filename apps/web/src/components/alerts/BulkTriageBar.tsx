'use client';

/**
 * Bulk triage for the alert queue.
 *
 * Depth 9.3 (parity 5.6 remainder). The route half existed only as
 * `POST /alerts/bulk-close`, and there was no selection anywhere in the
 * console — an analyst clearing a morning queue clicked through it one alert
 * at a time. Closing is also one triage decision out of several: the same
 * analyst reassigns, re-severities and moves things to in progress.
 *
 * Three rules this bar follows, each one a defect this repository has
 * shipped before:
 *
 * - **No toast-only control.** Every button here performs a real write and
 *   the bar reports what the server said it did, by count. A control that
 *   shows a success toast and changes nothing is worse than no control.
 * - **The preflight is surfaced, not swallowed.** The route refuses a match
 *   larger than `max_count` with a 409 carrying the real figure and writes
 *   nothing. The bar shows that figure and asks again, rather than retrying
 *   with a bigger number on the analyst's behalf — which would turn a
 *   deliberate guard into a formality.
 * - **A failure says so.** There is no optimistic update and no local
 *   "saved" state: the selection clears only after the server confirms, and
 *   an error renders as an error.
 */

import { useCallback, useState } from 'react';
import clsx from 'clsx';

import { ApiError, caseDepthApi, type BulkTriageChange } from '@/lib/api';

/** Statuses the route accepts. `closed` is absent on purpose — see below. */
const STATUSES = ['new', 'open', 'in_progress', 'resolved', 'dismissed'] as const;
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;

export interface BulkTriageBarProps {
  selectedIds: string[];
  onClearSelection: () => void;
  /** Called after a successful write so the caller can revalidate its list. */
  onApplied: (updated: number) => void;
}

type Outcome =
  | { kind: 'idle' }
  | { kind: 'working' }
  | { kind: 'applied'; updated: number; summary: string }
  | { kind: 'preflight'; matched: number; message: string }
  | { kind: 'failed'; message: string };

export function BulkTriageBar({ selectedIds, onClearSelection, onApplied }: BulkTriageBarProps) {
  const [status, setStatus] = useState<string>('');
  const [severity, setSeverity] = useState<string>('');
  const [unassign, setUnassign] = useState(false);
  const [outcome, setOutcome] = useState<Outcome>({ kind: 'idle' });

  const nothingChosen = status === '' && severity === '' && !unassign;

  const apply = useCallback(
    async (maxCount: number) => {
      const change: BulkTriageChange = {};
      if (status) change.set_status = status;
      if (severity) change.set_severity = severity;
      if (unassign) change.unassign = true;

      setOutcome({ kind: 'working' });
      try {
        const result = await caseDepthApi.bulkTriage(selectedIds, change, maxCount, 'bulk triage from the console');
        const parts = Object.entries(result.changes).map(([k, v]) => `${k}=${String(v)}`);
        setOutcome({
          kind: 'applied',
          updated: result.updated_count,
          summary: parts.join(', ') || 'no change',
        });
        onApplied(result.updated_count);
        onClearSelection();
      } catch (err) {
        if (err instanceof ApiError && err.status === 409) {
          // The server counted more rows than the caller said it expected and
          // wrote nothing. Show the real figure and let the analyst decide;
          // retrying automatically with a larger number would make the guard
          // a formality.
          const matched = Number(/(\d+) alert\(s\) match/.exec(err.body)?.[1] ?? selectedIds.length);
          setOutcome({ kind: 'preflight', matched, message: err.body || err.message });
          return;
        }
        setOutcome({
          kind: 'failed',
          message: err instanceof Error ? err.message : 'The bulk triage request failed.',
        });
      }
    },
    [onApplied, onClearSelection, selectedIds, severity, status, unassign],
  );

  if (selectedIds.length === 0) return null;

  return (
    <div
      className="bg-blue-500/10 border border-blue-500/30 rounded-xl px-4 py-3 space-y-2"
      role="region"
      aria-label="Bulk triage"
    >
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-sm text-blue-200 font-medium">
          {selectedIds.length} selected
        </span>

        <label className="text-xs text-gray-400">
          Status
          <select
            aria-label="Set status"
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="ml-2 bg-gray-900 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
          >
            <option value="">leave as is</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>

        <label className="text-xs text-gray-400">
          Severity
          <select
            aria-label="Set severity"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="ml-2 bg-gray-900 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
          >
            <option value="">leave as is</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>

        <label className="text-xs text-gray-400 flex items-center gap-1.5">
          <input
            type="checkbox"
            aria-label="Unassign"
            checked={unassign}
            onChange={(e) => setUnassign(e.target.checked)}
            className="accent-blue-500"
          />
          Unassign
        </label>

        <button
          type="button"
          disabled={nothingChosen || outcome.kind === 'working'}
          onClick={() => void apply(selectedIds.length)}
          className={clsx(
            'text-xs px-3 py-1.5 rounded-md border transition-colors',
            nothingChosen || outcome.kind === 'working'
              ? 'border-gray-700 bg-gray-800 text-gray-500 cursor-not-allowed'
              : 'border-blue-500/40 bg-blue-500/20 text-blue-200 hover:bg-blue-500/30',
          )}
        >
          {outcome.kind === 'working' ? 'Applying…' : 'Apply'}
        </button>

        <button
          type="button"
          onClick={onClearSelection}
          className="text-xs px-3 py-1.5 rounded-md border border-gray-700 text-gray-400 hover:text-gray-200"
        >
          Clear
        </button>

        {/*
          Closing in bulk deliberately is not here. It has its own route that
          snapshots every affected row into a named backup table first, and a
          second path to the same destination with weaker guarantees is how
          the weaker one becomes the one everybody uses.
        */}
        <span className="text-[11px] text-gray-500 ml-auto">
          To close in bulk, use the noise sweep — it snapshots every row first.
        </span>
      </div>

      {outcome.kind === 'applied' && (
        <p className="text-xs text-emerald-300" role="status">
          Updated {outcome.updated} alert{outcome.updated === 1 ? '' : 's'} ({outcome.summary}).
        </p>
      )}
      {outcome.kind === 'preflight' && (
        <div className="text-xs text-amber-300 space-y-1" role="status">
          <p>
            {outcome.matched} alert{outcome.matched === 1 ? '' : 's'} match and nothing was changed.
          </p>
          <button
            type="button"
            onClick={() => void apply(outcome.matched)}
            className="px-2 py-1 rounded border border-amber-400/40 bg-amber-400/10 hover:bg-amber-400/20"
          >
            Apply to all {outcome.matched}
          </button>
        </div>
      )}
      {outcome.kind === 'failed' && (
        <p className="text-xs text-red-400" role="alert">
          {outcome.message}
        </p>
      )}
    </div>
  );
}
