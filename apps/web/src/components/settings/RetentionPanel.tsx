'use client';

/**
 * Per-tenant retention windows.
 *
 * Wave 2, Phase 9.5.
 *
 * `/api/v1/data-lifecycle/retention` has had GET and PUT since migration 049
 * and no console binding at all, so the only way a tenant could set their own
 * retention was a curl command — on a surface that governs deletion of
 * evidence.
 *
 * The honesty problem this panel exists to avoid
 * ----------------------------------------------
 * `RETENTION_WORKER_ENABLED` defaults to **false**, and the worker has a
 * dry-run mode on top of that. A page that rendered three editable numbers
 * and a Save button would tell an operator their raw events are deleted after
 * 90 days when, on a default deployment, nothing deletes at all. The windows
 * are still meaningful — compliance evidence reads them — but they are a
 * *stated* policy, not an enforced one, and those are different claims. The
 * route now reports the worker's state and this panel leads with it.
 *
 * The other direction matters too: a failed read must not render the
 * defaults. 90/365/730 look exactly like a real answer, and an operator who
 * believes those are their windows will not set the ones they need.
 */

import { useCallback, useEffect, useState } from 'react';
import toast from 'react-hot-toast';

import { retentionApi, type RetentionPolicy } from '@/lib/api';
import { EmptyState } from '@/components/ui/EmptyState';

function inputClass() {
  return 'w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:border-blue-500 focus:outline-none';
}

function describeError(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}

/** Matches the route's bounds, so an out-of-range value is named before the round trip. */
const MIN_DAYS = 1;
const MAX_DAYS = 3650;

interface Field {
  key: keyof Pick<RetentionPolicy, 'raw_events_days' | 'alerts_days' | 'audit_days'>;
  label: string;
  help: string;
}

const FIELDS: Field[] = [
  {
    key: 'raw_events_days',
    label: 'Raw events',
    help: 'Normalised telemetry in the event lake. The largest store, and the one retention costs the most to extend.',
  },
  {
    key: 'alerts_days',
    label: 'Alerts',
    help: 'Alerts and their triage records in Postgres.',
  },
  {
    key: 'audit_days',
    label: 'Audit log',
    help: 'Administrative and agent-decision history. Usually the longest window, because an auditor asks for it after an incident rather than during one.',
  },
];

export function RetentionPanel() {
  const [policy, setPolicy] = useState<RetentionPolicy | null>(null);
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const value = await retentionApi.get();
      setPolicy(value);
      setDraft({
        raw_events_days: String(value.raw_events_days),
        alerts_days: String(value.alerts_days),
        audit_days: String(value.audit_days),
      });
      setLoadError(null);
    } catch (err) {
      // Deliberately no fallback policy: the defaults are a plausible answer
      // and rendering them over a failed read is how an operator ends up
      // believing in a window nobody set.
      setPolicy(null);
      setDraft({});
      setLoadError(describeError(err, 'Could not load the retention policy.'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async () => {
    const body: Partial<RetentionPolicy> = {};
    for (const field of FIELDS) {
      const raw = (draft[field.key] ?? '').trim();
      const days = Number(raw);
      if (!Number.isInteger(days) || days < MIN_DAYS || days > MAX_DAYS) {
        toast.error(`${field.label} must be a whole number of days between ${MIN_DAYS} and ${MAX_DAYS}`);
        return;
      }
      body[field.key] = days;
    }

    setBusy(true);
    try {
      const saved = await retentionApi.update(body);
      setPolicy(saved);
      setDraft({
        raw_events_days: String(saved.raw_events_days),
        alerts_days: String(saved.alerts_days),
        audit_days: String(saved.audit_days),
      });
      toast.success(
        saved.purge_worker_enabled && !saved.purge_worker_dry_run
          ? 'Retention saved. The purge worker applies it on its next pass.'
          : 'Retention saved as a stated policy. Nothing is deleted until the purge worker is enabled on this deployment.',
      );
    } catch (err) {
      toast.error(describeError(err, 'Could not save the retention policy'));
    } finally {
      setBusy(false);
    }
  };

  const enforcing = policy !== null && policy.purge_worker_enabled && !policy.purge_worker_dry_run;

  return (
    <div data-testid="retention-panel">
      <div className="border-b border-gray-800 px-6 py-4">
        <h2 className="text-base font-semibold text-gray-100">Retention</h2>
        <p className="mt-1 text-sm text-gray-500">
          How long this tenant keeps each class of data. Compliance evidence
          reads these windows, so they are worth setting even where deletion is
          not switched on.
        </p>
      </div>

      <div className="space-y-5 px-6 py-5">
        {loadError ? (
          <EmptyState title="Could not load the retention policy" description={loadError} />
        ) : loading ? (
          <EmptyState title="Loading retention policy…" description="" />
        ) : policy === null ? (
          <EmptyState
            title="Could not load the retention policy"
            description="The server did not return a policy."
          />
        ) : (
          <>
            <div
              data-testid="retention-enforcement"
              className={
                enforcing
                  ? 'rounded-lg border border-emerald-500/40 bg-emerald-500/5 p-4 text-sm text-emerald-200'
                  : 'rounded-lg border border-amber-500/40 bg-amber-500/5 p-4 text-sm text-amber-200'
              }
            >
              {enforcing ? (
                <>
                  The purge worker is enabled on this deployment. Data older
                  than the windows below is deleted on its next pass.
                </>
              ) : policy.purge_worker_enabled ? (
                <>
                  The purge worker is running in <strong>dry-run</strong> mode:
                  it reports what it would delete and deletes nothing. These
                  windows are a stated policy until dry-run is turned off.
                </>
              ) : (
                <>
                  The purge worker is <strong>not enabled</strong> on this
                  deployment, so nothing is deleted on these windows yet. They
                  are still read as your stated retention policy by compliance
                  evidence. An operator enables deletion with{' '}
                  <code className="rounded bg-gray-950 px-1 py-0.5 text-xs">
                    RETENTION_WORKER_ENABLED
                  </code>
                  .
                </>
              )}
            </div>

            <div className="space-y-4">
              {FIELDS.map((field) => (
                <label key={field.key} className="block text-sm">
                  <span className="mb-1 block text-gray-400">{field.label} (days)</span>
                  <input
                    className={inputClass()}
                    value={draft[field.key] ?? ''}
                    onChange={(e) => setDraft((d) => ({ ...d, [field.key]: e.target.value }))}
                    aria-label={`${field.label} retention in days`}
                    inputMode="numeric"
                  />
                  <span className="mt-1 block text-xs text-gray-500">{field.help}</span>
                </label>
              ))}
            </div>

            <button
              type="button"
              onClick={() => void save()}
              disabled={busy}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
            >
              {busy ? 'Working…' : 'Save retention policy'}
            </button>
          </>
        )}
      </div>
    </div>
  );
}
