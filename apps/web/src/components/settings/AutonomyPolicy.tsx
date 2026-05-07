'use client';

/**
 * Autonomy policy admin UI (Tier 1.3).
 *
 * Renders the configurable per-action confidence guardrails — three tiers per
 * agent action:
 *
 *   confidence ≥ auto         → agent executes silently
 *   review ≤ confidence < auto → agent queues for an analyst
 *   escalation ≤ c < review   → agent pages on-call
 *   confidence < escalation   → agent refuses
 *
 * Backed by the FastAPI endpoints in
 * ``services/api/app/api/v1/endpoints/autonomy_policy.py`` and the agent-side
 * loader in ``services/agents/app/policy/guardrails.py`` (which reads
 * ``services/agents/config/autonomy_policy.yaml`` defaults and overlays
 * tenant-specific DB overrides).
 *
 * Requires ``settings:read`` to view and ``settings:write`` to mutate. Both
 * permissions are enforced server-side; the UI gracefully degrades to read-only
 * when the API rejects writes.
 */

import { useMemo, useState } from 'react';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { motion, AnimatePresence } from 'framer-motion';
import toast from 'react-hot-toast';
import {
  autonomyPolicyApi,
  type AutonomyActionPolicy,
  type AutonomyBlastRadius,
  type AutonomyPolicyResponse,
  type AutonomyThresholdTriple,
} from '@/lib/api';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorState } from '@/components/ui/ErrorState';
import { EmptyState } from '@/components/ui/EmptyState';

// ─── Helpers ──────────────────────────────────────────────────────────────────

const BLAST_TONE: Record<AutonomyBlastRadius, string> = {
  read: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30',
  low: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30',
  medium: 'bg-amber-500/10 text-amber-300 ring-amber-500/30',
  high: 'bg-orange-500/10 text-orange-300 ring-orange-500/30',
  critical: 'bg-red-500/10 text-red-300 ring-red-500/30',
  custom: 'bg-blue-500/10 text-blue-300 ring-blue-500/30',
  unknown: 'bg-gray-500/10 text-gray-300 ring-gray-500/30',
};

function clamp(n: number, lo = 0, hi = 1): number {
  if (Number.isNaN(n)) return lo;
  return Math.min(hi, Math.max(lo, n));
}

function formatPct(n: number): string {
  return `${(n * 100).toFixed(0)}%`;
}

function thresholdsEqual(
  a: AutonomyThresholdTriple,
  b: AutonomyThresholdTriple,
): boolean {
  return (
    Math.abs(a.auto - b.auto) < 1e-9 &&
    Math.abs(a.review - b.review) < 1e-9 &&
    Math.abs(a.escalation - b.escalation) < 1e-9
  );
}

function validate(
  draft: AutonomyThresholdTriple,
): { ok: true } | { ok: false; reason: string } {
  if (draft.auto < 0 || draft.auto > 1)
    return { ok: false, reason: 'auto must be between 0 and 1' };
  if (draft.review < 0 || draft.review > 1)
    return { ok: false, reason: 'review must be between 0 and 1' };
  if (draft.escalation < 0 || draft.escalation > 1)
    return { ok: false, reason: 'escalation must be between 0 and 1' };
  if (draft.review > draft.auto)
    return { ok: false, reason: 'review must be ≤ auto' };
  if (draft.escalation > draft.review)
    return { ok: false, reason: 'escalation must be ≤ review' };
  return { ok: true };
}

// ─── Public component ─────────────────────────────────────────────────────────

export function AutonomyPolicyPanel() {
  const { data, error, isLoading, mutate } = useSWR<AutonomyPolicyResponse>(
    'settings:autonomy-policy',
    () => autonomyPolicyApi.list(),
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );

  const actions = data?.actions ?? [];

  return (
    <div>
      <PanelHeader
        title="Autonomy guardrails"
        description="Per-action confidence thresholds. The agent uses these to decide whether to act silently, queue for analyst review, page on-call, or refuse."
      />

      <div className="space-y-5 px-6 py-5">
        {/* Legend */}
        <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-4 text-xs text-gray-400">
          <p className="font-medium text-gray-300">How tiers map</p>
          <ul className="mt-2 space-y-1">
            <li>
              <Pill tone="emerald">≥ auto</Pill> agent executes the action
              silently
            </li>
            <li>
              <Pill tone="amber">review … auto</Pill> queues for an analyst to
              approve
            </li>
            <li>
              <Pill tone="orange">escalation … review</Pill> pages on-call
            </li>
            <li>
              <Pill tone="red">&lt; escalation</Pill> agent refuses
            </li>
          </ul>
          <p className="mt-3 text-[11px] text-gray-500">
            Defaults are loaded from{' '}
            <code className="font-mono text-gray-400">
              services/agents/config/autonomy_policy.yaml
            </code>
            . Tenant overrides written here are stored in{' '}
            <code className="font-mono text-gray-400">
              aisoc_autonomy_thresholds
            </code>{' '}
            and read on the next investigation.
          </p>
        </div>

        {/* List */}
        {isLoading && !data ? (
          <div className="space-y-3">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-32 w-full rounded-lg" />
            ))}
          </div>
        ) : error ? (
          <ErrorState
            title="Could not load autonomy policy"
            error={error}
            onRetry={() => mutate()}
          />
        ) : actions.length === 0 ? (
          <EmptyState
            title="No actions registered"
            description="No agent actions are registered for this tenant yet. Once the agent runs, this view will show every action it has attempted."
          />
        ) : (
          <ul className="space-y-3">
            {actions.map((a) => (
              <ActionRow
                key={a.action}
                action={a}
                onSaved={() => mutate()}
                onReset={() => mutate()}
              />
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

// ─── Per-row editor ───────────────────────────────────────────────────────────

function ActionRow({
  action,
  onSaved,
  onReset,
}: {
  action: AutonomyActionPolicy;
  onSaved: () => void;
  onReset: () => void;
}) {
  const [draft, setDraft] = useState<AutonomyThresholdTriple>(action.thresholds);
  const [reason, setReason] = useState('');
  const [saving, setSaving] = useState(false);
  const [resetting, setResetting] = useState(false);

  // Re-sync local state when SWR refreshes the row from the server.
  // We use a stable identity key so React re-creates the component on tenant
  // switch but a refresh that yields the same thresholds is a no-op.
  const remoteFingerprint = `${action.thresholds.auto}:${action.thresholds.review}:${action.thresholds.escalation}`;
  useMemo(() => {
    setDraft(action.thresholds);
  }, [remoteFingerprint]); // eslint-disable-line react-hooks/exhaustive-deps

  const dirty = !thresholdsEqual(draft, action.thresholds);
  const validation = validate(draft);
  const canSave = dirty && validation.ok && !saving;

  const onSave = async () => {
    if (!validation.ok) {
      toast.error(validation.reason);
      return;
    }
    setSaving(true);
    try {
      await autonomyPolicyApi.update(action.action, {
        auto: draft.auto,
        review: draft.review,
        escalation: draft.escalation,
        reason: reason.trim() || null,
      });
      toast.success(`${action.action} thresholds saved`);
      setReason('');
      onSaved();
    } catch (err) {
      const msg =
        err instanceof Error ? err.message : 'Could not save thresholds';
      toast.error(msg);
    } finally {
      setSaving(false);
    }
  };

  const onResetClick = async () => {
    if (!action.overridden) return;
    setResetting(true);
    try {
      await autonomyPolicyApi.reset(action.action);
      toast.success(`${action.action} reverted to default`);
      setReason('');
      onReset();
    } catch (err) {
      const msg =
        err instanceof Error ? err.message : 'Could not reset thresholds';
      toast.error(msg);
    } finally {
      setResetting(false);
    }
  };

  const overrideTag = action.overridden ? (
    <span className="rounded-full bg-blue-500/10 px-2 py-0.5 text-[11px] font-medium text-blue-300 ring-1 ring-blue-500/30">
      tenant override
    </span>
  ) : (
    <span className="rounded-full bg-gray-500/10 px-2 py-0.5 text-[11px] text-gray-400 ring-1 ring-gray-500/30">
      default
    </span>
  );

  return (
    <li className="rounded-lg border border-gray-800 bg-gray-950/40 p-4 transition-colors hover:border-gray-700">
      <div className="flex flex-col gap-1 border-b border-gray-800 pb-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="font-mono text-sm font-semibold text-gray-100">
              {action.action}
            </h3>
            <span
              className={clsx(
                'rounded-full px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset',
                BLAST_TONE[action.blast_radius] ?? BLAST_TONE.unknown,
              )}
            >
              blast: {action.blast_radius}
            </span>
            {overrideTag}
          </div>
          {action.last_updated_at ? (
            <p className="mt-1 text-[11px] text-gray-500">
              Last updated{' '}
              {new Date(action.last_updated_at).toLocaleString(undefined, {
                dateStyle: 'medium',
                timeStyle: 'short',
              })}
              {action.last_updated_by ? ` by ${action.last_updated_by}` : ''}
              {action.last_reason ? ` — “${action.last_reason}”` : ''}
            </p>
          ) : null}
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {action.overridden ? (
            <button
              type="button"
              onClick={onResetClick}
              disabled={resetting}
              className={clsx(
                'rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs text-gray-200',
                resetting
                  ? 'cursor-not-allowed opacity-60'
                  : 'hover:bg-gray-800',
              )}
            >
              {resetting ? 'Resetting…' : 'Reset to default'}
            </button>
          ) : null}
        </div>
      </div>

      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        <ThresholdInput
          label="Escalation"
          tone="red"
          help="Below this confidence the agent refuses."
          value={draft.escalation}
          remote={action.thresholds.escalation}
          defaultValue={action.default_thresholds.escalation}
          onChange={(v) => setDraft({ ...draft, escalation: clamp(v) })}
        />
        <ThresholdInput
          label="Review"
          tone="amber"
          help="At or above this, the agent queues for analyst review."
          value={draft.review}
          remote={action.thresholds.review}
          defaultValue={action.default_thresholds.review}
          onChange={(v) => setDraft({ ...draft, review: clamp(v) })}
        />
        <ThresholdInput
          label="Auto"
          tone="emerald"
          help="At or above this, the agent executes silently."
          value={draft.auto}
          remote={action.thresholds.auto}
          defaultValue={action.default_thresholds.auto}
          onChange={(v) => setDraft({ ...draft, auto: clamp(v) })}
        />
      </div>

      {/* Visual band */}
      <ThresholdBand draft={draft} />

      {/* Validation + reason + save */}
      <AnimatePresence>
        {dirty || !validation.ok ? (
          <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            className="mt-3 flex flex-col gap-2 rounded-lg border border-gray-800 bg-gray-950/40 p-3 sm:flex-row sm:items-end"
          >
            <label className="flex flex-1 flex-col gap-1.5">
              <span className="text-xs font-medium text-gray-300">
                Reason{' '}
                <span className="text-gray-500">
                  (optional — appears in audit log)
                </span>
              </span>
              <input
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder='e.g. "Lower auto threshold during incident response window"'
                className={clsx(
                  'w-full rounded-lg border border-gray-700 bg-gray-950/60 px-3 py-2 text-sm text-gray-100',
                  'placeholder:text-gray-600 focus:border-blue-500/60 focus:outline-none focus:ring-1 focus:ring-blue-500/40',
                )}
                maxLength={500}
              />
            </label>
            <div className="flex shrink-0 gap-2">
              <button
                type="button"
                onClick={() => {
                  setDraft(action.thresholds);
                  setReason('');
                }}
                className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-200 hover:bg-gray-800"
              >
                Discard
              </button>
              <button
                type="button"
                onClick={onSave}
                disabled={!canSave}
                className={clsx(
                  'rounded-lg px-4 py-2 text-sm font-medium transition-colors',
                  canSave
                    ? 'bg-blue-600 text-white hover:bg-blue-500'
                    : 'cursor-not-allowed bg-gray-800 text-gray-500',
                )}
              >
                {saving ? 'Saving…' : 'Save thresholds'}
              </button>
            </div>
          </motion.div>
        ) : null}
      </AnimatePresence>

      {!validation.ok ? (
        <p className="mt-2 text-xs text-red-300">{validation.reason}</p>
      ) : null}
    </li>
  );
}

// ─── Atomic UI ────────────────────────────────────────────────────────────────

function ThresholdInput({
  label,
  tone,
  help,
  value,
  remote,
  defaultValue,
  onChange,
}: {
  label: string;
  tone: 'red' | 'amber' | 'emerald';
  help: string;
  value: number;
  remote: number;
  defaultValue: number;
  onChange: (next: number) => void;
}) {
  const tones: Record<typeof tone, string> = {
    red: 'text-red-300',
    amber: 'text-amber-300',
    emerald: 'text-emerald-300',
  };
  const dirty = Math.abs(value - remote) > 1e-9;

  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950/60 p-3">
      <div className="flex items-center justify-between">
        <span className={clsx('text-xs font-semibold', tones[tone])}>
          {label}
        </span>
        <span
          className={clsx(
            'font-mono text-sm tabular-nums',
            dirty ? 'text-blue-300' : 'text-gray-200',
          )}
        >
          {formatPct(value)}
        </span>
      </div>
      <input
        type="range"
        min={0}
        max={1}
        step={0.01}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="mt-2 w-full accent-blue-500"
        aria-label={`${label} threshold`}
      />
      <p className="mt-1 text-[11px] text-gray-500">{help}</p>
      <p className="mt-1 text-[10px] text-gray-600">
        default {formatPct(defaultValue)}
      </p>
    </div>
  );
}

function ThresholdBand({ draft }: { draft: AutonomyThresholdTriple }) {
  // Stack three colored regions on a 0–100% horizontal bar so admins can see
  // the decision regions at a glance.
  const escalationPct = draft.escalation * 100;
  const reviewPct = draft.review * 100;
  const autoPct = draft.auto * 100;

  return (
    <div className="mt-3" aria-hidden>
      <div className="relative h-2.5 w-full overflow-hidden rounded-full bg-gray-900 ring-1 ring-gray-800">
        {/* refuse */}
        <div
          className="absolute inset-y-0 bg-red-500/30"
          style={{ left: 0, width: `${escalationPct}%` }}
        />
        {/* escalate */}
        <div
          className="absolute inset-y-0 bg-orange-500/30"
          style={{
            left: `${escalationPct}%`,
            width: `${Math.max(0, reviewPct - escalationPct)}%`,
          }}
        />
        {/* review */}
        <div
          className="absolute inset-y-0 bg-amber-500/30"
          style={{
            left: `${reviewPct}%`,
            width: `${Math.max(0, autoPct - reviewPct)}%`,
          }}
        />
        {/* auto */}
        <div
          className="absolute inset-y-0 bg-emerald-500/40"
          style={{ left: `${autoPct}%`, right: 0 }}
        />
      </div>
      <div className="mt-1 flex justify-between font-mono text-[10px] text-gray-500">
        <span>0%</span>
        <span>50%</span>
        <span>100%</span>
      </div>
    </div>
  );
}

function Pill({
  tone,
  children,
}: {
  tone: 'emerald' | 'amber' | 'orange' | 'red';
  children: React.ReactNode;
}) {
  const tones: Record<typeof tone, string> = {
    emerald: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30',
    amber: 'bg-amber-500/10 text-amber-300 ring-amber-500/30',
    orange: 'bg-orange-500/10 text-orange-300 ring-orange-500/30',
    red: 'bg-red-500/10 text-red-300 ring-red-500/30',
  };
  return (
    <span
      className={clsx(
        'mr-1 rounded-full px-2 py-0.5 text-[10px] font-medium ring-1 ring-inset',
        tones[tone],
      )}
    >
      {children}
    </span>
  );
}

// Local mirror of the SettingsView ``PanelHeader`` so this component is
// self-contained and can be exported / re-used in other admin surfaces.
function PanelHeader({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="flex flex-col gap-3 border-b border-gray-800 px-6 py-5 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <h2 className="text-lg font-semibold text-gray-100">{title}</h2>
        <p className="mt-1 max-w-xl text-sm text-gray-500">{description}</p>
      </div>
    </div>
  );
}

export default AutonomyPolicyPanel;
