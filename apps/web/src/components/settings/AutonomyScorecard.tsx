'use client';

/**
 * Autonomy posture scorecard (Phase C3).
 *
 * Sits atop the per-action guardrail editor (`AutonomyPolicy.tsx`) and answers
 * the question a CISO actually asks: "how autonomous is my SOC right now, and
 * where does a human still sign off?" It computes an honest posture from the
 * *configured* per-action policy (not fabricated runtime stats):
 *
 *   - **Posture** — Copilot (the safe default: high/critical-blast actions
 *     always require a human) vs Autopilot (at least one high-blast action is
 *     configured to auto-execute). Data-class scoping is expressed through the
 *     per-action blast radius, so the scorecard groups by blast radius.
 *   - **Distribution** — how many actions auto-execute, queue for review, or
 *     always gate on a human, bucketed by blast radius.
 *
 * The compute is a pure function so it's unit-tested directly; the component is
 * a thin presentational shell.
 */

import { clsx } from 'clsx';
import type { AutonomyActionPolicy, AutonomyBlastRadius } from '@/lib/api';

export type AutonomyPosture = 'copilot' | 'autopilot';

export interface AutonomyScorecardData {
  posture: AutonomyPosture;
  total: number;
  overridden: number;
  /** Actions whose `auto` threshold is reachable (auto-execute is configured). */
  autoExecuting: number;
  /** High/critical blast actions configured to auto-execute (the autopilot signal). */
  highBlastAuto: number;
  byBlast: Record<AutonomyBlastRadius, number>;
}

const HIGH_BLAST: ReadonlySet<AutonomyBlastRadius> = new Set(['high', 'critical']);

// An action "auto-executes" when its `auto` threshold is below 1.0 — i.e. some
// confidence level lets the agent act without a human. auto == 1.0 means
// "never auto" (always at least review), the safe copilot setting.
function autoExecutes(a: AutonomyActionPolicy): boolean {
  return a.thresholds.auto < 1;
}

export function computeScorecard(actions: AutonomyActionPolicy[]): AutonomyScorecardData {
  const byBlast: Record<AutonomyBlastRadius, number> = {
    read: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
    custom: 0,
    unknown: 0,
  };
  let overridden = 0;
  let autoExecuting = 0;
  let highBlastAuto = 0;

  for (const a of actions) {
    byBlast[a.blast_radius] = (byBlast[a.blast_radius] ?? 0) + 1;
    if (a.overridden) overridden += 1;
    if (autoExecutes(a)) {
      autoExecuting += 1;
      if (HIGH_BLAST.has(a.blast_radius)) highBlastAuto += 1;
    }
  }

  return {
    // Copilot is the default; only a high/critical-blast action configured to
    // auto-execute flips the posture to autopilot.
    posture: highBlastAuto > 0 ? 'autopilot' : 'copilot',
    total: actions.length,
    overridden,
    autoExecuting,
    highBlastAuto,
    byBlast,
  };
}

export function AutonomyScorecard({ actions }: { actions: AutonomyActionPolicy[] }) {
  const card = computeScorecard(actions);
  const isCopilot = card.posture === 'copilot';

  return (
    <div
      className="rounded-lg border border-gray-800 bg-gray-950/40 p-4"
      role="group"
      aria-label="Autonomy posture scorecard"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-xs uppercase tracking-wide text-gray-500">Current posture</p>
          <div className="mt-1 flex items-center gap-2">
            <span
              className={clsx(
                'rounded-full px-3 py-1 text-sm font-semibold ring-1 ring-inset',
                isCopilot
                  ? 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30'
                  : 'bg-amber-500/10 text-amber-300 ring-amber-500/30',
              )}
            >
              {isCopilot ? 'Copilot' : 'Autopilot'}
            </span>
            <span className="text-xs text-gray-400">
              {isCopilot
                ? 'High- and critical-blast actions always require a human.'
                : `${card.highBlastAuto} high-blast action${card.highBlastAuto === 1 ? '' : 's'} auto-execute — review carefully.`}
            </span>
          </div>
        </div>
        <dl className="flex gap-4 text-right">
          <Stat label="Actions" value={card.total} />
          <Stat label="Auto-exec" value={card.autoExecuting} />
          <Stat label="Overridden" value={card.overridden} />
        </dl>
      </div>

      <div className="mt-4 flex flex-wrap gap-2" aria-label="Actions by blast radius">
        {(Object.entries(card.byBlast) as [AutonomyBlastRadius, number][])
          .filter(([, n]) => n > 0)
          .map(([blast, n]) => (
            <span
              key={blast}
              className="rounded-full border border-gray-700 bg-gray-900 px-2.5 py-1 text-[11px] text-gray-300"
            >
              {blast}: <span className="font-mono text-gray-100">{n}</span>
            </span>
          ))}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wide text-gray-500">{label}</dt>
      <dd className="font-mono text-lg tabular-nums text-gray-100">{value}</dd>
    </div>
  );
}

export default AutonomyScorecard;
