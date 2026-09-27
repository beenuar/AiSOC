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
 *
 * Gap-closure Phase 2.2 added the second half. The posture above describes
 * what the tenant has *configured*; `TrackRecord` describes what the agent has
 * *earned*, measured against the same analysts' own closures. Both belong on
 * one card because the question they answer together is the only one worth
 * asking: is this posture justified. A configured posture on its own says
 * nothing about whether the agent deserves it, and the numbers on their own
 * say nothing about whether anyone has acted on them.
 *
 * The track record is optional. A deployment that has never run shadow mode
 * has no measurement, and the card says that rather than rendering zeroes,
 * which would read as an agent that agrees with nobody.
 */

import { clsx } from 'clsx';
import type {
  AgreementResponse,
  AutonomyActionPolicy,
  AutonomyBlastRadius,
} from '@/lib/api';

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

/** A rate as a percentage, or the words that mean there was no denominator. */
export function formatRate(value: number | null | undefined): string {
  return value === null || value === undefined ? 'not measured' : `${(value * 100).toFixed(1)}%`;
}

export interface TrackRecordSummary {
  /** Whether enough has been measured to say anything at all. */
  measured: boolean;
  agreement: number | null;
  maliciousRecall: number | null;
  abstention: number | null;
  answered: number;
  labelled: number;
  maliciousSupport: number;
  /** Progress toward the sample floors, as counts rather than a percentage. */
  decisionsNeeded: number;
  maliciousNeeded: number;
  windowDays: number;
  /** The trailing slice, which is where a gradual decline shows first. */
  recentAgreement: number | null;
  recentAnswered: number;
}

/**
 * Reduce the agreement response to what this card shows.
 *
 * Pure, and separate from the component, for the same reason
 * `computeScorecard` is: the interesting decisions here are about what counts
 * as measured and what a missing denominator renders as, and those are worth
 * asserting directly rather than through a DOM query.
 */
export function summariseTrackRecord(agreement: AgreementResponse | null | undefined): TrackRecordSummary | null {
  if (!agreement) return null;
  const { window: w, recent, thresholds } = agreement;
  return {
    // A tenant with closures but no *labelled* ones has been measured and has
    // nothing to show for it, which is a real state and a different one from
    // never having started.
    measured: w.resolved > 0,
    agreement: w.agreement_rate,
    maliciousRecall: w.malicious_recall,
    abstention: w.abstention_rate,
    answered: w.answered,
    labelled: w.labelled,
    maliciousSupport: w.malicious_support,
    decisionsNeeded: thresholds.min_decisions,
    maliciousNeeded: thresholds.min_malicious,
    windowDays: thresholds.window_days,
    recentAgreement: recent.agreement_rate,
    recentAnswered: recent.answered,
  };
}

export function AutonomyScorecard({
  actions,
  agreement,
}: {
  actions: AutonomyActionPolicy[];
  agreement?: AgreementResponse | null;
}) {
  const card = computeScorecard(actions);
  const isCopilot = card.posture === 'copilot';
  const record = summariseTrackRecord(agreement);

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

      <TrackRecord record={record} />
    </div>
  );
}

function TrackRecord({ record }: { record: TrackRecordSummary | null }) {
  if (record === null || !record.measured) {
    return (
      <p className="mt-4 border-t border-gray-800 pt-3 text-xs text-gray-500">
        No measured track record yet. Enable shadow mode for an alert class and the agent&apos;s
        verdicts will be scored against your analysts&apos; own closures, here and in the source SIEM.
      </p>
    );
  }

  return (
    <div className="mt-4 border-t border-gray-800 pt-3">
      <p className="text-[11px] uppercase tracking-wide text-gray-500">
        Measured track record, last {record.windowDays} days
      </p>
      <dl className="mt-2 flex flex-wrap gap-x-6 gap-y-2">
        <Stat
          label="Agreement"
          value={formatRate(record.agreement)}
          hint={`${record.answered} answered`}
        />
        <Stat
          label="Recall on malicious"
          value={formatRate(record.maliciousRecall)}
          hint={`${record.maliciousSupport} true positives`}
        />
        <Stat label="Abstained" value={formatRate(record.abstention)} hint={`${record.labelled} labelled`} />
        <Stat
          label="Sample"
          /* Counts, not a percentage. On a card where every other figure is a
             percentage, "47%" would be read as a fifth accuracy number. */
          value={`${record.labelled} / ${record.decisionsNeeded}`}
          hint={`${record.maliciousSupport} / ${record.maliciousNeeded} malicious`}
        />
      </dl>
      <p className="mt-2 text-[11px] text-gray-500">
        Most recent {record.recentAnswered} answered: {formatRate(record.recentAgreement)} agreement.
        Shown apart from the window because a decline that began this week is still
        absorbed by a month of earlier agreement.
      </p>
    </div>
  );
}

function Stat({
  label,
  value,
  hint,
}: {
  label: string;
  value: number | string;
  hint?: string;
}) {
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wide text-gray-500">{label}</dt>
      <dd className="font-mono text-lg tabular-nums text-gray-100">{value}</dd>
      {/* Every rate on this card travels with the count it was computed over.
          100% over four answers is not the claim 100% over four hundred is. */}
      {hint ? <p className="text-[11px] text-gray-500">{hint}</p> : null}
    </div>
  );
}

export default AutonomyScorecard;
