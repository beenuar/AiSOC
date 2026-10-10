'use client';

/**
 * Autonomy posture scorecard (Phase C3).
 *
 * Sits atop the per-action guardrail editor (`AutonomyPolicy.tsx`) and answers
 * the question a CISO actually asks: "how autonomous is my SOC right now, and
 * where does a human still sign off?"
 *
 *   - **Posture** — Copilot (the safe default: high/critical-blast actions
 *     always require a human) vs Autopilot (at least one high-blast action
 *     really does reach a vendor unattended). Data-class scoping is expressed
 *     through the per-action blast radius, so the scorecard groups by it.
 *   - **Distribution** — how many actions auto-execute, how many have no
 *     executor behind them at all, bucketed by blast radius.
 *
 * Where "auto-executes" comes from, and where it used to come from
 * ----------------------------------------------------------------
 * It is `effective_auto_execute`, which the API resolves from the autonomy
 * tier in force and the action's capability contract — the two things that
 * actually decide whether `services/actions` dispatches or queues.
 *
 * This card used to decide for itself, from the confidence threshold beside
 * each row: `thresholds.auto < 1` meant "some confidence level lets the agent
 * act", therefore auto-executing. Every one of the nineteen shipped defaults
 * is below 1.0 and seven are high- or critical-blast, so a freshly installed
 * deployment opened this page on **"Autopilot · 7 high-blast actions
 * auto-execute"** — while its dispatcher, at the default L1 tier, queued all
 * seven for human approval. The thresholds are read by no production path at
 * all, so the number was not merely stale; it described a mechanism that was
 * not running. A security product telling an operator their estate is
 * unattended when it is not is the kind of wrong that gets acted on.
 *
 * An absent `effective_auto_execute` counts as **not** auto-executing. The
 * failure to avoid is announcing autonomy that is not there, and inferring it
 * from whatever else is on the row is how that happened the first time.
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
  AutonomyEffective,
  AutonomyGrant,
} from '@/lib/api';

export type AutonomyPosture = 'copilot' | 'autopilot';

export interface AutonomyScorecardData {
  posture: AutonomyPosture;
  total: number;
  overridden: number;
  /** Actions that really do reach a vendor without a human. */
  autoExecuting: number;
  /** High/critical blast actions that do (the autopilot signal). */
  highBlastAuto: number;
  /** Actions with no executor registered behind the verb at all. */
  unimplemented: number;
  /**
   * High/critical-blast actions that no autonomy tier could ever run
   * unattended. When this accounts for all of them, the copilot claim is a
   * property of the contracts rather than of today's tier setting, and the
   * card is allowed to say so.
   */
  highBlastNeverAuto: number;
  highBlastTotal: number;
  byBlast: Record<AutonomyBlastRadius, number>;
}

const HIGH_BLAST: ReadonlySet<AutonomyBlastRadius> = new Set(['high', 'critical']);

// The API resolves this from the autonomy tier and the capability contract.
// Absent means "we were not told", which is rendered as not auto-executing:
// the alternative is guessing, and guessing from the threshold beside it is
// what made this card announce an autopilot posture no deployment held.
function autoExecutes(a: AutonomyActionPolicy): boolean {
  return a.effective_auto_execute === true;
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
  let unimplemented = 0;
  let highBlastNeverAuto = 0;
  let highBlastTotal = 0;

  for (const a of actions) {
    byBlast[a.blast_radius] = (byBlast[a.blast_radius] ?? 0) + 1;
    if (a.overridden) overridden += 1;
    if (a.executable === false) unimplemented += 1;
    const high = HIGH_BLAST.has(a.blast_radius);
    if (high) highBlastTotal += 1;
    if (autoExecutes(a)) {
      autoExecuting += 1;
      if (high) highBlastAuto += 1;
    }
    if (high && a.auto_executes_at_any_tier === false) highBlastNeverAuto += 1;
  }

  return {
    // Copilot is the default; only a high/critical-blast action that actually
    // executes without a human flips the posture to autopilot.
    posture: highBlastAuto > 0 ? 'autopilot' : 'copilot',
    total: actions.length,
    overridden,
    autoExecuting,
    highBlastAuto,
    unimplemented,
    highBlastNeverAuto,
    highBlastTotal,
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

/** The sentence beside the posture badge. */
export function postureSummary(card: AutonomyScorecardData): string {
  if (card.posture === 'autopilot') {
    return `${card.highBlastAuto} high-blast action${card.highBlastAuto === 1 ? '' : 's'} auto-execute — review carefully.`;
  }
  // Two different claims, and conflating them is how this card went wrong
  // before. "No tier ever runs these unattended" is a property of the
  // contracts and survives a tier change; "nothing does today" is a reading of
  // the current setting and does not.
  if (card.highBlastTotal > 0 && card.highBlastNeverAuto === card.highBlastTotal) {
    return 'High- and critical-blast actions always require a human — no autonomy tier executes them unattended.';
  }
  return 'Nothing here reaches a vendor without a human at the current autonomy tier.';
}

export function AutonomyScorecard({
  actions,
  agreement,
  grants,
  effective,
}: {
  actions: AutonomyActionPolicy[];
  agreement?: AgreementResponse | null;
  grants?: AutonomyGrant[];
  effective?: AutonomyEffective | null;
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
            <span className="text-xs text-gray-400">{postureSummary(card)}</span>
          </div>
        </div>
        <dl className="flex gap-4 text-right">
          <Stat label="Actions" value={card.total} />
          <Stat label="Auto-exec" value={card.autoExecuting} />
          {card.unimplemented > 0 ? (
            <Stat label="No executor" value={card.unimplemented} hint="advisory only" />
          ) : null}
          <Stat label="Overridden" value={card.overridden} />
        </dl>
      </div>

      <EffectiveControl effective={effective} />

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
      <EarnedAutonomy grants={grants ?? []} />
    </div>
  );
}

/** Where the posture above comes from: the tier, and what it may execute.
 *
 * Named on the card rather than left to the per-action rows because the badge
 * is the thing an operator reads and leaves with, and "Copilot" without the
 * tier beside it is a claim with no stated basis — which is exactly how a
 * posture derived from the wrong table went unchallenged.
 */
const TIER_SOURCE_LABEL: Record<string, string> = {
  tenant_policy: 'set for this tenant',
  environment: 'deployment default',
  unreadable_policy_floor: 'policy unreadable — held at the conservative floor',
};

function EffectiveControl({ effective }: { effective?: AutonomyEffective | null }) {
  if (!effective) return null;
  const source = TIER_SOURCE_LABEL[effective.tier_source] ?? effective.tier_source;

  return (
    <div className="mt-3 rounded-lg border border-gray-800 bg-gray-950/60 p-3">
      <p className="text-[11px] uppercase tracking-wide text-gray-500">What gates execution</p>
      <p className="mt-1 text-xs text-gray-300">
        Autonomy tier{' '}
        <span className="font-mono text-gray-100">{effective.tier_label}</span>{' '}
        <span className="text-gray-500">({source})</span>.{' '}
        {effective.max_automatic_impact === null
          ? 'This tier executes nothing without a human, not even a read.'
          : `Without a human it executes up to ${effective.max_automatic_impact.replace('_', ' ')} impact, and only where the action's own contract allows it.`}
      </p>
      {effective.thresholds_are_advisory ? (
        <p className="mt-2 text-[11px] text-amber-300/80">{effective.advisory_note}</p>
      ) : null}
      {effective.unimplemented_actions.length > 0 ? (
        <p className="mt-2 text-[11px] text-gray-500">
          No executor is registered for{' '}
          <span className="font-mono">{effective.unimplemented_actions.join(', ')}</span>. Thresholds
          for these change nothing.
        </p>
      ) : null}
    </div>
  );
}

/**
 * Capabilities this tenant holds, and how each one came to be held.
 *
 * Gap-closure Phase 2.3. The distinction this renders is the whole reason the
 * grant carries a `source` rather than a boolean: autonomy somebody earned and
 * autonomy somebody overruled a refusal to grant look identical in behaviour
 * and are very different things to be looking at during an incident review. A
 * demoted row stays visible for the same reason: a capability that was taken
 * away is more interesting than one that was never held.
 */
function EarnedAutonomy({ grants }: { grants: AutonomyGrant[] }) {
  if (grants.length === 0) return null;

  return (
    <div className="mt-4 border-t border-gray-800 pt-3">
      <p className="text-[11px] uppercase tracking-wide text-gray-500">Autonomy granted</p>
      <ul className="mt-2 space-y-1.5">
        {grants.map((grant) => (
          <li key={grant.id} className="flex flex-wrap items-baseline gap-2 text-sm">
            <span className="font-mono text-xs text-gray-300">
              {grant.capability} · {grant.scope_key}
            </span>
            <span
              className={clsx(
                'rounded px-1.5 py-0.5 text-[11px] ring-1 ring-inset',
                grant.state === 'demoted'
                  ? 'bg-gray-500/10 text-gray-400 ring-gray-600/40'
                  : grant.is_override
                    ? 'bg-amber-500/10 text-amber-300 ring-amber-500/30'
                    : 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30',
              )}
            >
              {grant.state === 'demoted'
                ? 'demoted'
                : grant.is_override
                  ? 'operator override'
                  : 'earned'}
            </span>
            <span className="text-[11px] text-gray-500">
              {grant.state === 'demoted'
                ? grant.demoted_reason || 'the evidence no longer supports it'
                : grant.is_override
                  ? grant.override_reason || 'no reason recorded'
                  : 'met every threshold on its own'}
            </span>
          </li>
        ))}
      </ul>
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
