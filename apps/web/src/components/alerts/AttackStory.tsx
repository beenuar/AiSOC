'use client';

/**
 * Attack story — the incident as a progression rather than a row.
 *
 * The rail answers "what is this alert". This answers "what happened", which
 * is the question an analyst actually holds in their head: an attack moved
 * through stages, touched these systems, and these are the things that would
 * stop it.
 *
 * The design constraint that shapes everything here is that **a story is the
 * easiest thing in a SOC console to fabricate**. Given one alert with one
 * technique, a plausible kill chain can be drawn in five stages and it will
 * look more convincing than the single event it came from. That is the
 * failure this component is written against, so:
 *
 *   - Stages come from MITRE tactics actually present on the alert, ordered
 *     by kill-chain position. Nothing is interpolated between them.
 *   - A single-stage incident renders as one stage, and says so. It does not
 *     become a chain.
 *   - Evidence is grouped by the source that produced it. A source with
 *     nothing is omitted rather than shown empty, and if no source is
 *     attributable the section says that instead of implying corroboration.
 *   - Confidence is the alert's own score. There is no second number
 *     computed here, because a number computed by a view is a number nobody
 *     can trace.
 *   - Actions are the backend's recommendations. Checking one stages it for
 *     approval; it does not execute, and the copy says so.
 */

import { useMemo, useState } from 'react';
import Link from 'next/link';
import { clsx } from 'clsx';
import type {
  Alert,
  MiniTimelineEvent,
  MitreAttack,
  RecommendedAction,
  RelatedEntity,
} from '@/lib/api';

// ─── Kill-chain ordering ─────────────────────────────────────────────────────

/**
 * ATT&CK Enterprise tactics in kill-chain order.
 *
 * Used only to *sort* tactics the alert already carries. It is deliberately
 * not used to fill gaps: an incident with initial-access and exfiltration
 * renders two stages, not the eleven between them, because the intervening
 * stages are a guess and a guess drawn as a diagram reads as a finding.
 */
const TACTIC_ORDER: readonly string[] = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
];

function tacticKey(tactic: string): string {
  return tactic.trim().toLowerCase().replace(/\s+/g, '-');
}

function tacticRank(tactic: string): number {
  const index = TACTIC_ORDER.indexOf(tacticKey(tactic));
  // Unknown tactics sort last rather than first: an unrecognised label is
  // more likely a vendor-specific string than a reconnaissance step.
  return index === -1 ? TACTIC_ORDER.length : index;
}

function titleCase(value: string): string {
  return value
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((word) => word[0].toUpperCase() + word.slice(1))
    .join(' ');
}

// ─── Derived model ───────────────────────────────────────────────────────────

export interface AttackStage {
  tactic: string;
  label: string;
  techniques: MitreAttack[];
}

/**
 * Group the alert's techniques into ordered stages.
 *
 * Exported for testing: the ordering and the no-interpolation rule are the
 * two properties worth pinning, and both are pure functions of the input.
 */
export function buildStages(techniques: readonly MitreAttack[]): AttackStage[] {
  const byTactic = new Map<string, AttackStage>();

  for (const technique of techniques) {
    if (!technique.tactic) continue;
    const key = tacticKey(technique.tactic);
    const existing = byTactic.get(key);
    if (existing) {
      // Same technique id twice is a duplicate, not a second occurrence.
      if (!existing.techniques.some((t) => t.techniqueId === technique.techniqueId)) {
        existing.techniques.push(technique);
      }
    } else {
      byTactic.set(key, {
        tactic: key,
        label: titleCase(key),
        techniques: [technique],
      });
    }
  }

  return [...byTactic.values()].sort((a, b) => tacticRank(a.tactic) - tacticRank(b.tactic));
}

/**
 * Evidence sources, counted. A source contributing nothing is absent from
 * the result rather than present with zero — an empty source in the UI reads
 * as "we looked and found nothing", which is a different claim from "this
 * source was not involved".
 */
export function buildEvidenceSources(
  alert: Pick<Alert, 'source'>,
  timeline: readonly MiniTimelineEvent[],
  entities: readonly RelatedEntity[],
): { source: string; count: number }[] {
  const counts = new Map<string, number>();

  const add = (name: string | null | undefined) => {
    const trimmed = (name ?? '').trim();
    if (!trimmed || trimmed.toLowerCase() === 'unknown') return;
    counts.set(trimmed, (counts.get(trimmed) ?? 0) + 1);
  };

  add(alert.source);
  for (const event of timeline) add(event.source === 'audit_log' ? 'Audit log' : 'Case timeline');
  for (const entity of entities) add(titleCase(entity.type));

  return [...counts.entries()]
    .map(([source, count]) => ({ source, count }))
    .sort((a, b) => b.count - a.count || a.source.localeCompare(b.source));
}

// ─── Props ───────────────────────────────────────────────────────────────────

export interface AttackStoryProps {
  alert: Alert;
  /** Called with the actions the analyst has staged for approval. */
  onStageActions?: (actions: RecommendedAction[]) => void;
  /**
   * Render the title block. Off inside the investigation rail, whose shell
   * already shows the title — two headings with the same text is noise on
   * screen and ambiguous to a screen reader.
   */
  showHeader?: boolean;
}

// ─── Component ───────────────────────────────────────────────────────────────

export function AttackStory({
  alert,
  onStageActions,
  showHeader = true,
}: AttackStoryProps) {
  const [staged, setStaged] = useState<Set<string>>(new Set());

  const stages = useMemo(() => buildStages(alert.mitreAttack ?? []), [alert.mitreAttack]);
  const sources = useMemo(
    () => buildEvidenceSources(alert, alert.miniTimeline ?? [], alert.relatedEntities ?? []),
    [alert],
  );
  const actions = alert.recommendedActions ?? [];

  const toggle = (action: RecommendedAction) => {
    const next = new Set(staged);
    if (next.has(action.action)) next.delete(action.action);
    else next.add(action.action);
    setStaged(next);
    onStageActions?.(actions.filter((a) => next.has(a.action)));
  };

  return (
    <section
      className="space-y-6 rounded-lg border border-gray-800 bg-gray-950/60 p-5"
      aria-label="Attack story"
    >
      {showHeader && (
        <header className="space-y-1">
          <p className="font-mono text-xs uppercase tracking-wide text-gray-500">
            {alert.sourceRef ?? alert.id.slice(0, 8)}
          </p>
          <h2 className="text-lg font-semibold text-gray-100">{alert.title}</h2>
        </header>
      )}

      {/* ── Progression ───────────────────────────────────────────────── */}
      <div>
        <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-gray-400">
          Progression
        </h3>

        {stages.length === 0 ? (
          <p className="text-sm text-gray-500">
            No ATT&amp;CK tactic is mapped to this alert, so there is no
            progression to show. That is a gap in the detection&rsquo;s
            metadata rather than a statement about the activity.
          </p>
        ) : (
          <>
            <ol className="space-y-0">
              {stages.map((stage, index) => (
                <li key={stage.tactic}>
                  <div className="flex gap-3">
                    <div className="flex flex-col items-center">
                      <span
                        className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-gray-700 bg-gray-900 font-mono text-[10px] text-gray-400"
                        aria-hidden="true"
                      >
                        {index + 1}
                      </span>
                      {index < stages.length - 1 && (
                        <span className="my-1 w-px grow bg-gray-800" aria-hidden="true" />
                      )}
                    </div>
                    <div className="pb-4">
                      <p className="text-sm font-medium text-gray-200">{stage.label}</p>
                      <ul className="mt-1 space-y-0.5">
                        {stage.techniques.map((technique) => (
                          <li key={technique.techniqueId} className="text-xs text-gray-400">
                            <Link
                              href={`/attack-graph?technique=${encodeURIComponent(technique.techniqueId)}`}
                              className="font-mono text-gray-500 hover:text-gray-300"
                            >
                              {technique.techniqueId}
                            </Link>{' '}
                            {technique.technique}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </li>
              ))}
            </ol>

            {stages.length === 1 && (
              <p className="text-xs text-gray-500">
                One stage observed. This is a single-stage detection, not a
                chain &mdash; nothing has been inferred about what came before
                or after.
              </p>
            )}
          </>
        )}
      </div>

      {/* ── Evidence ──────────────────────────────────────────────────── */}
      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-400">
          Evidence
        </h3>
        {sources.length === 0 ? (
          <p className="text-sm text-gray-500">
            No evidence source is attributable to this alert yet.
          </p>
        ) : (
          <ul className="space-y-1">
            {sources.map(({ source, count }) => (
              <li key={source} className="flex items-center justify-between text-sm">
                <span className="text-gray-300">{source}</span>
                <span className="font-mono text-xs text-gray-500">{count}</span>
              </li>
            ))}
          </ul>
        )}
        {sources.length === 1 && (
          <p className="mt-2 text-xs text-gray-500">
            A single source. Corroboration across sources is what raises
            confidence in a verdict, and there is none here.
          </p>
        )}
      </div>

      {/* ── Confidence ────────────────────────────────────────────────── */}
      {typeof alert.confidenceScore === 'number' && (
        <div>
          <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-400">
            Confidence
          </h3>
          <p className="text-sm text-gray-200">
            {alert.confidenceScore}
            <span className="text-gray-500">/100</span>
            {alert.confidenceLabel && (
              <span className="ml-2 text-xs text-gray-400">({alert.confidenceLabel})</span>
            )}
          </p>
          <p className="mt-1 text-xs text-gray-500">
            Scored by fusion from corroboration and source reliability.
            Independent of severity, and not a probability that the verdict is
            correct.
          </p>
        </div>
      )}

      {/* ── Response ──────────────────────────────────────────────────── */}
      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-400">
          Response
        </h3>
        {actions.length === 0 ? (
          <p className="text-sm text-gray-500">No actions have been recommended for this alert.</p>
        ) : (
          <>
            <ul className="space-y-2">
              {actions.map((action) => (
                <li key={action.action}>
                  <label className="flex cursor-pointer items-start gap-2">
                    <input
                      type="checkbox"
                      checked={staged.has(action.action)}
                      onChange={() => toggle(action)}
                      className="mt-0.5 h-4 w-4 shrink-0 rounded border-gray-700 bg-gray-900"
                    />
                    <span className="min-w-0">
                      <span className="text-sm text-gray-200">{action.action}</span>
                      {action.rationale && (
                        <span className="block text-xs text-gray-500">{action.rationale}</span>
                      )}
                      {action.risk && (
                        <span className="block text-xs text-amber-500/80">
                          Risk: {action.risk}
                        </span>
                      )}
                    </span>
                  </label>
                </li>
              ))}
            </ul>

            <p
              className={clsx(
                'mt-3 text-xs',
                staged.size > 0 ? 'text-gray-400' : 'text-gray-600',
              )}
            >
              {staged.size > 0
                ? `${staged.size} action${staged.size === 1 ? '' : 's'} staged. Submitting sends them for approval under the tenant's autonomy policy — nothing executes from this panel.`
                : 'Selecting an action stages it for approval. Nothing executes from this panel.'}
            </p>
          </>
        )}
      </div>
    </section>
  );
}
