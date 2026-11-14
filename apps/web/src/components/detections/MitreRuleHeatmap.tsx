'use client';

/**
 * Rule-centric MITRE ATT&CK coverage heatmap (WS-B3).
 *
 * Distinct from `CoverageView.tsx` which shows the *marketplace* tier mix
 * (how many community / imported / stable rules exist per technique). This
 * heatmap is purely about the operator's *current rule library state* —
 * "how many of my enabled rules cover technique T1059?". That's the
 * question senior analysts ask when deciding what to hunt for next, and
 * what tuning work to prioritise.
 *
 * Data shape comes from `GET /api/v1/detection/coverage` which is computed
 * server-side from the `detection_rules` table and uses the rule's first
 * declared MITRE tactic to plot it (see `_primary_tactic` in
 * `services/api/app/api/v1/endpoints/detection_compat.py`).
 */

import { useMemo } from 'react';
import useSWR from 'swr';
import { clsx } from 'clsx';

import { detectionApi, type DetectionCoverage } from '@/lib/api';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorState } from '@/components/ui/ErrorState';
import { EmptyState } from '@/components/ui/EmptyState';

// ─── Constants ───────────────────────────────────────────────────────────────

/** Bucket thresholds for the heatmap color ramp. */
const HEAT_BUCKETS: { min: number; class: string; label: string }[] = [
  { min: 5, class: 'bg-emerald-500/70 text-white', label: '5+' },
  { min: 3, class: 'bg-emerald-500/45 text-emerald-50', label: '3–4' },
  { min: 2, class: 'bg-emerald-500/30 text-emerald-100', label: '2' },
  { min: 1, class: 'bg-emerald-500/15 text-emerald-200', label: '1' },
];

const EMPTY_CELL_CLASS = 'bg-gray-800/40 text-gray-600';

function bucketClassFor(active: number, total: number): string {
  if (active === 0 && total > 0) {
    // Technique appears (rule exists) but no enabled rule — flag as a tuning gap.
    return 'bg-amber-500/15 text-amber-200 ring-1 ring-amber-500/30';
  }
  for (const bucket of HEAT_BUCKETS) {
    if (active >= bucket.min) return bucket.class;
  }
  return EMPTY_CELL_CLASS;
}

// ─── Component ───────────────────────────────────────────────────────────────

export function MitreRuleHeatmap() {
  const { data, error, isLoading, mutate } = useSWR<DetectionCoverage>(
    'detection:coverage',
    () => detectionApi.coverage(),
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );

  // Group cells by tactic for column-style rendering. Using ``useMemo`` so
  // we don't re-bucket on every keystroke when this is embedded in a tab
  // panel that re-renders often.
  const grouped = useMemo(() => {
    if (!data) return null;
    const byTactic = new Map<string, typeof data.cells>();
    for (const cell of data.cells) {
      const key = cell.tactic ?? 'unmapped';
      const list = byTactic.get(key) ?? [];
      list.push(cell);
      byTactic.set(key, list);
    }
    // Sort cells within each tactic by active count descending so the
    // strongest coverage is visible first.
    for (const list of byTactic.values()) {
      list.sort(
        (a, b) =>
          b.activeRules - a.activeRules ||
          a.techniqueId.localeCompare(b.techniqueId),
      );
    }
    return byTactic;
  }, [data]);

  if (isLoading) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-20 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (error) {
    return (
      <ErrorState
        title="Couldn't load detection coverage"
        description="The detection service didn't respond. Try reloading once it's back."
        error={error as Error}
        onRetry={() => mutate()}
      />
    );
  }

  if (!data || data.cells.length === 0) {
    return (
      <EmptyState
        title="No MITRE-mapped rules yet"
        description="Once your detection rules carry MITRE ATT&CK tactic and technique tags, they'll appear here grouped by kill-chain phase."
      />
    );
  }

  const { summary, tactics } = data;

  return (
    <div className="space-y-4">
      {/* Summary strip */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <SummaryCard
          label="Total rules"
          value={summary.totalRules}
          tone="neutral"
        />
        <SummaryCard
          label="Enabled rules"
          value={summary.activeRules}
          tone="positive"
        />
        <SummaryCard
          label="Techniques covered"
          value={summary.coveredTechniques}
          suffix={` / ${summary.techniques}`}
          tone="positive"
        />
        <SummaryCard
          label="Disabled rules"
          value={summary.inactiveRules}
          tone={summary.inactiveRules > 0 ? 'warning' : 'neutral'}
        />
      </div>

      {/* Heatmap */}
      <div className="overflow-x-auto rounded-lg border border-gray-800 bg-gray-900/40 p-3">
        <div className="flex gap-3 min-w-max">
          {tactics.map((tactic) => {
            const cells = grouped?.get(tactic) ?? [];
            return (
              <div
                key={tactic}
                className="flex w-32 flex-col gap-1.5"
                data-testid={`tactic-column-${tactic}`}
              >
                <header className="border-b border-gray-800 pb-1.5">
                  <div className="truncate text-[11px] font-semibold uppercase tracking-wide text-gray-300">
                    {humanizeTactic(tactic)}
                  </div>
                  <div className="text-[10px] text-gray-500">
                    {cells.length} technique{cells.length === 1 ? '' : 's'}
                  </div>
                </header>
                <div className="space-y-1">
                  {cells.map((cell) => (
                    <div
                      key={cell.techniqueId}
                      className={clsx(
                        'rounded px-1.5 py-1 text-[11px] font-mono leading-tight transition-colors',
                        bucketClassFor(cell.activeRules, cell.totalRules),
                      )}
                      title={[
                        cell.techniqueId,
                        `${cell.activeRules} enabled / ${cell.totalRules} total`,
                        cell.inactiveRules > 0
                          ? `${cell.inactiveRules} disabled`
                          : null,
                      ]
                        .filter(Boolean)
                        .join(' • ')}
                    >
                      <div className="flex items-center justify-between gap-1">
                        <span className="truncate">{cell.techniqueId}</span>
                        <span className="text-[10px] opacity-80">
                          {cell.activeRules}
                        </span>
                      </div>
                    </div>
                  ))}
                  {cells.length === 0 && (
                    <div className="rounded px-1.5 py-1 text-[10px] italic text-gray-600">
                      No rules
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-3 text-[11px] text-gray-500">
        <span className="font-medium text-gray-400">Active rules:</span>
        {[...HEAT_BUCKETS]
          .reverse()
          .map((bucket) => (
            <span key={bucket.label} className="inline-flex items-center gap-1.5">
              <span className={clsx('h-3 w-4 rounded', bucket.class)} />
              {bucket.label}
            </span>
          ))}
        <span className="inline-flex items-center gap-1.5">
          <span className="h-3 w-4 rounded bg-amber-500/15 ring-1 ring-amber-500/30" />
          tuning gap (rules disabled)
        </span>
      </div>
    </div>
  );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

interface SummaryCardProps {
  label: string;
  value: number;
  suffix?: string;
  tone: 'neutral' | 'positive' | 'warning';
}

function SummaryCard({ label, value, suffix, tone }: SummaryCardProps) {
  const toneClass =
    tone === 'positive'
      ? 'text-emerald-300'
      : tone === 'warning'
        ? 'text-amber-300'
        : 'text-gray-100';
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900/40 px-3 py-2.5">
      <div className="text-[11px] uppercase tracking-wide text-gray-500">
        {label}
      </div>
      <div className={clsx('mt-1 font-mono text-xl font-semibold', toneClass)}>
        {value}
        {suffix && (
          <span className="text-sm font-normal text-gray-500">{suffix}</span>
        )}
      </div>
    </div>
  );
}

/**
 * Convert backend tactic strings (kebab-case or snake_case) into the
 * Title-Case labels analysts read in the ATT&CK navigator.
 *
 * We do this in the UI rather than the API so the wire format stays close
 * to what `DetectionRule.mitre_tactics` actually stores.
 */
function humanizeTactic(raw: string): string {
  if (raw === 'unmapped') return 'Unmapped';
  return raw
    .split(/[-_]/)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}
