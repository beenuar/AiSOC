'use client';

/**
 * Rule-confidence trends panel (WS-B3).
 *
 * The plan asks for "confidence trends". We don't capture rule confidence
 * historically yet, so we render the *snapshot* analyst question that
 * actually drives tuning work:
 *
 *   1. How is rule confidence distributed across the library? (histogram)
 *   2. Which MITRE tactics are weakest on average? (per-tactic averages)
 *   3. Which specific rules are dragging the average down vs which are
 *      pulling it up? (lowest / highest tables)
 *
 * Backed by `GET /api/v1/detection/confidence`. See
 * `_build_confidence` in `services/api/app/api/v1/endpoints/detection_compat.py`.
 */

import { useMemo } from 'react';
import Link from 'next/link';
import useSWR from 'swr';
import { clsx } from 'clsx';

import {
  detectionApi,
  type DetectionConfidence,
  type ConfidenceBucket,
  type ConfidenceRuleEntry,
  type TacticConfidence,
} from '@/lib/api';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorState } from '@/components/ui/ErrorState';
import { EmptyState } from '@/components/ui/EmptyState';

// ─── Constants ───────────────────────────────────────────────────────────────

/**
 * Confidence-floor → tone mapping for histogram bars and tactic bars.
 *
 * 0–25 is critically untrustworthy (red), 26–50 needs tuning (amber),
 * 51–75 is acceptable (sky), 76–100 is high-trust (emerald). The same
 * scale is used everywhere on this page so an analyst's eye learns one
 * color story.
 */
function toneForConfidence(
  value: number,
): { bar: string; text: string; ring: string } {
  if (value < 26) {
    return {
      bar: 'bg-rose-500/70',
      text: 'text-rose-300',
      ring: 'ring-rose-500/30',
    };
  }
  if (value < 51) {
    return {
      bar: 'bg-amber-500/70',
      text: 'text-amber-300',
      ring: 'ring-amber-500/30',
    };
  }
  if (value < 76) {
    return {
      bar: 'bg-sky-500/70',
      text: 'text-sky-300',
      ring: 'ring-sky-500/30',
    };
  }
  return {
    bar: 'bg-emerald-500/70',
    text: 'text-emerald-300',
    ring: 'ring-emerald-500/30',
  };
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-300 ring-red-500/40',
  high: 'bg-orange-500/10 text-orange-300 ring-orange-500/40',
  medium: 'bg-yellow-500/10 text-yellow-300 ring-yellow-500/40',
  low: 'bg-blue-500/10 text-blue-300 ring-blue-500/40',
  info: 'bg-slate-500/10 text-slate-300 ring-slate-500/40',
};

// ─── Component ───────────────────────────────────────────────────────────────

export function ConfidenceTrends() {
  const { data, error, isLoading, mutate } = useSWR<DetectionConfidence>(
    'detection:confidence',
    () => detectionApi.confidence(),
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );

  const maxBucketCount = useMemo(() => {
    if (!data) return 0;
    return data.buckets.reduce((acc, b) => Math.max(acc, b.count), 0);
  }, [data]);

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[0, 1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-20 w-full" />
          ))}
        </div>
        <Skeleton className="h-56 w-full" />
        <Skeleton className="h-72 w-full" />
      </div>
    );
  }

  if (error) {
    return (
      <ErrorState
        title="Couldn't load confidence trends"
        description="The detection service didn't respond. Try reloading once it's back."
        error={error as Error}
        onRetry={() => mutate()}
      />
    );
  }

  if (!data || data.summary.totalRules === 0) {
    return (
      <EmptyState
        title="No rules yet"
        description="Once you author or import a few detection rules, this view tracks how confident the library is per MITRE tactic and surfaces the weakest rules to tune first."
      />
    );
  }

  const { summary, buckets, tactics, lowest, highest } = data;
  const summaryTone = toneForConfidence(summary.avgConfidence);

  return (
    <div className="space-y-5">
      {/* Summary strip */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <SummaryCard
          label="Avg confidence"
          value={`${summary.avgConfidence}/100`}
          tone={summaryTone.text}
          hint={`Active ${summary.avgConfidenceActive}/100`}
        />
        <SummaryCard
          label="Median"
          value={`${summary.medianConfidence}/100`}
          tone="text-gray-100"
          hint={`${summary.totalRules} rule${summary.totalRules === 1 ? '' : 's'}`}
        />
        <SummaryCard
          label="Active rules"
          value={String(summary.activeRules)}
          tone="text-gray-100"
          hint={`${summary.totalRules - summary.activeRules} disabled`}
        />
        <SummaryCard
          label="Below trust gate"
          value={String(summary.lowConfidence)}
          tone={summary.lowConfidence > 0 ? 'text-amber-300' : 'text-gray-100'}
          hint="< 60/100 confidence"
        />
      </div>

      {/* Histogram */}
      <section
        aria-label="Confidence distribution"
        className="rounded-lg border border-gray-800 bg-gray-900/40 p-4"
      >
        <header className="flex items-baseline justify-between">
          <h2 className="text-sm font-semibold text-gray-100">
            Confidence distribution
          </h2>
          <span className="text-[11px] uppercase tracking-wide text-gray-500">
            Active rules shown stacked on enabled rules
          </span>
        </header>
        <p className="mt-1 text-xs text-gray-500">
          Where the rule library sits today on the 0–100 confidence scale.
          Bars fill more darkly with their <em>active</em> share so a tall
          but pale bar means many disabled rules in that band.
        </p>
        <div className="mt-4 grid grid-cols-4 gap-3">
          {buckets.map((bucket) => (
            <HistogramBar
              key={bucket.label}
              bucket={bucket}
              maxCount={maxBucketCount}
            />
          ))}
        </div>
      </section>

      {/* Per-tactic averages */}
      <section
        aria-label="Average confidence by MITRE tactic"
        className="rounded-lg border border-gray-800 bg-gray-900/40 p-4"
      >
        <header className="flex items-baseline justify-between">
          <h2 className="text-sm font-semibold text-gray-100">
            Confidence by MITRE tactic
          </h2>
          <span className="text-[11px] uppercase tracking-wide text-gray-500">
            Lower bars = tuning priority
          </span>
        </header>
        <p className="mt-1 text-xs text-gray-500">
          Each row averages the confidence of every rule whose primary
          MITRE tactic falls in that column. Faded portion of each bar
          shows the gap between all rules and the *active* rules — wide
          gaps mean low-confidence rules have been disabled but never
          retired.
        </p>
        <ul className="mt-4 space-y-2.5">
          {tactics.length === 0 ? (
            <li className="text-xs text-gray-500">
              No rules tagged with a MITRE tactic yet.
            </li>
          ) : (
            tactics.map((tactic) => (
              <TacticBar key={tactic.tactic} tactic={tactic} />
            ))
          )}
        </ul>
      </section>

      {/* Worst & best lists side by side on desktop */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <RuleList
          title="Lowest confidence"
          subtitle="Tune or retire — these rules are dragging the average down."
          tone="critical"
          entries={lowest}
        />
        <RuleList
          title="Highest confidence"
          subtitle="High-trust rules — copy their tradecraft when you author new coverage."
          tone="positive"
          entries={highest}
        />
      </div>
    </div>
  );
}

// ─── Sub-components ──────────────────────────────────────────────────────────

interface HistogramBarProps {
  bucket: ConfidenceBucket;
  maxCount: number;
}

function HistogramBar({ bucket, maxCount }: HistogramBarProps) {
  // Use the bucket midpoint as the tone signal so visual color tracks
  // confidence rather than count.
  const mid = (bucket.floor + bucket.ceil) / 2;
  const tone = toneForConfidence(mid);
  const totalPct = maxCount === 0 ? 0 : (bucket.count / maxCount) * 100;
  const activePct =
    bucket.count === 0 ? 0 : (bucket.activeCount / bucket.count) * 100;
  return (
    <div className="flex flex-col items-center gap-1.5">
      <div className="flex h-32 w-full items-end justify-center">
        <div
          className="relative w-full max-w-[3.5rem] overflow-hidden rounded-t-md bg-gray-800/60"
          style={{ height: `${Math.max(totalPct, bucket.count > 0 ? 4 : 0)}%` }}
          aria-label={`${bucket.count} rules between ${bucket.label} confidence, ${bucket.activeCount} active`}
        >
          <div
            className={clsx('absolute bottom-0 left-0 right-0', tone.bar)}
            style={{ height: `${activePct}%` }}
          />
        </div>
      </div>
      <div className="text-center">
        <div className={clsx('font-mono text-sm font-semibold', tone.text)}>
          {bucket.count}
        </div>
        <div className="text-[10px] uppercase tracking-wide text-gray-500">
          {bucket.label}
        </div>
        {bucket.activeCount !== bucket.count && (
          <div className="text-[10px] text-gray-500">
            {bucket.activeCount} active
          </div>
        )}
      </div>
    </div>
  );
}

interface TacticBarProps {
  tactic: TacticConfidence;
}

function TacticBar({ tactic }: TacticBarProps) {
  const tone = toneForConfidence(tactic.avgConfidence);
  const total = Math.max(0, Math.min(100, tactic.avgConfidence));
  const active = Math.max(0, Math.min(100, tactic.avgConfidenceActive));
  return (
    <li className="grid grid-cols-[10rem_1fr_5rem] items-center gap-3">
      <div className="truncate text-xs font-medium text-gray-300">
        {humanizeTactic(tactic.tactic)}
      </div>
      <div className="relative h-2.5 w-full overflow-hidden rounded-full bg-gray-800/70">
        <div
          className={clsx('absolute inset-y-0 left-0 opacity-40', tone.bar)}
          style={{ width: `${total}%` }}
          aria-hidden
        />
        <div
          className={clsx('absolute inset-y-0 left-0', tone.bar)}
          style={{ width: `${active}%` }}
          aria-hidden
        />
      </div>
      <div className="text-right text-xs">
        <span className={clsx('font-mono font-semibold', tone.text)}>
          {tactic.avgConfidenceActive}
        </span>
        <span className="text-gray-600">/100</span>
        <div className="text-[10px] text-gray-500">
          {tactic.activeRules}/{tactic.rules} active
        </div>
      </div>
    </li>
  );
}

interface RuleListProps {
  title: string;
  subtitle: string;
  tone: 'critical' | 'positive';
  entries: ConfidenceRuleEntry[];
}

function RuleList({ title, subtitle, tone, entries }: RuleListProps) {
  const headerTone =
    tone === 'critical' ? 'text-rose-200' : 'text-emerald-200';
  return (
    <section
      aria-label={title}
      className="rounded-lg border border-gray-800 bg-gray-900/40 p-4"
    >
      <header>
        <h2 className={clsx('text-sm font-semibold', headerTone)}>{title}</h2>
        <p className="mt-1 text-xs text-gray-500">{subtitle}</p>
      </header>
      {entries.length === 0 ? (
        <p className="mt-4 text-xs text-gray-500">No rules to show.</p>
      ) : (
        <ul className="mt-3 divide-y divide-gray-800/80">
          {entries.map((entry) => (
            <li key={entry.ruleId}>
              <RuleListRow entry={entry} />
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

interface RuleListRowProps {
  entry: ConfidenceRuleEntry;
}

function RuleListRow({ entry }: RuleListRowProps) {
  const tone = toneForConfidence(entry.confidence);
  return (
    <Link
      href={`/detection/${entry.ruleId}`}
      className="group flex items-center gap-3 py-2.5 transition-colors hover:bg-gray-900/60"
    >
      <span
        className={clsx(
          'inline-flex h-2 w-2 shrink-0 rounded-full',
          entry.enabled ? 'bg-emerald-400' : 'bg-gray-600',
        )}
        title={entry.enabled ? 'Enabled' : 'Disabled'}
      />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <h3 className="truncate text-sm text-gray-100 group-hover:text-blue-300">
            {entry.name}
          </h3>
          {entry.severity && (
            <span
              className={clsx(
                'rounded-md px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ring-1',
                SEVERITY_BADGE[entry.severity] ??
                  'bg-gray-800 text-gray-300 ring-gray-700',
              )}
            >
              {entry.severity}
            </span>
          )}
        </div>
        <div className="mt-0.5 flex items-center gap-3 text-[11px] text-gray-500">
          {entry.primaryTactic && (
            <span>{humanizeTactic(entry.primaryTactic)}</span>
          )}
          <span>
            FP rate{' '}
            <span className="font-mono text-gray-400">
              {(entry.fpRate * 100).toFixed(1)}%
            </span>
          </span>
        </div>
      </div>
      <div className="text-right">
        <div className={clsx('font-mono text-sm font-semibold', tone.text)}>
          {entry.confidence}
        </div>
        <div className="text-[10px] uppercase tracking-wide text-gray-500">
          /100
        </div>
      </div>
    </Link>
  );
}

interface SummaryCardProps {
  label: string;
  value: string;
  hint?: string;
  tone: string;
}

function SummaryCard({ label, value, hint, tone }: SummaryCardProps) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900/40 px-3 py-2.5">
      <div className="text-[11px] uppercase tracking-wide text-gray-500">
        {label}
      </div>
      <div className={clsx('mt-1 font-mono text-xl font-semibold', tone)}>
        {value}
      </div>
      {hint && (
        <div className="mt-0.5 text-[11px] text-gray-500">{hint}</div>
      )}
    </div>
  );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * MITRE tactic IDs come back as ``initial-access`` or ``credential-access``
 * — render them as ``Initial Access`` for the UI without a lookup table.
 */
function humanizeTactic(tactic: string): string {
  if (!tactic) return 'Unmapped';
  return tactic
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}
