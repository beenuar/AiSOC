'use client';

/**
 * Detection drift inbox (WS-B3).
 *
 * Lists detection rules that need analyst attention based on rule-quality
 * heuristics computed server-side:
 *
 *   - high_fp_rate   — rule's false-positive rate exceeds the tuning gate
 *   - low_confidence — rule confidence has decayed below the trust gate
 *   - stale          — rule is enabled but hasn't triggered in N days
 *
 * Thresholds live with the backend (see ``DRIFT_FP_RATE_THRESHOLD``,
 * ``DRIFT_LOW_CONFIDENCE_THRESHOLD``, ``DRIFT_STALE_DAYS`` in
 * ``services/api/app/api/v1/endpoints/detection_compat.py``) so the UI
 * doesn't drift from operator policy when the gates change.
 */

import { useMemo, useState } from 'react';
import Link from 'next/link';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { formatDistanceToNow } from 'date-fns';

import { detectionApi, type DetectionDrift, type DetectionDriftEntry } from '@/lib/api';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorState } from '@/components/ui/ErrorState';
import { EmptyState } from '@/components/ui/EmptyState';

// ─── Issue presentation ──────────────────────────────────────────────────────

type IssueId = 'high_fp_rate' | 'low_confidence' | 'stale';

interface IssueMeta {
  label: string;
  description: string;
  badge: string;
}

const ISSUE_META: Record<IssueId, IssueMeta> = {
  high_fp_rate: {
    label: 'High FP rate',
    description:
      'False-positive rate is above the tuning gate. Tune the rule or raise its confidence threshold.',
    badge: 'bg-rose-500/15 text-rose-200 ring-1 ring-rose-500/30',
  },
  low_confidence: {
    label: 'Low confidence',
    description:
      'Rule confidence has decayed. Either re-tune against fresh telemetry or retire it.',
    badge: 'bg-amber-500/15 text-amber-200 ring-1 ring-amber-500/30',
  },
  stale: {
    label: 'Stale',
    description:
      'Rule is enabled but has not fired recently. Confirm coverage is still relevant.',
    badge: 'bg-sky-500/15 text-sky-200 ring-1 ring-sky-500/30',
  },
};

const ALL_ISSUES: (IssueId | 'all')[] = [
  'all',
  'high_fp_rate',
  'low_confidence',
  'stale',
];

const FILTER_LABEL: Record<(typeof ALL_ISSUES)[number], string> = {
  all: 'All',
  high_fp_rate: 'High FP',
  low_confidence: 'Low conf.',
  stale: 'Stale',
};

// ─── Component ───────────────────────────────────────────────────────────────

export function DriftInbox() {
  const { data, error, isLoading, mutate } = useSWR<DetectionDrift>(
    'detection:drift',
    () => detectionApi.drift(),
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );

  const [issueFilter, setIssueFilter] = useState<IssueId | 'all'>('all');

  const filtered = useMemo(() => {
    if (!data) return [];
    if (issueFilter === 'all') return data.entries;
    return data.entries.filter((entry) =>
      entry.issues.includes(issueFilter),
    );
  }, [data, issueFilter]);

  if (isLoading) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-20 w-full" />
        {[0, 1, 2].map((i) => (
          <Skeleton key={i} className="h-16 w-full" />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <ErrorState
        title="Couldn't load drift inbox"
        description="The detection service didn't respond. Try reloading once it's back."
        error={error as Error}
        onRetry={() => mutate()}
      />
    );
  }

  if (!data || data.entries.length === 0) {
    // Every heuristic here reads confidence, false-positive rate or last
    // trigger, and the compiled corpus records none of them. Reporting a
    // clean inbox over a library nothing could be judged against would be a
    // verdict rather than an absence of one.
    const unscored = data?.summary.unscored ?? 0;
    return (
      <EmptyState
        title={
          unscored > 0
            ? 'Nothing here can be judged yet'
            : 'No rules need attention'
        }
        description={
          unscored > 0
            ? `Every scored rule is healthy. ${unscored.toLocaleString()} rules loaded by the detection engine carry no confidence, false-positive rate or trigger history, so drift cannot be assessed for them — this is not a clean bill of health for those rules.`
            : 'Every active rule is firing on schedule with healthy confidence and a tolerable false-positive rate. Drop back into the rule list to author new coverage.'
        }
      />
    );
  }

  const { summary } = data;

  return (
    <div className="space-y-4">
      {/* Summary strip */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <SummaryCard
          label="Need attention"
          value={summary.total}
          tone={summary.total > 0 ? 'warning' : 'neutral'}
        />
        <SummaryCard
          label="High FP rate"
          value={summary.highFpRate}
          tone={summary.highFpRate > 0 ? 'critical' : 'neutral'}
        />
        <SummaryCard
          label="Low confidence"
          value={summary.lowConfidence}
          tone={summary.lowConfidence > 0 ? 'warning' : 'neutral'}
        />
        <SummaryCard
          label="Stale"
          value={summary.stale}
          tone={summary.stale > 0 ? 'info' : 'neutral'}
        />
      </div>

      {/* Filter */}
      <div className="inline-flex rounded-md border border-gray-800 bg-gray-950 p-0.5 text-xs">
        {ALL_ISSUES.map((opt) => (
          <button
            key={opt}
            type="button"
            onClick={() => setIssueFilter(opt)}
            className={clsx(
              'rounded px-3 py-1.5 transition-colors',
              issueFilter === opt
                ? 'bg-gray-800 text-gray-100'
                : 'text-gray-400 hover:text-gray-200',
            )}
          >
            {FILTER_LABEL[opt]}
            {opt !== 'all' && (
              <span className="ml-1.5 text-gray-500">
                ({issueCount(data.entries, opt as IssueId)})
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Entries */}
      {filtered.length === 0 ? (
        <EmptyState
          title="No rules in this bucket"
          description="Switch to another bucket to see rules that need attention."
        />
      ) : (
        <ul className="space-y-2">
          {filtered.map((entry) => (
            <li key={entry.ruleId}>
              <DriftRow entry={entry} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ─── Sub-components ──────────────────────────────────────────────────────────

interface DriftRowProps {
  entry: DetectionDriftEntry;
}

function DriftRow({ entry }: DriftRowProps) {
  const lastFired = entry.lastTriggeredAt
    ? formatDistanceToNow(new Date(entry.lastTriggeredAt), { addSuffix: true })
    : 'never';
  return (
    <Link
      href={`/detection/${entry.ruleId}`}
      className="group block rounded-lg border border-gray-800 bg-gray-900/40 p-3 transition-colors hover:border-gray-700 hover:bg-gray-900/70"
    >
      <div className="flex items-center gap-3">
        {/* Status dot */}
        <span
          className={clsx(
            'inline-flex h-2 w-2 rounded-full',
            entry.enabled ? 'bg-emerald-400' : 'bg-gray-600',
          )}
          title={entry.enabled ? 'Enabled' : 'Disabled'}
        />

        {/* Body */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="truncate text-sm font-medium text-gray-100 group-hover:text-blue-300">
              {entry.name}
            </h3>
            {entry.issues.map((issueId) => {
              const meta = ISSUE_META[issueId as IssueId];
              if (!meta) return null;
              return (
                <span
                  key={issueId}
                  title={meta.description}
                  className={clsx(
                    'rounded-md px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide',
                    meta.badge,
                  )}
                >
                  {meta.label}
                </span>
              );
            })}
          </div>
          <div
            className="mt-1 flex flex-wrap items-center gap-3 text-[11px] text-gray-500"
            suppressHydrationWarning
          >
            <span>
              Confidence{' '}
              <span className="font-mono text-gray-300">
                {Math.round(entry.confidence)}
              </span>
              {' / 100'}
            </span>
            <span>
              FP rate{' '}
              <span className="font-mono text-gray-300">
                {(entry.fpRate * 100).toFixed(1)}%
              </span>
            </span>
            <span>
              Last fired{' '}
              <span className="text-gray-400">{lastFired}</span>
              {entry.daysSinceTriggered != null && (
                <span className="text-gray-600">
                  {' '}
                  ({entry.daysSinceTriggered}d)
                </span>
              )}
            </span>
          </div>
        </div>

        {/* Severity */}
        <div className="text-[10px] uppercase tracking-wide text-gray-500">
          {entry.severity}
        </div>
      </div>
    </Link>
  );
}

interface SummaryCardProps {
  label: string;
  value: number;
  tone: 'neutral' | 'info' | 'warning' | 'critical';
}

function SummaryCard({ label, value, tone }: SummaryCardProps) {
  const toneClass =
    tone === 'critical'
      ? 'text-rose-300'
      : tone === 'warning'
        ? 'text-amber-300'
        : tone === 'info'
          ? 'text-sky-300'
          : 'text-gray-100';
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900/40 px-3 py-2.5">
      <div className="text-[11px] uppercase tracking-wide text-gray-500">
        {label}
      </div>
      <div className={clsx('mt-1 font-mono text-xl font-semibold', toneClass)}>
        {value}
      </div>
    </div>
  );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function issueCount(entries: DetectionDriftEntry[], issue: IssueId): number {
  return entries.reduce(
    (acc, entry) => (entry.issues.includes(issue) ? acc + 1 : acc),
    0,
  );
}
