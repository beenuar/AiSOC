'use client';

/**
 * Detection coverage, as a ratio of techniques with at least one *active* rule.
 *
 * `GET /api/v1/detection/coverage` distinguishes total rules from active ones
 * and counts techniques covered by an active rule. That distinction is the
 * whole point: a corpus of 800 rules with half of them disabled covers far
 * less than the headline rule count implies, and a disabled rule is exactly as
 * useful as no rule.
 *
 * The panel therefore leads with covered-vs-total techniques, names the number
 * of inactive rules explicitly rather than folding them into a total, and
 * lists the tactics with the thinnest active coverage — which is the part an
 * operator can act on this week.
 */

import useSWR from 'swr';
import Link from 'next/link';
import { clsx } from 'clsx';
import { detectionApi, type DetectionCoverage } from '@/lib/api';
import { EmptyState } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';

/** Tactics ranked by how little active coverage they have. */
export function thinnestTactics(
  coverage: DetectionCoverage,
  take = 5,
): Array<{ tactic: string; covered: number; total: number }> {
  const byTactic = new Map<string, { covered: number; total: number }>();

  for (const cell of coverage.cells) {
    // Cells carry `tactic: string | null`. A technique with no tactic cannot
    // be attributed to one, so it is counted in the summary above but not
    // ranked here — inventing an "Unknown" bucket would imply a gap in a
    // tactic that does not exist.
    if (!cell.tactic) continue;
    const entry = byTactic.get(cell.tactic) ?? { covered: 0, total: 0 };
    entry.total += 1;
    if (cell.activeRules > 0) entry.covered += 1;
    byTactic.set(cell.tactic, entry);
  }

  return [...byTactic.entries()]
    .map(([tactic, v]) => ({ tactic, ...v }))
    .sort((a, b) => a.covered / Math.max(a.total, 1) - b.covered / Math.max(b.total, 1))
    .slice(0, take);
}

export function DetectionCoveragePanel() {
  const { data, error, isLoading, mutate } = useSWR(
    'ops-detection-coverage',
    () => detectionApi.coverage(),
    { refreshInterval: 300_000, revalidateOnFocus: false },
  );

  const summary = data?.summary;
  const ratio =
    summary && summary.techniques > 0 ? summary.coveredTechniques / summary.techniques : null;

  return (
    <section
      aria-labelledby="ops-coverage-heading"
      className="rounded-xl border border-gray-800/60 bg-gray-900/40"
    >
      <div className="px-4 py-3">
        <h2 id="ops-coverage-heading" className="text-sm font-medium text-gray-300">
          Detection coverage
        </h2>
        <p className="mt-0.5 text-[11px] text-gray-500">
          Techniques with at least one enabled rule. A disabled rule covers nothing.
        </p>
      </div>

      {isLoading && !data ? (
        <div className="m-4 h-24 animate-pulse rounded bg-gray-800/40" />
      ) : error ? (
        <ErrorState
          title="Coverage unavailable"
          error={error}
          onRetry={() => {
            void mutate();
          }}
          className="m-4"
        />
      ) : !summary || summary.techniques === 0 ? (
        <EmptyState
          title="No detection rules loaded"
          description="Coverage is computed from the rules this tenant has enabled."
          action={
            <Link
              href="/detection"
              className="text-sm text-blue-400 underline underline-offset-2 hover:text-blue-300"
            >
              Browse detection rules
            </Link>
          }
          className="m-4"
        />
      ) : (
        <div className="space-y-4 px-4 pb-4">
          <div className="flex items-end gap-6">
            <div>
              <p className="text-[11px] uppercase tracking-wider text-gray-500">
                Techniques covered
              </p>
              <p className="text-2xl font-semibold text-gray-100">
                {`${summary.coveredTechniques} / ${summary.techniques}`}
              </p>
            </div>
            <div>
              <p className="text-[11px] uppercase tracking-wider text-gray-500">Active rules</p>
              <p className="text-2xl font-semibold text-gray-100">
                {summary.activeRules.toLocaleString()}
              </p>
              {summary.inactiveRules > 0 && (
                <p className="text-[11px] text-amber-300/80">
                  {`${summary.inactiveRules.toLocaleString()} disabled`}
                </p>
              )}
            </div>
          </div>

          {ratio !== null && (
            <div>
              <div className="h-1.5 rounded-full bg-gray-800">
                <div
                  className={clsx(
                    'h-1.5 rounded-full',
                    ratio >= 0.6 ? 'bg-green-500/70' : ratio >= 0.3 ? 'bg-yellow-500/70' : 'bg-red-500/70',
                  )}
                  style={{ width: `${Math.round(ratio * 100)}%` }}
                />
              </div>
              <p className="mt-1 text-[11px] text-gray-500">
                {`${Math.round(ratio * 100)}% of known techniques have an enabled rule.`}
              </p>
            </div>
          )}

          {data && (
            <div>
              <p className="mb-2 text-[11px] uppercase tracking-wider text-gray-500">
                Thinnest tactics
              </p>
              <ul className="space-y-1.5">
                {thinnestTactics(data).map((t) => (
                  <li key={t.tactic} className="flex items-baseline justify-between gap-3">
                    <span className="truncate text-xs text-gray-300">{t.tactic}</span>
                    <span className="shrink-0 text-[11px] text-gray-500">
                      {`${t.covered}/${t.total} covered`}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
