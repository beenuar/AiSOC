'use client';

/**
 * Coverage gap advisor.
 *
 * Reads `GET /api/v1/detection/coverage` — the same endpoint behind the MITRE
 * rule heatmap and the operations panel — and ranks the tenant's own ATT&CK
 * techniques by how much enabled coverage they have.
 *
 * What this replaced: fifteen invented technique verdicts in a module-scope
 * `TECHNIQUES` array, no API call anywhere in the file, and a recommendation
 * column that asserted deployment state the component could not possibly know
 * ("Existing PowerShell & Bash rules active", "Ransomware canary files
 * active"). The four headline cards were computed from that array, so
 * "Coverage 50%" and "Critical Gaps 5" were byte-identical on every
 * deployment, and the only button raised a success toast and created nothing.
 *
 * Two things the wired version is deliberately careful about.
 *
 * The endpoint returns a cell per technique **that at least one rule
 * references**. A technique nobody has written a rule for never appears, so
 * a percentage computed over `cells` is not coverage of ATT&CK — on a tenant
 * with three rules it would read 100%. The page therefore reports the
 * fraction, names its own blind spot, and publishes no coverage score.
 *
 * And "covered" means *enabled*. A technique whose only rules are switched
 * off is the actionable case and gets its own status, because a disabled rule
 * detects exactly as much as no rule.
 */

import { useMemo, useState } from 'react';
import Link from 'next/link';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { detectionApi, type DetectionCoverage, type DetectionCoverageCell } from '@/lib/api';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';
import { Skeleton } from '@/components/ui/Skeleton';

type CoverageStatus = 'covered' | 'unenforced';
type StatusFilter = CoverageStatus | 'all';

const STATUS_STYLES: Record<CoverageStatus, { bg: string; text: string; label: string }> = {
  covered: { bg: 'bg-green-500/20', text: 'text-green-400', label: 'Covered' },
  unenforced: { bg: 'bg-amber-500/20', text: 'text-amber-400', label: 'Unenforced' },
};

const FILTERS: ReadonlyArray<{ id: StatusFilter; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'unenforced', label: 'Unenforced' },
  { id: 'covered', label: 'Covered' },
];

function statusOf(cell: DetectionCoverageCell): CoverageStatus {
  return cell.activeRules > 0 ? 'covered' : 'unenforced';
}

/** Unenforced first, then the thinnest coverage, then by id for stability. */
function ranked(cells: DetectionCoverageCell[]): DetectionCoverageCell[] {
  return [...cells].sort(
    (a, b) =>
      a.activeRules - b.activeRules ||
      b.inactiveRules - a.inactiveRules ||
      a.techniqueId.localeCompare(b.techniqueId),
  );
}

export default function CoverageAdvisorView() {
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');

  const { data, error, isLoading, mutate } = useSWR<DetectionCoverage>(
    'coverage-advisor',
    () => detectionApi.coverage(),
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );

  const cells = useMemo(() => ranked(data?.cells ?? []), [data]);
  const visible = useMemo(
    () => (statusFilter === 'all' ? cells : cells.filter((c) => statusOf(c) === statusFilter)),
    [cells, statusFilter],
  );

  const summary = data?.summary;

  return (
    <div className="space-y-8 p-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-white">Coverage Gap Advisor</h1>
        <p className="text-gray-400 mt-1">
          MITRE ATT&amp;CK techniques your detection rules reference, ranked by how much enabled
          coverage each one has.
        </p>
      </div>

      {isLoading && !data ? (
        <div className="space-y-4">
          <Skeleton className="h-24 w-full rounded-xl" />
          <Skeleton className="h-64 w-full rounded-xl" />
        </div>
      ) : error ? (
        // `ErrorState` and `EmptyState` both open at `h3`, so they need an
        // `h2` above them or the page jumps h1 → h3 and fails the axe
        // heading-order rule. The section heading is the honest one anyway:
        // these branches stand in for the gap-analysis table.
        <GapAnalysisSection>
          <ErrorState
            title="Coverage unavailable"
            description="The detection service did not answer, so there is nothing to report about your rules."
            error={error}
            onRetry={() => {
              void mutate();
            }}
          />
        </GapAnalysisSection>
      ) : !summary || summary.techniques === 0 ? (
        <GapAnalysisSection>
          <EmptyState
            icon={EmptyStateIcons.shield}
            title="No detection rules reference a technique yet"
            description="Coverage is computed from the rules this tenant has loaded. Add or import rules and their ATT&CK mappings appear here."
            action={
              <Link
                href="/detection"
                className="rounded-lg bg-gray-800 px-4 py-2 text-sm text-gray-200 hover:bg-gray-700 transition-colors"
              >
                Browse detection rules
              </Link>
            }
          />
        </GapAnalysisSection>
      ) : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <SummaryCard
              label="Techniques with an enabled rule"
              value={`${summary.coveredTechniques} / ${summary.techniques}`}
            />
            <SummaryCard
              label="Unenforced techniques"
              value={`${summary.techniques - summary.coveredTechniques}`}
              hint="every rule for these is switched off"
            />
            <SummaryCard label="Enabled rules" value={summary.activeRules.toLocaleString()} />
            <SummaryCard
              label="Disabled rules"
              value={summary.inactiveRules.toLocaleString()}
              hint={summary.inactiveRules > 0 ? 'detecting nothing while off' : undefined}
            />
          </div>

          <p className="text-xs text-gray-500">
            Scope: this endpoint reports one row per technique at least one of your rules
            references. Techniques with no rule at all do not appear, so the fraction above is
            coverage of your own corpus and not of ATT&amp;CK. Generated{' '}
            {data?.generatedAt ?? 'unknown'}.
          </p>

          <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 overflow-hidden">
            <div className="px-5 py-4 border-b border-gray-800/60 flex flex-wrap items-center gap-3">
              <h2 className="text-lg font-semibold text-white flex-1 min-w-0">Gap analysis</h2>
              <div className="flex gap-2">
                {FILTERS.map((f) => (
                  <button
                    key={f.id}
                    onClick={() => setStatusFilter(f.id)}
                    className={clsx(
                      'text-xs px-3 py-1 rounded-lg border transition-colors',
                      statusFilter === f.id
                        ? 'bg-blue-600/15 text-blue-300 border-blue-600/30'
                        : 'text-gray-400 border-gray-800 hover:border-gray-700',
                    )}
                    aria-pressed={statusFilter === f.id}
                  >
                    {f.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800/60 text-left text-gray-400">
                    <th className="px-5 py-3 font-medium">Technique</th>
                    <th className="px-5 py-3 font-medium">Tactic</th>
                    <th className="px-5 py-3 font-medium text-center">Enabled rules</th>
                    <th className="px-5 py-3 font-medium text-center">Disabled rules</th>
                    <th className="px-5 py-3 font-medium text-center">Status</th>
                    <th className="px-5 py-3 font-medium">Next step</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-0">
                        <EmptyState
                          icon={EmptyStateIcons.shield}
                          title="No techniques match this filter"
                          description="Try a different coverage status or view all techniques."
                          action={
                            <button
                              type="button"
                              onClick={() => setStatusFilter('all')}
                              className="rounded-lg bg-gray-800 px-4 py-2 text-sm text-gray-200 hover:bg-gray-700 transition-colors"
                            >
                              Show all techniques
                            </button>
                          }
                        />
                      </td>
                    </tr>
                  ) : (
                    visible.map((cell) => <CoverageRow key={cell.techniqueId} cell={cell} />)
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function GapAnalysisSection({ children }: { children: React.ReactNode }) {
  return (
    <section aria-labelledby="coverage-gap-analysis">
      <h2 id="coverage-gap-analysis" className="sr-only">
        Gap analysis
      </h2>
      {children}
    </section>
  );
}

function SummaryCard({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 p-4">
      <p className="text-xs text-gray-400 uppercase tracking-wider">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-white">{value}</p>
      {hint && <p className="mt-0.5 text-[11px] text-gray-500">{hint}</p>}
    </div>
  );
}

function CoverageRow({ cell }: { cell: DetectionCoverageCell }) {
  const status = statusOf(cell);
  const style = STATUS_STYLES[status];

  return (
    <tr className="border-b border-gray-800/40 hover:bg-gray-800/30 transition-colors">
      <td className="px-5 py-3 font-mono text-xs">
        <a
          href={`https://attack.mitre.org/techniques/${cell.techniqueId.replace('.', '/')}/`}
          target="_blank"
          rel="noreferrer"
          className="text-blue-400 hover:text-blue-300"
        >
          {cell.techniqueId}
        </a>
        {cell.techniqueName && <span className="ml-2 text-gray-300">{cell.techniqueName}</span>}
      </td>
      <td className="px-5 py-3 text-gray-300">{cell.tactic ?? 'unmapped'}</td>
      <td className="px-5 py-3 text-center text-gray-200">{cell.activeRules}</td>
      <td className="px-5 py-3 text-center text-gray-200">{cell.inactiveRules}</td>
      <td className="px-5 py-3 text-center">
        <span
          className={clsx(
            'inline-block px-2.5 py-0.5 rounded-full text-xs font-medium',
            style.bg,
            style.text,
          )}
        >
          {style.label}
        </span>
      </td>
      <td className="px-5 py-3 text-gray-400">
        {status === 'unenforced' ? (
          // A real navigation to the rules that exist and are switched off,
          // rather than the success toast that used to claim a draft rule had
          // been created and created nothing.
          <Link
            href={`/detection?technique=${encodeURIComponent(cell.techniqueId)}`}
            className="text-xs text-blue-400 hover:text-blue-300 underline underline-offset-2"
          >
            {`Enable one of ${cell.inactiveRules} rule${cell.inactiveRules === 1 ? '' : 's'} disabled`}
          </Link>
        ) : (
          <span className="text-xs text-gray-500">Nothing to do</span>
        )}
      </td>
    </tr>
  );
}
