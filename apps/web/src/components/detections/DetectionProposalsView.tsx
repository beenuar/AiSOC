'use client';

// Wave 2 — w2-dac. Lightweight queue for the detection-as-code lifecycle:
// propose → review (comment / attach eval report) → eval-gated → promote.
// Backend at /api/v1/detection-proposals enforces the ≥ 1pp MITRE
// regression gate against the active baseline; this UI is a thin operator
// surface for that pipeline.

import { useState } from 'react';
import Link from 'next/link';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { formatDistanceToNow } from 'date-fns';
import toast from 'react-hot-toast';
import {
  detectionProposalsApi,
  type DetectionProposal,
  type DetectionProposalStatus,
} from '@/lib/api';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorState } from '@/components/ui/ErrorState';
import { EmptyState } from '@/components/ui/EmptyState';

const STATUS_COPY: Record<
  DetectionProposalStatus,
  { label: string; tone: string }
> = {
  proposed: { label: 'Proposed', tone: 'bg-gray-700/40 text-gray-200' },
  in_review: { label: 'In review', tone: 'bg-blue-500/20 text-blue-200' },
  eval_passed: {
    label: 'Eval passed',
    tone: 'bg-emerald-500/20 text-emerald-200',
  },
  eval_failed: { label: 'Eval failed', tone: 'bg-red-500/20 text-red-200' },
  approved: { label: 'Approved', tone: 'bg-emerald-500/20 text-emerald-200' },
  rejected: { label: 'Rejected', tone: 'bg-red-500/20 text-red-200' },
  promoted: { label: 'Promoted', tone: 'bg-violet-500/20 text-violet-200' },
};

function fmtPct(n?: number): string {
  if (n === undefined || n === null || Number.isNaN(n)) return '—';
  return `${(n * 100).toFixed(1)}%`;
}

export function DetectionProposalsView() {
  const [filter, setFilter] = useState<DetectionProposalStatus | 'all'>('all');

  const { data, error, isLoading, mutate } = useSWR(
    ['detection-proposals', filter],
    () =>
      detectionProposalsApi.list(
        filter === 'all' ? undefined : { status: filter },
      ),
  );

  const proposals = data ?? [];

  const decide = async (
    p: DetectionProposal,
    decision: 'approve' | 'reject',
  ) => {
    try {
      await detectionProposalsApi.decide(p.id, { decision });
      toast.success(decision === 'approve' ? 'Approved' : 'Rejected');
      mutate();
    } catch (err) {
      console.warn(`Decide ${decision} failed`, err);
      toast.error(`Could not ${decision} proposal`);
    }
  };

  const promote = async (p: DetectionProposal) => {
    try {
      const result = await detectionProposalsApi.promote(p.id);
      // WS-B4: git PR path — Author: Beenu - beenu@cyble.com
      // If a GitHub PR was created, surface the URL in the success toast so
      // the operator can jump directly to the PR without hunting for it.
      if (result?.github_pr_url) {
        toast.success(
          <span>
            Promoted to active rule —{' '}
            <a
              href={result.github_pr_url}
              target="_blank"
              rel="noopener noreferrer"
              className="underline"
            >
              Open PR
            </a>
          </span>,
        );
      } else {
        toast.success('Promoted to active rule');
      }
      mutate();
    } catch (err) {
      console.warn('Promote failed', err);
      toast.error('Promote blocked — check eval gate');
    }
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-gray-100">
            Detection proposals
          </h1>
          <p className="mt-1 max-w-2xl text-sm text-gray-500">
            Detection-as-code lifecycle. Every proposal is graded by{' '}
            <code className="rounded bg-gray-800 px-1 py-0.5 text-xs text-gray-300">
              run_evals.py
            </code>{' '}
            and a ≥ 1pp MITRE accuracy regression vs. the active baseline
            blocks promotion to a live rule.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link
            href="/detection"
            className="rounded-md border border-gray-800 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800"
          >
            ← Active rules
          </Link>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        {(['all', ...(Object.keys(STATUS_COPY) as DetectionProposalStatus[])] as Array<
          DetectionProposalStatus | 'all'
        >).map((opt) => (
          <button
            key={opt}
            onClick={() => setFilter(opt)}
            className={clsx(
              'rounded-md border px-3 py-1.5 text-xs transition-colors',
              filter === opt
                ? 'border-blue-500/40 bg-blue-500/10 text-blue-200'
                : 'border-gray-800 text-gray-400 hover:bg-gray-800/50',
            )}
          >
            {opt === 'all' ? 'All' : STATUS_COPY[opt].label}
          </button>
        ))}
      </div>

      {isLoading ? (
        <div className="space-y-3">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-28 w-full" />
          ))}
        </div>
      ) : error ? (
        <ErrorState
          title="Couldn't load proposals"
          description="The detection-as-code service didn't respond."
          error={error}
          onRetry={() => mutate()}
        />
      ) : proposals.length === 0 ? (
        <EmptyState
          title="No proposals yet"
          description="Proposals appear here as soon as someone POSTs to /api/v1/detection-proposals or imports a detection from the catalog with the eval gate enabled."
        />
      ) : (
        <ul className="space-y-3">
          {proposals.map((p) => (
            <li
              key={p.id}
              className="rounded-lg border border-gray-800 bg-gray-900/40 p-4"
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={clsx(
                        'rounded px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide',
                        STATUS_COPY[p.status].tone,
                      )}
                    >
                      {STATUS_COPY[p.status].label}
                    </span>
                    <h3 className="truncate text-base font-medium text-gray-100">
                      {p.name}
                    </h3>
                    <span className="text-xs text-gray-500">
                      {p.rule_language.toUpperCase()} · {p.severity}
                    </span>
                  </div>
                  {p.description && (
                    <p className="mt-1 text-sm text-gray-400">
                      {p.description}
                    </p>
                  )}
                  <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-gray-500">
                    <span suppressHydrationWarning>
                      Updated{' '}
                      {formatDistanceToNow(new Date(p.updated_at), {
                        addSuffix: true,
                      })}
                    </span>
                    {p.mitre_techniques?.length > 0 && (
                      <span>MITRE: {p.mitre_techniques.join(', ')}</span>
                    )}
                  </div>
                  {p.eval_result && 'candidate' in p.eval_result && (
                    <div className="mt-3 grid grid-cols-2 gap-3 rounded-md border border-gray-800 bg-gray-950/60 p-3 text-xs sm:grid-cols-4">
                      <div>
                        <div className="text-gray-500">Candidate MITRE</div>
                        <div className="font-mono text-gray-200">
                          {fmtPct(p.eval_result.candidate?.mitre_accuracy)}
                        </div>
                      </div>
                      <div>
                        <div className="text-gray-500">Baseline MITRE</div>
                        <div className="font-mono text-gray-200">
                          {fmtPct(p.eval_result.baseline?.mitre_accuracy)}
                        </div>
                      </div>
                      <div>
                        <div className="text-gray-500">Regression</div>
                        <div
                          className={clsx(
                            'font-mono',
                            p.eval_result.regressed
                              ? 'text-red-300'
                              : 'text-emerald-300',
                          )}
                        >
                          {p.eval_result.drop_pp !== undefined
                            ? `${(p.eval_result.drop_pp * 100).toFixed(2)}pp`
                            : '—'}
                        </div>
                      </div>
                      <div>
                        <div className="text-gray-500">Gate</div>
                        <div
                          className={clsx(
                            'font-medium',
                            p.eval_result.passed
                              ? 'text-emerald-300'
                              : 'text-red-300',
                          )}
                        >
                          {p.eval_result.passed ? 'PASS' : 'FAIL'}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
                <div className="flex shrink-0 flex-col gap-2">
                  {p.status === 'eval_passed' || p.status === 'in_review' ? (
                    <>
                      <button
                        onClick={() => decide(p, 'approve')}
                        className="rounded-md bg-emerald-500/20 px-3 py-1.5 text-xs font-medium text-emerald-200 hover:bg-emerald-500/30"
                      >
                        Approve
                      </button>
                      <button
                        onClick={() => decide(p, 'reject')}
                        className="rounded-md border border-red-500/40 px-3 py-1.5 text-xs text-red-300 hover:bg-red-500/10"
                      >
                        Reject
                      </button>
                    </>
                  ) : null}
                  {p.status === 'approved' && (
                    <button
                      onClick={() => promote(p)}
                      className="rounded-md bg-violet-500/20 px-3 py-1.5 text-xs font-medium text-violet-200 hover:bg-violet-500/30"
                    >
                      Promote → Active
                    </button>
                  )}
                  {/* WS-B4: git PR path — Author: Beenu - beenu@cyble.com
                      For already-promoted proposals that have an associated GitHub PR,
                      surface a direct link in the card footer so operators don't need
                      to re-trigger promotion to find the PR. */}
                  {p.github_pr_url && (
                    <a
                      href={p.github_pr_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 rounded-md bg-sky-500/10 px-3 py-1.5 text-xs font-medium text-sky-300 hover:bg-sky-500/20"
                    >
                      <svg
                        className="h-3.5 w-3.5"
                        viewBox="0 0 16 16"
                        fill="currentColor"
                        aria-hidden="true"
                      >
                        <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
                      </svg>
                      View PR
                    </a>
                  )}
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
