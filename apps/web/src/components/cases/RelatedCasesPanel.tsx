'use client';

import Link from 'next/link';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { format } from 'date-fns';

import { casesApi, getActiveTenantId, type RelatedCase } from '@/lib/api';

const SEVERITY_STYLE: Record<RelatedCase['severity'], string> = {
  critical: 'bg-red-500/15 text-red-300',
  high: 'bg-orange-500/15 text-orange-300',
  medium: 'bg-yellow-500/15 text-yellow-300',
  low: 'bg-blue-500/15 text-blue-300',
  info: 'bg-slate-500/15 text-slate-300',
};

function SharedEvidence({ related }: { related: RelatedCase }) {
  return (
    <div className="mt-3 space-y-2 text-xs">
      {related.shared_alert_count > 0 && (
        <div>
          <p className="text-slate-300">
            {related.shared_alert_count} shared {related.shared_alert_count === 1 ? 'alert' : 'alerts'}
          </p>
          <ul className="mt-1 space-y-1">
            {related.shared_alert_ids.map((id) => (
              <li key={id}>
                <Link
                  href={`/alerts/${encodeURIComponent(id)}`}
                  className="break-all font-mono text-emerald-300 underline decoration-emerald-500/30 hover:decoration-emerald-300"
                >
                  {id}
                </Link>
              </li>
            ))}
          </ul>
          {related.shared_alert_count > related.shared_alert_ids.length && (
            <p className="mt-1 text-slate-400">
              Showing {related.shared_alert_ids.length} of {related.shared_alert_count} shared alerts.
            </p>
          )}
        </div>
      )}
      {related.shared_observable_count > 0 && (
        <div>
          <p className="text-slate-300">
            {related.shared_observable_count} shared{' '}
            {related.shared_observable_count === 1 ? 'observable' : 'observables'}
          </p>
          <ul className="mt-1 space-y-1">
            {related.shared_observables.map(({ kind, value }) => (
              <li key={JSON.stringify([kind, value])} className="flex items-start gap-2">
                <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] uppercase text-slate-400">
                  {kind}
                </span>
                <span className="min-w-0 break-all font-mono text-slate-200">{value}</span>
              </li>
            ))}
          </ul>
          {related.shared_observable_count > related.shared_observables.length && (
            <p className="mt-1 text-slate-400">
              Showing {related.shared_observables.length} of {related.shared_observable_count} shared
              observables.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

/** Read-only case pivots backed by the current tenant's stored evidence. */
export function RelatedCasesPanel({ caseId }: { caseId: string }) {
  const { data, error, isLoading, isValidating, mutate } = useSWR(
    ['case:related', getActiveTenantId(), caseId],
    () => casesApi.getRelated(caseId),
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );

  return (
    <section
      aria-label="Related cases"
      className="space-y-3 rounded-xl border border-slate-800/80 bg-slate-900/40 p-4"
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-200">Related cases</h2>
          <p className="mt-1 text-xs text-slate-400">
            Shared alerts or exact observable matches in this tenant. Review the evidence to decide
            whether the cases belong to the same incident.
          </p>
        </div>
        {!error && (
          <button
            type="button"
            onClick={() => void mutate()}
            disabled={isValidating}
            className="shrink-0 rounded-md border border-slate-700 px-2.5 py-1.5 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-50"
          >
            {isValidating ? 'Refreshing…' : 'Refresh'}
          </button>
        )}
      </div>

      {error ? (
        <div role="alert" className="rounded-md border border-red-500/30 bg-red-500/5 p-3">
          <p className="text-sm text-red-300">Could not load related cases.</p>
          <p className="mt-1 text-xs text-slate-400">Try again to check for shared evidence.</p>
          <button
            type="button"
            onClick={() => void mutate()}
            disabled={isValidating}
            className="mt-2 rounded-md border border-red-500/40 px-2.5 py-1.5 text-xs text-red-200 hover:bg-red-500/10 disabled:opacity-50"
          >
            {isValidating ? 'Retrying…' : 'Retry'}
          </button>
        </div>
      ) : isLoading || !data ? (
        <p role="status" className="text-xs text-slate-400">Finding related cases…</p>
      ) : data.related.length === 0 ? (
        <p className="text-xs text-slate-400">No related cases found</p>
      ) : (
        <>
          <p className="text-xs text-slate-400">
            Ranked by shared alerts, then shared observables, then newest case.
            {data.has_more && ` Showing ${data.related.length} ${data.related.length === 1 ? 'match' : 'matches'}; additional related cases exist.`}
          </p>
          <ul className="grid max-h-[30rem] gap-3 overflow-y-auto md:grid-cols-2 xl:grid-cols-3">
            {data.related.map((related) => (
              <li key={related.id} className="min-w-0 rounded-lg border border-slate-800 bg-slate-950/30 p-3">
                <div className="flex flex-wrap items-center gap-2 text-[11px]">
                  <span className={clsx('rounded px-1.5 py-0.5 font-semibold uppercase', SEVERITY_STYLE[related.severity])}>
                    {related.severity}
                  </span>
                  <span className="capitalize text-slate-400">{related.status}</span>
                </div>
                <Link
                  href={`/cases/${encodeURIComponent(related.id)}`}
                  className="mt-2 block break-words text-sm font-medium text-emerald-200 hover:underline"
                >
                  <span className="mr-2 font-mono text-xs text-slate-400">{related.case_number || related.id}</span>
                  {related.title}
                </Link>
                {related.created_at && (
                  <p className="mt-1 text-[11px] text-slate-400">
                    Created{' '}
                    <time dateTime={related.created_at} suppressHydrationWarning>
                      {format(new Date(related.created_at), 'MMM d, yyyy HH:mm')}
                    </time>
                  </p>
                )}
                <SharedEvidence related={related} />
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
