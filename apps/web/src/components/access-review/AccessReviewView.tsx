'use client';

/**
 * Access review (depth plan wave 2, 1.2).
 *
 * Read-only. Nothing on this page changes a vendor object: every finding
 * names the object a person should change and stops there. The one write is
 * acknowledging a finding, which records a decision about the review rather
 * than touching the estate.
 *
 * The empty states carry the weight
 * ---------------------------------
 * Three of them, and they are deliberately different sentences:
 *
 * - **never run** — no review has happened. Not a clean bill of health.
 * - **nothing reviewed** — a review ran over zero principals, because no
 *   posture has been collected for that provider.
 * - **no findings** — a review ran over a real inventory and found nothing.
 *
 * Only the third is good news. Rendering all three as "0 findings" would
 * present an estate nobody looked at as an estate with nothing wrong, which
 * is the single most reassuring thing this page could get wrong.
 *
 * A fourth state is rendered per provider rather than globally: a review
 * where `usage_measured_for` is below `reviewed_principals` is partial, and
 * the unused-access, dormancy and right-sizing findings were not computed
 * at all for the remainder. That is said in words next to the counts.
 */

import { useCallback, useEffect, useState } from 'react';

import {
  accessReviewApi,
  type AccessReviewFinding,
  type AccessReviewSummary,
} from '@/lib/api';

const PROVIDERS = ['aws', 'azure', 'gcp', 'gws', 'github', 'okta'] as const;

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-300 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  medium: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  low: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
  info: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
};

export function AccessReviewView() {
  const [summary, setSummary] = useState<AccessReviewSummary | null>(null);
  const [findings, setFindings] = useState<AccessReviewFinding[]>([]);
  const [provider, setProvider] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  // An error is rendered as an error. The repository's recorded defect here
  // is a catch block that falls back to plausible-looking data, so a failed
  // read must never be indistinguishable from a clean review.
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [nextSummary, nextFindings] = await Promise.all([
        accessReviewApi.summary(provider || undefined),
        accessReviewApi.findings({ provider: provider || undefined }),
      ]);
      setSummary(nextSummary);
      setFindings(nextFindings.items);
    } catch (err) {
      setSummary(null);
      setFindings([]);
      setError(
        err instanceof Error
          ? `The access review could not be loaded: ${err.message}. This is a read failure, not an empty review.`
          : 'The access review could not be loaded. This is a read failure, not an empty review.',
      );
    } finally {
      setLoading(false);
    }
  }, [provider]);

  useEffect(() => {
    void load();
  }, [load]);

  const runFor = async (target: string) => {
    setRunning(true);
    setError(null);
    try {
      await accessReviewApi.run(target);
      await load();
    } catch (err) {
      setError(
        err instanceof Error
          ? `The review could not be run: ${err.message}`
          : 'The review could not be run.',
      );
    } finally {
      setRunning(false);
    }
  };

  const acknowledge = async (finding: AccessReviewFinding) => {
    const note = window.prompt(
      `Acknowledge "${finding.title}" for ${finding.principal_id}. Why is this acceptable?`,
      '',
    );
    if (note === null) return;
    try {
      await accessReviewApi.acknowledge(finding.id, note);
      await load();
    } catch (err) {
      setError(
        err instanceof Error ? `The acknowledgement failed: ${err.message}` : 'The acknowledgement failed.',
      );
    }
  };

  return (
    <div className="space-y-6 p-6">
      <header className="space-y-2">
        <h1 className="text-2xl font-semibold">Access review</h1>
        <p className="max-w-3xl text-sm text-slate-400">
          What each principal was granted, through which object, and whether it was used.
          This page is read-only: every finding names the object to change and nothing here
          changes it for you.
        </p>
      </header>

      <div className="flex flex-wrap items-center gap-3">
        <label className="text-sm text-slate-400" htmlFor="access-review-provider">
          Provider
        </label>
        <select
          id="access-review-provider"
          className="rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm"
          value={provider}
          onChange={(event) => setProvider(event.target.value)}
        >
          <option value="">All</option>
          {PROVIDERS.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
        {PROVIDERS.map((p) => (
          <button
            key={p}
            type="button"
            disabled={running}
            onClick={() => void runFor(p)}
            className="rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:border-slate-500 disabled:opacity-50"
          >
            {running ? 'Running…' : `Review ${p}`}
          </button>
        ))}
      </div>

      {error ? (
        <div className="rounded border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">
          {error}
        </div>
      ) : null}

      {loading ? <p className="text-sm text-slate-400">Loading…</p> : null}

      {!loading && !error && summary?.state === 'never_run' ? (
        <div className="rounded border border-slate-700 bg-slate-900/60 p-5">
          <h2 className="text-base font-medium">Nothing has been reviewed yet</h2>
          <p className="mt-2 max-w-2xl text-sm text-slate-400">{summary.note}</p>
        </div>
      ) : null}

      {!loading && !error && summary?.state === 'reviewed' ? (
        <section className="space-y-3">
          <h2 className="text-base font-medium">Coverage</h2>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {summary.providers.map((row) => (
              <article key={row.provider} className="rounded border border-slate-700 bg-slate-900/60 p-4">
                <div className="flex items-baseline justify-between">
                  <h3 className="text-sm font-medium uppercase tracking-wide text-slate-300">
                    {row.provider}
                  </h3>
                  <span className="text-xs text-slate-500">
                    {row.last_run_at ? new Date(row.last_run_at).toLocaleString() : 'never'}
                  </span>
                </div>

                {row.run_state === 'nothing_reviewed' ? (
                  <p className="mt-3 text-sm text-amber-300">
                    Nothing reviewed — no posture has been collected for this provider. This is
                    not a clean bill of health.
                  </p>
                ) : (
                  <dl className="mt-3 space-y-1 text-sm text-slate-400">
                    <div className="flex justify-between">
                      <dt>Principals reviewed</dt>
                      <dd className="text-slate-200">{row.reviewed_principals}</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt>Open findings</dt>
                      <dd className="text-slate-200">{row.finding_count}</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt>Usage measured for</dt>
                      <dd className="text-slate-200">
                        {row.usage_measured_for} / {row.reviewed_principals}
                      </dd>
                    </div>
                  </dl>
                )}

                {row.note ? <p className="mt-3 text-xs text-amber-300/90">{row.note}</p> : null}

                {row.run_state === 'no_findings' ? (
                  <p className="mt-3 text-sm text-emerald-300">
                    Reviewed, nothing found.
                  </p>
                ) : null}
              </article>
            ))}
          </div>
        </section>
      ) : null}

      {!loading && !error && summary?.state === 'reviewed' ? (
        <section className="space-y-3">
          <h2 className="text-base font-medium">
            Findings{findings.length ? ` (${findings.length})` : ''}
          </h2>

          {findings.length === 0 ? (
            <p className="text-sm text-slate-400">
              No open findings for the selected provider. Check the coverage cards above for
              whether that is because nothing was wrong or because nothing could be reviewed.
            </p>
          ) : (
            <ul className="space-y-3">
              {findings.map((finding) => (
                <li
                  key={finding.id}
                  className="rounded border border-slate-700 bg-slate-900/60 p-4 space-y-2"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`rounded border px-2 py-0.5 text-xs uppercase ${
                        SEVERITY_STYLES[finding.severity] ?? SEVERITY_STYLES.info
                      }`}
                    >
                      {finding.severity}
                    </span>
                    <span className="text-xs uppercase tracking-wide text-slate-500">
                      {finding.provider}
                    </span>
                    <h3 className="text-sm font-medium text-slate-100">{finding.title}</h3>
                  </div>

                  <p className="font-mono text-xs text-slate-400">{finding.principal_id}</p>
                  <p className="text-sm text-slate-300">{finding.detail}</p>

                  <div className="rounded bg-slate-950/60 p-3 text-sm">
                    <p className="text-slate-400">
                      <span className="text-slate-500">Change: </span>
                      {finding.object_hint}
                    </p>
                    <p className="mt-1 text-slate-300">{finding.recommendation}</p>
                    {finding.best_fit_role ? (
                      <p className="mt-1 text-slate-300">
                        <span className="text-slate-500">Smallest role covering what was used: </span>
                        <code>{finding.best_fit_role}</code>
                      </p>
                    ) : null}
                  </div>

                  {!finding.usage_measured ? (
                    <p className="text-xs text-amber-300/90">
                      Usage was not measured for this principal, so this finding was computed from
                      the grant alone.
                    </p>
                  ) : null}

                  <button
                    type="button"
                    onClick={() => void acknowledge(finding)}
                    className="rounded border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500"
                  >
                    Acknowledge
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      ) : null}
    </div>
  );
}
