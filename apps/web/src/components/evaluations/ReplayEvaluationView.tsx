'use client';

/**
 * "Evaluate on your history": triage measured against this tenant's own analysts.
 *
 * Gap-closure Phase 1.4.
 *
 * The rule that shapes this whole view is that **no number appears without the
 * sample size behind it**. A precision of 1.00 across two predictions is not a
 * precision of 1.00 across two hundred, and a page that prints only the ratio
 * has thrown the distinction away. So the headline is rendered inside a block
 * that carries the counts, not above one.
 *
 * The thin-corpus case is the one this view exists to get right. Below the
 * platform's floor of malicious cases the API returns `headline_accuracy: null`
 * with a `headline_withheld_reason`, and this renders the reason in place of
 * the number rather than a dash, a zero or an empty card. Zero would say the
 * agent got every answer wrong, which is a different fact with a different
 * remedy; a dash says nothing at all. The reason says which it is and why.
 *
 * Nothing here is mocked. A failed run shows its own error, an empty list shows
 * an empty state, and a run still going shows its status. There is no
 * fabricated sample report behind any of those.
 */

import { useCallback, useMemo, useState } from 'react';
import useSWR from 'swr';
import { clsx } from 'clsx';
import {
  connectorsApi,
  evaluationsApi,
  type Connector,
  type ReplayCapabilities,
  type ReplayEvaluationDetail,
  type ReplayEvaluationSummary,
  type ReplayExportFormat,
} from '@/lib/api';
import { EmptyState } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';

/** Poll while a run is moving. Stops as soon as it reaches a terminal state. */
const POLL_MS = 3000;

function pct(value: number | null | undefined): string {
  // "not measured" rather than "0%". A rate with no denominator and a rate
  // that genuinely is zero are different facts, and only one of them is a
  // statement about the agent.
  return value === null || value === undefined ? 'not measured' : `${(value * 100).toFixed(1)}%`;
}

function when(value: string | null): string {
  if (!value) return '';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function windowLabel(run: ReplayEvaluationSummary): string {
  const start = new Date(run.window_start);
  const end = new Date(run.window_end);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
    return `${run.window_start} to ${run.window_end}`;
  }
  return `${start.toLocaleDateString()} to ${end.toLocaleDateString()}`;
}

const STATUS_STYLES: Record<string, string> = {
  queued: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
  running: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
  completed: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  failed: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
};

function StatusPill({ status }: { status: string }) {
  return (
    <span
      className={clsx(
        'inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium',
        STATUS_STYLES[status] ?? STATUS_STYLES.queued,
      )}
    >
      {status}
    </span>
  );
}

/**
 * One measurement and the count it was computed over, always together.
 */
function Figure({
  label,
  value,
  over,
}: {
  label: string;
  value: string;
  over: string;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
      <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
      <div className="mt-1 text-2xl font-semibold text-slate-100">{value}</div>
      <div className="mt-1 text-xs text-slate-400">{over}</div>
    </div>
  );
}

// ───────────────────────────────────────────────────────────────────────────
// Starting a run
// ───────────────────────────────────────────────────────────────────────────

function StartPanel({
  capabilities,
  connectors,
  onStarted,
}: {
  capabilities: ReplayCapabilities | undefined;
  connectors: Connector[];
  onStarted: (id: string) => void;
}) {
  const replayable = useMemo(() => {
    // `Connector.type` is the wire field the list route returns; the
    // capabilities route speaks `connector_type`. They are the same value
    // under two names, and this is the only place the two meet.
    const supported = new Set((capabilities?.connectors ?? []).map((c) => c.connector_type));
    return connectors.filter((c) => supported.has(c.type));
  }, [capabilities, connectors]);

  // The chosen connector is derived rather than synchronised into state by an
  // effect. The list arrives asynchronously, and seeding a default from an
  // effect would render one frame with nothing selected and then re-render.
  const [chosen, setChosen] = useState('');
  const connectorId = chosen || replayable[0]?.id || '';
  const [days, setDays] = useState(capabilities?.default_window_days ?? 90);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const start = useCallback(async () => {
    if (!connectorId) return;
    setSubmitting(true);
    setError(null);
    try {
      const until = new Date();
      const since = new Date(until.getTime() - days * 24 * 60 * 60 * 1000);
      const run = await evaluationsApi.start({
        connector_id: connectorId,
        since: since.toISOString(),
        until: until.toISOString(),
      });
      onStarted(run.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start the evaluation.');
    } finally {
      setSubmitting(false);
    }
  }, [connectorId, days, onStarted]);

  if (replayable.length === 0) {
    return (
      <EmptyState
        title="No connected source can be replayed yet"
        description={
          'Replay reads the findings your analysts already closed. It needs a connected ' +
          (capabilities?.connectors ?? []).map((c) => c.label).join(', ') +
          ' instance. Connect one, then come back.'
        }
        action={
          <a
            href="/connectors"
            className="rounded-md bg-sky-600 px-4 py-2 text-sm font-medium text-white"
          >
            Connect a source
          </a>
        }
      />
    );
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5">
      <h2 className="text-sm font-semibold text-slate-200">Run an evaluation</h2>
      <p className="mt-1 max-w-3xl text-sm text-slate-400">
        AiSOC reads the findings your analysts closed in this window, replays them through the
        same triage path production runs, and grades the result against the labels they chose.
        Nothing is written back to your SIEM and no alert, memory or action is created.
      </p>

      <div className="mt-4 flex flex-wrap items-end gap-4">
        <label className="flex flex-col gap-1 text-xs text-slate-400">
          Source
          <select
            className="min-w-[16rem] rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
            value={connectorId}
            onChange={(event) => setChosen(event.target.value)}
          >
            {replayable.map((connector) => (
              <option key={connector.id} value={connector.id}>
                {connector.name}
              </option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1 text-xs text-slate-400">
          Window
          <select
            className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
            value={days}
            onChange={(event) => setDays(Number(event.target.value))}
          >
            {[30, 60, 90, 180, 365].map((option) => (
              <option key={option} value={option}>
                Last {option} days
              </option>
            ))}
          </select>
        </label>

        <button
          type="button"
          onClick={start}
          disabled={submitting || !connectorId}
          className="rounded-md bg-sky-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
        >
          {submitting ? 'Starting...' : 'Evaluate on my history'}
        </button>
      </div>

      {capabilities ? (
        <p className="mt-3 text-xs text-slate-500">
          The earlier {Math.round(capabilities.default_train_fraction * 100)}% of the window fixes
          what the agent is allowed to know; only the later period is graded. A headline accuracy
          is printed only when that period holds at least {capabilities.min_malicious_for_headline}{' '}
          confirmed-malicious cases.
        </p>
      ) : null}

      {error ? <p className="mt-3 text-sm text-rose-400">{error}</p> : null}
    </div>
  );
}

// ───────────────────────────────────────────────────────────────────────────
// The report
// ───────────────────────────────────────────────────────────────────────────

function Headline({ run }: { run: ReplayEvaluationDetail }) {
  const withheld = run.headline_accuracy === null;
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5">
      <div className="grid gap-4 sm:grid-cols-3">
        <Figure
          label="Recall on malicious"
          value={pct(run.malicious_recall)}
          over={`over ${run.malicious_support} confirmed-malicious case${run.malicious_support === 1 ? '' : 's'}`}
        />
        <Figure
          label="Headline accuracy"
          value={withheld ? 'withheld' : pct(run.headline_accuracy)}
          over={withheld ? 'see the reason below' : `over ${run.graded} answered decisions`}
        />
        <Figure
          label="History read"
          value={String(run.findings_read)}
          over={`${run.findings_labelled} carried an analyst label, ${run.decisions_recorded} replayed`}
        />
      </div>

      {withheld && run.headline_withheld_reason ? (
        <p className="mt-4 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">
          {run.headline_withheld_reason}
        </p>
      ) : null}
    </div>
  );
}

/**
 * How the number was produced, next to the number itself.
 *
 * The method block is not a footnote here. A replayed finding carries none of
 * the fusion-stage enrichment a live alert has, and the report says which
 * enrichments are missing; an operator deciding whether to believe a figure
 * needs that on the same screen.
 */
function MethodPanel({ run }: { run: ReplayEvaluationDetail }) {
  const method = (run.method ?? {}) as Record<string, any>;
  const split = (method.split ?? {}) as Record<string, any>;
  const frozen = (method.frozen_context ?? {}) as Record<string, any>;
  const limits: string[] = Array.isArray(method.envelope_limits) ? method.envelope_limits : [];
  const writes = (method.shadow_writes_attempted ?? {}) as Record<string, number>;
  const attempted = Object.values(writes).reduce((total, count) => total + (count || 0), 0);

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5">
      <h3 className="text-sm font-semibold text-slate-200">Method and sample sizes</h3>

      <dl className="mt-3 grid gap-x-8 gap-y-2 text-sm sm:grid-cols-2">
        <div className="flex justify-between gap-4 border-b border-slate-800 py-1">
          <dt className="text-slate-400">Source</dt>
          <dd className="text-slate-200">{run.vendor}</dd>
        </div>
        <div className="flex justify-between gap-4 border-b border-slate-800 py-1">
          <dt className="text-slate-400">Window</dt>
          <dd className="text-slate-200">{windowLabel(run)}</dd>
        </div>
        <div className="flex justify-between gap-4 border-b border-slate-800 py-1">
          <dt className="text-slate-400">Split</dt>
          <dd className="text-slate-200">
            {split.train_findings ?? 0} train / {split.test_findings ?? 0} graded, cut at{' '}
            {when(split.split_at ?? null)}
          </dd>
        </div>
        <div className="flex justify-between gap-4 border-b border-slate-800 py-1">
          <dt className="text-slate-400">Confidence intervals</dt>
          <dd className="text-slate-200">
            bootstrap, {run.bootstrap_resamples} resamples, seed {run.bootstrap_seed}
          </dd>
        </div>
        <div className="flex justify-between gap-4 border-b border-slate-800 py-1">
          <dt className="text-slate-400">Frozen context</dt>
          <dd className="text-slate-200">
            {frozen.statements_frozen ?? 0} statements, {frozen.priors_frozen ?? 0} priors
            {frozen.statements_dropped_after_split
              ? `, ${frozen.statements_dropped_after_split} dropped as later than the split`
              : ''}
          </dd>
        </div>
        <div className="flex justify-between gap-4 border-b border-slate-800 py-1">
          <dt className="text-slate-400">Writes suppressed</dt>
          <dd className="text-slate-200">
            {attempted} attempted, 0 performed
          </dd>
        </div>
      </dl>

      {limits.length > 0 ? (
        <div className="mt-4">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-400">
            What a replayed finding does not carry
          </h4>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-slate-400">
            {limits.map((limit) => (
              <li key={limit}>{limit}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function ExportBar({ id }: { id: string }) {
  const formats: Array<{ format: ReplayExportFormat; label: string }> = [
    { format: 'markdown', label: 'Markdown' },
    { format: 'json', label: 'JSON' },
    { format: 'pdf', label: 'PDF' },
  ];
  const [excludeLatency, setExcludeLatency] = useState(false);

  return (
    <div className="flex flex-wrap items-center gap-3">
      <span className="text-xs uppercase tracking-wide text-slate-400">Export</span>
      {formats.map(({ format, label }) => (
        <a
          key={format}
          href={evaluationsApi.exportUrl(id, format, excludeLatency)}
          className="rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-200 hover:border-slate-500"
        >
          {label}
        </a>
      ))}
      <label className="flex items-center gap-2 text-xs text-slate-400">
        <input
          type="checkbox"
          checked={excludeLatency}
          onChange={(event) => setExcludeLatency(event.target.checked)}
        />
        Exclude wall-clock latency, so two runs over one window compare cleanly
      </label>
    </div>
  );
}

function ReportPanel({ run }: { run: ReplayEvaluationDetail }) {
  if (run.status === 'failed') {
    return (
      <ErrorState
        title="This evaluation did not complete"
        description={
          run.error ??
          'No reason was recorded. Nothing was measured, so no report was produced.'
        }
      />
    );
  }
  if (run.status !== 'completed') {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5 text-sm text-slate-400">
        This evaluation is {run.status}. Replaying a window of findings through triage takes a
        few minutes; the report appears here when it finishes.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Headline run={run} />
      <MethodPanel run={run} />
      <ExportBar id={run.id} />
      <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5">
        <h3 className="text-sm font-semibold text-slate-200">Full report</h3>
        {/*
          Rendered as preformatted text rather than through a Markdown
          renderer. The report embeds connector-supplied values and model
          output (rule ids, vendor names, hallucinated indicator examples),
          and this is the one presentation that cannot turn any of it into
          markup. The same bytes are what the Markdown export downloads.
        */}
        <pre className="mt-3 max-h-[36rem] overflow-auto whitespace-pre-wrap break-words rounded-lg bg-slate-950 p-4 font-mono text-xs leading-relaxed text-slate-300">
          {run.report_markdown}
        </pre>
      </div>
    </div>
  );
}

// ───────────────────────────────────────────────────────────────────────────
// The page
// ───────────────────────────────────────────────────────────────────────────

export function ReplayEvaluationView() {
  const [selected, setSelected] = useState<string | null>(null);

  const { data: capabilities } = useSWR('replay-capabilities', () =>
    evaluationsApi.capabilities(),
  );
  const { data: connectorList } = useSWR('replay-connectors', () => connectorsApi.list());
  // `connectorsApi.list()` returns the envelope, not the array. Unwrapped once
  // here rather than in the panel, so the panel takes a plain list.
  const connectors: Connector[] = Array.isArray(connectorList)
    ? connectorList
    : (connectorList?.connectors ?? []);
  const {
    data: runs,
    error: runsError,
    isLoading,
    mutate: refreshRuns,
  } = useSWR('replay-evaluations', () => evaluationsApi.list(), {
    refreshInterval: POLL_MS,
  });

  const activeId = selected ?? runs?.[0]?.id ?? null;
  const activeSummary = runs?.find((run) => run.id === activeId);

  const { data: detail } = useSWR(
    activeId ? ['replay-evaluation', activeId] : null,
    () => evaluationsApi.get(activeId as string),
    {
      // Stop polling the moment the run stops moving. A terminal run will
      // never change again, and a page left open should not keep asking.
      refreshInterval: activeSummary?.is_terminal ? 0 : POLL_MS,
    },
  );

  const onStarted = useCallback(
    (id: string) => {
      setSelected(id);
      void refreshRuns();
    },
    [refreshRuns],
  );

  return (
    <div className="space-y-6 p-6">
      <header>
        <h1 className="text-xl font-semibold text-slate-100">Evaluate on your history</h1>
        <p className="mt-1 max-w-3xl text-sm text-slate-400">
          Measure AiSOC triage against your own analysts&apos; past decisions, on your own data,
          before trusting it. Every rate below travels with the number of cases it was computed
          over.
        </p>
      </header>

      <StartPanel capabilities={capabilities} connectors={connectors} onStarted={onStarted} />

      {runsError ? (
        <ErrorState title="Could not load past evaluations" error={runsError} />
      ) : null}

      {!runsError && !isLoading && (runs?.length ?? 0) === 0 ? (
        <EmptyState
          title="No evaluation has been run yet"
          description="Start one above. It reads only findings your analysts already closed, and writes nothing back."
        />
      ) : null}

      {(runs?.length ?? 0) > 0 ? (
        <div className="grid gap-6 lg:grid-cols-[18rem_1fr]">
          <aside className="space-y-2">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-slate-400">
              Evaluations
            </h2>
            {runs?.map((run) => (
              <button
                key={run.id}
                type="button"
                onClick={() => setSelected(run.id)}
                className={clsx(
                  'w-full rounded-lg border p-3 text-left',
                  run.id === activeId
                    ? 'border-sky-500/50 bg-sky-500/10'
                    : 'border-slate-800 bg-slate-900/40 hover:border-slate-700',
                )}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm text-slate-200">{run.vendor}</span>
                  <StatusPill status={run.status} />
                </div>
                <div className="mt-1 text-xs text-slate-400">{windowLabel(run)}</div>
                <div className="mt-1 text-xs text-slate-500">
                  {run.status === 'completed'
                    ? `${run.graded} graded, ${run.malicious_support} malicious`
                    : when(run.created_at)}
                </div>
              </button>
            ))}
          </aside>

          <section>{detail ? <ReportPanel run={detail} /> : null}</section>
        </div>
      ) : null}
    </div>
  );
}
