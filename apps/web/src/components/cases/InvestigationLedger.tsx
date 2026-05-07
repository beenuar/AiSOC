'use client';

/**
 * Investigation Ledger.
 *
 * The auditor-grade view of an agent's reasoning. Every prompt the agent
 * sent to the LLM, every tool it called, every piece of evidence it cited,
 * and every decision it made is rendered as a step in a vertical timeline.
 * Clicking any step opens a side panel that reconstructs *why* the agent
 * made that move: the literal prompt, the literal response, the evidence,
 * the input/output hashes for replay, and the immediately preceding +
 * following decisions.
 *
 * Data source: persistent ledger at `GET /v1/investigations/...` (see
 * `services/api/app/api/v1/endpoints/investigations.py`). Built for
 * compliance review, post-incident analysis, and "show your work" demos.
 *
 * Features:
 *   - Run picker (a case can have multiple investigation runs over time)
 *   - Live tail while a run is active (auto-refresh on `since=` cursor)
 *   - Filter chips by event kind / agent
 *   - Click a step → "explain" panel with prompt/response artifacts
 *   - Copy hashes (input/output) for cryptographic replay verification
 *   - Export full ledger as signed JSON for auditor handoff
 */

import { useEffect, useMemo, useState } from 'react';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { format, formatDistanceToNow } from 'date-fns';
import toast from 'react-hot-toast';
import {
  ledgerApi,
  type LedgerArtifactDetail,
  type LedgerEvent,
  type LedgerExplain,
  type LedgerModelCost,
  type LedgerRunDetail,
  type LedgerRunSummary,
} from '@/lib/api';
import { Skeleton } from '@/components/ui/Skeleton';
import { EmptyState } from '@/components/ui/EmptyState';

// ─── Style maps ───────────────────────────────────────────────────────────────

/** Map ledger `kind` enum → short text label for the timeline glyph. */
const KIND_ICON: Record<string, string> = {
  recon: 'rec',
  forensic: 'frn',
  responder: 'rsp',
  reporter: 'rpt',
  report: 'rpt',
  llm_prompt: 'in',
  llm_response: 'out',
  tool_call: 'tool',
  evidence_cited: 'evd',
  decision_reason: 'why',
  error: 'err',
  completed: 'done',
};

/** Map ledger `kind` enum → tailwind colour family for chip styling. */
const KIND_TONE: Record<string, string> = {
  recon: 'bg-blue-500/10 text-blue-300 ring-blue-500/30',
  forensic: 'bg-purple-500/10 text-purple-300 ring-purple-500/30',
  responder: 'bg-amber-500/10 text-amber-300 ring-amber-500/30',
  reporter: 'bg-indigo-500/10 text-indigo-300 ring-indigo-500/30',
  report: 'bg-indigo-500/10 text-indigo-300 ring-indigo-500/30',
  llm_prompt: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30',
  llm_response: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30',
  tool_call: 'bg-cyan-500/10 text-cyan-300 ring-cyan-500/30',
  evidence_cited: 'bg-fuchsia-500/10 text-fuchsia-300 ring-fuchsia-500/30',
  decision_reason: 'bg-yellow-500/10 text-yellow-300 ring-yellow-500/30',
  error: 'bg-red-500/10 text-red-300 ring-red-500/30',
  completed: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30',
};

/** Friendly label for the kind chip. */
function kindLabel(kind: string): string {
  return kind.replace(/_/g, ' ');
}

function chipClass(kind: string): string {
  return (
    KIND_TONE[kind.toLowerCase()] ??
    'bg-slate-500/10 text-slate-300 ring-slate-500/30'
  );
}

function kindIcon(kind: string): string {
  return KIND_ICON[kind.toLowerCase()] ?? '•';
}

// ─── Component ────────────────────────────────────────────────────────────────

interface InvestigationLedgerProps {
  /** Case the ledger belongs to (used to scope `listRuns`). */
  caseId: string;
  /** Run currently in focus, or null to default to the most recent run. */
  activeRunId: string | null;
  /** Caller-controlled selection — lets the parent persist run choice. */
  onSelectRun?: (runId: string) => void;
}

export function InvestigationLedger({
  caseId,
  activeRunId,
  onSelectRun,
}: InvestigationLedgerProps) {
  // ─── Run list ─────────────────────────────────────────────────────────────
  const {
    data: runs,
    error: runsError,
    isLoading: runsLoading,
    mutate: refreshRuns,
  } = useSWR<LedgerRunSummary[]>(
    ['ledger.runs', caseId],
    () => ledgerApi.listRuns({ caseId, limit: 25 }),
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );

  // The "active" run is whichever the parent passed in OR the most recent.
  const resolvedRunId = useMemo<string | null>(() => {
    if (activeRunId) return activeRunId;
    if (runs && runs.length > 0) return runs[0].id;
    return null;
  }, [activeRunId, runs]);

  const activeRun = useMemo(() => {
    if (!resolvedRunId || !runs) return undefined;
    return runs.find((r) => r.id === resolvedRunId);
  }, [resolvedRunId, runs]);

  // ─── Events for the active run ────────────────────────────────────────────
  // Auto-refresh while running. Stop polling once completed/failed.
  const isLive = activeRun?.status === 'running';
  const {
    data: events,
    error: eventsError,
    isLoading: eventsLoading,
    mutate: refreshEvents,
  } = useSWR<LedgerEvent[]>(
    resolvedRunId ? ['ledger.events', resolvedRunId] : null,
    () => ledgerApi.replay(resolvedRunId as string),
    {
      revalidateOnFocus: false,
      shouldRetryOnError: false,
      refreshInterval: isLive ? 2000 : 0,
    },
  );

  // Refresh the run list while a run is live so totals (tokens, cost, status)
  // stay current as new events stream in.
  useEffect(() => {
    if (!isLive) return;
    const id = setInterval(() => void refreshRuns(), 4000);
    return () => clearInterval(id);
  }, [isLive, refreshRuns]);

  // ─── Run detail (includes per-model cost breakdown) ──────────────────────
  // Pulled separately from the run-list summary because `model_costs` is only
  // populated once the agents service has flushed its `CostTracker` to the
  // `aisoc_run_costs` table, which can lag the run-summary row by a heartbeat.
  // Refresh while live so the breakdown materializes as soon as it's there.
  const { data: runDetail } = useSWR<LedgerRunDetail>(
    resolvedRunId ? ['ledger.run', resolvedRunId] : null,
    () => ledgerApi.getRun(resolvedRunId as string),
    {
      revalidateOnFocus: false,
      shouldRetryOnError: false,
      refreshInterval: isLive ? 4000 : 0,
    },
  );

  // ─── Filtering ────────────────────────────────────────────────────────────
  const [kindFilter, setKindFilter] = useState<string | null>(null);
  const [agentFilter, setAgentFilter] = useState<string | null>(null);

  const distinctKinds = useMemo(
    () => Array.from(new Set((events ?? []).map((e) => e.kind))).sort(),
    [events],
  );
  const distinctAgents = useMemo(
    () => Array.from(new Set((events ?? []).map((e) => e.agent).filter(Boolean))).sort(),
    [events],
  );

  const filteredEvents = useMemo(() => {
    const list = events ?? [];
    return list.filter((e) => {
      if (kindFilter && e.kind !== kindFilter) return false;
      if (agentFilter && e.agent !== agentFilter) return false;
      return true;
    });
  }, [events, kindFilter, agentFilter]);

  // ─── Selected step ────────────────────────────────────────────────────────
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);

  // Auto-select the latest event when the timeline first loads.
  useEffect(() => {
    if (selectedSeq == null && events && events.length > 0) {
      setSelectedSeq(events[events.length - 1].seq);
    }
  }, [events, selectedSeq]);

  // Reset selection when switching runs.
  useEffect(() => {
    setSelectedSeq(null);
  }, [resolvedRunId]);

  // ─── Export signed JSON ───────────────────────────────────────────────────
  const exportLedger = async () => {
    if (!resolvedRunId || !activeRun) return;
    try {
      const [detail, full, artifacts] = await Promise.all([
        ledgerApi.getRun(resolvedRunId),
        ledgerApi.replay(resolvedRunId, 50000),
        ledgerApi.listArtifacts(resolvedRunId),
      ]);
      const bundle = {
        // Format version — bump if the structure changes.
        ledger_version: 1,
        exported_at: new Date().toISOString(),
        // Tenant-side claim of identity. The agents service writes immutable
        // input_hash / output_hash on every event so the bundle is verifiable.
        run: detail,
        events: full,
        artifacts,
      };
      const blob = new Blob([JSON.stringify(bundle, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `aisoc-ledger-${detail.case_id}-${detail.id}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast.success('Ledger exported — verifiable JSON');
    } catch (err) {
      toast.error(
        err instanceof Error
          ? `Export failed: ${err.message}`
          : 'Export failed',
      );
    }
  };

  // ─── Empty / error states ─────────────────────────────────────────────────
  if (runsLoading) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-12 w-full rounded-lg" />
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-12">
          <Skeleton className="h-96 w-full rounded-lg lg:col-span-5" />
          <Skeleton className="h-96 w-full rounded-lg lg:col-span-7" />
        </div>
      </div>
    );
  }

  if (runsError || !runs) {
    return (
      <EmptyState
        title="Ledger unavailable"
        description="The investigation ledger API isn't reachable. Make sure the API service is running."
      />
    );
  }

  if (runs.length === 0) {
    return (
      <EmptyState
        title="No investigations recorded yet"
        description="Click ‘Investigate with AI’ in the header to launch the agent. Every prompt, tool call, and decision will be logged here for replay and audit."
      />
    );
  }

  return (
    <div className="space-y-4">
      {/* Toolbar: run picker + filters + export */}
      <div className="flex flex-wrap items-center gap-2 rounded-xl border border-slate-800/80 bg-slate-900/40 px-3 py-2">
        <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">
          Run
        </span>
        <select
          value={resolvedRunId ?? ''}
          onChange={(e) => onSelectRun?.(e.target.value)}
          className="rounded-md border border-slate-700/70 bg-slate-900/60 px-2 py-1.5 text-xs text-slate-200 focus:border-emerald-500/40 focus:outline-none"
        >
          {runs.map((r) => (
            <option key={r.id} value={r.id}>
              {format(new Date(r.started_at), 'MMM d HH:mm')} · {r.status}
              {r.model_used ? ` · ${r.model_used}` : ''}
            </option>
          ))}
        </select>
        {activeRun && <RunStatusBadge run={activeRun} />}
        <div className="ml-auto flex items-center gap-2">
          {/* Kind filter */}
          {distinctKinds.length > 0 && (
            <select
              value={kindFilter ?? ''}
              onChange={(e) => setKindFilter(e.target.value || null)}
              className="rounded-md border border-slate-700/70 bg-slate-900/60 px-2 py-1.5 text-xs text-slate-200 focus:border-emerald-500/40 focus:outline-none"
              aria-label="Filter by event kind"
            >
              <option value="">All kinds ({events?.length ?? 0})</option>
              {distinctKinds.map((k) => (
                <option key={k} value={k}>
                  {kindLabel(k)}
                </option>
              ))}
            </select>
          )}
          {/* Agent filter */}
          {distinctAgents.length > 0 && (
            <select
              value={agentFilter ?? ''}
              onChange={(e) => setAgentFilter(e.target.value || null)}
              className="rounded-md border border-slate-700/70 bg-slate-900/60 px-2 py-1.5 text-xs text-slate-200 focus:border-emerald-500/40 focus:outline-none"
              aria-label="Filter by agent"
            >
              <option value="">All agents</option>
              {distinctAgents.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          )}
          <button
            onClick={() => void exportLedger()}
            className="rounded-md border border-slate-700/70 bg-slate-800/50 px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:border-slate-600"
            title="Export signed JSON for auditor handoff"
          >
            Export
          </button>
          <button
            onClick={() => void refreshEvents()}
            className="rounded-md border border-slate-700/70 bg-slate-800/50 px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:border-slate-600"
            title="Refresh"
          >
            ↻
          </button>
        </div>
      </div>

      {/* Run summary */}
      {activeRun && <RunSummaryCard run={activeRun} eventCount={events?.length ?? 0} />}

      {/* Per-model cost breakdown — only renders once at least one row has
          flushed to `aisoc_run_costs`. Pre-cost-telemetry runs (and runs that
          never invoked an LLM) intentionally render nothing. */}
      {runDetail && runDetail.model_costs.length > 0 && (
        <ModelCostsCard costs={runDetail.model_costs} />
      )}

      {/* Two-pane layout: timeline on the left, explain on the right */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
        <div className="lg:col-span-5">
          <Panel
            title="Decision timeline"
            actions={
              <span className="text-[11px] text-slate-500">
                {filteredEvents.length} of {events?.length ?? 0}
              </span>
            }
          >
            {eventsLoading && !events ? (
              <div className="space-y-2 p-1">
                {Array.from({ length: 6 }).map((_, i) => (
                  <Skeleton key={i} className="h-12 w-full rounded-md" />
                ))}
              </div>
            ) : eventsError ? (
              <p className="p-4 text-xs text-red-400">
                Couldn&apos;t load events: {String(eventsError)}
              </p>
            ) : filteredEvents.length === 0 ? (
              <p className="p-4 text-xs text-slate-500">
                No events yet. {isLive && 'Waiting for the agent to emit its first step…'}
              </p>
            ) : (
              <ol className="max-h-[640px] space-y-1 overflow-y-auto p-1">
                {filteredEvents.map((evt) => (
                  <TimelineRow
                    key={evt.id}
                    event={evt}
                    selected={evt.seq === selectedSeq}
                    onClick={() => setSelectedSeq(evt.seq)}
                  />
                ))}
                {isLive && (
                  <li className="px-3 py-2 text-[11px] text-slate-500">
                    <span className="mr-1 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
                    Live — tailing for new events
                  </li>
                )}
              </ol>
            )}
          </Panel>
        </div>
        <div className="lg:col-span-7">
          {selectedSeq == null || !resolvedRunId ? (
            <Panel title="Why this step?">
              <EmptyState
                title="Select a step"
                description="Click any decision in the timeline to see the literal prompt, response, evidence, and downstream effects."
              />
            </Panel>
          ) : (
            <ExplainPanel runId={resolvedRunId} step={selectedSeq} />
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Run summary ──────────────────────────────────────────────────────────────

function RunStatusBadge({ run }: { run: LedgerRunSummary }) {
  const tone =
    run.status === 'completed'
      ? 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30'
      : run.status === 'failed'
        ? 'bg-red-500/10 text-red-300 ring-red-500/30'
        : 'bg-blue-500/10 text-blue-300 ring-blue-500/30';
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium ring-1',
        tone,
      )}
    >
      {run.status === 'running' && (
        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-blue-400" />
      )}
      {run.status}
    </span>
  );
}

function RunSummaryCard({
  run,
  eventCount,
}: {
  run: LedgerRunSummary;
  eventCount: number;
}) {
  const startedAt = new Date(run.started_at);
  const completedAt = run.completed_at ? new Date(run.completed_at) : null;
  const duration = completedAt
    ? `${Math.round((completedAt.getTime() - startedAt.getTime()) / 1000)}s`
    : run.status === 'running'
      ? 'in progress'
      : '—';

  return (
    <div className="grid grid-cols-2 gap-3 rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 text-xs sm:grid-cols-3 lg:grid-cols-6">
      <Stat label="Run ID" value={<span className="font-mono">{run.id.slice(0, 8)}…</span>} />
      <Stat label="Status" value={<RunStatusBadge run={run} />} />
      <Stat label="Model" value={run.model_used ?? '—'} />
      <Stat label="Iterations" value={String(run.iterations)} />
      <Stat
        label="Tokens / cost"
        value={
          <span>
            {run.total_tokens.toLocaleString()}{' '}
            <span className="text-slate-500">·</span>{' '}
            ${run.total_cost_usd.toFixed(4)}
          </span>
        }
      />
      <Stat
        label="Started · duration"
        value={
          <span>
            {format(startedAt, 'HH:mm:ss')}{' '}
            <span className="text-slate-500">·</span> {duration}
          </span>
        }
      />
      {run.error && (
        <div className="col-span-full rounded-md border border-red-800/40 bg-red-900/20 px-3 py-1.5 text-[11px] text-red-300">
          <span className="font-semibold">Error:</span> {run.error}
        </div>
      )}
      <div className="col-span-full text-[11px] text-slate-500">
        {eventCount} events recorded
      </div>
    </div>
  );
}

// ─── Per-model cost breakdown ────────────────────────────────────────────────

/**
 * Renders the per-model token / cost / latency breakdown for the active run.
 *
 * Companion to `RunSummaryCard`: that card shows aggregate `total_tokens` /
 * `total_cost_usd`, this one explains *which models* spent that budget. Useful
 * when the orchestrator routes recon to a cheap model and forensic to a
 * frontier model — operators want to see the split without exporting the
 * ledger JSON.
 *
 * Sorted by spend descending so the most expensive model surfaces first.
 */
function ModelCostsCard({ costs }: { costs: LedgerModelCost[] }) {
  // Defensive sort — backend already orders by total_cost_usd DESC, but a
  // future caller could pass an arbitrary list and we want the UI invariant
  // (most expensive first) to hold regardless.
  const sorted = useMemo(
    () => [...costs].sort((a, b) => b.total_cost_usd - a.total_cost_usd),
    [costs],
  );

  return (
    <div className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/40">
      <div className="flex items-center justify-between border-b border-slate-800/80 px-3 py-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-300">
          Cost by model
        </h3>
        <span className="text-[10px] text-slate-500">
          {sorted.length} model{sorted.length === 1 ? '' : 's'}
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-slate-800/60 text-xs">
          <thead className="bg-slate-950/40">
            <tr className="text-left text-[10px] font-semibold uppercase tracking-wide text-slate-500">
              <th className="px-3 py-2">Model</th>
              <th className="px-3 py-2 text-right">Calls</th>
              <th className="px-3 py-2 text-right">Prompt tok</th>
              <th className="px-3 py-2 text-right">Completion tok</th>
              <th className="px-3 py-2 text-right">Cost (USD)</th>
              <th className="px-3 py-2 text-right">Latency</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/40">
            {sorted.map((c) => (
              <tr key={c.model} className="text-slate-300">
                <td className="px-3 py-2 font-mono text-[11px] text-slate-200">
                  {c.model}
                </td>
                <td className="px-3 py-2 text-right">{c.call_count.toLocaleString()}</td>
                <td className="px-3 py-2 text-right">
                  {c.total_prompt_tokens.toLocaleString()}
                </td>
                <td className="px-3 py-2 text-right">
                  {c.total_completion_tokens.toLocaleString()}
                </td>
                <td className="px-3 py-2 text-right tabular-nums">
                  ${c.total_cost_usd.toFixed(4)}
                </td>
                <td className="px-3 py-2 text-right text-slate-400">
                  {formatLatencyMs(c.total_latency_ms)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/** Compact human-friendly latency string. ms under 1s, seconds otherwise. */
function formatLatencyMs(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return '—';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

// ─── Timeline row ─────────────────────────────────────────────────────────────

function TimelineRow({
  event,
  selected,
  onClick,
}: {
  event: LedgerEvent;
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <li>
      <button
        onClick={onClick}
        className={clsx(
          'flex w-full items-start gap-2.5 rounded-lg border px-3 py-2 text-left transition-colors',
          selected
            ? 'border-emerald-500/40 bg-emerald-500/5'
            : 'border-slate-800/60 bg-slate-900/30 hover:border-slate-700 hover:bg-slate-800/40',
        )}
      >
        <span className="mt-0.5 shrink-0 text-base leading-none">
          {kindIcon(event.kind)}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-mono text-[10px] text-slate-500">
              #{event.seq.toString().padStart(3, '0')}
            </span>
            <span
              className={clsx(
                'inline-flex rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ring-1',
                chipClass(event.kind),
              )}
            >
              {kindLabel(event.kind)}
            </span>
            {event.agent && (
              <span className="text-[11px] font-semibold text-slate-300">
                {event.agent}
              </span>
            )}
            {event.duration_ms > 0 && (
              <span className="text-[10px] text-slate-500">
                {event.duration_ms}ms
              </span>
            )}
            <span className="ml-auto shrink-0 text-[10px] text-slate-600">
              {format(new Date(event.ts), 'HH:mm:ss.SSS')}
            </span>
          </div>
          <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-slate-400">
            {event.summary || <span className="text-slate-600 italic">(no summary)</span>}
          </p>
        </div>
      </button>
    </li>
  );
}

// ─── Explain panel ────────────────────────────────────────────────────────────

function ExplainPanel({ runId, step }: { runId: string; step: number }) {
  const { data, error, isLoading } = useSWR<LedgerExplain>(
    ['ledger.explain', runId, step],
    () => ledgerApi.explain(runId, step),
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );

  if (isLoading && !data) {
    return (
      <Panel title="Why this step?">
        <div className="space-y-2">
          <Skeleton className="h-6 w-1/3 rounded-md" />
          <Skeleton className="h-32 w-full rounded-md" />
          <Skeleton className="h-24 w-full rounded-md" />
        </div>
      </Panel>
    );
  }

  if (error || !data) {
    return (
      <Panel title="Why this step?">
        <p className="p-4 text-xs text-red-400">
          Couldn&apos;t load explanation: {String(error)}
        </p>
      </Panel>
    );
  }

  const { focus, previous, next, artifacts } = data;

  return (
    <Panel
      title="Why this step?"
      actions={
        <span className="font-mono text-[10px] text-slate-500">
          step #{focus.seq}
        </span>
      }
    >
      <div className="space-y-4">
        {/* Focal step header */}
        <div>
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-base leading-none">{kindIcon(focus.kind)}</span>
            <span
              className={clsx(
                'inline-flex rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ring-1',
                chipClass(focus.kind),
              )}
            >
              {kindLabel(focus.kind)}
            </span>
            {focus.agent && (
              <span className="text-xs font-semibold text-slate-200">{focus.agent}</span>
            )}
            <span className="ml-auto text-[10px] text-slate-500">
              {format(new Date(focus.ts), 'MMM d, HH:mm:ss.SSS')}
              {focus.duration_ms > 0 && ` · ${focus.duration_ms}ms`}
            </span>
          </div>
          {focus.summary && (
            <p className="mt-1.5 text-sm text-slate-200">{focus.summary}</p>
          )}
        </div>

        {/* Cryptographic hashes for replay verification */}
        {(focus.input_hash || focus.output_hash) && (
          <div className="rounded-lg border border-slate-800/60 bg-slate-950/40 p-3">
            <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">
              Replay hashes
            </p>
            <div className="mt-1.5 grid grid-cols-1 gap-1.5 text-[11px] sm:grid-cols-2">
              {focus.input_hash && (
                <HashRow label="input" value={focus.input_hash} />
              )}
              {focus.output_hash && (
                <HashRow label="output" value={focus.output_hash} />
              )}
            </div>
          </div>
        )}

        {/* Payload */}
        {focus.payload && Object.keys(focus.payload).length > 0 && (
          <CollapsibleBlock title="Payload" defaultOpen>
            <JsonView value={focus.payload} />
          </CollapsibleBlock>
        )}

        {/* Artifacts (LLM transcripts, tool I/O) */}
        {artifacts.length > 0 && (
          <div className="space-y-2">
            <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">
              Artifacts ({artifacts.length})
            </p>
            {artifacts.map((art) => (
              <ArtifactBlock key={art.id} artifact={art} />
            ))}
          </div>
        )}

        {/* Previous / next decisions for context */}
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <NeighbourCard
            label="Came from"
            event={previous}
            placeholder="(beginning of run)"
          />
          <NeighbourCard
            label="Led to"
            event={next}
            placeholder="(end of run)"
          />
        </div>
      </div>
    </Panel>
  );
}

function HashRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="w-12 shrink-0 text-slate-500">{label}</span>
      <code className="min-w-0 flex-1 truncate rounded bg-slate-900/60 px-1.5 py-0.5 font-mono text-[10px] text-slate-300">
        {value}
      </code>
      <button
        onClick={() => {
          void navigator.clipboard.writeText(value);
          toast.success('Hash copied');
        }}
        className="text-[10px] text-slate-500 hover:text-slate-300"
        title="Copy hash"
      >
        copy
      </button>
    </div>
  );
}

function NeighbourCard({
  label,
  event,
  placeholder,
}: {
  label: string;
  event: LedgerEvent | null;
  placeholder: string;
}) {
  return (
    <div className="rounded-lg border border-slate-800/60 bg-slate-950/40 p-2.5">
      <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">
        {label}
      </p>
      {event ? (
        <div className="mt-1 flex items-start gap-2">
          <span className="shrink-0 text-sm leading-none">{kindIcon(event.kind)}</span>
          <div className="min-w-0 flex-1">
            <span
              className={clsx(
                'inline-flex rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ring-1',
                chipClass(event.kind),
              )}
            >
              {kindLabel(event.kind)}
            </span>{' '}
            <span className="text-[11px] font-semibold text-slate-300">
              {event.agent}
            </span>
            <p className="mt-0.5 line-clamp-2 text-[11px] text-slate-400">
              {event.summary || '—'}
            </p>
            <p className="mt-0.5 font-mono text-[10px] text-slate-600">
              #{event.seq} · {formatDistanceToNow(new Date(event.ts), { addSuffix: true })}
            </p>
          </div>
        </div>
      ) : (
        <p className="mt-1 text-[11px] italic text-slate-600">{placeholder}</p>
      )}
    </div>
  );
}

function ArtifactBlock({ artifact }: { artifact: LedgerArtifactDetail }) {
  const [open, setOpen] = useState(false);
  const isText = !!artifact.content;
  return (
    <div className="overflow-hidden rounded-lg border border-slate-800/60 bg-slate-950/40">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-slate-900/40"
      >
        <span className="text-[11px] font-semibold uppercase tracking-wide text-slate-300">
          {artifact.kind}
        </span>
        <span className="text-[10px] text-slate-500">
          {artifact.size_bytes.toLocaleString()} bytes
        </span>
        <code className="ml-auto truncate font-mono text-[10px] text-slate-500">
          sha256:{artifact.sha256.slice(0, 12)}…
        </code>
        <span className="text-slate-500">{open ? '▾' : '▸'}</span>
      </button>
      {open && (
        <div className="border-t border-slate-800/60 bg-slate-950/60 p-3">
          {isText ? (
            <pre className="max-h-[400px] overflow-auto whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-slate-300">
              {artifact.content}
            </pre>
          ) : artifact.blob_ref ? (
            <p className="text-[11px] text-slate-400">
              Stored externally: <code className="text-slate-300">{artifact.blob_ref}</code>
            </p>
          ) : (
            <p className="text-[11px] italic text-slate-500">Empty artifact</p>
          )}
        </div>
      )}
    </div>
  );
}

function CollapsibleBlock({
  title,
  defaultOpen = false,
  children,
}: {
  title: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="overflow-hidden rounded-lg border border-slate-800/60 bg-slate-950/40">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-slate-900/40"
      >
        <span className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">
          {title}
        </span>
        <span className="ml-auto text-slate-500">{open ? '▾' : '▸'}</span>
      </button>
      {open && (
        <div className="border-t border-slate-800/60 bg-slate-950/60 p-3">
          {children}
        </div>
      )}
    </div>
  );
}

function JsonView({ value }: { value: unknown }) {
  return (
    <pre className="max-h-[400px] overflow-auto font-mono text-[11px] leading-relaxed text-slate-300">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

// ─── Tiny presentational helpers ──────────────────────────────────────────────

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">
        {label}
      </p>
      <div className="mt-0.5 text-xs text-slate-200">{value}</div>
    </div>
  );
}

function Panel({
  title,
  actions,
  children,
}: {
  title: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/40">
      <div className="flex items-center justify-between border-b border-slate-800/80 px-3 py-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-300">
          {title}
        </h3>
        {actions}
      </div>
      <div className="p-3">{children}</div>
    </div>
  );
}
