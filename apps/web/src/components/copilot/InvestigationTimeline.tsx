"use client";

/**
 * InvestigationTimeline — WS-D3
 *
 * Scrubbable investigation timeline with:
 *   • Visual timeline track with scrubber (click any node to jump)
 *   • Per-node decision-provenance tooltip (reason, confidence, tool, next phase)
 *   • Agent-decision diff badges when the same agent re-ran a step
 *   • Artifact indicator (paper-clip icon)
 *   • Live progress for in-progress runs via polling
 *
 * Author: Beenu <beenu@cyble.com>
 */

import { useCallback, useEffect, useRef, useState } from "react";

// ---------------------------------------------------------------------------
// Types (mirror backend TimelineResponse / TimelineNode)
// ---------------------------------------------------------------------------

interface TimelineDecision {
  reason: string | null;
  confidence: number | null;
  next_phase: string | null;
  tool_name: string | null;
  tool_args: Record<string, unknown> | null;
  tool_result_summary: string | null;
}

interface TimelineNode {
  seq: number;
  ts: string;
  kind: string;
  agent: string;
  summary: string;
  duration_ms: number;
  decision: TimelineDecision | null;
  has_artifact: boolean;
  diff_vs_prev_attempt: string | null;
}

interface TimelineResponse {
  run_id: string;
  case_id: string;
  status: string;
  total_duration_ms: number;
  attempt_count: number;
  nodes: TimelineNode[];
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface Props {
  /** Active investigation run ID. When provided the component fetches live data. */
  runId?: string;
  /** Optionally override the API base URL (useful for tests / storybook). */
  apiBase?: string;
  /** Called when the user clicks an artifact-bearing node. */
  onArtifactClick?: (runId: string, seq: number) => void;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const KIND_LABELS: Record<string, string> = {
  run_start: "Run started",
  agent_start: "Agent initialised",
  step: "Step",
  decision: "Decision",
  tool_call: "Tool call",
  tool_result: "Tool result",
  agent_output: "Agent output",
  run_end: "Run finished",
  error: "Error",
};

const KIND_COLORS: Record<string, string> = {
  run_start: "bg-blue-500",
  agent_start: "bg-indigo-500",
  step: "bg-slate-400",
  decision: "bg-yellow-500",
  tool_call: "bg-teal-500",
  tool_result: "bg-teal-300",
  agent_output: "bg-emerald-500",
  run_end: "bg-blue-700",
  error: "bg-red-500",
};

function kindColor(kind: string): string {
  return KIND_COLORS[kind] ?? "bg-slate-400";
}

function kindLabel(kind: string): string {
  return KIND_LABELS[kind] ?? kind.replace(/_/g, " ");
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
}

function confidenceBadge(c: number): string {
  if (c >= 0.8) return "text-emerald-400";
  if (c >= 0.6) return "text-yellow-400";
  return "text-red-400";
}

// ---------------------------------------------------------------------------
// Tooltip component
// ---------------------------------------------------------------------------

function DecisionTooltip({ decision }: { decision: TimelineDecision }) {
  return (
    <div className="absolute bottom-full left-1/2 z-50 mb-2 -translate-x-1/2 w-72 rounded-lg border border-slate-700 bg-slate-900 p-3 text-xs shadow-xl">
      <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
        Decision provenance
      </div>
      {decision.reason && (
        <p className="mb-1 text-slate-200">
          <span className="font-medium text-slate-400">Reason: </span>
          {decision.reason}
        </p>
      )}
      {decision.confidence !== null && (
        <p className="mb-1">
          <span className="font-medium text-slate-400">Confidence: </span>
          <span className={confidenceBadge(decision.confidence)}>
            {(decision.confidence * 100).toFixed(0)}%
          </span>
        </p>
      )}
      {decision.next_phase && (
        <p className="mb-1 text-slate-200">
          <span className="font-medium text-slate-400">Next phase: </span>
          {decision.next_phase}
        </p>
      )}
      {decision.tool_name && (
        <p className="mb-1 text-slate-200">
          <span className="font-medium text-slate-400">Tool: </span>
          <code className="rounded bg-slate-800 px-1 text-teal-300">
            {decision.tool_name}
          </code>
        </p>
      )}
      {decision.tool_args && (
        <details className="mb-1">
          <summary className="cursor-pointer text-slate-400 hover:text-slate-200">
            Args ▸
          </summary>
          <pre className="mt-1 overflow-auto rounded bg-slate-800 p-1 text-slate-300">
            {JSON.stringify(decision.tool_args, null, 2)}
          </pre>
        </details>
      )}
      {decision.tool_result_summary && (
        <p className="text-slate-200">
          <span className="font-medium text-slate-400">Result: </span>
          {decision.tool_result_summary}
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Single timeline node
// ---------------------------------------------------------------------------

interface NodeProps {
  node: TimelineNode;
  isFocused: boolean;
  isLast: boolean;
  onClick: () => void;
  onArtifactClick?: () => void;
  totalDurationMs: number;
  firstTs: number;
}

function TimelineNodeCard({
  node,
  isFocused,
  isLast,
  onClick,
  onArtifactClick,
  totalDurationMs,
  firstTs,
}: NodeProps) {
  const [showTooltip, setShowTooltip] = useState(false);
  const nodeTs = new Date(node.ts).getTime();
  const offsetPct =
    totalDurationMs > 0
      ? Math.min(((nodeTs - firstTs) / totalDurationMs) * 100, 100)
      : 0;

  return (
    <div
      className={`relative flex gap-3 rounded-lg px-3 py-2 transition-colors cursor-pointer
        ${isFocused ? "bg-slate-700/60 ring-1 ring-slate-500" : "hover:bg-slate-800/60"}`}
      onClick={onClick}
    >
      {/* vertical connector */}
      {!isLast && (
        <div className="absolute left-5 top-9 bottom-0 w-0.5 bg-slate-700" />
      )}

      {/* dot */}
      <div className="relative z-10 mt-1 flex h-4 w-4 flex-shrink-0 items-center justify-center">
        <button
          className={`h-3 w-3 rounded-full ring-2 ring-slate-900 ${kindColor(node.kind)} transition-transform ${isFocused ? "scale-150" : "hover:scale-125"}`}
          title={kindLabel(node.kind)}
        />
      </div>

      {/* content */}
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline gap-2 flex-wrap">
          <span className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">
            {kindLabel(node.kind)}
          </span>
          <span className="text-[10px] text-slate-500">
            {new Date(node.ts).toLocaleTimeString()}
          </span>
          <span className="text-[10px] text-slate-600">
            +{formatDuration(node.duration_ms)}
          </span>
          <span className="text-[10px] font-mono text-indigo-400">{node.agent}</span>

          {node.diff_vs_prev_attempt && (
            <span
              className="rounded bg-amber-900/60 px-1 text-[10px] text-amber-300"
              title={node.diff_vs_prev_attempt}
            >
              ↺ retry diff
            </span>
          )}

          {node.has_artifact && (
            <button
              className="text-[10px] text-slate-400 hover:text-white"
              title="Open transcript artifact"
              onClick={(e) => {
                e.stopPropagation();
                onArtifactClick?.();
              }}
            >
              📎
            </button>
          )}
        </div>

        <p className="mt-0.5 text-sm text-slate-200 leading-snug line-clamp-2">
          {node.summary}
        </p>

        {/* scrubber position hint */}
        <div className="mt-1 text-[9px] text-slate-600">
          t+{offsetPct.toFixed(1)}%
        </div>

        {/* decision tooltip trigger */}
        {node.decision && (
          <div className="relative mt-1 inline-block">
            <button
              className="rounded bg-yellow-900/50 px-1.5 py-0.5 text-[10px] text-yellow-300 hover:bg-yellow-900"
              onMouseEnter={() => setShowTooltip(true)}
              onMouseLeave={() => setShowTooltip(false)}
              onClick={(e) => e.stopPropagation()}
            >
              ⚡ decision provenance
            </button>
            {showTooltip && <DecisionTooltip decision={node.decision} />}
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Scrubber bar
// ---------------------------------------------------------------------------

function ScrubberBar({
  nodes,
  focusedSeq,
  totalDurationMs,
  firstTs,
  onScrub,
}: {
  nodes: TimelineNode[];
  focusedSeq: number | null;
  totalDurationMs: number;
  firstTs: number;
  onScrub: (seq: number) => void;
}) {
  const barRef = useRef<HTMLDivElement>(null);

  const handleClick = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      if (!barRef.current || nodes.length === 0 || totalDurationMs === 0) return;
      const rect = barRef.current.getBoundingClientRect();
      const pct = (e.clientX - rect.left) / rect.width;
      const targetMs = pct * totalDurationMs;
      // Find closest node by offset
      let closest = nodes[0];
      let minDist = Infinity;
      for (const n of nodes) {
        const dist = Math.abs(
          new Date(n.ts).getTime() - firstTs - targetMs,
        );
        if (dist < minDist) {
          minDist = dist;
          closest = n;
        }
      }
      onScrub(closest.seq);
    },
    [nodes, totalDurationMs, firstTs, onScrub],
  );

  return (
    <div className="mb-4 px-3">
      <div
        ref={barRef}
        className="relative h-3 cursor-crosshair rounded-full bg-slate-700"
        onClick={handleClick}
        title="Click to jump to a point in the timeline"
      >
        {nodes.map((n) => {
          const pct =
            totalDurationMs > 0
              ? Math.min(
                  ((new Date(n.ts).getTime() - firstTs) / totalDurationMs) * 100,
                  100,
                )
              : 0;
          const isFocused = n.seq === focusedSeq;
          return (
            <div
              key={n.seq}
              className={`absolute top-1/2 -translate-y-1/2 -translate-x-1/2 rounded-full transition-all
                ${kindColor(n.kind)}
                ${isFocused ? "h-3 w-3 ring-2 ring-white" : "h-1.5 w-1.5"}`}
              style={{ left: `${pct}%` }}
            />
          );
        })}
        {/* playhead */}
        {focusedSeq !== null && (() => {
          const focused = nodes.find((n) => n.seq === focusedSeq);
          if (!focused) return null;
          const pct =
            totalDurationMs > 0
              ? Math.min(
                  ((new Date(focused.ts).getTime() - firstTs) / totalDurationMs) * 100,
                  100,
                )
              : 0;
          return (
            <div
              className="absolute top-0 bottom-0 w-0.5 bg-white/80 pointer-events-none"
              style={{ left: `${pct}%` }}
            />
          );
        })()}
      </div>
      <div className="mt-1 flex justify-between text-[10px] text-slate-600">
        <span>0s</span>
        <span>{formatDuration(totalDurationMs)}</span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

/** Synthetic demo timeline shown when no runId is provided. */
function makeDemoTimeline(): TimelineResponse {
  const base = Date.now() - 45000;
  const makeTs = (offsetMs: number) =>
    new Date(base + offsetMs).toISOString();

  return {
    run_id: "demo-run",
    case_id: "CASE-001",
    status: "completed",
    total_duration_ms: 45000,
    attempt_count: 1,
    nodes: [
      {
        seq: 1,
        ts: makeTs(0),
        kind: "run_start",
        agent: "orchestrator",
        summary: "Investigation started for CASE-001",
        duration_ms: 12,
        decision: null,
        has_artifact: false,
        diff_vs_prev_attempt: null,
      },
      {
        seq: 2,
        ts: makeTs(800),
        kind: "agent_start",
        agent: "triage",
        summary: "Triage agent initialised; loading alert context",
        duration_ms: 200,
        decision: null,
        has_artifact: false,
        diff_vs_prev_attempt: null,
      },
      {
        seq: 3,
        ts: makeTs(2000),
        kind: "decision",
        agent: "triage",
        summary: "Classified as credential-stuffing attack; routing to Identity investigation",
        duration_ms: 850,
        decision: {
          reason:
            "Three failed MFA events from distinct ASNs in under 60 s — confidence below 0.6 triggers forensic escalation",
          confidence: 0.52,
          next_phase: "identity-forensics",
          tool_name: null,
          tool_args: null,
          tool_result_summary: null,
        },
        has_artifact: false,
        diff_vs_prev_attempt: null,
      },
      {
        seq: 4,
        ts: makeTs(5000),
        kind: "tool_call",
        agent: "identity",
        summary: "Querying Okta audit logs for user alice@example.com",
        duration_ms: 1200,
        decision: {
          reason: "Target user identified from alert entity extraction",
          confidence: 0.88,
          next_phase: null,
          tool_name: "okta_get_user_events",
          tool_args: { user: "alice@example.com", window_minutes: 60 },
          tool_result_summary: "12 events returned; 3 failed MFA, 1 successful login from US",
        },
        has_artifact: true,
        diff_vs_prev_attempt: null,
      },
      {
        seq: 5,
        ts: makeTs(11000),
        kind: "tool_result",
        agent: "identity",
        summary: "Okta returned 12 events; anomalous login from 185.x.x.x flagged",
        duration_ms: 80,
        decision: null,
        has_artifact: true,
        diff_vs_prev_attempt: null,
      },
      {
        seq: 6,
        ts: makeTs(14000),
        kind: "decision",
        agent: "identity",
        summary: "Confidence now 0.82 — escalating to automated containment",
        duration_ms: 310,
        decision: {
          reason: "Anomalous IP + impossible travel confirmed; confidence crossed 0.8 threshold",
          confidence: 0.82,
          next_phase: "containment",
          tool_name: null,
          tool_args: null,
          tool_result_summary: null,
        },
        has_artifact: false,
        diff_vs_prev_attempt: null,
      },
      {
        seq: 7,
        ts: makeTs(18000),
        kind: "tool_call",
        agent: "response",
        summary: "Suspending Okta session for alice@example.com",
        duration_ms: 950,
        decision: {
          reason: "Playbook: suspend-and-notify on confirmed account compromise",
          confidence: 0.95,
          next_phase: null,
          tool_name: "okta_suspend_user_session",
          tool_args: { user: "alice@example.com", notify_user: true },
          tool_result_summary: "Session suspended; email dispatched to alice@example.com",
        },
        has_artifact: false,
        diff_vs_prev_attempt: null,
      },
      {
        seq: 8,
        ts: makeTs(25000),
        kind: "agent_output",
        agent: "response",
        summary: "Containment complete — session suspended, user notified, ticket created",
        duration_ms: 120,
        decision: null,
        has_artifact: false,
        diff_vs_prev_attempt: null,
      },
      {
        seq: 9,
        ts: makeTs(45000),
        kind: "run_end",
        agent: "orchestrator",
        summary: "Investigation closed successfully in 45 s",
        duration_ms: 30,
        decision: null,
        has_artifact: false,
        diff_vs_prev_attempt: null,
      },
    ],
  };
}

export default function InvestigationTimeline({
  runId,
  apiBase = "/api/v1",
  onArtifactClick,
}: Props) {
  const [timeline, setTimeline] = useState<TimelineResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [focusedSeq, setFocusedSeq] = useState<number | null>(null);
  const focusedRef = useRef<HTMLDivElement>(null);
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchTimeline = useCallback(async () => {
    if (!runId) return;
    try {
      const res = await fetch(`${apiBase}/investigations/${runId}/timeline`, {
        credentials: "include",
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: TimelineResponse = await res.json();
      setTimeline(data);
      setError(null);
      // Poll while run is still in progress
      if (data.status === "running") {
        pollRef.current = setTimeout(fetchTimeline, 3000);
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load timeline");
    } finally {
      setLoading(false);
    }
  }, [runId, apiBase]);

  useEffect(() => {
    if (!runId) {
      setTimeline(makeDemoTimeline());
      return;
    }
    setLoading(true);
    setError(null);
    fetchTimeline();
    return () => {
      if (pollRef.current) clearTimeout(pollRef.current);
    };
  }, [runId, fetchTimeline]);

  // Scroll focused node into view
  useEffect(() => {
    if (focusedRef.current) {
      focusedRef.current.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }, [focusedSeq]);

  const data = timeline;
  const nodes = data?.nodes ?? [];
  const firstTs = nodes.length > 0 ? new Date(nodes[0].ts).getTime() : 0;

  if (loading) {
    return (
      <div className="flex h-48 items-center justify-center text-slate-400 text-sm">
        Loading timeline…
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-lg border border-red-800 bg-red-950/30 p-4 text-sm text-red-300">
        {error}
      </div>
    );
  }

  if (!data) return null;

  return (
    <div className="flex flex-col gap-2 text-slate-100">
      {/* Header */}
      <div className="flex items-center justify-between px-3 pb-1">
        <div>
          <p className="text-sm font-semibold">
            {data.case_id}{" "}
            <span
              className={`ml-2 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase
                ${data.status === "completed" ? "bg-emerald-900/70 text-emerald-300" :
                  data.status === "running" ? "bg-blue-900/70 text-blue-300 animate-pulse" :
                  data.status === "failed" ? "bg-red-900/70 text-red-300" :
                  "bg-slate-700 text-slate-300"}`}
            >
              {data.status}
            </span>
          </p>
          <p className="text-[11px] text-slate-400">
            {nodes.length} events · {formatDuration(data.total_duration_ms)} ·{" "}
            {data.attempt_count} attempt{data.attempt_count !== 1 ? "s" : ""}
          </p>
        </div>

        {focusedSeq !== null && (
          <button
            className="text-xs text-slate-400 hover:text-white"
            onClick={() => setFocusedSeq(null)}
          >
            ✕ clear focus
          </button>
        )}
      </div>

      {/* Scrubber */}
      {nodes.length > 1 && (
        <ScrubberBar
          nodes={nodes}
          focusedSeq={focusedSeq}
          totalDurationMs={data.total_duration_ms}
          firstTs={firstTs}
          onScrub={setFocusedSeq}
        />
      )}

      {/* Event list */}
      <div className="flex flex-col gap-0.5 overflow-y-auto max-h-[60vh] pr-1">
        {nodes.map((node, idx) => {
          const isFocused = node.seq === focusedSeq;
          return (
            <div key={node.seq} ref={isFocused ? (focusedRef as React.RefObject<HTMLDivElement>) : undefined}>
              <TimelineNodeCard
                node={node}
                isFocused={isFocused}
                isLast={idx === nodes.length - 1}
                totalDurationMs={data.total_duration_ms}
                firstTs={firstTs}
                onClick={() => setFocusedSeq(isFocused ? null : node.seq)}
                onArtifactClick={
                  node.has_artifact && onArtifactClick
                    ? () => onArtifactClick(data.run_id, node.seq)
                    : undefined
                }
              />
            </div>
          );
        })}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-x-3 gap-y-1 border-t border-slate-800 px-3 pt-2 text-[10px] text-slate-500">
        {Object.entries(KIND_COLORS).map(([k, cls]) => (
          <span key={k} className="flex items-center gap-1">
            <span className={`inline-block h-2 w-2 rounded-full ${cls}`} />
            {kindLabel(k)}
          </span>
        ))}
      </div>
    </div>
  );
}
