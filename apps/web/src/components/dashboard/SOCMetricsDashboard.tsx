"use client";

import { useCallback } from "react";
import useSWR from "swr";

interface SOCKpis {
  mttd_hours: number;
  mttr_hours: number;
  mttc_hours: number;
  false_positive_rate: number;
  escalation_rate: number;
  alert_volume_7d: number;
  cases_opened_7d: number;
  cases_closed_7d: number;
  analyst_overrides_7d: number;
}

interface AttackHeatmapCell {
  tactic: string;
  technique: string;
  count: number;
}

interface CalibrationBucket {
  predicted_lower: number;
  predicted_upper: number;
  sample_count: number;
  actual_tp_rate: number;
}

interface SOCMetrics {
  kpis: SOCKpis;
  attack_heatmap: AttackHeatmapCell[];
  calibration_curve: CalibrationBucket[];
}

interface CostAggregateRow {
  model: string;
  runs: number;
  calls: number;
  total_prompt_tokens: number;
  total_completion_tokens: number;
  total_cost_usd: number;
  total_latency_ms: number;
  avg_cost_per_run: number;
  avg_latency_per_call_ms: number;
}

interface CostAggregate {
  window_days: number;
  by_model: CostAggregateRow[];
  totals: CostAggregateRow | null;
}

const fetcher = (url: string) =>
  fetch(url, { credentials: "include" }).then((r) => r.json());

function formatUsd(n: number): string {
  if (n >= 100) return `$${n.toFixed(0)}`;
  if (n >= 1) return `$${n.toFixed(2)}`;
  return `$${n.toFixed(4)}`;
}

function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return `${n}`;
}

function KpiCard({
  label,
  value,
  unit,
  color,
}: {
  label: string;
  value: string | number;
  unit?: string;
  color?: string;
}) {
  return (
    <div className="bg-gray-900 border border-gray-700 rounded-lg p-4 flex flex-col gap-1">
      <span className="text-xs text-gray-400 uppercase tracking-wider">{label}</span>
      <span className={`text-2xl font-bold ${color ?? "text-white"}`}>
        {value}
        {unit && <span className="text-sm font-normal text-gray-400 ml-1">{unit}</span>}
      </span>
    </div>
  );
}

const TACTIC_COLORS: Record<string, string> = {
  "Initial Access": "bg-red-900",
  Execution: "bg-orange-900",
  Persistence: "bg-yellow-900",
  "Privilege Escalation": "bg-amber-900",
  "Defense Evasion": "bg-lime-900",
  "Credential Access": "bg-green-900",
  Discovery: "bg-teal-900",
  "Lateral Movement": "bg-cyan-900",
  Collection: "bg-sky-900",
  Exfiltration: "bg-blue-900",
  "Command and Control": "bg-indigo-900",
  Impact: "bg-purple-900",
};

function AttackHeatmap({ cells }: { cells: AttackHeatmapCell[] }) {
  const tacticGroups: Record<string, AttackHeatmapCell[]> = {};
  for (const cell of cells) {
    if (!tacticGroups[cell.tactic]) tacticGroups[cell.tactic] = [];
    tacticGroups[cell.tactic].push(cell);
  }

  const maxCount = Math.max(...cells.map((c) => c.count), 1);

  if (cells.length === 0) {
    return (
      <div className="text-gray-500 text-sm flex items-center justify-center h-32">
        No ATT&amp;CK data in the selected period.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {Object.entries(tacticGroups).map(([tactic, techniques]) => (
        <div key={tactic}>
          <div className="text-xs font-semibold text-gray-300 mb-1 uppercase tracking-wide">
            {tactic}
          </div>
          <div className="flex flex-wrap gap-1">
            {techniques.map((cell) => {
              const intensity = Math.max(0.15, cell.count / maxCount);
              const bgClass = TACTIC_COLORS[tactic] ?? "bg-gray-800";
              return (
                <div
                  key={cell.technique}
                  title={`${cell.technique}: ${cell.count} alerts`}
                  className={`${bgClass} border border-gray-600 rounded px-2 py-1 text-xs text-gray-200 cursor-default`}
                  style={{ opacity: intensity }}
                >
                  {cell.technique}
                  <span className="ml-1 text-gray-400">({cell.count})</span>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

export function SOCMetricsDashboard() {
  const { data, error, isLoading, mutate } = useSWR<SOCMetrics>(
    "/api/v1/metrics/soc",
    fetcher,
    { refreshInterval: 60_000 }
  );

  const refresh = useCallback(() => mutate(), [mutate]);

  if (error) {
    return (
      <div className="p-6 text-red-400 text-sm">
        Failed to load SOC metrics. {error?.message ?? ""}
      </div>
    );
  }

  const kpis = data?.kpis;
  const heatmap = data?.attack_heatmap ?? [];
  const calibration = data?.calibration_curve ?? [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">SOC Performance Metrics</h2>
        <button
          onClick={refresh}
          className="text-xs text-gray-400 hover:text-gray-200 px-3 py-1 border border-gray-700 rounded transition-colors"
        >
          Refresh
        </button>
      </div>

      {/* KPI Grid */}
      {isLoading ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Array.from({ length: 7 }).map((_, i) => (
            <div key={i} className="bg-gray-900 border border-gray-700 rounded-lg p-4 animate-pulse h-20" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <KpiCard
            label="MTTD"
            value={kpis?.mttd_hours.toFixed(1) ?? "—"}
            unit="hrs"
            color={
              (kpis?.mttd_hours ?? 0) > 4
                ? "text-red-400"
                : (kpis?.mttd_hours ?? 0) > 2
                ? "text-yellow-400"
                : "text-green-400"
            }
          />
          <KpiCard
            label="MTTR"
            value={kpis?.mttr_hours.toFixed(1) ?? "—"}
            unit="hrs"
            color={
              (kpis?.mttr_hours ?? 0) > 24
                ? "text-red-400"
                : (kpis?.mttr_hours ?? 0) > 8
                ? "text-yellow-400"
                : "text-green-400"
            }
          />
          <KpiCard
            label="MTTC"
            value={kpis?.mttc_hours.toFixed(1) ?? "—"}
            unit="hrs"
            color={
              (kpis?.mttc_hours ?? 0) > 24
                ? "text-red-400"
                : (kpis?.mttc_hours ?? 0) > 8
                ? "text-yellow-400"
                : "text-green-400"
            }
          />
          <KpiCard
            label="Escalation Rate"
            value={
              kpis ? `${(kpis.escalation_rate * 100).toFixed(1)}%` : "—"
            }
            color={
              (kpis?.escalation_rate ?? 0) > 0.5
                ? "text-red-400"
                : (kpis?.escalation_rate ?? 0) > 0.25
                ? "text-yellow-400"
                : "text-green-400"
            }
          />
          <KpiCard
            label="False Positive Rate"
            value={
              kpis
                ? `${(kpis.false_positive_rate * 100).toFixed(1)}%`
                : "—"
            }
            color={
              (kpis?.false_positive_rate ?? 0) > 0.3
                ? "text-red-400"
                : (kpis?.false_positive_rate ?? 0) > 0.15
                ? "text-yellow-400"
                : "text-green-400"
            }
          />
          <KpiCard
            label="Alert Volume (7d)"
            value={kpis?.alert_volume_7d ?? "—"}
          />
          <KpiCard
            label="Cases Opened (7d)"
            value={kpis?.cases_opened_7d ?? "—"}
          />
          <KpiCard
            label="Cases Closed (7d)"
            value={kpis?.cases_closed_7d ?? "—"}
            color="text-green-400"
          />
          <KpiCard
            label="Analyst Overrides (7d)"
            value={kpis?.analyst_overrides_7d ?? "—"}
            color="text-blue-400"
          />
        </div>
      )}

      {/* Confidence Calibration Curve */}
      <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-300 mb-1">
          Agent Confidence Calibration (7d)
        </h3>
        <p className="text-xs text-gray-500 mb-4">
          Predicted confidence vs. actual true-positive rate. Diagonal alignment indicates
          well-calibrated confidence.
        </p>
        {isLoading ? (
          <div className="h-40 animate-pulse bg-gray-800 rounded" />
        ) : (
          <CalibrationCurve buckets={calibration} />
        )}
      </div>

      {/* ATT&CK Heatmap */}
      <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-300 mb-4">
          ATT&amp;CK Technique Heatmap
        </h3>
        {isLoading ? (
          <div className="h-40 animate-pulse bg-gray-800 rounded" />
        ) : (
          <AttackHeatmap cells={heatmap} />
        )}
      </div>

      {/* Investigation Cost Telemetry */}
      <CostTelemetryPanel />
    </div>
  );
}

function CostTelemetryPanel() {
  const { data, error, isLoading } = useSWR<CostAggregate>(
    "/api/v1/investigations/costs/aggregate?window_days=30",
    fetcher,
    { refreshInterval: 60_000 },
  );

  const totals = data?.totals;
  const byModel = data?.by_model ?? [];
  const maxModelCost = Math.max(...byModel.map((m) => m.total_cost_usd), 0.0001);

  return (
    <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
      <div className="flex items-center justify-between mb-1">
        <h3 className="text-sm font-semibold text-gray-300">
          Investigation Cost Telemetry (30d)
        </h3>
        <span className="text-xs text-gray-500">
          Tokens · Latency · Spend per model, aggregated across runs
        </span>
      </div>
      <p className="text-xs text-gray-500 mb-4">
        Source of truth for TCO transparency. Per-run breakdowns are available on
        each investigation detail view.
      </p>

      {error ? (
        <div className="text-red-400 text-sm">
          Failed to load cost telemetry. {(error as Error)?.message ?? ""}
        </div>
      ) : isLoading ? (
        <div className="h-32 animate-pulse bg-gray-800 rounded" />
      ) : !totals || totals.runs === 0 ? (
        <div className="text-gray-500 text-sm flex items-center justify-center h-24">
          No investigation runs with cost telemetry in the last 30 days.
        </div>
      ) : (
        <div className="space-y-4">
          {/* Totals strip */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <KpiCard
              label="Total Spend"
              value={formatUsd(totals.total_cost_usd)}
              color={
                totals.total_cost_usd > 100
                  ? "text-red-400"
                  : totals.total_cost_usd > 25
                  ? "text-yellow-400"
                  : "text-green-400"
              }
            />
            <KpiCard label="Runs" value={totals.runs} />
            <KpiCard label="LLM Calls" value={totals.calls} />
            <KpiCard
              label="Avg $/Run"
              value={formatUsd(totals.avg_cost_per_run)}
            />
            <KpiCard
              label="Avg Latency/Call"
              value={`${(totals.avg_latency_per_call_ms / 1000).toFixed(2)}`}
              unit="s"
              color={
                totals.avg_latency_per_call_ms > 10_000
                  ? "text-red-400"
                  : totals.avg_latency_per_call_ms > 5_000
                  ? "text-yellow-400"
                  : "text-green-400"
              }
            />
          </div>

          {/* Per-model breakdown */}
          <div className="overflow-x-auto">
            <table className="min-w-full text-xs">
              <thead>
                <tr className="text-gray-500 border-b border-gray-800">
                  <th className="text-left py-2 pr-4 font-medium">Model</th>
                  <th className="text-right py-2 pr-4 font-medium">Runs</th>
                  <th className="text-right py-2 pr-4 font-medium">Calls</th>
                  <th className="text-right py-2 pr-4 font-medium">Prompt Tokens</th>
                  <th className="text-right py-2 pr-4 font-medium">Completion Tokens</th>
                  <th className="text-right py-2 pr-4 font-medium">Spend</th>
                  <th className="text-left py-2 font-medium">Share</th>
                </tr>
              </thead>
              <tbody>
                {byModel.map((row) => {
                  const sharePct = (row.total_cost_usd / maxModelCost) * 100;
                  return (
                    <tr
                      key={row.model}
                      className="border-b border-gray-800/50 last:border-0"
                    >
                      <td className="py-2 pr-4 text-gray-200 font-mono">
                        {row.model}
                      </td>
                      <td className="py-2 pr-4 text-right text-gray-400">
                        {row.runs}
                      </td>
                      <td className="py-2 pr-4 text-right text-gray-400">
                        {row.calls}
                      </td>
                      <td className="py-2 pr-4 text-right text-gray-400 font-mono">
                        {formatTokens(row.total_prompt_tokens)}
                      </td>
                      <td className="py-2 pr-4 text-right text-gray-400 font-mono">
                        {formatTokens(row.total_completion_tokens)}
                      </td>
                      <td className="py-2 pr-4 text-right text-white font-mono">
                        {formatUsd(row.total_cost_usd)}
                      </td>
                      <td className="py-2 min-w-[120px]">
                        <div className="h-2 bg-gray-800 rounded overflow-hidden">
                          <div
                            className="h-full bg-blue-700"
                            style={{ width: `${sharePct}%` }}
                          />
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function CalibrationCurve({ buckets }: { buckets: CalibrationBucket[] }) {
  if (!buckets || buckets.length === 0) {
    return (
      <div className="text-gray-500 text-sm flex items-center justify-center h-40">
        Not enough labeled investigations to compute calibration yet.
      </div>
    );
  }

  const maxSamples = Math.max(...buckets.map((b) => b.sample_count), 1);

  return (
    <div className="space-y-2">
      {/* Header row */}
      <div className="grid grid-cols-12 gap-2 text-xs text-gray-500 px-1">
        <div className="col-span-3">Confidence Bin</div>
        <div className="col-span-6">Predicted vs Actual TP Rate</div>
        <div className="col-span-2 text-right">Actual</div>
        <div className="col-span-1 text-right">N</div>
      </div>
      {buckets.map((bucket) => {
        const lo = (bucket.predicted_lower * 100).toFixed(0);
        const hi = (bucket.predicted_upper * 100).toFixed(0);
        const midpoint = (bucket.predicted_lower + bucket.predicted_upper) / 2;
        const actual = bucket.actual_tp_rate;
        // Drift is gap between actual and the midpoint of the predicted band.
        const drift = Math.abs(actual - midpoint);
        const driftColor =
          drift > 0.2
            ? "bg-red-500"
            : drift > 0.1
            ? "bg-yellow-500"
            : "bg-green-500";
        const sampleOpacity = Math.max(
          0.2,
          bucket.sample_count / maxSamples
        );

        return (
          <div
            key={`${bucket.predicted_lower}-${bucket.predicted_upper}`}
            className="grid grid-cols-12 gap-2 items-center text-xs"
            title={`Predicted ${lo}-${hi}%; actual TP rate ${(actual * 100).toFixed(
              1,
            )}%; ${bucket.sample_count} samples`}
          >
            <div className="col-span-3 text-gray-400">
              {lo}-{hi}%
            </div>
            <div className="col-span-6 relative h-5 bg-gray-800 rounded">
              {/* Predicted band */}
              <div
                className="absolute top-0 bottom-0 bg-blue-900 opacity-40 rounded"
                style={{
                  left: `${bucket.predicted_lower * 100}%`,
                  width: `${(bucket.predicted_upper - bucket.predicted_lower) * 100}%`,
                }}
              />
              {/* Actual marker */}
              <div
                className={`absolute top-0 bottom-0 w-1 ${driftColor}`}
                style={{
                  left: `calc(${actual * 100}% - 2px)`,
                  opacity: sampleOpacity,
                }}
              />
            </div>
            <div
              className={`col-span-2 text-right font-mono ${
                drift > 0.2
                  ? "text-red-400"
                  : drift > 0.1
                  ? "text-yellow-400"
                  : "text-green-400"
              }`}
            >
              {(actual * 100).toFixed(1)}%
            </div>
            <div className="col-span-1 text-right text-gray-500 font-mono">
              {bucket.sample_count}
            </div>
          </div>
        );
      })}
    </div>
  );
}
