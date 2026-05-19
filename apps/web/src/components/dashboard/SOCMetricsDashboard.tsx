"use client";

import { useCallback } from "react";
import useSWR from "swr";

import {
  metricsApi,
  investigationsApi,
  type SOCMetrics,
  type AttackHeatmapCell,
  type CalibrationBucket,
  type CostAggregate,
} from "@/lib/api";

const MOCK_SOC_METRICS: SOCMetrics = {
  kpis: {
    mttd_hours: 1.4,
    mttr_hours: 6.2,
    mttc_hours: 14.8,
    false_positive_rate: 0.12,
    escalation_rate: 0.18,
    alert_volume_7d: 1247,
    cases_opened_7d: 23,
    cases_closed_7d: 34,
    analyst_overrides_7d: 8,
  },
  attack_heatmap: [
    { tactic: "Execution", technique: "T1059 Command & Scripting", count: 42 },
    { tactic: "Execution", technique: "T1204 User Execution", count: 18 },
    { tactic: "Defense Evasion", technique: "T1027 Obfuscated Files", count: 31 },
    { tactic: "Defense Evasion", technique: "T1070 Indicator Removal", count: 14 },
    { tactic: "Credential Access", technique: "T1003 OS Credential Dumping", count: 22 },
    { tactic: "Credential Access", technique: "T1110 Brute Force", count: 9 },
    { tactic: "Lateral Movement", technique: "T1021 Remote Services", count: 17 },
    { tactic: "Command and Control", technique: "T1071 Application Layer", count: 26 },
    { tactic: "Command and Control", technique: "T1105 Ingress Tool Transfer", count: 11 },
    { tactic: "Exfiltration", technique: "T1048 Exfiltration Over Alt Protocol", count: 7 },
    { tactic: "Initial Access", technique: "T1566 Phishing", count: 35 },
    { tactic: "Persistence", technique: "T1053 Scheduled Task/Job", count: 19 },
  ],
  calibration_curve: [
    { predicted_lower: 0.0, predicted_upper: 0.2, sample_count: 48, actual_tp_rate: 0.08 },
    { predicted_lower: 0.2, predicted_upper: 0.4, sample_count: 62, actual_tp_rate: 0.31 },
    { predicted_lower: 0.4, predicted_upper: 0.6, sample_count: 85, actual_tp_rate: 0.52 },
    { predicted_lower: 0.6, predicted_upper: 0.8, sample_count: 73, actual_tp_rate: 0.71 },
    { predicted_lower: 0.8, predicted_upper: 1.0, sample_count: 41, actual_tp_rate: 0.88 },
  ],
};

const MOCK_COST_AGGREGATE: CostAggregate = {
  window_days: 30,
  by_model: [
    { model: "gpt-4o", runs: 312, calls: 1840, total_prompt_tokens: 4_620_000, total_completion_tokens: 890_000, total_cost_usd: 42.18, total_latency_ms: 7_360_000, avg_cost_per_run: 0.1352, avg_latency_per_call_ms: 4000 },
    { model: "gpt-4o-mini", runs: 580, calls: 3200, total_prompt_tokens: 2_100_000, total_completion_tokens: 620_000, total_cost_usd: 4.86, total_latency_ms: 3_200_000, avg_cost_per_run: 0.0084, avg_latency_per_call_ms: 1000 },
    { model: "claude-3.5-sonnet", runs: 145, calls: 870, total_prompt_tokens: 3_480_000, total_completion_tokens: 710_000, total_cost_usd: 29.61, total_latency_ms: 4_350_000, avg_cost_per_run: 0.2042, avg_latency_per_call_ms: 5000 },
  ],
  totals: { model: "all", runs: 1037, calls: 5910, total_prompt_tokens: 10_200_000, total_completion_tokens: 2_220_000, total_cost_usd: 76.65, total_latency_ms: 14_910_000, avg_cost_per_run: 0.0739, avg_latency_per_call_ms: 2523 },
};

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
    // Opaque cache key — `metricsApi.getSOC()` routes through the
    // tenant- and auth-aware `request()` helper, which attaches
    // `X-Tenant-Id` and `Authorization` headers and is bound to the
    // same-origin proxy in `next.config.*` rewrites.
    "soc-metrics",
    () => metricsApi.getSOC(),
    {
      refreshInterval: 60_000,
      fallbackData: MOCK_SOC_METRICS,
      shouldRetryOnError: true,
      errorRetryCount: 3,
      errorRetryInterval: 4000,
      revalidateOnMount: true,
      revalidateOnFocus: false,
    }
  );

  const refresh = useCallback(() => mutate(), [mutate]);

  const isValidSOC =
    !!data &&
    typeof data.kpis?.mttd_hours === "number" &&
    Array.isArray(data.attack_heatmap);
  const resolved = isValidSOC ? data : MOCK_SOC_METRICS;
  const kpis = resolved.kpis;
  const heatmap = resolved.attack_heatmap ?? [];
  const calibration = resolved.calibration_curve ?? [];
  // We surface the error inline rather than swapping the whole panel out for
  // a blocking error state — the mock fallback keeps the page legible while
  // the user retries.
  const errorMessage =
    error instanceof Error
      ? error.message
      : error
        ? String(error)
        : null;

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

      {errorMessage && (
        <div className="rounded border border-red-900/60 bg-red-950/40 px-3 py-2 text-xs text-red-200">
          <span className="font-semibold">SOC metrics unavailable:</span>{" "}
          {errorMessage}. Showing last known mock baseline; the live numbers
          will refresh automatically once the API recovers.
        </div>
      )}

      {/* KPI Grid */}
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

      {/* Confidence Calibration Curve */}
      <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-300 mb-1">
          Agent Confidence Calibration (7d)
        </h3>
        <p className="text-xs text-gray-500 mb-4">
          Predicted confidence vs. actual true-positive rate. Diagonal alignment indicates
          well-calibrated confidence.
        </p>
        <CalibrationCurve buckets={calibration} />
      </div>

      {/* ATT&CK Heatmap */}
      <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-300 mb-4">
          ATT&amp;CK Technique Heatmap
        </h3>
        <AttackHeatmap cells={heatmap} />
      </div>

      {/* Investigation Cost Telemetry */}
      <CostTelemetryPanel />
    </div>
  );
}

function CostTelemetryPanel() {
  const { data, error, isLoading } = useSWR<CostAggregate>(
    "cost-aggregate:30",
    () => investigationsApi.getCostAggregate(30),
    {
      refreshInterval: 60_000,
      fallbackData: MOCK_COST_AGGREGATE,
      shouldRetryOnError: true,
      errorRetryCount: 3,
      errorRetryInterval: 4000,
      revalidateOnMount: true,
      revalidateOnFocus: false,
    },
  );

  const isValidCost =
    !!data &&
    Array.isArray(data.by_model) &&
    typeof data.window_days === "number";
  const resolved = isValidCost ? data : MOCK_COST_AGGREGATE;
  const totals = resolved.totals;
  const byModel = resolved.by_model ?? [];
  const maxModelCost = Math.max(...byModel.map((m) => m.total_cost_usd), 0.0001);
  const errorMessage =
    error instanceof Error
      ? error.message
      : error
        ? String(error)
        : null;

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

      {errorMessage && (
        <div className="mb-3 rounded border border-red-900/60 bg-red-950/40 px-3 py-2 text-xs text-red-200">
          <span className="font-semibold">Cost telemetry unavailable:</span>{" "}
          {errorMessage}. Showing baseline projections until the API recovers.
        </div>
      )}

      {isLoading && !resolved ? (
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
