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
import { demoFallback } from '@/lib/demoFallback';
import { EmptyState } from '@/components/ui/EmptyState';

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
    mttd_sample_count: 1247,
    mttr_sample_count: 34,
    mttc_sample_count: 12,
    false_positive_rate_sample_count: 412,
    escalation_rate_sample_count: 168,
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
  hint,
}: {
  label: string;
  value: string | number;
  unit?: string;
  color?: string;
  hint?: string;
}) {
  return (
    <div className="bg-gray-900 border border-gray-700 rounded-lg p-4 flex flex-col gap-1">
      <span className="text-xs text-gray-400 uppercase tracking-wider">{label}</span>
      <span className={`text-2xl font-bold ${color ?? "text-white"}`}>
        {value}
        {unit && <span className="text-sm font-normal text-gray-400 ml-1">{unit}</span>}
      </span>
      {hint && <span className="text-[10px] text-gray-500">{hint}</span>}
    </div>
  );
}

/**
 * A mean over no samples is unmeasured, not zero.
 *
 * The API reports each mean alongside the number of rows it averaged. Without
 * that, these tiles could not distinguish "we respond in 0.0 hours" from
 * "nothing has been resolved yet", and they rendered the first — an
 * unbeatable MTTR for a tenant that had done nothing. `sampleCount` is
 * optional so an older API, which sends no counts, keeps its previous
 * behaviour rather than blanking every tile.
 */
function MeanHoursCard({
  label,
  hours,
  sampleCount,
  warnAbove,
  cautionAbove,
  window,
}: {
  label: string;
  hours: number | undefined;
  sampleCount: number | undefined;
  warnAbove: number;
  cautionAbove: number;
  window: string;
}) {
  if (hours === undefined || sampleCount === 0) {
    return (
      <KpiCard
        label={label}
        value="—"
        color="text-gray-500"
        hint={sampleCount === 0 ? `not measured · no closures in ${window}` : undefined}
      />
    );
  }
  return (
    <KpiCard
      label={label}
      value={hours.toFixed(1)}
      unit="hrs"
      color={hours > warnAbove ? "text-red-400" : hours > cautionAbove ? "text-yellow-400" : "text-green-400"}
      hint={
        sampleCount === undefined
          ? undefined
          : `mean of ${sampleCount} over ${window}`
      }
    />
  );
}

/**
 * A ratio over an empty denominator is unmeasured, not zero.
 *
 * Same defect as the means above, one step removed: the API computed
 * `x / n if n > 0 else 0.0`, so a tenant that had resolved nothing and gated
 * nothing scored 0% false positives and 0% escalations — the two best numbers
 * on the page, both awarded for having done nothing. The denominator now
 * travels with each rate, so the tile can say which it is. `sampleCount` is
 * optional, so an older API that sends no counts keeps its previous
 * behaviour rather than blanking the tile.
 */
function RateCard({
  label,
  rate,
  sampleCount,
  denominatorLabel,
  warnAbove,
  cautionAbove,
  window,
}: {
  label: string;
  rate: number | undefined;
  sampleCount: number | undefined;
  denominatorLabel: string;
  warnAbove: number;
  cautionAbove: number;
  window: string;
}) {
  if (rate === undefined || sampleCount === 0) {
    return (
      <KpiCard
        label={label}
        value="—"
        color="text-gray-500"
        hint={sampleCount === 0 ? `not measured · no ${denominatorLabel} in ${window}` : undefined}
      />
    );
  }
  return (
    <KpiCard
      label={label}
      value={`${(rate * 100).toFixed(1)}%`}
      color={rate > warnAbove ? "text-red-400" : rate > cautionAbove ? "text-yellow-400" : "text-green-400"}
      hint={
        sampleCount === undefined
          ? undefined
          : `over ${sampleCount} ${denominatorLabel} in ${window}`
      }
    />
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
  const { data, error, mutate } = useSWR<SOCMetrics>(
    // Opaque cache key — `metricsApi.getSOC()` routes through the
    // tenant- and auth-aware `request()` helper, which attaches
    // `X-Tenant-Id` and `Authorization` headers and is bound to the
    // same-origin proxy in `next.config.*` rewrites.
    "soc-metrics",
    () => metricsApi.getSOC(),
    {
      refreshInterval: 60_000,
      fallbackData: demoFallback(MOCK_SOC_METRICS),
      shouldRetryOnError: true,
      errorRetryCount: 3,
      errorRetryInterval: 4000,
      revalidateOnMount: true,
      revalidateOnFocus: false,
    }
  );

  const refresh = useCallback(() => mutate(), [mutate]);

  // `MOCK_SOC_METRICS` is reachable only through the `demoFallback` above,
  // which is `undefined` outside the hosted demo.
  //
  // It used to also be substituted here, unconditionally, whenever `data` was
  // absent or malformed — which is exactly the first-paint and error case. A
  // self-hoster therefore saw MTTD 1.4h, a populated ATT&CK heatmap and an LLM
  // spend line naming models they had never configured, presented as their own
  // numbers. When there is no payload there are now no numbers.
  const isValidSOC =
    !!data &&
    typeof data.kpis?.mttd_hours === "number" &&
    Array.isArray(data.attack_heatmap);
  const kpis = isValidSOC ? data.kpis : undefined;
  const heatmap = isValidSOC ? (data.attack_heatmap ?? []) : [];
  const calibration = isValidSOC ? (data.calibration_curve ?? []) : [];
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
          {errorMessage}. No figures are shown below; they will populate once
          the API recovers.
        </div>
      )}

      {!kpis && !errorMessage && (
        <EmptyState
          title="No SOC performance data yet"
          description="MTTD, MTTR, escalation and false-positive rates are computed from closed cases. They appear once the first investigations complete."
          className="px-4 py-6"
        />
      )}

      {/* KPI Grid */}
      {kpis && (
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <MeanHoursCard
            label="MTTD"
            hours={kpis?.mttd_hours}
            sampleCount={kpis?.mttd_sample_count}
            warnAbove={4}
            cautionAbove={2}
            window="7d"
          />
          <MeanHoursCard
            label="MTTR"
            hours={kpis?.mttr_hours}
            sampleCount={kpis?.mttr_sample_count}
            warnAbove={24}
            cautionAbove={8}
            window="30d"
          />
          <MeanHoursCard
            label="MTTC"
            hours={kpis?.mttc_hours}
            sampleCount={kpis?.mttc_sample_count}
            warnAbove={24}
            cautionAbove={8}
            window="7d"
          />
          <RateCard
            label="Escalation Rate"
            rate={kpis?.escalation_rate}
            sampleCount={kpis?.escalation_rate_sample_count}
            denominatorLabel="gate decisions"
            warnAbove={0.5}
            cautionAbove={0.25}
            window="7d"
          />
          <RateCard
            label="False Positive Rate"
            rate={kpis?.false_positive_rate}
            sampleCount={kpis?.false_positive_rate_sample_count}
            denominatorLabel="resolved alerts"
            warnAbove={0.3}
            cautionAbove={0.15}
            window="7d"
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
      fallbackData: demoFallback(MOCK_COST_AGGREGATE),
      shouldRetryOnError: true,
      errorRetryCount: 3,
      errorRetryInterval: 4000,
      revalidateOnMount: true,
      revalidateOnFocus: false,
    },
  );

  // Same rule as the SOC panel: the mock is the demo fallback and nothing
  // else. Naming `gpt-4o` / `claude-3.5-sonnet` and a $76.65 spend to a
  // tenant that runs neither is a fabricated claim about their own estate.
  const isValidCost =
    !!data &&
    Array.isArray(data.by_model) &&
    typeof data.window_days === "number";
  const totals = isValidCost ? data.totals : undefined;
  const byModel = isValidCost ? (data.by_model ?? []) : [];
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
          {errorMessage}. No spend figures are shown until the API recovers.
        </div>
      )}

      {isLoading && !isValidCost ? (
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
