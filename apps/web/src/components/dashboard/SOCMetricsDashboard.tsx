"use client";

import { useCallback } from "react";
import useSWR from "swr";

interface SOCKpis {
  mttd_hours: number;
  mttr_hours: number;
  false_positive_rate: number;
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

interface SOCMetrics {
  kpis: SOCKpis;
  attack_heatmap: AttackHeatmapCell[];
}

const fetcher = (url: string) =>
  fetch(url, { credentials: "include" }).then((r) => r.json());

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
    </div>
  );
}
