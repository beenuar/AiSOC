'use client';

import { useState } from 'react';
import useSWR, { mutate } from 'swr';

const fetcher = async (url: string) => {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const text = await r.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error('Invalid JSON');
  }
};

interface SeverityMetrics {
  total: number;
  breaches: number;
  breach_rate: number;
  mttd_avg: number | null;
  mttr_avg: number | null;
  mttc_avg: number | null;
  mttd_target: number | null;
  mttr_target: number | null;
  mttc_target: number | null;
}

interface KpiBarPayload {
  targets: {
    false_positive_rate_max_pct: number;
    alert_to_incident_ratio_min: number;
    mitre_technique_tagging_min_pct: number;
    mitre_subtechnique_tagging_min_pct: number;
  };
  observed: {
    total_alerts: number;
    false_positives: number;
    false_positive_rate_pct: number;
    distinct_cases: number;
    alert_to_incident_ratio: number;
    mitre_technique_tagging_pct: number;
    mitre_subtechnique_tagging_pct: number;
  };
  breaches: {
    false_positive_rate: boolean;
    alert_to_incident_ratio: boolean;
    mitre_technique_tagging: boolean;
    mitre_subtechnique_tagging: boolean;
  };
  breach_count: number;
}

interface SLAMetrics {
  period_days: number;
  computed_at: string;
  overall: {
    total_alerts: number;
    total_breaches: number;
    breach_rate: number;
    mttd_avg: number | null;
    mttr_avg: number | null;
    mttc_avg: number | null;
  };
  per_severity: Record<string, SeverityMetrics>;
  kpi_bar: KpiBarPayload | null;
}

interface SLAConfig {
  id: string;
  severity: string;
  mttd_target: number;
  mttr_target: number;
  mttc_target: number;
}

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400',
  high:     'text-orange-400',
  medium:   'text-yellow-400',
  low:      'text-blue-400',
  info:     'text-slate-400',
};

const SEVERITY_BG: Record<string, string> = {
  critical: 'bg-red-900/30 border-red-700',
  high:     'bg-orange-900/30 border-orange-700',
  medium:   'bg-yellow-900/30 border-yellow-700',
  low:      'bg-blue-900/30 border-blue-700',
  info:     'bg-slate-900/30 border-slate-700',
};

function fmtMinutes(min: number | null): string {
  if (min === null || min === undefined) return '—';
  if (min < 60) return `${Math.round(min * 10) / 10}m`;
  const h = Math.floor(min / 60);
  const m = Math.round(min % 60);
  return m > 0 ? `${h}h ${m}m` : `${h}h`;
}

function StatusBadge({ value, target }: { value: number | null; target: number | null }) {
  if (value === null || target === null) {
    return <span className="text-gray-500">—</span>;
  }
  const ok = value <= target;
  return (
    <span className={ok ? 'text-green-400' : 'text-red-400'}>
      {fmtMinutes(value)}
      <span className="ml-1 text-xs text-gray-500">/ {fmtMinutes(target)}</span>
    </span>
  );
}

function EditConfigModal({
  config,
  onClose,
  onSaved,
}: {
  config: SLAConfig;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [mttd, setMttd] = useState(config.mttd_target);
  const [mttr, setMttr] = useState(config.mttr_target);
  const [mttc, setMttc] = useState(config.mttc_target);
  const [saving, setSaving] = useState(false);

  const save = async () => {
    setSaving(true);
    await fetch(`/api/v1/sla/config/${config.severity}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mttd_target: mttd, mttr_target: mttr, mttc_target: mttc }),
    });
    setSaving(false);
    onSaved();
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-6 w-full max-w-sm space-y-4">
        <h3 className="text-white font-semibold text-lg capitalize">{config.severity} SLA Targets</h3>
        {[
          { label: 'MTTD (min)', val: mttd, set: setMttd },
          { label: 'MTTR (min)', val: mttr, set: setMttr },
          { label: 'MTTC (min)', val: mttc, set: setMttc },
        ].map(({ label, val, set }) => (
          <div key={label}>
            <label className="text-gray-400 text-xs block mb-1">{label}</label>
            <input
              type="number"
              min={1}
              value={val}
              onChange={(e) => set(Number(e.target.value))}
              className="w-full bg-gray-800 border border-gray-600 text-white rounded px-3 py-1.5 text-sm"
            />
          </div>
        ))}
        <div className="flex gap-2 pt-2">
          <button
            onClick={save}
            disabled={saving}
            className="flex-1 bg-blue-600 hover:bg-blue-500 text-white rounded px-3 py-2 text-sm font-medium disabled:opacity-50"
          >
            {saving ? 'Saving…' : 'Save'}
          </button>
          <button
            onClick={onClose}
            className="flex-1 bg-gray-700 hover:bg-gray-600 text-white rounded px-3 py-2 text-sm"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

type KpiBarTargets = KpiBarPayload['targets'];

function EditKpiBarModal({
  targets,
  onClose,
  onSaved,
}: {
  targets: KpiBarTargets;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [fpMax, setFpMax] = useState(targets.false_positive_rate_max_pct);
  const [ratioMin, setRatioMin] = useState(targets.alert_to_incident_ratio_min);
  const [mitreMin, setMitreMin] = useState(targets.mitre_technique_tagging_min_pct);
  const [subMin, setSubMin] = useState(targets.mitre_subtechnique_tagging_min_pct);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const save = async () => {
    setErr(null);
    setSaving(true);
    try {
      const res = await fetch('/api/v1/sla/kpi-targets', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          false_positive_rate_max_pct: fpMax,
          alert_to_incident_ratio_min: ratioMin,
          mitre_technique_tagging_min_pct: mitreMin,
          mitre_subtechnique_tagging_min_pct: subMin,
        }),
      });
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        setErr((j as { detail?: string }).detail ?? `HTTP ${res.status}`);
        setSaving(false);
        return;
      }
      onSaved();
      onClose();
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-md space-y-4 rounded-xl border border-gray-700 bg-gray-900 p-6">
        <h3 className="text-lg font-semibold text-white">2026 KPI bar targets</h3>
        <p className="text-xs text-gray-500">
          Published defaults apply until you override. Metrics use the same look-back as SLA metrics.
        </p>
        {[
          {
            label: 'False positive rate (max %)',
            val: fpMax,
            set: setFpMax,
            min: 0,
            max: 100,
            step: 0.5,
          },
          {
            label: 'Alert-to-incident ratio (min)',
            val: ratioMin,
            set: setRatioMin,
            min: 1,
            max: 500,
            step: 1,
          },
          {
            label: 'MITRE technique tagging (min %)',
            val: mitreMin,
            set: setMitreMin,
            min: 0,
            max: 100,
            step: 1,
          },
          {
            label: 'MITRE sub-technique tagging (min %)',
            val: subMin,
            set: setSubMin,
            min: 0,
            max: 100,
            step: 1,
          },
        ].map(({ label, val, set, min, max, step }) => (
          <div key={label}>
            <label className="mb-1 block text-xs text-gray-400">{label}</label>
            <input
              type="number"
              min={min}
              max={max}
              step={step}
              value={val}
              onChange={(e) => set(Number(e.target.value))}
              className="w-full rounded border border-gray-600 bg-gray-800 px-3 py-1.5 text-sm text-white"
            />
          </div>
        ))}
        {err && <p className="text-sm text-red-400">{err}</p>}
        <div className="flex gap-2 pt-2">
          <button
            type="button"
            onClick={save}
            disabled={saving}
            className="flex-1 rounded bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
          >
            {saving ? 'Saving…' : 'Save'}
          </button>
          <button
            type="button"
            onClick={onClose}
            className="flex-1 rounded bg-gray-700 px-3 py-2 text-sm text-white hover:bg-gray-600"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

function KpiBarSection({
  kpi,
  days,
  onEditTargets,
}: {
  kpi: KpiBarPayload;
  days: number;
  onEditTargets: () => void;
}) {
  const { targets, observed, breaches, breach_count } = kpi;

  const rows: {
    key: string;
    label: string;
    observed: string;
    target: string;
    breach: boolean;
  }[] = [
    {
      key: 'fp',
      label: 'False positive rate',
      observed: `${observed.false_positive_rate_pct}% (${observed.false_positives} / ${observed.total_alerts})`,
      target: `≤ ${targets.false_positive_rate_max_pct}%`,
      breach: breaches.false_positive_rate,
    },
    {
      key: 'ratio',
      label: 'Alert-to-incident ratio',
      observed:
        observed.distinct_cases > 0
          ? `${observed.alert_to_incident_ratio}:1`
          : `${observed.total_alerts} alerts, no linked cases`,
      target: `≥ ${targets.alert_to_incident_ratio_min}:1 when cases exist`,
      breach: breaches.alert_to_incident_ratio,
    },
    {
      key: 'mitre',
      label: 'MITRE technique coverage',
      observed: `${observed.mitre_technique_tagging_pct}%`,
      target: `≥ ${targets.mitre_technique_tagging_min_pct}%`,
      breach: breaches.mitre_technique_tagging,
    },
    {
      key: 'sub',
      label: 'MITRE sub-technique coverage',
      observed: `${observed.mitre_subtechnique_tagging_pct}%`,
      target: `≥ ${targets.mitre_subtechnique_tagging_min_pct}%`,
      breach: breaches.mitre_subtechnique_tagging,
    },
  ];

  return (
    <div className="rounded-xl border border-violet-500/25 bg-violet-950/20 p-5">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-lg font-semibold text-white">2026 KPI bar</h2>
          <p className="text-xs text-gray-500">
            Operational quality vs tenant targets (last {days} days)
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span
            className={
              breach_count > 0
                ? 'rounded-full border border-red-500/40 bg-red-500/10 px-3 py-1 text-xs font-medium text-red-300'
                : 'rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-300'
            }
          >
            {breach_count === 0 ? 'All KPIs met' : `${breach_count} breach${breach_count === 1 ? '' : 'es'}`}
          </span>
          <button
            type="button"
            onClick={onEditTargets}
            className="text-xs text-violet-300 hover:text-violet-200"
          >
            Edit targets
          </button>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[520px] text-left text-sm">
          <thead>
            <tr className="border-b border-gray-700 text-gray-500">
              <th className="py-2 pr-4 font-medium">Metric</th>
              <th className="py-2 pr-4 font-medium">Observed</th>
              <th className="py-2 pr-4 font-medium">Target</th>
              <th className="py-2 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.key} className="border-b border-gray-800/80">
                <td className="py-2.5 pr-4 text-gray-200">{r.label}</td>
                <td className="py-2.5 pr-4 text-white">{r.observed}</td>
                <td className="py-2.5 pr-4 text-gray-400">{r.target}</td>
                <td className="py-2.5">
                  {r.breach ? (
                    <span className="text-red-400">Breach</span>
                  ) : (
                    <span className="text-emerald-400">OK</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const MOCK_SLA_METRICS: SLAMetrics = {
  period_days: 30,
  computed_at: '2026-05-06T12:00:00Z',
  overall: { total_alerts: 847, total_breaches: 23, breach_rate: 2.7, mttd_avg: 24.4, mttr_avg: 42.5, mttc_avg: 112.0 },
  per_severity: {
    critical: { total: 42, breaches: 3, breach_rate: 7.1, mttd_avg: 8.2, mttr_avg: 18.5, mttc_avg: 35.1, mttd_target: 15, mttr_target: 30, mttc_target: 60 },
    high: { total: 186, breaches: 8, breach_rate: 4.3, mttd_avg: 15.4, mttr_avg: 38.2, mttc_avg: 72.6, mttd_target: 30, mttr_target: 60, mttc_target: 120 },
    medium: { total: 312, breaches: 9, breach_rate: 2.9, mttd_avg: 28.7, mttr_avg: 65.3, mttc_avg: 124.8, mttd_target: 60, mttr_target: 120, mttc_target: 240 },
    low: { total: 307, breaches: 3, breach_rate: 1.0, mttd_avg: 45.2, mttr_avg: 98.6, mttc_avg: 215.4, mttd_target: 120, mttr_target: 240, mttc_target: 480 },
  },
  kpi_bar: null,
};

const MOCK_SLA_CONFIGS: SLAConfig[] = [
  { id: 'sla-1', severity: 'critical', mttd_target: 15, mttr_target: 30, mttc_target: 60 },
  { id: 'sla-2', severity: 'high', mttd_target: 30, mttr_target: 60, mttc_target: 120 },
  { id: 'sla-3', severity: 'medium', mttd_target: 60, mttr_target: 120, mttc_target: 240 },
  { id: 'sla-4', severity: 'low', mttd_target: 120, mttr_target: 240, mttc_target: 480 },
];

export function SLADashboard() {
  const [days, setDays] = useState(30);
  const [editConfig, setEditConfig] = useState<SLAConfig | null>(null);
  const [editKpiTargets, setEditKpiTargets] = useState<KpiBarTargets | null>(null);

  const { data: rawMetrics, error: metricsError } = useSWR<SLAMetrics>(
    `/api/v1/sla/metrics?days=${days}`,
    fetcher,
    {
      refreshInterval: 60_000,
      fallbackData: MOCK_SLA_METRICS,
      shouldRetryOnError: false,
      errorRetryCount: 0,
      revalidateOnFocus: false,
    }
  );

  const isValidMetrics =
    rawMetrics &&
    typeof rawMetrics.overall?.total_alerts === 'number' &&
    typeof rawMetrics.per_severity === 'object';
  const metrics = isValidMetrics ? rawMetrics : MOCK_SLA_METRICS;

  const { data: configs } = useSWR<SLAConfig[]>('/api/v1/sla/config', fetcher, {
    fallbackData: MOCK_SLA_CONFIGS,
    shouldRetryOnError: false,
    errorRetryCount: 0,
    revalidateOnFocus: false,
  });

  const configBySeverity = (configs ?? []).reduce<Record<string, SLAConfig>>(
    (acc, c) => ({ ...acc, [c.severity]: c }),
    {}
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">SLA Tracking</h1>
          <p className="text-gray-400 text-sm mt-1">
            MTTD / MTTR / MTTC metrics vs configured targets
          </p>
        </div>
        <select
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
          className="bg-gray-800 border border-gray-600 text-white text-sm rounded px-3 py-1.5"
        >
          {[7, 14, 30, 60, 90].map((d) => (
            <option key={d} value={d}>
              Last {d} days
            </option>
          ))}
        </select>
      </div>

      {metricsError && (
        <div className="rounded-md border border-amber-500/30 bg-amber-500/5 px-4 py-2 text-xs text-amber-200">
          SLA API unreachable — showing demo metrics so you can explore the dashboard.
        </div>
      )}

      {/* Overall summary cards */}
      {metrics && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { label: 'Total Alerts', value: metrics.overall.total_alerts },
            { label: 'SLA Breaches', value: metrics.overall.total_breaches },
            { label: 'Breach Rate', value: `${metrics.overall.breach_rate}%` },
            {
              label: 'Avg MTTR',
              value: fmtMinutes(metrics.overall.mttr_avg),
            },
          ].map(({ label, value }) => (
            <div
              key={label}
              className="bg-gray-800 border border-gray-700 rounded-lg p-4"
            >
              <p className="text-gray-400 text-xs">{label}</p>
              <p className="text-white text-2xl font-semibold mt-1">{value}</p>
            </div>
          ))}
        </div>
      )}

      {metrics?.kpi_bar && (
        <KpiBarSection
          kpi={metrics.kpi_bar}
          days={days}
          onEditTargets={() => setEditKpiTargets(metrics.kpi_bar!.targets)}
        />
      )}

      {/* Per-severity breakdown */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {SEVERITIES.map((sev) => {
            const s = metrics.per_severity[sev];
            const cfg = configBySeverity[sev];
            if (!s) return null;
            return (
              <div
                key={sev}
                className={`border rounded-lg p-5 ${SEVERITY_BG[sev]}`}
              >
                <div className="flex items-center justify-between mb-4">
                  <h2
                    className={`font-semibold text-base capitalize ${SEVERITY_COLORS[sev]}`}
                  >
                    {sev}
                  </h2>
                  <div className="flex items-center gap-3">
                    <span className="text-gray-400 text-xs">
                      {s.total} alerts · {s.breaches} breaches ({s.breach_rate}%)
                    </span>
                    {cfg && (
                      <button
                        onClick={() => setEditConfig(cfg)}
                        className="text-xs text-blue-400 hover:text-blue-300"
                      >
                        Edit targets
                      </button>
                    )}
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-3 text-sm">
                  {[
                    { metric: 'MTTD', avg: s.mttd_avg, target: s.mttd_target },
                    { metric: 'MTTR', avg: s.mttr_avg, target: s.mttr_target },
                    { metric: 'MTTC', avg: s.mttc_avg, target: s.mttc_target },
                  ].map(({ metric, avg, target }) => (
                    <div key={metric}>
                      <p className="text-gray-500 text-xs mb-1">{metric}</p>
                      <StatusBadge value={avg} target={target} />
                    </div>
                  ))}
                </div>
                {/* Breach indicator bar */}
                <div className="mt-4">
                  <div className="h-1.5 w-full bg-gray-700 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${
                        s.breach_rate > 50
                          ? 'bg-red-500'
                          : s.breach_rate > 20
                          ? 'bg-yellow-500'
                          : 'bg-green-500'
                      }`}
                      style={{ width: `${Math.min(s.breach_rate, 100)}%` }}
                    />
                  </div>
                  <p className="text-gray-500 text-xs mt-1">
                    {s.breach_rate}% breach rate
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Edit modal */}
      {editConfig && (
        <EditConfigModal
          config={editConfig}
          onClose={() => setEditConfig(null)}
          onSaved={() => {
            mutate('/api/v1/sla/config');
            mutate(`/api/v1/sla/metrics?days=${days}`);
          }}
        />
      )}

      {editKpiTargets && (
        <EditKpiBarModal
          targets={editKpiTargets}
          onClose={() => setEditKpiTargets(null)}
          onSaved={() => {
            mutate('/api/v1/sla/kpi-targets');
            mutate(`/api/v1/sla/metrics?days=${days}`);
          }}
        />
      )}
    </div>
  );
}
