'use client';

import { useState } from 'react';
import useSWR, { mutate } from 'swr';

const fetcher = (url: string) => fetch(url).then((r) => r.json());

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
}

interface SLAConfig {
  id: string;
  severity: string;
  mttd_target: number;
  mttr_target: number;
  mttc_target: number;
}

const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400',
  high:     'text-orange-400',
  medium:   'text-yellow-400',
  low:      'text-blue-400',
};

const SEVERITY_BG: Record<string, string> = {
  critical: 'bg-red-900/30 border-red-700',
  high:     'bg-orange-900/30 border-orange-700',
  medium:   'bg-yellow-900/30 border-yellow-700',
  low:      'bg-blue-900/30 border-blue-700',
};

function fmtMinutes(min: number | null): string {
  if (min === null || min === undefined) return '—';
  if (min < 60) return `${min}m`;
  const h = Math.floor(min / 60);
  const m = min % 60;
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

export function SLADashboard() {
  const [days, setDays] = useState(30);
  const [editConfig, setEditConfig] = useState<SLAConfig | null>(null);

  const { data: metrics, isLoading: metricsLoading } = useSWR<SLAMetrics>(
    `/api/v1/sla/metrics?days=${days}`,
    fetcher,
    { refreshInterval: 60_000 }
  );

  const { data: configs } = useSWR<SLAConfig[]>('/api/v1/sla/config', fetcher);

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

      {/* Per-severity breakdown */}
      {metricsLoading && (
        <p className="text-gray-400 text-sm">Loading metrics…</p>
      )}

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
    </div>
  );
}
