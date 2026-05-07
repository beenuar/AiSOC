'use client';

import { useState, useCallback } from 'react';
import useSWR from 'swr';
import Link from 'next/link';
import { alertsApi, type Alert, type AlertFilters, type ConfidenceLabel } from '@/lib/api';
import { clsx } from 'clsx';
import { formatDistanceToNow } from 'date-fns';
import { EntityRiskQueue } from './EntityRiskQueue';

// Wave 1 of the AiSOC v6 capability roadmap. The "entities" tab renders the
// rolled-up Risk-Based Alerting queue — alerts contribute time-decayed risk
// points to the entities they touch, and the queue surfaces those entities
// (not the raw alerts) to the analyst. The "alerts" tab keeps the legacy
// alert-centric grid for tenants that prefer it or have RBA disabled.
type ViewMode = 'entities' | 'alerts';

// ─── Config ───────────────────────────────────────────────────────────────────

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', dot: 'bg-red-500', text: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' },
  high: { label: 'High', dot: 'bg-orange-500', text: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20' },
  medium: { label: 'Medium', dot: 'bg-yellow-500', text: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20' },
  low: { label: 'Low', dot: 'bg-blue-500', text: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/20' },
  info: { label: 'Info', dot: 'bg-gray-500', text: 'text-gray-400', bg: 'bg-gray-500/10 border-gray-500/20' },
};

const STATUS_CONFIG = {
  new: { label: 'New', color: 'text-purple-400 bg-purple-500/10 border-purple-500/20' },
  triaged: { label: 'Triaged', color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20' },
  investigating: { label: 'Investigating', color: 'text-blue-400 bg-blue-500/10 border-blue-500/20' },
  resolved: { label: 'Resolved', color: 'text-green-400 bg-green-500/10 border-green-500/20' },
  false_positive: { label: 'False Positive', color: 'text-gray-400 bg-gray-500/10 border-gray-500/20' },
};

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_ALERTS: Alert[] = Array.from({ length: 25 }, (_, i): Alert => {
  const sev = (['critical', 'high', 'high', 'medium', 'medium', 'medium', 'low', 'info'] as const)[i % 8];
  const src = ['CrowdStrike', 'Splunk', 'AWS Security Hub', 'Okta', 'Microsoft Sentinel'][i % 5];
  const status = (['new', 'investigating', 'new', 'resolved', 'false_positive'] as const)[i % 5];
  const conf = (['high', 'high', 'medium', 'medium', 'medium', 'low'] as const)[i % 6];
  const confScore = conf === 'high' ? 0.78 + (i % 5) * 0.03 : conf === 'medium' ? 0.45 + (i % 5) * 0.03 : 0.18 + (i % 5) * 0.03;
  return {
    id: `ALT-${String(1000 + i).padStart(4, '0')}`,
    title: [
      'Suspicious PowerShell Execution via Encoded Command',
      'Lateral Movement via WMI Remote Execution',
      'Credential Dumping Detected: LSASS Access',
      'New Admin Account Created Outside Business Hours',
      'DNS Tunneling Activity Detected',
      'Brute Force Attack: 50+ Failed Logins in 5 Minutes',
      'Malicious File Download: Known Malware Signature',
      'Privilege Escalation: Sudo Command Without Password',
      'Ransomware Behavior: Mass File Encryption Attempt',
      'Command and Control Beacon Traffic Detected',
    ][i % 10],
    description: 'Automated detection based on behavioral analytics and threat intelligence correlation.',
    severity: sev,
    status,
    source: src,
    createdAt: new Date(Date.now() - i * 1800000).toISOString(),
    updatedAt: new Date(Date.now() - i * 900000).toISOString(),
    tenantId: 'default',
    assignee: i % 3 === 0 ? 'analyst@aisoc.dev' : undefined,
    tags: i % 2 === 0 ? ['mitre:T1059', 'endpoint'] : ['network'],
    iocs: [],
    mitreAttack: i % 3 === 0 ? [{ tactic: 'Execution', technique: 'PowerShell', techniqueId: 'T1059.001' }] : [],
    riskScore: Math.floor(Math.random() * 100),
    confidenceLabel: conf,
    confidenceScore: Number(confScore.toFixed(2)),
  };
});

// Wave 1 — Detection confidence chip rendered inline in the alert grid so an
// analyst can spot low-confidence alerts at a glance without clicking through.
// Click-through still goes to AlertDetailView for the full evidence chain.
const CONFIDENCE_ROW_CONFIG: Record<ConfidenceLabel, { label: string; cls: string }> = {
  high: { label: 'HIGH', cls: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' },
  medium: { label: 'MED', cls: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20' },
  low: { label: 'LOW', cls: 'text-gray-400 bg-gray-500/10 border-gray-500/20' },
};

function ConfidencePill({ label }: { label: ConfidenceLabel }) {
  const cfg = CONFIDENCE_ROW_CONFIG[label];
  return (
    <span
      className={clsx('text-[10px] font-mono font-medium px-1.5 py-0.5 rounded border shrink-0', cfg.cls)}
      title={`Detection confidence: ${cfg.label}`}
    >
      {cfg.label}
    </span>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function SeverityDot({ severity }: { severity: string }) {
  const cfg = SEVERITY_CONFIG[severity as keyof typeof SEVERITY_CONFIG] || SEVERITY_CONFIG.info;
  return <span className={clsx('w-2 h-2 rounded-full shrink-0', cfg.dot)} />;
}

function SeverityBadge({ severity }: { severity: string }) {
  const cfg = SEVERITY_CONFIG[severity as keyof typeof SEVERITY_CONFIG] || SEVERITY_CONFIG.info;
  return (
    <span className={clsx('text-xs px-2 py-0.5 rounded border', cfg.text, cfg.bg)}>
      {cfg.label}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_CONFIG[status as keyof typeof STATUS_CONFIG] || STATUS_CONFIG.new;
  return (
    <span className={clsx('text-xs px-2 py-0.5 rounded border', cfg.color)}>
      {cfg.label}
    </span>
  );
}

function FiltersBar({
  filters,
  onChange,
  total,
}: {
  filters: AlertFilters;
  onChange: (f: AlertFilters) => void;
  total: number;
}) {
  const severities = ['all', 'critical', 'high', 'medium', 'low', 'info'] as const;
  const statuses = ['all', 'new', 'investigating', 'resolved', 'false_positive'] as const;

  return (
    <div className="flex items-center gap-3 flex-wrap py-3 px-4 bg-gray-900/40 border border-gray-800/60 rounded-xl">
      <div className="flex items-center gap-1">
        {severities.map((s) => (
          <button
            key={s}
            onClick={() => onChange({ ...filters, severity: s === 'all' ? undefined : s, page: 1 })}
            className={clsx(
              'text-xs px-2.5 py-1 rounded-lg transition-colors capitalize',
              (s === 'all' && !filters.severity) || filters.severity === s
                ? 'bg-blue-600 text-white'
                : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/60'
            )}
          >
            {s}
          </button>
        ))}
      </div>
      <div className="w-px h-4 bg-gray-700" />
      <div className="flex items-center gap-1">
        {statuses.map((s) => (
          <button
            key={s}
            onClick={() => onChange({ ...filters, status: s === 'all' ? undefined : s, page: 1 })}
            className={clsx(
              'text-xs px-2.5 py-1 rounded-lg transition-colors',
              (s === 'all' && !filters.status) || filters.status === s
                ? 'bg-gray-700 text-gray-200'
                : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/60'
            )}
          >
            {s === 'all' ? 'All status' : s.replace('_', ' ')}
          </button>
        ))}
      </div>
      <span className="ml-auto text-xs text-gray-600">{total} total</span>
    </div>
  );
}

function AlertRow({ alert }: { alert: Alert }) {
  return (
    <Link
      href={`/alerts/${alert.id}`}
      className="flex items-center gap-4 px-4 py-3 hover:bg-gray-800/20 transition-colors border-b border-gray-800/40 last:border-0"
    >
      <SeverityDot severity={alert.severity} />

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <p className="text-sm text-gray-200 truncate hover:text-white">{alert.title}</p>
          {alert.mitreAttack && alert.mitreAttack.length > 0 && (
            <span className="text-xs bg-orange-500/10 text-orange-400 border border-orange-500/20 px-1.5 py-0.5 rounded shrink-0">
              {alert.mitreAttack[0].techniqueId}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 mt-0.5">
          <span className="text-xs text-gray-600">{alert.source}</span>
          {alert.assignee && (
            <>
              <span className="text-gray-700">·</span>
              <span className="text-xs text-gray-600">{alert.assignee}</span>
            </>
          )}
        </div>
      </div>

      <div className="flex items-center gap-2 shrink-0">
        {alert.confidenceLabel && <ConfidencePill label={alert.confidenceLabel} />}
        <SeverityBadge severity={alert.severity} />
        <StatusBadge status={alert.status} />
        <span className="text-xs text-gray-600 w-24 text-right">
          {formatDistanceToNow(new Date(alert.createdAt), { addSuffix: true })}
        </span>
      </div>
    </Link>
  );
}

// ─── Main View ────────────────────────────────────────────────────────────────

export function AlertsView() {
  const [filters, setFilters] = useState<AlertFilters>({ page: 1, pageSize: 25 });
  // Default to the entity-centric queue — that's the whole point of Wave 1's
  // RBA work. Analysts can flip back to the raw alert grid for legacy
  // workflows or when triaging a specific alert ID.
  const [viewMode, setViewMode] = useState<ViewMode>('entities');

  const { data, error, isLoading } = useSWR(
    ['alerts', filters],
    () => alertsApi.list(filters),
    {
      fallbackData: {
        alerts: MOCK_ALERTS,
        total: MOCK_ALERTS.length,
        page: 1,
        pageSize: 25,
      },
      refreshInterval: 30000,
    }
  );

  const handleFilterChange = useCallback((newFilters: AlertFilters) => {
    setFilters(newFilters);
  }, []);

  const alerts = data?.alerts || [];
  const total = data?.total || 0;

  const critCount = alerts.filter((a) => a.severity === 'critical').length;
  const highCount = alerts.filter((a) => a.severity === 'high').length;
  const newCount = alerts.filter((a) => a.status === 'new').length;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-100">Alerts</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            {viewMode === 'entities'
              ? 'Risk-Based Alerting · entity-centric triage queue'
              : 'Real-time security event monitoring and triage'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div
            role="tablist"
            aria-label="View mode"
            className="inline-flex items-center bg-gray-900/60 border border-gray-800/60 rounded-lg p-0.5"
          >
            <button
              type="button"
              role="tab"
              aria-selected={viewMode === 'entities'}
              onClick={() => setViewMode('entities')}
              className={clsx(
                'text-xs px-3 py-1.5 rounded-md transition-colors',
                viewMode === 'entities'
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 hover:text-gray-200',
              )}
            >
              Entities
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={viewMode === 'alerts'}
              onClick={() => setViewMode('alerts')}
              className={clsx(
                'text-xs px-3 py-1.5 rounded-md transition-colors',
                viewMode === 'alerts'
                  ? 'bg-gray-700 text-gray-100'
                  : 'text-gray-400 hover:text-gray-200',
              )}
            >
              Alerts
            </button>
          </div>
          <button className="bg-blue-600 hover:bg-blue-500 text-white text-sm px-4 py-2 rounded-lg transition-colors">
            + Create Alert
          </button>
        </div>
      </div>

      {viewMode === 'entities' ? (
        <EntityRiskQueue />
      ) : (
        <AlertsTable
          alerts={alerts}
          total={total}
          critCount={critCount}
          highCount={highCount}
          newCount={newCount}
          filters={filters}
          isLoading={isLoading}
          error={error}
          onFilterChange={handleFilterChange}
        />
      )}
    </div>
  );
}

// ─── Legacy alert-centric grid (extracted for the view-mode toggle) ──────────

function AlertsTable({
  alerts,
  total,
  critCount,
  highCount,
  newCount,
  filters,
  isLoading,
  error,
  onFilterChange,
}: {
  alerts: Alert[];
  total: number;
  critCount: number;
  highCount: number;
  newCount: number;
  filters: AlertFilters;
  isLoading: boolean;
  error: unknown;
  onFilterChange: (f: AlertFilters) => void;
}) {
  return (
    <div className="space-y-4">
      {/* Stats strip */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total', value: total, color: 'text-gray-200' },
          { label: 'Critical', value: critCount, color: 'text-red-400' },
          { label: 'High', value: highCount, color: 'text-orange-400' },
          { label: 'Unresolved', value: newCount, color: 'text-purple-400' },
        ].map((stat) => (
          <div key={stat.label} className="bg-gray-900/60 border border-gray-800/60 rounded-xl px-4 py-3">
            <p className="text-xs text-gray-500">{stat.label}</p>
            <p className={clsx('text-2xl font-bold mt-1', stat.color)}>{stat.value}</p>
          </div>
        ))}
      </div>

      <FiltersBar filters={filters} onChange={onFilterChange} total={total} />

      {/* Table */}
      <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl overflow-hidden">
        <div className="flex items-center px-4 py-2 border-b border-gray-800/60 bg-gray-900/80">
          <span className="text-xs text-gray-500 flex-1">ALERT</span>
          <span className="text-xs text-gray-500 w-20">SEVERITY</span>
          <span className="text-xs text-gray-500 w-24">STATUS</span>
          <span className="text-xs text-gray-500 w-24 text-right">TIME</span>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center h-32">
            <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          </div>
        ) : error ? (
          <div className="flex items-center justify-center h-32 text-red-400 text-sm">
            Failed to load alerts
          </div>
        ) : alerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 text-gray-500">
            <p className="text-sm">No alerts found</p>
          </div>
        ) : (
          <div>
            {alerts.map((alert) => (
              <AlertRow key={alert.id} alert={alert} />
            ))}
          </div>
        )}
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between text-xs text-gray-500">
        <span>Showing {alerts.length} of {total} alerts</span>
        <div className="flex items-center gap-1">
          <button
            onClick={() => onFilterChange({ ...filters, page: Math.max(1, (filters.page || 1) - 1) })}
            disabled={(filters.page || 1) <= 1}
            className="px-2 py-1 rounded bg-gray-800 hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Prev
          </button>
          <span className="px-2">Page {filters.page || 1}</span>
          <button
            onClick={() => onFilterChange({ ...filters, page: (filters.page || 1) + 1 })}
            disabled={alerts.length < (filters.pageSize || 25)}
            className="px-2 py-1 rounded bg-gray-800 hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
