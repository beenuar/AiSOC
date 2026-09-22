'use client';

/**
 * Entity-centric Risk-Based Alerting (RBA) queue.
 *
 * Wave 1 of the AiSOC v6 capability roadmap. Renders the rolled-up entity
 * queue produced by the fusion service's EntityRiskEngine. Each row is a
 * *user / host / ip / domain* with a time-decayed score, contributing alerts,
 * and a severity histogram — not a raw alert. Goal: surface ≤ 1 entity per
 * promotion-worthy cluster of alerts so the analyst opens "the user
 * fox.beach" rather than 47 separate alert rows.
 */

import { useState } from 'react';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { formatDistanceToNow } from 'date-fns';
import {
  entityRiskApi,
  type AlertSeverity,
  type EntityRiskRecord,
  type EntityRiskStats,
  type EntityType,
} from '@/lib/api';
import { demoFallback } from '@/lib/demoFallback';

// ─── Visual config ───────────────────────────────────────────────────────────

const ENTITY_TYPE_CONFIG: Record<
  EntityType,
  { label: string; icon: string; tint: string }
> = {
  user: { label: 'User', icon: '👤', tint: 'text-purple-300' },
  host: { label: 'Host', icon: '🖥️', tint: 'text-cyan-300' },
  ip: { label: 'IP', icon: '🌐', tint: 'text-blue-300' },
  domain: { label: 'Domain', icon: '🔗', tint: 'text-emerald-300' },
};

const SEVERITY_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  info: 'bg-gray-500',
};

const MOCK_ENTITIES: EntityRiskRecord[] = [
  {
    tenant_id: 'demo', entity_type: 'user' as EntityType, entity_value: 'jsmith@acme.corp',
    score: 92.4, display_score: 92, threshold: 80, promoted: true, promoted_incident_id: null, alert_count: 8,
    severity_histogram: { critical: 2, high: 3, medium: 2, low: 1, info: 0 },
    first_seen: '2026-05-06T06:15:00Z', last_seen: '2026-05-06T12:42:00Z',
    contributions: [
      { alert_id: 'ALT-4021', title: 'Impossible Travel Detected', severity: 'critical' as AlertSeverity, source: 'Okta', raw_points: 28, observed_at: '2026-05-06T12:42:00Z' },
      { alert_id: 'ALT-4018', title: 'Suspicious MFA Reset', severity: 'high' as AlertSeverity, source: 'Azure AD', raw_points: 18, observed_at: '2026-05-06T11:30:00Z' },
      { alert_id: 'ALT-4015', title: 'Bulk File Download from SharePoint', severity: 'high' as AlertSeverity, source: 'Microsoft 365', raw_points: 15, observed_at: '2026-05-06T10:15:00Z' },
    ],
  },
  {
    tenant_id: 'demo', entity_type: 'host' as EntityType, entity_value: 'WS-PROD-042',
    score: 78.1, display_score: 78, threshold: 80, promoted: false, promoted_incident_id: null, alert_count: 5,
    severity_histogram: { critical: 1, high: 2, medium: 2, low: 0, info: 0 },
    first_seen: '2026-05-06T08:30:00Z', last_seen: '2026-05-06T12:15:00Z',
    contributions: [
      { alert_id: 'ALT-4019', title: 'PowerShell Encoded Command', severity: 'critical' as AlertSeverity, source: 'CrowdStrike', raw_points: 25, observed_at: '2026-05-06T12:15:00Z' },
      { alert_id: 'ALT-4016', title: 'LSASS Memory Access', severity: 'high' as AlertSeverity, source: 'CrowdStrike', raw_points: 20, observed_at: '2026-05-06T11:00:00Z' },
    ],
  },
  {
    tenant_id: 'demo', entity_type: 'ip' as EntityType, entity_value: '198.51.100.42',
    score: 65.3, display_score: 65, threshold: 80, promoted: false, promoted_incident_id: null, alert_count: 4,
    severity_histogram: { critical: 0, high: 1, medium: 3, low: 0, info: 0 },
    first_seen: '2026-05-06T09:00:00Z', last_seen: '2026-05-06T11:45:00Z',
    contributions: [
      { alert_id: 'ALT-4020', title: 'C2 Beacon Pattern Detected', severity: 'high' as AlertSeverity, source: 'Splunk', raw_points: 22, observed_at: '2026-05-06T11:45:00Z' },
    ],
  },
  {
    tenant_id: 'demo', entity_type: 'domain' as EntityType, entity_value: 'updates.evil-cdn.xyz',
    score: 88.7, display_score: 89, threshold: 80, promoted: true, promoted_incident_id: null, alert_count: 6,
    severity_histogram: { critical: 1, high: 3, medium: 2, low: 0, info: 0 },
    first_seen: '2026-05-06T07:00:00Z', last_seen: '2026-05-06T12:30:00Z',
    contributions: [
      { alert_id: 'ALT-4022', title: 'Known Malicious Domain Resolution', severity: 'critical' as AlertSeverity, source: 'Threat Intel', raw_points: 30, observed_at: '2026-05-06T12:30:00Z' },
      { alert_id: 'ALT-4017', title: 'DNS Tunneling Suspected', severity: 'high' as AlertSeverity, source: 'Splunk', raw_points: 18, observed_at: '2026-05-06T10:45:00Z' },
    ],
  },
  {
    tenant_id: 'demo', entity_type: 'user' as EntityType, entity_value: 'admin@partner.co',
    score: 45.2, display_score: 45, threshold: 80, promoted: false, promoted_incident_id: null, alert_count: 3,
    severity_histogram: { critical: 0, high: 0, medium: 2, low: 1, info: 0 },
    first_seen: '2026-05-06T10:00:00Z', last_seen: '2026-05-06T12:00:00Z',
    contributions: [
      { alert_id: 'ALT-4023', title: 'Failed Login Brute Force', severity: 'medium' as AlertSeverity, source: 'Okta', raw_points: 12, observed_at: '2026-05-06T12:00:00Z' },
    ],
  },
];

const MOCK_ENTITY_STATS: EntityRiskStats = {
  tenant_id: 'demo',
  total: 5,
  promoted: 2,
  alert_count: 26,
  threshold: 80,
  bands: { critical: 1, high: 1, medium: 2, low: 1 },
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function bandFor(score: number, threshold: number): {
  label: string;
  text: string;
  bg: string;
  bar: string;
} {
  // Bands are anchored on the configured promotion threshold so the queue
  // visually reflects the operator's tuning, not magic numbers.
  if (score >= threshold) {
    return {
      label: 'Critical',
      text: 'text-red-300',
      bg: 'bg-red-500/10 border-red-500/30',
      bar: 'bg-red-500',
    };
  }
  if (score >= threshold * 0.66) {
    return {
      label: 'High',
      text: 'text-orange-300',
      bg: 'bg-orange-500/10 border-orange-500/30',
      bar: 'bg-orange-500',
    };
  }
  if (score >= threshold * 0.33) {
    return {
      label: 'Medium',
      text: 'text-yellow-300',
      bg: 'bg-yellow-500/10 border-yellow-500/30',
      bar: 'bg-yellow-500',
    };
  }
  return {
    label: 'Low',
    text: 'text-blue-300',
    bg: 'bg-blue-500/10 border-blue-500/30',
    bar: 'bg-blue-500',
  };
}

// ─── Sub-components ──────────────────────────────────────────────────────────

function RatioStat({
  alertCount,
  incidentCount,
}: {
  alertCount: number;
  incidentCount: number;
}) {
  // Alert-to-incident ratio is the published 2026 KPI bar (≥ 50:1). We always
  // surface it here because it's the single number that measures whether RBA
  // is actually delivering — collapsing N alerts into 1 entity-incident.
  const ratio =
    incidentCount > 0
      ? alertCount / incidentCount
      : alertCount > 0
      ? Number.POSITIVE_INFINITY
      : 0;
  const meets = ratio >= 50;
  const display = !Number.isFinite(ratio)
    ? `${alertCount}:0`
    : ratio === 0
    ? '0:0'
    : `${ratio.toFixed(1)}:1`;
  return (
    <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl px-4 py-3">
      <p className="text-xs text-gray-500">Alert → Incident</p>
      <p
        className={clsx(
          'text-2xl font-bold mt-1',
          meets ? 'text-green-400' : 'text-yellow-400',
        )}
      >
        {display}
      </p>
      <p className="text-[10px] text-gray-600 mt-0.5">
        2026 bar ≥ 50:1 {meets ? '✓' : '↑'}
      </p>
    </div>
  );
}

function SeverityHistogram({
  histogram,
}: {
  histogram: Record<string, number>;
}) {
  const order: Array<keyof typeof SEVERITY_DOT> = [
    'critical',
    'high',
    'medium',
    'low',
    'info',
  ];
  return (
    <div className="flex items-center gap-2">
      {order.map((sev) => {
        const count = histogram[sev] ?? 0;
        if (count === 0) return null;
        return (
          <span
            key={sev}
            className="flex items-center gap-1 text-[11px] text-gray-400"
            title={`${count} ${sev}`}
          >
            <span
              className={clsx('w-1.5 h-1.5 rounded-full', SEVERITY_DOT[sev])}
            />
            {count}
          </span>
        );
      })}
    </div>
  );
}

function ScoreBar({
  score,
  threshold,
}: {
  score: number;
  threshold: number;
}) {
  const band = bandFor(score, threshold);
  // Cap the rendered fill at 1.5× threshold so very-high entities don't visually
  // saturate at the same width as merely-high ones.
  const max = threshold * 1.5;
  const pct = Math.min(100, (score / max) * 100);
  return (
    <div className="flex items-center gap-2 w-32 shrink-0">
      <div className="flex-1 h-1.5 bg-gray-800 rounded-full overflow-hidden">
        <div
          className={clsx('h-full rounded-full', band.bar)}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className={clsx('text-xs font-mono shrink-0', band.text)}>
        {Math.round(score)}
      </span>
    </div>
  );
}

function EntityRow({
  record,
  onSelect,
}: {
  record: EntityRiskRecord;
  onSelect: () => void;
}) {
  const cfg = ENTITY_TYPE_CONFIG[record.entity_type] ?? ENTITY_TYPE_CONFIG.user;
  const band = bandFor(record.score, record.threshold);
  return (
    <button
      type="button"
      onClick={onSelect}
      className="w-full flex items-center gap-4 px-4 py-3 hover:bg-gray-800/20 transition-colors border-b border-gray-800/40 last:border-0 text-left"
    >
      <span className="text-base shrink-0" aria-hidden>
        {cfg.icon}
      </span>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className={clsx('text-xs uppercase tracking-wider', cfg.tint)}>
            {cfg.label}
          </span>
          <span className="text-sm text-gray-200 truncate font-medium">
            {record.entity_value}
          </span>
          {record.promoted && (
            <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-red-500/15 text-red-300 border border-red-500/30 shrink-0">
              Promoted
            </span>
          )}
        </div>
        <div className="flex items-center gap-3 mt-1">
          <span className="text-xs text-gray-500">
            {record.alert_count} alert{record.alert_count === 1 ? '' : 's'}
          </span>
          <span className="text-gray-700">·</span>
          <SeverityHistogram histogram={record.severity_histogram} />
          <span className="text-gray-700">·</span>
          <span className="text-xs text-gray-500" suppressHydrationWarning>
            last seen{' '}
            {formatDistanceToNow(new Date(record.last_seen), {
              addSuffix: true,
            })}
          </span>
        </div>
      </div>

      <ScoreBar score={record.score} threshold={record.threshold} />

      <span
        className={clsx(
          'text-[10px] uppercase tracking-wider px-2 py-0.5 rounded border shrink-0 w-20 text-center',
          band.text,
          band.bg,
        )}
      >
        {band.label}
      </span>
    </button>
  );
}

function EntityDetailDrawer({
  entity,
  onClose,
}: {
  entity: EntityRiskRecord;
  onClose: () => void;
}) {
  const cfg = ENTITY_TYPE_CONFIG[entity.entity_type] ?? ENTITY_TYPE_CONFIG.user;
  // Pull a fresh detail record so contributions are up-to-date when the drawer
  // opens — falls back to the row data on error.
  const { data } = useSWR(
    ['entity-risk-detail', entity.entity_type, entity.entity_value],
    () => entityRiskApi.get(entity.entity_type, entity.entity_value),
    { fallbackData: entity, refreshInterval: 30000 },
  );
  const record = data ?? entity;
  const band = bandFor(record.score, record.threshold);

  return (
    <div className="fixed inset-0 z-50 flex">
      <div
        className="flex-1 bg-black/60"
        onClick={onClose}
        aria-hidden="true"
      />
      <aside className="w-[480px] max-w-[90vw] bg-gray-950 border-l border-gray-800 overflow-y-auto">
        <header className="px-5 py-4 border-b border-gray-800 flex items-start justify-between gap-3 sticky top-0 bg-gray-950 z-10">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-base" aria-hidden>
                {cfg.icon}
              </span>
              <span
                className={clsx(
                  'text-xs uppercase tracking-wider',
                  cfg.tint,
                )}
              >
                {cfg.label}
              </span>
            </div>
            <h2 className="text-lg text-gray-100 font-medium truncate mt-1">
              {record.entity_value}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-gray-300 text-xl leading-none px-2"
            aria-label="Close"
          >
            ×
          </button>
        </header>

        <div className="px-5 py-4 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className={clsx('rounded-xl px-3 py-2.5 border', band.bg)}>
              <p className="text-[10px] uppercase tracking-wider text-gray-500">
                Risk score
              </p>
              <p className={clsx('text-2xl font-bold', band.text)}>
                {Math.round(record.score)}
              </p>
              <p className="text-[10px] text-gray-500 mt-0.5">
                threshold {Math.round(record.threshold)}
              </p>
            </div>
            <div className="rounded-xl px-3 py-2.5 border border-gray-800/60 bg-gray-900/60">
              <p className="text-[10px] uppercase tracking-wider text-gray-500">
                Alerts (window)
              </p>
              <p className="text-2xl font-bold text-gray-200">
                {record.alert_count}
              </p>
              <p className="text-[10px] text-gray-500 mt-0.5" suppressHydrationWarning>
                first seen{' '}
                {formatDistanceToNow(new Date(record.first_seen), {
                  addSuffix: true,
                })}
              </p>
            </div>
          </div>

          {record.promoted && record.promoted_incident_id && (
            <div className="rounded-xl px-3 py-2.5 border border-red-500/30 bg-red-500/10">
              <p className="text-[10px] uppercase tracking-wider text-red-300">
                Promoted to incident
              </p>
              <p className="text-sm font-mono text-red-200 mt-1 break-all">
                {record.promoted_incident_id}
              </p>
            </div>
          )}

          <div>
            <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-2">
              Contributing alerts
            </h3>
            {record.contributions.length === 0 ? (
              <p className="text-sm text-gray-600">
                No contributions in the current decay window.
              </p>
            ) : (
              <ol className="space-y-1.5">
                {record.contributions.map((c) => (
                  <li
                    key={c.alert_id}
                    className="flex items-start gap-2 text-sm border border-gray-800/60 bg-gray-900/40 rounded-lg px-3 py-2"
                  >
                    <span
                      className={clsx(
                        'w-1.5 h-1.5 rounded-full mt-1.5 shrink-0',
                        SEVERITY_DOT[c.severity] ?? SEVERITY_DOT.info,
                      )}
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-gray-200 truncate">
                          {c.title ?? c.alert_id}
                        </span>
                        <span className="text-[10px] text-gray-500 shrink-0">
                          +{Math.round(c.raw_points)}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 mt-0.5 text-[11px] text-gray-500">
                        {c.source && <span>{c.source}</span>}
                        {c.source && <span className="text-gray-700">·</span>}
                        <span suppressHydrationWarning>
                          {formatDistanceToNow(new Date(c.observed_at), {
                            addSuffix: true,
                          })}
                        </span>
                      </div>
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </div>
        </div>
      </aside>
    </div>
  );
}

// ─── Main view ───────────────────────────────────────────────────────────────

export function EntityRiskQueue() {
  const [promotedOnly, setPromotedOnly] = useState(false);
  const [selected, setSelected] = useState<EntityRiskRecord | null>(null);

  const { data: queue, error: queueError, isLoading: queueLoading } = useSWR(
    ['entity-risk-queue', promotedOnly],
    () => entityRiskApi.queue({ limit: 50, promotedOnly }),
    {
      refreshInterval: 30000,
      fallbackData: demoFallback({ tenant_id: 'demo', entities: MOCK_ENTITIES, threshold: 80 }),
    },
  );
  const { data: stats } = useSWR<EntityRiskStats>(
    'entity-risk-stats',
    () => entityRiskApi.stats(),
    { refreshInterval: 30000, fallbackData: demoFallback(MOCK_ENTITY_STATS) },
  );

  const entities = queue?.entities ?? [];
  // Fall back to the queue's threshold (from the engine config) when the
  // stats endpoint is still loading — keeps the score bars stable.
  const threshold = stats?.threshold ?? queue?.threshold ?? 80;
  const promotedCount = stats?.promoted ?? entities.filter((e) => e.promoted).length;
  const total = stats?.total ?? entities.length;
  const alertCount = stats?.alert_count ?? entities.reduce((sum, e) => sum + e.alert_count, 0);

  return (
    <div className="space-y-4">
      {/* Stats strip — anchored on the 2026 KPI bar */}
      <div className="grid grid-cols-4 gap-3">
        <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl px-4 py-3">
          <p className="text-xs text-gray-500">Active entities</p>
          <p className="text-2xl font-bold mt-1 text-gray-200">{total}</p>
          <p className="text-[10px] text-gray-600 mt-0.5">
            threshold {Math.round(threshold)} pts
          </p>
        </div>
        <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl px-4 py-3">
          <p className="text-xs text-gray-500">Promoted</p>
          <p className="text-2xl font-bold mt-1 text-red-400">
            {promotedCount}
          </p>
          <p className="text-[10px] text-gray-600 mt-0.5">
            entity-incidents
          </p>
        </div>
        <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl px-4 py-3">
          <p className="text-xs text-gray-500">Contributing alerts</p>
          <p className="text-2xl font-bold mt-1 text-gray-200">{alertCount}</p>
          <p className="text-[10px] text-gray-600 mt-0.5">
            current decay window
          </p>
        </div>
        <RatioStat alertCount={alertCount} incidentCount={promotedCount} />
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap py-3 px-4 bg-gray-900/40 border border-gray-800/60 rounded-xl">
        <div className="flex items-center gap-1">
          <button
            onClick={() => setPromotedOnly(false)}
            className={clsx(
              'text-xs px-2.5 py-1 rounded-lg transition-colors',
              !promotedOnly
                ? 'bg-blue-600 text-white'
                : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/60',
            )}
          >
            All entities
          </button>
          <button
            onClick={() => setPromotedOnly(true)}
            className={clsx(
              'text-xs px-2.5 py-1 rounded-lg transition-colors',
              promotedOnly
                ? 'bg-red-600 text-white'
                : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/60',
            )}
          >
            Promoted only
          </button>
        </div>
        <span className="ml-auto text-xs text-gray-600">
          {entities.length} shown
        </span>
      </div>

      {queueError && (
        <div className="rounded-md border border-amber-500/30 bg-amber-500/5 px-4 py-2 text-xs text-amber-200">
          Fusion service unreachable — showing demo entity queue so you can explore Risk-Based Alerting.
        </div>
      )}

      {/* Queue */}
      <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl overflow-hidden">
        <div className="flex items-center px-4 py-2 border-b border-gray-800/60 bg-gray-900/80 gap-4">
          <span className="text-xs text-gray-500 flex-1">ENTITY</span>
          <span className="text-xs text-gray-500 w-32">RISK</span>
          <span className="text-xs text-gray-500 w-20 text-center">BAND</span>
        </div>

        {queueLoading && entities.length === 0 ? (
          <div className="flex items-center justify-center h-32">
            <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          </div>
        ) : entities.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 text-gray-500 gap-1">
            <p className="text-sm">
              {promotedOnly
                ? 'No entities have crossed the promotion threshold yet.'
                : 'No entities are currently being tracked.'}
            </p>
            <p className="text-[11px] text-gray-600">
              Decay window: 24h · half-life: 4h
            </p>
          </div>
        ) : (
          <div>
            {entities.map((record) => (
              <EntityRow
                key={`${record.entity_type}:${record.entity_value}`}
                record={record}
                onSelect={() => setSelected(record)}
              />
            ))}
          </div>
        )}
      </div>

      {selected && (
        <EntityDetailDrawer
          entity={selected}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}
