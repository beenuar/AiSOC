'use client';

/**
 * FunnelKpiBar
 * ============
 * Six-tile KPI strip that mirrors the reference SOC console's funnel widget.
 *
 * Tiles, left to right:
 *   1. Events of Interest          (24h delta)
 *   2. Correlation Instances       (24h delta)
 *   3. Alerts Generated            (24h delta)
 *   4. Signal / Noise              (24h delta — higher is better)
 *   5. MTTD                        (24h delta — lower is better)
 *   6. Analyst Queue Depth         (24h delta — lower is better)
 *
 * Data source: `GET /api/v1/metrics/funnel?period=…` ({@link metricsApi.getFunnel}).
 * Polls every 60 s with stale-while-revalidate.
 *
 * Author: Beenu Arora <beenu@cyble.com>
 */

import useSWR from 'swr';
import { clsx } from 'clsx';
import { metricsApi, type FunnelMetrics } from '@/lib/api';

type Period = '1h' | '24h' | '7d' | '30d';

interface FunnelKpiBarProps {
  /** Time window for the funnel. Defaults to `24h` (matches DashboardView). */
  period?: Period;
  /** Override the SWR cache key — useful when multiple bars coexist. */
  cacheKey?: string;
}

interface TileProps {
  label: string;
  value: string;
  delta: number | null;
  /**
   * When `true`, a *negative* delta is rendered green (good) and positive is red
   * (worse). When `false`, positive is green. Mirrors the reference console's
   * coloring for MTTD / Queue (lower-is-better) vs Events / Alerts.
   */
  lowerIsBetter?: boolean;
  /** Tiny note under the value (e.g. "events", "alerts/sec"). */
  unit?: string;
}

function formatNumber(n: number): string {
  if (!Number.isFinite(n)) return '—';
  if (Math.abs(n) >= 1_000_000)
    return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, '')}M`;
  if (Math.abs(n) >= 1_000)
    return `${(n / 1_000).toFixed(1).replace(/\.0$/, '')}k`;
  return String(Math.round(n));
}

function formatDurationSeconds(sec: number): string {
  if (!Number.isFinite(sec) || sec < 0) return '—';
  if (sec < 60) return `${Math.round(sec)}s`;
  if (sec < 3600) return `${Math.round(sec / 60)}m`;
  return `${(sec / 3600).toFixed(1).replace(/\.0$/, '')}h`;
}

function formatPercent(ratio: number): string {
  if (!Number.isFinite(ratio)) return '—';
  return `${(ratio * 100).toFixed(1).replace(/\.0$/, '')}%`;
}

function formatDelta(delta: number | null): string {
  if (delta === null || !Number.isFinite(delta)) return '—';
  const pct = delta * 100;
  const rounded = Math.abs(pct) >= 10 ? Math.round(pct) : pct.toFixed(1);
  const sign = pct > 0 ? '+' : pct < 0 ? '−' : '';
  return `${sign}${Math.abs(Number(rounded))}%`;
}

function Tile({ label, value, delta, lowerIsBetter = false, unit }: TileProps) {
  const isGood =
    delta === null || delta === 0
      ? null
      : lowerIsBetter
        ? delta < 0
        : delta > 0;
  const deltaColor =
    isGood === null
      ? 'text-gray-500'
      : isGood
        ? 'text-green-400'
        : 'text-red-400';

  return (
    <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-4 min-w-0">
      <p className="text-[11px] text-gray-500 font-medium uppercase tracking-wider truncate">
        {label}
      </p>
      <p className="text-2xl font-bold text-gray-100 mt-1 tabular-nums truncate">
        {value}
      </p>
      <div className="flex items-baseline gap-2 mt-1">
        <span className={clsx('text-xs font-medium tabular-nums', deltaColor)}>
          {formatDelta(delta)}
        </span>
        {unit && <span className="text-[11px] text-gray-600 truncate">{unit}</span>}
      </div>
    </div>
  );
}

function LoadingTile({ label }: { label: string }) {
  return (
    <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-4 min-w-0">
      <p className="text-[11px] text-gray-500 font-medium uppercase tracking-wider truncate">
        {label}
      </p>
      <div className="mt-2 h-7 w-20 rounded bg-gray-800/60 animate-pulse" />
      <div className="mt-2 h-3 w-12 rounded bg-gray-800/40 animate-pulse" />
    </div>
  );
}

const TILE_LABELS = [
  'Events of Interest',
  'Correlation Instances',
  'Alerts Generated',
  'Signal / Noise',
  'MTTD',
  'Analyst Queue',
] as const;

export function FunnelKpiBar({
  period = '24h',
  cacheKey,
}: FunnelKpiBarProps = {}) {
  const key = cacheKey ?? `funnel-metrics:${period}`;
  const { data, error, isLoading } = useSWR<FunnelMetrics>(
    key,
    () => metricsApi.getFunnel(period),
    {
      refreshInterval: 60_000,
      revalidateOnFocus: false,
      shouldRetryOnError: false,
    },
  );

  if (isLoading || !data) {
    return (
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-base font-semibold text-gray-100">Operations Funnel</h2>
          <span className="text-xs text-gray-500">Last {period}</span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          {TILE_LABELS.map((l) => (
            <LoadingTile key={l} label={l} />
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-4 text-sm text-gray-400">
        Funnel metrics unavailable.
      </div>
    );
  }

  const { deltas } = data;

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <div>
          <h2 className="text-base font-semibold text-gray-100">
            Operations Funnel
          </h2>
          <p className="text-xs text-gray-500 mt-0.5">
            Live tenant pipeline: events → correlations → alerts
          </p>
        </div>
        <span className="text-xs text-gray-500">Last {period}</span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <Tile
          label="Events of Interest"
          value={formatNumber(data.events_of_interest)}
          delta={deltas.events_of_interest}
          unit="events"
        />
        <Tile
          label="Correlation Instances"
          value={formatNumber(data.correlation_instances)}
          delta={deltas.correlation_instances}
          unit="groups"
        />
        <Tile
          label="Alerts Generated"
          value={formatNumber(data.alerts_generated)}
          delta={deltas.alerts_generated}
          unit="alerts"
        />
        <Tile
          label="Signal / Noise"
          value={formatPercent(data.signal_to_noise)}
          delta={deltas.signal_to_noise}
          unit="of dispositioned"
        />
        <Tile
          label="MTTD"
          value={formatDurationSeconds(data.mttd_seconds)}
          delta={deltas.mttd_seconds}
          lowerIsBetter
          unit="to first-seen"
        />
        <Tile
          label="Analyst Queue"
          value={formatNumber(data.analyst_queue_depth)}
          delta={deltas.analyst_queue_depth}
          lowerIsBetter
          unit="open"
        />
      </div>
    </div>
  );
}

export default FunnelKpiBar;
