'use client';

/**
 * PipelineHealth
 * ==============
 * Five-stage pipeline health strip (ingest → normalize → fuse → correlate → alert).
 * Each stage shows backlog, p95 latency, error rate, and an at-a-glance status
 * ({@link Status}). Mirrors the reference SOC console's pipeline-health rail.
 *
 * Data source: `GET /api/v1/health/pipeline` ({@link metricsApi.getPipelineHealth}).
 * Polls every 30 s; ignores SWR retries (the endpoint never throws under nominal
 * conditions — failures are reported in the row).
 *
 * Author: Beenu Arora <beenu@cyble.com>
 */

import useSWR from 'swr';
import { clsx } from 'clsx';
import {
  metricsApi,
  type PipelineHealth as PipelineHealthData,
  type PipelineStage,
} from '@/lib/api';

type Status = PipelineStage['status'];

const STAGE_LABELS: Record<PipelineStage['stage'], string> = {
  ingest: 'Ingest',
  normalize: 'Normalize',
  fuse: 'Fuse',
  correlate: 'Correlate',
  alert: 'Alert',
};

const STAGE_DESCRIPTIONS: Record<PipelineStage['stage'], string> = {
  ingest: 'Connector → raw events',
  normalize: 'OCSF mapping',
  fuse: 'Alert fusion',
  correlate: 'Cross-source correlation',
  alert: 'Final alert emission',
};

const STAGE_ORDER: PipelineStage['stage'][] = [
  'ingest',
  'normalize',
  'fuse',
  'correlate',
  'alert',
];

function statusStyles(status: Status) {
  switch (status) {
    case 'green':
      return {
        dot: 'bg-green-500',
        ring: 'ring-green-500/30',
        text: 'text-green-400',
        bar: 'bg-green-500/70',
      };
    case 'yellow':
      return {
        dot: 'bg-amber-500',
        ring: 'ring-amber-500/30',
        text: 'text-amber-400',
        bar: 'bg-amber-500/70',
      };
    case 'red':
      return {
        dot: 'bg-red-500',
        ring: 'ring-red-500/30',
        text: 'text-red-400',
        bar: 'bg-red-500/70',
      };
    default:
      return {
        dot: 'bg-gray-600',
        ring: 'ring-gray-600/30',
        text: 'text-gray-500',
        bar: 'bg-gray-600/50',
      };
  }
}

function formatLatency(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '—';
  if (ms < 1) return '< 1 ms';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1).replace(/\.0$/, '')} s`;
  return `${(ms / 60_000).toFixed(1).replace(/\.0$/, '')} m`;
}

function formatBacklog(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '—';
  if (n >= 1_000_000)
    return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, '')}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1).replace(/\.0$/, '')}k`;
  return String(Math.round(n));
}

function formatErrorRate(ratio: number): string {
  if (!Number.isFinite(ratio) || ratio < 0) return '—';
  if (ratio === 0) return '0%';
  if (ratio < 0.001) return '< 0.1%';
  return `${(ratio * 100).toFixed(2).replace(/\.?0+$/, '')}%`;
}

function StageCard({ stage }: { stage: PipelineStage }) {
  const styles = statusStyles(stage.status);
  return (
    <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-4 min-w-0">
      <div className="flex items-center justify-between mb-1">
        <p className="text-sm font-semibold text-gray-100 truncate">
          {STAGE_LABELS[stage.stage]}
        </p>
        <span
          className={clsx('h-2.5 w-2.5 rounded-full ring-2', styles.dot, styles.ring)}
          aria-label={`status ${stage.status}`}
        />
      </div>
      <p className="text-[11px] text-gray-500 truncate">
        {STAGE_DESCRIPTIONS[stage.stage]}
      </p>

      <dl className="mt-3 space-y-1.5">
        <div className="flex items-baseline justify-between text-xs">
          <dt className="text-gray-500">Backlog</dt>
          <dd className="font-medium text-gray-200 tabular-nums">
            {formatBacklog(stage.backlog)}
          </dd>
        </div>
        <div className="flex items-baseline justify-between text-xs">
          <dt className="text-gray-500">p95</dt>
          <dd className="font-medium text-gray-200 tabular-nums">
            {formatLatency(stage.p95_latency_ms)}
          </dd>
        </div>
        <div className="flex items-baseline justify-between text-xs">
          <dt className="text-gray-500">Errors</dt>
          <dd className={clsx('font-medium tabular-nums', styles.text)}>
            {formatErrorRate(stage.error_rate)}
          </dd>
        </div>
      </dl>
    </div>
  );
}

function LoadingStage({ stage }: { stage: PipelineStage['stage'] }) {
  return (
    <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-4 min-w-0">
      <div className="flex items-center justify-between mb-1">
        <p className="text-sm font-semibold text-gray-100 truncate">
          {STAGE_LABELS[stage]}
        </p>
        <span className="h-2.5 w-2.5 rounded-full bg-gray-700 animate-pulse" />
      </div>
      <p className="text-[11px] text-gray-500 truncate">
        {STAGE_DESCRIPTIONS[stage]}
      </p>
      <div className="mt-3 space-y-2">
        <div className="h-3 w-full rounded bg-gray-800/60 animate-pulse" />
        <div className="h-3 w-full rounded bg-gray-800/60 animate-pulse" />
        <div className="h-3 w-2/3 rounded bg-gray-800/60 animate-pulse" />
      </div>
    </div>
  );
}

export function PipelineHealth() {
  const { data, error, isLoading } = useSWR<PipelineHealthData>(
    'pipeline-health',
    () => metricsApi.getPipelineHealth(),
    {
      refreshInterval: 30_000,
      revalidateOnFocus: false,
      shouldRetryOnError: false,
    },
  );

  // Build a stage→data map and render in canonical order so the UI never
  // re-orders mid-flight even if the API ever changes its ordering.
  const stagesByName: Partial<Record<PipelineStage['stage'], PipelineStage>> = {};
  for (const s of data?.stages ?? []) stagesByName[s.stage] = s;

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <div>
          <h2 className="text-base font-semibold text-gray-100">
            Pipeline Health
          </h2>
          <p className="text-xs text-gray-500 mt-0.5">
            Ingest → normalize → fuse → correlate → alert
          </p>
        </div>
        {error ? (
          <span className="text-xs text-red-400">unavailable</span>
        ) : (
          <span className="text-xs text-gray-500">Live</span>
        )}
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {STAGE_ORDER.map((name) => {
          const stage = stagesByName[name];
          if (isLoading || !stage) return <LoadingStage key={name} stage={name} />;
          return <StageCard key={name} stage={stage} />;
        })}
      </div>
    </div>
  );
}

export default PipelineHealth;
