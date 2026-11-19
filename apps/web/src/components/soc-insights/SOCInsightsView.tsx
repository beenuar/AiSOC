/**
 * SOC Insights dashboard view (T3.1).
 *
 * Owns the data-fetching + layout for the 7-tile grid. Split out of
 * the route file so the page module can stay a pure server component
 * (per Next.js App Router conventions); this file is the "use client"
 * boundary.
 */
'use client';

import { useEffect, useMemo, useRef } from 'react';
import { useTenant } from '@/components/layout/TenantProvider';
import { useTimeWindow } from '@/components/layout/TimeWindowProvider';
import useSWR from 'swr';

import { useRealtimeChannel } from '@/lib/realtime';
import {
  type InsightTile,
  type InsightsWindow,
  type SOCInsightsResponse,
  insightsApi,
  getActiveTenantId,
} from '@/lib/api';

import { InsightTileCard } from './InsightTileCard';
import { Sparkline } from './Sparkline';

const WINDOW_OPTIONS: InsightsWindow[] = ['24h', '7d', '30d'];

interface RealtimePoke {
  type: string;
  reason?: string;
  timestamp?: string;
}

export function SOCInsightsView() {
  // Bound to the global selector rather than a private `useState`. Two
  // controls on one page that both say "24h" and move independently is the
  // kind of thing a user reads as the data itself being wrong.
  //
  // This endpoint has no 1h window, so a global `1h` is clamped to `24h` --
  // and the clamp is *shown*, not silent. Rendering a day of data under a
  // header reading "1h" would be a quietly wrong number, which is worse than
  // an explicit note.
  const { window: globalWindow, setWindow: setGlobalWindow } = useTimeWindow();
  const clamped = globalWindow === '1h';
  const window: InsightsWindow = clamped ? '24h' : globalWindow;
  // Subscribe to tenant changes, but key by the exact identity used by the
  // transport. The picker can fall back to the home tenant on a list error
  // while a child override remains active. No picker request blocks this read.
  useTenant();
  const tenantId = getActiveTenantId();
  const { last } = useRealtimeChannel<RealtimePoke>('insights');

  return (
    <InsightsPanel
      key={`${tenantId}:${window}`}
      tenantId={tenantId}
      window={window}
      clamped={clamped}
      onWindowChange={setGlobalWindow}
      last={last}
    />
  );
}

interface InsightsPanelProps {
  tenantId: string;
  window: InsightsWindow;
  clamped: boolean;
  onWindowChange: (w: InsightsWindow) => void;
  last: RealtimePoke | null;
}

function InsightsPanel({ tenantId, window, clamped, onWindowChange, last }: InsightsPanelProps) {
  const { data, error, isValidating, mutate } = useSWR<SOCInsightsResponse>(
    ['insights:soc', tenantId, window],
    async () => {
      const snapshot = await insightsApi.getSOC(window);
      // The API owns tenant authorization. Never label a credential-scoped
      // response as another tenant.
      if (snapshot.tenant_id !== tenantId) {
        throw new Error('SOC Insights did not return data for the selected tenant.');
      }
      if (snapshot.window !== window) {
        throw new Error('SOC Insights did not return data for the selected time window.');
      }
      return snapshot;
    },
    {
      // Focus/remount requests share SWR's short deduplication window. An
      // explicit realtime refresh below still fetches a fresh snapshot.
      revalidateOnFocus: true,
      revalidateIfStale: true,
      dedupingInterval: 2_000,
    },
  );

  const seenEvent = useRef(last);
  const refreshPending = useRef(false);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (last !== seenEvent.current) {
      seenEvent.current = last;
      if (last?.type === 'insights_updated' || last?.type === 'case.updated') {
        refreshPending.current = true;
      }
    }

    // A burst becomes one request. Events arriving during a request queue
    // one follow-up, so a slow response cannot cause overlapping queries.
    if (isValidating) {
      if (refreshTimer.current !== null) clearTimeout(refreshTimer.current);
      refreshTimer.current = null;
      return;
    }
    if (!refreshPending.current || refreshTimer.current !== null) return;
    refreshTimer.current = setTimeout(() => {
      refreshTimer.current = null;
      refreshPending.current = false;
      // No data argument: keep the successful snapshot while revalidating.
      void mutate();
    }, 250);
  }, [last, isValidating, mutate]);

  useEffect(() => () => {
    if (refreshTimer.current !== null) clearTimeout(refreshTimer.current);
  }, []);

  return (
    <div className="space-y-5">
      <Header
        window={window}
        clamped={clamped}
        onWindowChange={onWindowChange}
        generatedAt={data?.generated_at}
        manualMinutes={data?.manual_investigation_minutes}
        refreshing={Boolean(data && isValidating)}
      />

      {error ? (
        <ErrorState
          message={error instanceof Error ? error.message : String(error)}
          stale={Boolean(data)}
          onRetry={() => { void mutate(); }}
        />
      ) : null}
      {data ? <TileGrid tiles={data.tiles} /> : error ? null : <LoadingSkeleton />}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Subcomponents
// ---------------------------------------------------------------------------

interface HeaderProps {
  window: InsightsWindow;
  clamped: boolean;
  onWindowChange: (w: InsightsWindow) => void;
  generatedAt: string | undefined;
  manualMinutes: number | undefined;
  refreshing: boolean;
}

function Header({ window, clamped, onWindowChange, generatedAt, manualMinutes, refreshing }: HeaderProps) {
  const stamp = useMemo(() => {
    if (!generatedAt) return null;
    try {
      return new Date(generatedAt).toLocaleTimeString();
    } catch {
      return generatedAt;
    }
  }, [generatedAt]);

  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h1 className="text-xl font-semibold text-fg-primary">SOC Insights</h1>
        <p className="mt-1 max-w-prose text-sm text-fg-muted">
          Seven operational tiles for the SOC, refreshed every 30 seconds and
          on case changes. Deltas compare against the immediately preceding
          window. Estimated analyst hours saved assumes {manualMinutes ?? 45}
          {' '}minutes per closed case.
        </p>
        {clamped ? (
          <p className="mt-1 text-xs text-amber-500/90">
            These tiles have no 1-hour window, so they are showing 24 hours.
          </p>
        ) : null}
      </div>
      <div className="flex items-center gap-4">
        {stamp ? (
          <span role="status" className="text-xs text-fg-muted">
            {refreshing ? 'Refreshing…' : `Updated ${stamp}`}
          </span>
        ) : null}
        <WindowSelector value={window} onChange={onWindowChange} />
      </div>
    </div>
  );
}

interface WindowSelectorProps {
  value: InsightsWindow;
  onChange: (w: InsightsWindow) => void;
}

function WindowSelector({ value, onChange }: WindowSelectorProps) {
  return (
    <div
      role="radiogroup"
      aria-label="Window"
      className="inline-flex rounded-md border border-surface-border bg-surface-card p-0.5 text-xs"
    >
      {WINDOW_OPTIONS.map((option) => {
        const active = option === value;
        return (
          <button
            key={option}
            type="button"
            role="radio"
            aria-checked={active}
            onClick={() => onChange(option)}
            className={
              active
                ? 'rounded bg-brand-600 px-3 py-1 font-medium text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/50'
                : 'rounded px-3 py-1 text-fg-muted hover:bg-surface-hover hover:text-fg-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/50'
            }
          >
            {option}
          </button>
        );
      })}
    </div>
  );
}

interface TileGridProps {
  tiles: InsightTile[];
}

function TileGrid({ tiles }: TileGridProps) {
  return (
    <div
      // 7 tiles fit comfortably as a 4×2 grid at lg, 2×4 at md, 1 per
      // row on phones. The grid keeps a constant ratio so the
      // sparkline width doesn't jump between window changes.
      className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4"
      data-testid="soc-insights-tiles"
    >
      {tiles.map((tile) => (
        <InsightTileCard
          key={tile.key}
          tile={tile}
          sparkline={<Sparkline points={tile.sparkline.points} />}
        />
      ))}
    </div>
  );
}

function LoadingSkeleton() {
  // Match the tile grid and minimum card height while the first snapshot loads.
  return (
    <div
      className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4"
      aria-busy="true"
      aria-label="Loading SOC insights"
    >
      {Array.from({ length: 7 }).map((_, i) => (
        <div
          key={i}
          className="h-32 animate-pulse rounded-xl border border-surface-border bg-surface-card"
        />
      ))}
    </div>
  );
}

interface ErrorStateProps {
  message: string;
  stale: boolean;
  onRetry: () => void;
}

function ErrorState({ message, stale, onRetry }: ErrorStateProps) {
  return (
    <div
      role="alert"
      className="rounded-xl border border-red-500/30 bg-red-500/5 p-5 text-sm"
    >
      <p className="font-medium text-fg-primary">
        {stale
          ? 'Unable to refresh SOC Insights. Showing the last successful update.'
          : 'SOC Insights are temporarily unavailable.'}
      </p>
      <p className="mt-1 text-fg-muted">{message}</p>
      <button
        type="button"
        onClick={onRetry}
        className="mt-3 rounded-md border border-surface-border bg-surface-card px-3 py-1.5 text-xs font-medium text-fg-secondary hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/50"
      >
        Retry
      </button>
    </div>
  );
}
