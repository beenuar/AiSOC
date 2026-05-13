/**
 * SOC Insights dashboard view (T3.1).
 *
 * Owns the data-fetching + layout for the 7-tile grid. Split out of
 * the route file so the page module can stay a pure server component
 * (per Next.js App Router conventions); this file is the "use client"
 * boundary.
 */
'use client';

import { useEffect, useMemo, useState } from 'react';
import useSWR from 'swr';

import { useRealtimeChannel } from '@/lib/realtime';
import {
  type InsightTile,
  type InsightsWindow,
  type SOCInsightsResponse,
  insightsApi,
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
  const [window, setWindow] = useState<InsightsWindow>('24h');

  const { data, error, isLoading, mutate } = useSWR<SOCInsightsResponse>(
    ['insights:soc', window],
    () => insightsApi.getSOC(window),
    {
      // The realtime channel pokes us every 30s; we also revalidate
      // on focus in case the tab was backgrounded long enough for
      // the WebSocket to disconnect.
      revalidateOnFocus: true,
      revalidateIfStale: true,
      // Don't dedupe identical-key refetches — the realtime poke is
      // explicit "go look again", we want it honoured even if SWR
      // just fetched.
      dedupingInterval: 0,
    },
  );

  // Subscribe to `insights_updated` events from the realtime service.
  // The hook keeps the socket alive and reconnects with exponential
  // backoff; we just react to the last received frame.
  const { last } = useRealtimeChannel<RealtimePoke>('insights');

  useEffect(() => {
    if (last?.type === 'insights_updated' || last?.type === 'case.updated') {
      // Force a re-fetch — pass false to suppress the optimistic
      // "loading" flash; users keep seeing the old tiles for the
      // 100-200ms until the new ones arrive.
      mutate(undefined, { revalidate: true });
    }
  }, [last, mutate]);

  return (
    <div className="space-y-6 p-6">
      <Header
        window={window}
        onWindowChange={setWindow}
        generatedAt={data?.generated_at}
        manualMinutes={data?.manual_investigation_minutes}
      />

      {error ? (
        <ErrorState
          message={error instanceof Error ? error.message : String(error)}
          onRetry={() => mutate()}
        />
      ) : isLoading || !data ? (
        <LoadingSkeleton />
      ) : (
        <TileGrid tiles={data.tiles} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Subcomponents
// ---------------------------------------------------------------------------

interface HeaderProps {
  window: InsightsWindow;
  onWindowChange: (w: InsightsWindow) => void;
  generatedAt: string | undefined;
  manualMinutes: number | undefined;
}

function Header({ window, onWindowChange, generatedAt, manualMinutes }: HeaderProps) {
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
        <h1 className="text-2xl font-semibold tracking-tight">SOC Insights</h1>
        <p className="mt-1 max-w-prose text-sm text-muted-foreground">
          Seven operational tiles for the SOC, refreshed every 30 seconds and
          on case changes. Deltas compare against the immediately preceding
          window. Hours-saved assumes {manualMinutes ?? 45} minutes of analyst
          time per auto-closed case.
        </p>
      </div>
      <div className="flex items-center gap-4">
        {stamp ? (
          <span className="text-xs text-muted-foreground" aria-live="polite">
            Updated {stamp}
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
      className="inline-flex rounded-md border border-border bg-card p-0.5 text-xs"
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
                ? 'rounded bg-primary px-3 py-1 font-medium text-primary-foreground'
                : 'rounded px-3 py-1 text-muted-foreground hover:text-foreground'
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
  // 7 skeleton tiles arranged on the same grid. The fixed heights
  // mean the layout doesn't reflow when the real data arrives.
  return (
    <div
      className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4"
      aria-busy="true"
      aria-label="Loading SOC insights"
    >
      {Array.from({ length: 7 }).map((_, i) => (
        <div
          key={i}
          className="h-32 animate-pulse rounded-lg border border-border bg-card"
        />
      ))}
    </div>
  );
}

interface ErrorStateProps {
  message: string;
  onRetry: () => void;
}

function ErrorState({ message, onRetry }: ErrorStateProps) {
  return (
    <div
      role="alert"
      className="rounded-lg border border-destructive/30 bg-destructive/5 p-6 text-sm"
    >
      <p className="font-medium text-destructive">
        SOC Insights are temporarily unavailable.
      </p>
      <p className="mt-1 text-muted-foreground">{message}</p>
      <button
        type="button"
        onClick={onRetry}
        className="mt-3 rounded border border-border bg-background px-3 py-1.5 text-xs font-medium hover:bg-muted"
      >
        Retry
      </button>
    </div>
  );
}
