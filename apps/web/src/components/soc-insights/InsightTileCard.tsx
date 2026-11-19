/**
 * Single tile on the SOC Insights dashboard (T3.1).
 *
 * Pure presentational — takes the typed payload from the aggregator
 * endpoint and renders value + delta + sparkline. All formatting is
 * keyed off the tile's ``unit`` so a future tile can ship by adding
 * a new branch here instead of teaching every consumer about a new
 * unit.
 */
'use client';

import type { ReactNode } from 'react';

import type { InsightTile } from '@/lib/api';

interface InsightTileCardProps {
  tile: InsightTile;
  sparkline: ReactNode;
}

export function InsightTileCard({ tile, sparkline }: InsightTileCardProps) {
  const direction = deltaDirection(tile);
  const deltaLabel = formatDelta(tile.delta_pct);
  const deltaTitle =
    tile.delta_pct === null
      ? 'No data for the previous window — delta undefined.'
      : `Compared to the previous window: ${deltaLabel}.`;

  return (
    <div
      className="flex min-h-32 flex-col justify-between rounded-xl border border-surface-border bg-surface-card p-5"
      // The `aria-label` rolls the value + delta into one string so a
      // screen reader announces the change without us shipping a
      // table-with-headers.
      aria-label={`${tile.label}: ${formatValue(tile)}, ${deltaTitle}`}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="text-xs uppercase tracking-wide text-fg-muted">
          {tile.label}
        </span>
        <span
          className={
            direction === 'up'
              ? 'rounded-full bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-400 [[data-theme=light]_&]:text-emerald-700'
              : direction === 'down'
                ? 'rounded-full bg-rose-500/10 px-2 py-0.5 text-xs font-medium text-rose-400 [[data-theme=light]_&]:text-rose-700'
                : 'rounded-full bg-surface-hover px-2 py-0.5 text-xs font-medium text-fg-muted'
          }
          title={deltaTitle}
        >
          {deltaLabel}
        </span>
      </div>

      <div className="mt-2 flex flex-wrap items-end justify-between gap-2">
        <span className="text-3xl font-bold tabular-nums text-fg-primary">{formatValue(tile)}</span>
        <div className="text-fg-muted">{sparkline}</div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatValue(tile: InsightTile): string {
  // An averaging tile that averaged nothing publishes 0.0 with a
  // `sample_count` of 0, because making the mean nullable would break
  // every generated client. The pair is the measurement, so the console
  // has to read both: rendering "0.0h" for MTTA on a tenant where nobody
  // acknowledged anything claims instant response.
  //
  // `=== 0` rather than falsiness, and only when the field is present, so
  // an older server that does not send it is unaffected.
  if (tile.sample_count === 0) return 'not measured';

  switch (tile.unit) {
    case 'hours':
      return `${tile.value.toFixed(1)}h`;
    case 'hours_saved':
      // Round whole hours — fractional analyst hours are noise at the
      // dashboard level. The headline number is the talking-point.
      return `${Math.round(tile.value)}h`;
    case 'pct':
      // Server emits 0–1; render as percentage.
      return `${(tile.value * 100).toFixed(1)}%`;
    case 'usd':
      return tile.value < 1
        ? `$${tile.value.toFixed(3)}`
        : `$${tile.value.toFixed(2)}`;
    case 'count':
    default:
      return Number.isInteger(tile.value)
        ? tile.value.toString()
        : tile.value.toFixed(1);
  }
}

function formatDelta(delta: number | null): string {
  if (delta === null) return '—';
  const sign = delta > 0 ? '+' : '';
  return `${sign}${delta.toFixed(1)}%`;
}

/**
 * Classify the delta into a UX direction.
 *
 * Note: for tiles where "more = worse" (MTTA, MTTR, FP rate, cost,
 * alerts/day) a positive delta should *not* be celebrated. We push
 * those into ``down`` (red) so the colour matches the operator's
 * intuition. ``analyst_hours_saved`` flips the polarity.
 */
function deltaDirection(tile: InsightTile): 'up' | 'down' | 'flat' {
  if (tile.delta_pct === null || tile.delta_pct === 0) return 'flat';
  const positive = tile.delta_pct > 0;
  const goodWhenUp = tile.key === 'analyst_hours_saved';
  return positive === goodWhenUp ? 'up' : 'down';
}
