/**
 * T3.8 — AiSOC console StatusPill primitive.
 *
 * Compact status indicator with an animated dot for live states. Used
 * in the runs panel, connector cards, ingest health bar, etc.
 */
import { clsx } from 'clsx';
import type { HTMLAttributes } from 'react';

export type StatusKind =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'unknown';

const STATUS_META: Record<StatusKind, { label: string; classes: string; pulse: boolean }> = {
  pending: { label: 'Pending', classes: 'text-yellow-300 bg-yellow-900/30 border-yellow-800', pulse: false },
  running: { label: 'Running', classes: 'text-blue-300 bg-blue-900/30 border-blue-800', pulse: true },
  completed: { label: 'Completed', classes: 'text-green-300 bg-green-900/30 border-green-800', pulse: false },
  failed: { label: 'Failed', classes: 'text-red-300 bg-red-900/30 border-red-800', pulse: false },
  cancelled: { label: 'Cancelled', classes: 'text-gray-400 bg-gray-800/60 border-gray-700', pulse: false },
  unknown: { label: 'Unknown', classes: 'text-gray-500 bg-gray-900/40 border-gray-800', pulse: false },
};

export interface StatusPillProps extends HTMLAttributes<HTMLSpanElement> {
  status: StatusKind;
  /** Override the rendered label (defaults to the canonical name). */
  label?: string;
}

export function StatusPill({ status, label, className, ...rest }: StatusPillProps) {
  const meta = STATUS_META[status];
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-medium',
        meta.classes,
        className,
      )}
      {...rest}
    >
      <span
        aria-hidden="true"
        className={clsx(
          'h-1.5 w-1.5 rounded-full bg-current',
          meta.pulse && 'animate-pulse',
        )}
      />
      {label ?? meta.label}
    </span>
  );
}
