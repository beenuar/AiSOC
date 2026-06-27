/**
 * T3.8 — AiSOC console Badge primitive.
 *
 * The console scatters ~30 inline ``<span class="text-xs ...">`` badges
 * with subtly different palettes. This component codifies the five
 * semantic tones we actually use (info / success / warning / danger /
 * neutral) plus the AiSOC-specific severity tones (low / medium / high
 * / critical) that mirror the OCSF severity ladder.
 *
 * Use this anywhere you would have inlined a label pill: alert
 * severity, run status, MITRE tactic, connector mode, etc.
 */
import { clsx } from 'clsx';
import type { HTMLAttributes, ReactNode } from 'react';

export type BadgeTone =
  | 'neutral'
  | 'info'
  | 'success'
  | 'warning'
  | 'danger'
  | 'severity-info'
  | 'severity-low'
  | 'severity-medium'
  | 'severity-high'
  | 'severity-critical';

const TONE_CLASSES: Record<BadgeTone, string> = {
  neutral: 'bg-gray-800/80 text-gray-300 border-gray-700',
  info: 'bg-blue-900/40 text-blue-300 border-blue-800',
  success: 'bg-green-900/40 text-green-300 border-green-800',
  warning: 'bg-amber-900/40 text-amber-200 border-amber-800',
  danger: 'bg-red-900/40 text-red-300 border-red-800',
  'severity-info': 'bg-slate-800 text-slate-300 border-slate-700',
  'severity-low': 'bg-blue-900/40 text-blue-300 border-blue-800',
  'severity-medium': 'bg-amber-900/40 text-amber-200 border-amber-800',
  'severity-high': 'bg-orange-900/50 text-orange-300 border-orange-800',
  'severity-critical': 'bg-red-900/60 text-red-200 border-red-700',
};

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone;
  icon?: ReactNode;
  /** Small dot on the left, common for status indicators. */
  dot?: boolean;
}

export function Badge({
  tone = 'neutral',
  icon,
  dot,
  className,
  children,
  ...rest
}: BadgeProps) {
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-medium',
        TONE_CLASSES[tone],
        className,
      )}
      {...rest}
    >
      {dot && (
        <span
          aria-hidden="true"
          className="h-1.5 w-1.5 rounded-full bg-current opacity-80"
        />
      )}
      {icon}
      {children}
    </span>
  );
}
