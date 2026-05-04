/**
 * Tiny formatting helpers shared across the mobile responder surface.
 *
 * Kept in `lib/responder/` rather than `lib/` so we can iterate on the
 * mobile UX (e.g. tweak severity tone palettes for OLED contrast) without
 * touching desktop console behavior.
 */

import type { AlertSeverity, AlertStatus, CaseSeverity, CaseStatus } from '@/lib/api';

/** Compact, human-friendly relative time ("3m ago", "2d ago"). */
export function formatRelative(timestamp: string | null | undefined): string {
  if (!timestamp) return '—';
  const now = Date.now();
  const then = new Date(timestamp).getTime();
  if (Number.isNaN(then)) return '—';
  const delta = Math.max(0, now - then);
  const seconds = Math.round(delta / 1000);
  if (seconds < 5) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(timestamp).toLocaleDateString();
}

/** Inverse: "until 3:42pm" / "for 25m". */
export function formatUntil(timestamp: string | null | undefined): string | null {
  if (!timestamp) return null;
  const target = new Date(timestamp).getTime();
  if (Number.isNaN(target)) return null;
  const delta = target - Date.now();
  if (delta <= 0) return null;
  const minutes = Math.round(delta / 60000);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h`;
  const days = Math.round(hours / 24);
  return `${days}d`;
}

interface SeverityTone {
  /** Background color used on pill / bar accents. */
  bg: string;
  /** Foreground / text color paired with `bg`. */
  fg: string;
  /** Accent border for cards. Tailwind class. */
  border: string;
  /** Single-letter glyph for the radial / index badges. */
  glyph: string;
  /** Numeric ranking for sort order (higher = more critical). */
  rank: number;
}

const SEVERITY_TONES: Record<AlertSeverity | CaseSeverity | 'info', SeverityTone> = {
  critical: {
    bg: 'bg-red-500/15',
    fg: 'text-red-300',
    border: 'border-l-red-500',
    glyph: 'C',
    rank: 4,
  },
  high: {
    bg: 'bg-orange-500/15',
    fg: 'text-orange-300',
    border: 'border-l-orange-500',
    glyph: 'H',
    rank: 3,
  },
  medium: {
    bg: 'bg-yellow-500/15',
    fg: 'text-yellow-300',
    border: 'border-l-yellow-500',
    glyph: 'M',
    rank: 2,
  },
  low: {
    bg: 'bg-blue-500/15',
    fg: 'text-blue-300',
    border: 'border-l-blue-500',
    glyph: 'L',
    rank: 1,
  },
  info: {
    bg: 'bg-slate-500/15',
    fg: 'text-slate-300',
    border: 'border-l-slate-500',
    glyph: 'I',
    rank: 0,
  },
};

/** Returns Tailwind classes + rank for a severity. Falls back to "info" tone. */
export function severityTone(severity: AlertSeverity | CaseSeverity | string | undefined | null): SeverityTone {
  if (!severity) return SEVERITY_TONES.info;
  const key = severity.toLowerCase() as keyof typeof SEVERITY_TONES;
  return SEVERITY_TONES[key] ?? SEVERITY_TONES.info;
}

interface StatusTone {
  bg: string;
  fg: string;
  label: string;
}

const ALERT_STATUS: Record<string, StatusTone> = {
  new: { bg: 'bg-blue-500/20', fg: 'text-blue-300', label: 'New' },
  triaged: { bg: 'bg-yellow-500/20', fg: 'text-yellow-300', label: 'Triaged' },
  investigating: { bg: 'bg-purple-500/20', fg: 'text-purple-300', label: 'Investigating' },
  in_progress: { bg: 'bg-purple-500/20', fg: 'text-purple-300', label: 'Active' },
  resolved: { bg: 'bg-green-500/20', fg: 'text-green-300', label: 'Resolved' },
  closed: { bg: 'bg-slate-500/20', fg: 'text-slate-300', label: 'Closed' },
  false_positive: { bg: 'bg-slate-500/20', fg: 'text-slate-400', label: 'FP' },
  snoozed: { bg: 'bg-amber-500/20', fg: 'text-amber-300', label: 'Snoozed' },
};

const CASE_STATUS: Record<string, StatusTone> = {
  open: { bg: 'bg-blue-500/20', fg: 'text-blue-300', label: 'Open' },
  in_progress: { bg: 'bg-purple-500/20', fg: 'text-purple-300', label: 'Active' },
  pending: { bg: 'bg-yellow-500/20', fg: 'text-yellow-300', label: 'Pending' },
  resolved: { bg: 'bg-green-500/20', fg: 'text-green-300', label: 'Resolved' },
  closed: { bg: 'bg-slate-500/20', fg: 'text-slate-300', label: 'Closed' },
};

export function alertStatusTone(status: AlertStatus | string | undefined | null): StatusTone {
  if (!status) return ALERT_STATUS.new;
  const key = status.toLowerCase();
  return ALERT_STATUS[key] ?? { bg: 'bg-slate-500/20', fg: 'text-slate-300', label: status };
}

export function caseStatusTone(status: CaseStatus | string | undefined | null): StatusTone {
  if (!status) return CASE_STATUS.open;
  const key = status.toLowerCase();
  return CASE_STATUS[key] ?? { bg: 'bg-slate-500/20', fg: 'text-slate-300', label: status };
}
