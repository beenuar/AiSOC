/**
 * Single canonical source of truth for case status across the console.
 *
 * The backend `aisoc_cases.status` column uses a 6-state lifecycle:
 *   new → triaged → investigating → contained → resolved → closed
 * (see services/api/app/api/v1/endpoints/cases.py `_STATUS_ORDER`).
 *
 * The web console used to maintain its own 5-state vocabulary plus two
 * translation maps, which is how the detail header ended up rendering a
 * pill and a dropdown that could never agree, and how label casing drifted
 * between screens ("In Progress" vs "In progress"). That vocabulary is gone:
 * every screen imports this file. Never re-declare status strings, labels,
 * or colors anywhere else, and never derive labels with CSS text-transform
 * or case helpers — render `label` from this map verbatim.
 */

export const CASE_STATUS_ORDER = [
  'new',
  'triaged',
  'investigating',
  'contained',
  'resolved',
  'closed',
] as const;

export type CaseStatus = (typeof CASE_STATUS_ORDER)[number];

export interface CaseStatusMeta {
  value: CaseStatus;
  label: string;
  /** Tailwind dot classes for the indicator bullet. */
  dot: string;
  /** Tailwind classes for the pill/badge surface. */
  pill: string;
  /** Terminal statuses may not transition further (mirrors backend rule). */
  terminal: boolean;
}

export const CASE_STATUS: Record<CaseStatus, CaseStatusMeta> = {
  new: {
    value: 'new',
    label: 'New',
    dot: 'bg-slate-400',
    pill: 'text-slate-300 bg-slate-700/50 border-slate-600/50',
    terminal: false,
  },
  triaged: {
    value: 'triaged',
    label: 'Triaged',
    dot: 'bg-amber-400',
    pill: 'text-amber-300 bg-amber-500/10 border-amber-500/20',
    terminal: false,
  },
  investigating: {
    value: 'investigating',
    label: 'Investigating',
    dot: 'bg-blue-400 animate-pulse',
    pill: 'text-blue-300 bg-blue-500/10 border-blue-500/20',
    terminal: false,
  },
  contained: {
    value: 'contained',
    label: 'Contained',
    dot: 'bg-teal-400',
    pill: 'text-teal-300 bg-teal-500/10 border-teal-500/20',
    terminal: false,
  },
  resolved: {
    value: 'resolved',
    label: 'Resolved',
    dot: 'bg-emerald-400',
    pill: 'text-emerald-300 bg-emerald-500/10 border-emerald-500/20',
    terminal: true,
  },
  closed: {
    value: 'closed',
    label: 'Closed',
    dot: 'bg-slate-600',
    pill: 'text-slate-500 bg-slate-800/50 border-slate-700/50',
    terminal: true,
  },
};

/**
 * Legacy spellings seen in stored payloads, cached drafts, and older
 * exports. Map to canonical; the backend's own `_STATUS_ALIASES` covers
 * the write side, this covers the read side.
 */
const STATUS_ALIASES: Record<string, CaseStatus> = {
  new: 'new',
  open: 'new',
  triaged: 'triaged',
  pending: 'triaged',
  investigating: 'investigating',
  in_progress: 'investigating',
  active: 'investigating',
  contained: 'contained',
  resolved: 'resolved',
  closed: 'closed',
};

/** Tolerant lookup — never returns undefined; unknown spellings collapse to `new`. */
export function statusMeta(raw: unknown): CaseStatusMeta {
  if (typeof raw === 'string') {
    const canonical = STATUS_ALIASES[raw.toLowerCase()];
    if (canonical) return CASE_STATUS[canonical];
  }
  return CASE_STATUS.new;
}

/** Canonical value for any raw status string (wire-safe). */
export function canonicalStatus(raw: unknown): CaseStatus {
  return statusMeta(raw).value;
}

// ─── Display groups ────────────────────────────────────────────────────────
// The /cases list groups the six canonical statuses into five cards/chips.
// Labels live here so no screen can invent its own casing. Grouping is a
// presentation concern only — the wire format stays canonical.

export interface CaseStatusGroup {
  key: 'all' | 'open' | 'in_progress' | 'resolved' | 'closed';
  label: string;
  /** Canonical statuses folded into this group; `null` means "everything". */
  members: readonly CaseStatus[] | null;
}

export const CASE_STATUS_GROUPS: readonly CaseStatusGroup[] = [
  { key: 'all', label: 'All Cases', members: null },
  { key: 'open', label: 'Open', members: ['new', 'triaged'] },
  { key: 'in_progress', label: 'In Progress', members: ['investigating', 'contained'] },
  { key: 'resolved', label: 'Resolved', members: ['resolved'] },
  { key: 'closed', label: 'Closed', members: ['closed'] },
] as const;

export function statusInGroup(raw: unknown, group: CaseStatusGroup): boolean {
  if (!group.members) return true;
  return group.members.includes(canonicalStatus(raw));
}
