'use client';

import { clsx } from 'clsx';

/**
 * The user's *organisation-level* role, surfaced in the TopBar so operators
 * always know what permissions they're operating under. Tone is tuned per
 * role so an `admin` badge visually outranks a `viewer` badge.
 *
 * Unknown roles fall back to a neutral slate styling — a future RBAC
 * iteration could add bespoke colours, but we'd rather render *something*
 * informative than a confident-but-wrong label.
 */
const ROLE_STYLES: Record<string, { label: string; classes: string }> = {
  admin: {
    label: 'Admin',
    classes:
      'bg-rose-500/10 text-rose-200 border-rose-500/30 dark:bg-rose-500/15',
  },
  responder: {
    label: 'Responder',
    classes:
      'bg-amber-500/10 text-amber-200 border-amber-500/30 dark:bg-amber-500/15',
  },
  analyst: {
    label: 'Analyst',
    classes:
      'bg-brand-500/10 text-brand-200 border-brand-500/30 dark:bg-brand-500/15',
  },
  viewer: {
    label: 'Viewer',
    classes:
      'bg-slate-500/10 text-slate-200 border-slate-500/30 dark:bg-slate-500/15',
  },
  auditor: {
    label: 'Auditor',
    classes:
      'bg-emerald-500/10 text-emerald-200 border-emerald-500/30 dark:bg-emerald-500/15',
  },
};

const FALLBACK = {
  label: 'User',
  classes: 'bg-slate-500/10 text-slate-300 border-slate-500/30',
};

interface RoleBadgeProps {
  role: string | null | undefined;
  /** Visible label override, e.g. "Admin · Acme Corp". */
  label?: string;
  className?: string;
  /** Optional tooltip (title attribute). */
  tooltip?: string;
}

/**
 * W5 — Role badge surfaced in the TopBar.
 *
 * Renders the user's role with role-specific styling. We intentionally use
 * `border-*` + a translucent background instead of solid fills so the badge
 * sits cleanly against both light- and dark-mode chrome.
 */
export function RoleBadge({ role, label, className, tooltip }: RoleBadgeProps) {
  const norm = (role ?? '').toLowerCase();
  const style = ROLE_STYLES[norm] ?? FALLBACK;
  const displayLabel = label ?? style.label;
  return (
    <span
      title={tooltip}
      className={clsx(
        'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide',
        style.classes,
        className,
      )}
    >
      <span
        aria-hidden
        className="h-1.5 w-1.5 rounded-full bg-current opacity-80"
      />
      {displayLabel}
    </span>
  );
}
