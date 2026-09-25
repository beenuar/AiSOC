import { clsx } from 'clsx';
import type { ReactNode } from 'react';

// WS-F5 — empty-state polish across list views.
// Two variants:
//   - "default": filtered/no-data states with optional CTA
//   - "planned-v1.1": deferred features that should NOT advertise an
//     outbound link (per plan: "deferred features show 'planned for v1.1'
//     copy with NO outbound links"). The amber accent + badge make it
//     visually obvious this isn't a bug or a misconfiguration.
type EmptyStateVariant = 'default' | 'planned-v1.1';

interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
  variant?: EmptyStateVariant;
  /**
   * Override the default badge text. Only renders for non-default variants.
   * Defaults to "Planned for v1.1" for the planned-v1.1 variant.
   */
  badge?: string;
  /**
   * Heading level for `title`. Defaults to `h3`, which is right when this sits
   * inside a section that already has an `h2`.
   *
   * It is wrong when the nearest heading above is the page `h1` — the level
   * skip fails axe-core's `heading-order` rule, and a screen-reader user
   * navigating by heading is told there is a missing section between the page
   * title and this. `ConnectorsView` is that case.
   */
  headingLevel?: 'h2' | 'h3';
}

const VARIANT_STYLES: Record<EmptyStateVariant, {
  container: string;
  iconWrap: string;
  badge: string;
  badgeLabel: string;
}> = {
  default: {
    container:
      'border-gray-800 bg-gray-900/30',
    iconWrap:
      'bg-gray-800/60 text-blue-400',
    badge: '',
    badgeLabel: '',
  },
  'planned-v1.1': {
    container:
      'border-amber-500/30 bg-amber-500/[0.04]',
    iconWrap:
      'bg-amber-500/10 text-amber-300',
    badge:
      'inline-flex items-center gap-1 rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-300',
    badgeLabel: 'Planned for v1.1',
  },
};

/**
 * Friendly placeholder shown when a list/section has no data yet.
 *
 * Pair with a clear `action` so users can do *something* — a link to
 * docs, a "Connect data source" button, or a way to seed demo data —
 * UNLESS the variant is "planned-v1.1", in which case the action
 * should be omitted (deferred features don't advertise outbound links).
 */
export function EmptyState({
  icon,
  title,
  description,
  action,
  className,
  variant = 'default',
  badge,
  headingLevel: Heading = 'h3',
}: EmptyStateProps) {
  const styles = VARIANT_STYLES[variant];
  const badgeText = badge ?? styles.badgeLabel;
  const showBadge = variant !== 'default' && badgeText.length > 0;

  return (
    <div
      className={clsx(
        'flex flex-col items-center justify-center rounded-xl border border-dashed px-6 py-12 text-center',
        styles.container,
        className,
      )}
      role="status"
    >
      {icon && (
        <div
          className={clsx(
            'mb-4 flex h-12 w-12 items-center justify-center rounded-full',
            styles.iconWrap,
          )}
        >
          {icon}
        </div>
      )}
      {showBadge && <span className={clsx('mb-3', styles.badge)}>{badgeText}</span>}
      <Heading className="text-base font-semibold text-gray-100">{title}</Heading>
      {description && (
        <p className="mt-1 max-w-md text-sm text-gray-500">{description}</p>
      )}
      {action && variant === 'default' && <div className="mt-5">{action}</div>}
    </div>
  );
}

// ─── Shared empty-state icons ────────────────────────────────────────────────
//
// Lightweight inline SVGs sized for the EmptyState icon slot (h-12 w-12 wrap,
// the SVG itself uses h-6 w-6 inside). Keeping them here avoids pulling in a
// full icon library just for empty states and ensures consistent sizing /
// stroke weight across views.

const baseIconProps = {
  className: 'h-6 w-6',
  fill: 'none' as const,
  viewBox: '0 0 24 24',
  stroke: 'currentColor' as const,
  strokeWidth: 1.75,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
};

export const EmptyStateIcons = {
  alert: (
    <svg {...baseIconProps} aria-hidden="true">
      <path d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
    </svg>
  ),
  case: (
    <svg {...baseIconProps} aria-hidden="true">
      <path d="M2.25 7.125C2.25 6.504 2.754 6 3.375 6h17.25c.621 0 1.125.504 1.125 1.125v9.75c0 .621-.504 1.125-1.125 1.125H3.375A1.125 1.125 0 012.25 16.875v-9.75z" />
      <path d="M9 6V4.875C9 4.254 9.504 3.75 10.125 3.75h3.75c.621 0 1.125.504 1.125 1.125V6" />
    </svg>
  ),
  search: (
    <svg {...baseIconProps} aria-hidden="true">
      <path d="M21 21l-4.35-4.35m0 0A7.5 7.5 0 1010.5 18a7.5 7.5 0 006.15-1.35z" />
    </svg>
  ),
  shield: (
    <svg {...baseIconProps} aria-hidden="true">
      <path d="M12 2.25l7.5 3.375v5.25c0 4.5-3.375 8.25-7.5 9-4.125-.75-7.5-4.5-7.5-9V5.625L12 2.25z" />
      <path d="M9.75 12l1.5 1.5L15 9.75" />
    </svg>
  ),
  audit: (
    <svg {...baseIconProps} aria-hidden="true">
      <path d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
    </svg>
  ),
  marketplace: (
    <svg {...baseIconProps} aria-hidden="true">
      <path d="M2.25 3h1.386c.51 0 .955.343 1.087.835l.383 1.437M7.5 14.25a3 3 0 00-3 3h15.75M7.5 14.25l-1.299-6.486a1.125 1.125 0 011.103-1.347h13.392c.717 0 1.255.66 1.11 1.363l-1.298 6.348a1.125 1.125 0 01-1.103.872H8.603a1.125 1.125 0 01-1.103-.75z" />
      <path d="M16.5 19.5a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0zM10.5 19.5a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0z" />
    </svg>
  ),
  ledger: (
    <svg {...baseIconProps} aria-hidden="true">
      <path d="M3.75 6h16.5M3.75 12h16.5M3.75 18h16.5" />
    </svg>
  ),
};
