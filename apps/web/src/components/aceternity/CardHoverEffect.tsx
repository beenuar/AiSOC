// Source: https://ui.aceternity.com/components/card-hover-effect
// Licensed under MIT. Trimmed down to a hover-state overlay that any card
// can opt into via `<CardHoverEffect />` as a sibling. The lift transform
// is dropped under `prefers-reduced-motion` while the colour shift stays.
'use client';

import { motion, useReducedMotion } from 'framer-motion';
import { cn } from '@/lib/utils';

interface CardHoverEffectProps {
  isActive: boolean;
  className?: string;
  /** Tailwind background-color class to swap in on hover. */
  activeClassName?: string;
}

/**
 * Renders the hover overlay for a parent card. Parent must:
 *
 *   1. Be `position: relative` and have `onMouseEnter` / `onMouseLeave`
 *      handlers wired into `isActive`.
 *   2. Render `<CardHoverEffect isActive={…} />` as its first child.
 *
 * `framer-motion` keeps `opacity` cheap (compositor-only) so no layout
 * thrash on hover.
 */
export function CardHoverEffect({
  isActive,
  className,
  activeClassName = 'bg-brand-500/8',
}: CardHoverEffectProps) {
  const prefersReducedMotion = useReducedMotion();
  return (
    <motion.span
      aria-hidden="true"
      className={cn(
        'pointer-events-none absolute inset-0 rounded-[inherit]',
        activeClassName,
        className,
      )}
      initial={{ opacity: 0 }}
      animate={{ opacity: isActive ? 1 : 0 }}
      transition={{
        duration: prefersReducedMotion ? 0 : isActive ? 0.25 : 0.15,
        ease: [0.45, 0, 0.55, 1],
      }}
    />
  );
}
