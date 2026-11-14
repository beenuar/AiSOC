// Source: https://ui.aceternity.com/components/animated-tooltip
// Licensed under MIT. Lightweight wrapper that shows a hover tooltip with
// a framer-motion fade + 6 px translate. Falls back to instant-visible
// under `prefers-reduced-motion`.
'use client';

import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import { type ReactNode, useId, useState } from 'react';
import { cn } from '@/lib/utils';

interface AnimatedTooltipProps {
  label: string;
  children: ReactNode;
  className?: string;
}

export function AnimatedTooltip({ label, children, className }: AnimatedTooltipProps) {
  const [open, setOpen] = useState(false);
  const tooltipId = useId();
  const prefersReducedMotion = useReducedMotion();
  return (
    <span
      className={cn('relative inline-flex items-center', className)}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      <span aria-describedby={open ? tooltipId : undefined}>{children}</span>
      <AnimatePresence>
        {open && (
          <motion.span
            id={tooltipId}
            role="tooltip"
            initial={{ opacity: 0, y: prefersReducedMotion ? 0 : 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: prefersReducedMotion ? 0 : 6 }}
            transition={{ duration: prefersReducedMotion ? 0 : 0.2, ease: [0.16, 1, 0.3, 1] }}
            className="pointer-events-none absolute left-1/2 top-full z-50 mt-2 w-max max-w-[14rem] -translate-x-1/2 rounded-md border border-surface-border bg-surface-raised px-3 py-2 text-xs leading-relaxed text-fg-secondary shadow-[0_8px_24px_-12px_rgba(0,0,0,0.5)]"
          >
            {label}
          </motion.span>
        )}
      </AnimatePresence>
    </span>
  );
}
