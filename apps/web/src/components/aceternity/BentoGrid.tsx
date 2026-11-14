// Source: https://ui.aceternity.com/components/bento-grid
// Licensed under MIT. Vendored implementation, trimmed to the two pieces
// the landing page needs: a 3-column responsive grid and a card primitive
// that hover-lifts and exposes the standard `header / icon / title /
// description` slots that the feature-grid section consumes.
'use client';

import { motion, useReducedMotion } from 'framer-motion';
import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

interface BentoGridProps {
  className?: string;
  children: ReactNode;
}

export function BentoGrid({ className, children }: BentoGridProps) {
  return (
    <div
      className={cn(
        'mx-auto grid w-full max-w-7xl auto-rows-[18rem] grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3',
        className,
      )}
    >
      {children}
    </div>
  );
}

interface BentoGridItemProps {
  className?: string;
  header?: ReactNode;
  icon?: ReactNode;
  title: ReactNode;
  description?: ReactNode;
}

export function BentoGridItem({
  className,
  header,
  icon,
  title,
  description,
}: BentoGridItemProps) {
  const prefersReducedMotion = useReducedMotion();
  return (
    <motion.div
      whileHover={prefersReducedMotion ? undefined : { y: -2 }}
      transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
      className={cn(
        'group/bento relative row-span-1 flex flex-col justify-between space-y-4 overflow-hidden rounded-xl border border-surface-border bg-surface-raised/70 p-5 shadow-[0_1px_2px_rgba(0,0,0,0.4)] transition-colors duration-200 ease-landing-out-quart hover:border-brand-500/40',
        className,
      )}
    >
      {header && <div className="relative">{header}</div>}
      <div className="flex flex-col gap-2">
        {icon && <div className="text-brand-300">{icon}</div>}
        <h3 className="font-display text-base font-semibold leading-snug text-fg-primary">
          {title}
        </h3>
        {description && (
          <p className="text-sm leading-relaxed text-fg-secondary">{description}</p>
        )}
      </div>
    </motion.div>
  );
}
