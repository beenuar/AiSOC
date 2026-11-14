// Source: https://magicui.design/docs/components/shine-border
// Licensed under MIT. Vendored implementation. Adds a soft tri-stop
// conic-gradient border to the parent (must be `position: relative`)
// that animates around its perimeter. Cheaper than `BorderBeam` for the
// cases where a constant, low-energy frame is all we need (deploy-
// options "sovereign" card, pricing teaser card).
'use client';

import { useReducedMotion } from 'framer-motion';
import { cn } from '@/lib/utils';

interface ShineBorderProps {
  className?: string;
  /** Animation duration in seconds. */
  duration?: number;
  /** Tailwind class for border-width (defaults to `[--border-radius:1rem]` parent). */
  borderWidth?: number;
  /** Comma-separated CSS color stops. */
  colors?: readonly string[];
}

export function ShineBorder({
  className,
  duration = 14,
  borderWidth = 1,
  // VelvetEdge defaults — emerald → mint → sapphire tri-stop. Per spec
  // rule 7 the consumer should not stack a third jewel tone on the same
  // card body; the tail returns to the emerald hue family on purpose.
  colors = ['#064E3B', '#34D399', '#1E3A8A'],
}: ShineBorderProps) {
  const prefersReducedMotion = useReducedMotion();
  if (prefersReducedMotion) {
    return (
      <span
        aria-hidden="true"
        className={cn(
          'pointer-events-none absolute inset-0 rounded-[inherit] border border-velvet-emerald/40',
          className,
        )}
      />
    );
  }
  return (
    <span
      aria-hidden="true"
      style={
        {
          '--shine-duration': `${duration}s`,
          '--shine-border-width': `${borderWidth}px`,
          '--shine-color-stops': colors.join(','),
        } as React.CSSProperties
      }
      className={cn(
        // Solid 1 px border in the brand gradient. Cheaper than the upstream
        // conic-gradient + mask-composite trick and still reads as "active"
        // against the surface-raised card body.
        'pointer-events-none absolute inset-0 rounded-[inherit] [background:linear-gradient(135deg,var(--shine-color-stops))] [padding:var(--shine-border-width)]',
        '[mask-composite:exclude] [mask:linear-gradient(white,white)_content-box,linear-gradient(white,white)]',
        className,
      )}
    />
  );
}
