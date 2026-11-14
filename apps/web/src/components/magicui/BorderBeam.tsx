// Source: https://magicui.design/docs/components/border-beam
// Licensed under MIT. Vendored implementation. A brand-tinted comet
// traces the border of the parent (which must be `position: relative`
// and have a non-zero border-radius). Driven by a single CSS keyframe
// (`border-beam` in `globals.css`) using the new `offset-path` API.
// Falls back to a static 1 px brand border under `prefers-reduced-motion`.
'use client';

import { useReducedMotion } from 'framer-motion';
import { cn } from '@/lib/utils';

interface BorderBeamProps {
  className?: string;
  /** Size of the comet in pixels. */
  size?: number;
  /** Animation duration in seconds. */
  duration?: number;
  /** Comet gradient start color. */
  colorFrom?: string;
  /** Comet gradient end color. */
  colorTo?: string;
  /** Negative delay in seconds to phase-shift the beam. */
  delay?: number;
}

export function BorderBeam({
  className,
  size = 200,
  duration = 12,
  // VelvetEdge defaults — emerald-mint head fading into sapphire tail.
  // Callers can still pass any hex (e.g. ruby for destructive surfaces)
  // since the colors flow through CSS custom properties.
  colorFrom = '#34D399',
  colorTo = '#1E3A8A',
  delay = 0,
}: BorderBeamProps) {
  const prefersReducedMotion = useReducedMotion();
  if (prefersReducedMotion) {
    return (
      <span
        aria-hidden="true"
        className={cn(
          'pointer-events-none absolute inset-0 rounded-[inherit] border border-velvet-emerald-mint/30',
          className,
        )}
      />
    );
  }
  return (
    <span
      aria-hidden="true"
      className={cn(
        'pointer-events-none absolute inset-0 rounded-[inherit] [border:calc(var(--border-width)*1px)_solid_transparent]',
        '[mask-clip:padding-box,border-box] [mask-composite:intersect] [mask-image:linear-gradient(transparent,transparent),linear-gradient(white,white)]',
        // The single moving dot drawn along the border path.
        'after:absolute after:aspect-square after:w-[calc(var(--size)*1px)] after:animate-[border-beam_calc(var(--duration)*1s)_infinite_linear]',
        'after:[background:linear-gradient(to_left,var(--color-from),var(--color-to),transparent)] after:[offset-anchor:90%_50%] after:[offset-path:rect(0_auto_auto_0_round_calc(var(--size)*1px))]',
        className,
      )}
      style={
        {
          '--size': String(size),
          '--duration': String(duration),
          '--border-width': '1.4',
          '--color-from': colorFrom,
          '--color-to': colorTo,
          animationDelay: `${delay}s`,
        } as React.CSSProperties
      }
    />
  );
}
