// Source: https://ui.aceternity.com/components/wavy-background
// Licensed under MIT. Vendored implementation. Renders three sine-wave
// SVG paths layered over a brand gradient; cheaper than the canvas version
// in the upstream library, so it stays under the perf budget when the
// final-cta band enters the viewport. Falls back to a flat
// `landing.gradient.cta` background under `prefers-reduced-motion`.
'use client';

import { motion, useReducedMotion } from 'framer-motion';
import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

interface WavyBackgroundProps {
  children?: ReactNode;
  className?: string;
  containerClassName?: string;
  /** Stroke opacity for each wave layer. */
  waveOpacity?: number;
}

// VelvetEdge wave strokes — emerald → mint → sapphire so the final-CTA
// band reads as a jewel-tone gradient rather than the brand-blue legacy.
const WAVE_STROKES = ['#064E3B', '#34D399', '#1E3A8A'] as const;

export function WavyBackground({
  children,
  className,
  containerClassName,
  waveOpacity = 0.35,
}: WavyBackgroundProps) {
  const prefersReducedMotion = useReducedMotion();
  return (
    <div
      className={cn(
        // VelvetEdge final-cta gradient is the new emerald → ruby surface
        // wash; falls back gracefully when reduced-motion suppresses the
        // animated waves above.
        'relative isolate overflow-hidden bg-velvet-cta-grad',
        containerClassName,
      )}
    >
      {!prefersReducedMotion && (
        <svg
          className="pointer-events-none absolute inset-0 h-full w-full"
          viewBox="0 0 1440 600"
          preserveAspectRatio="none"
          aria-hidden="true"
        >
          {WAVE_STROKES.map((stroke, idx) => (
            <motion.path
              key={stroke}
              d="M0 320 C 240 220 480 420 720 320 S 1200 220 1440 320 V 600 H 0 Z"
              fill={stroke}
              fillOpacity={waveOpacity / (idx + 1)}
              initial={{ x: 0 }}
              animate={{ x: [0, -120, 0] }}
              transition={{
                duration: 18 + idx * 4,
                repeat: Infinity,
                ease: 'easeInOut',
                delay: idx * -3,
              }}
              style={{ filter: 'blur(2px)' }}
            />
          ))}
        </svg>
      )}
      <div className={cn('relative z-10', className)}>{children}</div>
    </div>
  );
}
