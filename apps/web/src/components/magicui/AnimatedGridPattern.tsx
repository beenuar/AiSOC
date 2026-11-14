// Source: https://magicui.design/docs/components/animated-grid-pattern
// Licensed under MIT. Vendored implementation. Renders a subtle grid of
// equally-sized squares; a handful of randomly-chosen squares fade in and
// out on a stagger so the hero never feels static. Disabled entirely
// under `prefers-reduced-motion` — a flat grid still tells the same story.
'use client';

import { motion, useReducedMotion } from 'framer-motion';
import { useEffect, useMemo, useState } from 'react';
import { cn } from '@/lib/utils';

interface AnimatedGridPatternProps {
  className?: string;
  /** Side length (px) of one grid square. */
  width?: number;
  height?: number;
  /** Total number of squares that participate in the fade animation. */
  numSquares?: number;
  /** Max opacity any single square reaches during fade. */
  maxOpacity?: number;
  /** Duration (seconds) for each fade cycle. */
  duration?: number;
  /** Delay (seconds) between cycles for each square. */
  repeatDelay?: number;
}

interface Square {
  id: number;
  x: number;
  y: number;
}

export function AnimatedGridPattern({
  className,
  width = 56,
  height = 56,
  numSquares = 48,
  maxOpacity = 0.08,
  duration = 3,
  repeatDelay = 1,
}: AnimatedGridPatternProps) {
  const prefersReducedMotion = useReducedMotion();
  const [dim, setDim] = useState({ w: 0, h: 0 });

  useEffect(() => {
    const update = () => {
      if (typeof window === 'undefined') return;
      setDim({ w: window.innerWidth, h: window.innerHeight });
    };
    update();
    window.addEventListener('resize', update);
    return () => window.removeEventListener('resize', update);
  }, []);

  const cols = Math.max(1, Math.ceil(dim.w / width));
  const rows = Math.max(1, Math.ceil(dim.h / height));

  const squares = useMemo<Square[]>(() => {
    if (cols === 0 || rows === 0) return [];
    return Array.from({ length: numSquares }, (_, idx) => ({
      id: idx,
      x: Math.floor(Math.random() * cols),
      y: Math.floor(Math.random() * rows),
    }));
  }, [cols, rows, numSquares]);

  return (
    <svg
      aria-hidden="true"
      // VelvetEdge retheme — emerald-mint grid lines at low alpha so the
      // pattern hints at the jewel surface without ever cresting body-text
      // contrast. Reduced-motion users still see the static grid; only
      // the per-square fade animation is suppressed.
      className={cn(
        'pointer-events-none absolute inset-0 h-full w-full text-velvet-emerald-mint/12 [mask-image:radial-gradient(circle_at_center,white,transparent_70%)]',
        className,
      )}
    >
      <defs>
        <pattern id="aisoc-grid-pattern" width={width} height={height} patternUnits="userSpaceOnUse">
          <path d={`M.5 ${height}V.5H${width}`} fill="none" stroke="currentColor" strokeWidth="1" />
        </pattern>
      </defs>
      <rect width="100%" height="100%" fill="url(#aisoc-grid-pattern)" />
      {!prefersReducedMotion &&
        squares.map(({ id, x, y }) => (
          <motion.rect
            key={id}
            width={width - 1}
            height={height - 1}
            x={x * width + 1}
            y={y * height + 1}
            fill="currentColor"
            initial={{ opacity: 0 }}
            animate={{ opacity: [0, maxOpacity, 0] }}
            transition={{
              duration,
              repeat: Infinity,
              repeatDelay,
              delay: id * 0.12,
              ease: 'easeInOut',
            }}
          />
        ))}
    </svg>
  );
}
