// Source: https://magicui.design/docs/components/meteors
// Licensed under MIT. Vendored implementation. Renders a configurable
// number of meteor streaks across the parent. Each meteor uses the
// shared `animate-meteor` keyframe in `globals.css`; the JS layer only
// computes initial start positions and a per-meteor delay. Hidden under
// `prefers-reduced-motion`.
//
// Random positions are generated in `useEffect` rather than during render
// because this is a Client Component that still SSRs in the Next.js App
// Router. Running `Math.random()` during render would produce different
// values on the server and on hydration, triggering a hydration mismatch
// warning. Deferring to `useEffect` means SSR ships zero meteors and the
// client populates them after mount — imperceptible for a purely decorative
// background.
'use client';

import { useReducedMotion } from 'framer-motion';
import { useEffect, useState } from 'react';
import { cn } from '@/lib/utils';

interface MeteorsProps {
  /** Number of meteors to render. Default 18 — pre-trimmed for the perf budget. */
  number?: number;
  className?: string;
}

interface Meteor {
  id: number;
  top: string;
  left: string;
  delay: string;
  duration: string;
}

export function Meteors({ number = 18, className }: MeteorsProps) {
  const prefersReducedMotion = useReducedMotion();
  const [meteors, setMeteors] = useState<Meteor[]>([]);

  useEffect(() => {
    setMeteors(
      Array.from({ length: number }, (_, idx) => ({
        id: idx,
        top: `${Math.floor(Math.random() * 100)}%`,
        left: `${Math.floor(Math.random() * 100)}%`,
        delay: `${Math.random() * 4}s`,
        duration: `${4 + Math.random() * 6}s`,
      })),
    );
  }, [number]);

  if (prefersReducedMotion) return null;

  return (
    <div className={cn('pointer-events-none absolute inset-0 overflow-hidden', className)}>
      {meteors.map(({ id, top, left, delay, duration }) => (
        <span
          key={id}
          aria-hidden="true"
          // VelvetEdge retheme — meteors are mint-tinted (`#34D399` at low
          // alpha) so they read as emerald sparks against the jewel-tone
          // surface base. The trail uses the same hue with a soft fade.
          className="absolute h-0.5 w-0.5 rotate-[215deg] animate-meteor rounded-full bg-emerald-200 shadow-[0_0_0_1px_rgba(52,211,153,0.16)] before:absolute before:top-1/2 before:h-px before:w-12 before:-translate-y-1/2 before:bg-gradient-to-r before:from-emerald-200 before:to-transparent before:content-['']"
          style={{ top, left, animationDelay: delay, animationDuration: duration }}
        />
      ))}
    </div>
  );
}
