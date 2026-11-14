// Source: https://magicui.design/docs/components/animated-beam
// Licensed under MIT. Vendored implementation. Draws a curved SVG path
// between two ref'd DOM nodes (e.g. two agent cards) and animates a
// brand-tinted comet along it. Falls back to a static path under
// `prefers-reduced-motion` per `landing-page-motion-spec.md` §2.5.
'use client';

import { motion, useReducedMotion } from 'framer-motion';
import { type RefObject, useCallback, useEffect, useId, useState } from 'react';
import { cn } from '@/lib/utils';

interface AnimatedBeamProps {
  containerRef: RefObject<HTMLElement | null>;
  fromRef: RefObject<HTMLElement | null>;
  toRef: RefObject<HTMLElement | null>;
  className?: string;
  /** Negative for an arc that bows upward, positive for downward. */
  curvature?: number;
  /** Comet duration in seconds. */
  duration?: number;
  /** Negative phase shift (in seconds) so multiple beams don't fire in lockstep. */
  delay?: number;
  pathColor?: string;
  pathOpacity?: number;
  gradientStart?: string;
  gradientStop?: string;
  reverse?: boolean;
}

export function AnimatedBeam({
  containerRef,
  fromRef,
  toRef,
  className,
  curvature = -30,
  duration = 3,
  delay = 0,
  // VelvetEdge default — faint mint stroke for the static base path so it
  // reads as "absent" against surface-base, plus an emerald → sapphire
  // comet so the moving accent stays inside the two-jewel-tone rule.
  pathColor = 'rgba(52,211,153,0.18)',
  pathOpacity = 1,
  gradientStart = '#34D399',
  gradientStop = '#1E3A8A',
  reverse = false,
}: AnimatedBeamProps) {
  const id = useId();
  const [path, setPath] = useState('');
  const [size, setSize] = useState({ w: 0, h: 0 });
  const prefersReducedMotion = useReducedMotion();

  const update = useCallback(() => {
    const container = containerRef.current;
    const from = fromRef.current;
    const to = toRef.current;
    if (!container || !from || !to) return;
    const cRect = container.getBoundingClientRect();
    const fRect = from.getBoundingClientRect();
    const tRect = to.getBoundingClientRect();
    setSize({ w: cRect.width, h: cRect.height });
    const x1 = fRect.left + fRect.width / 2 - cRect.left;
    const y1 = fRect.top + fRect.height / 2 - cRect.top;
    const x2 = tRect.left + tRect.width / 2 - cRect.left;
    const y2 = tRect.top + tRect.height / 2 - cRect.top;
    const midX = (x1 + x2) / 2;
    const midY = (y1 + y2) / 2 + curvature;
    setPath(`M ${x1},${y1} Q ${midX},${midY} ${x2},${y2}`);
  }, [containerRef, fromRef, toRef, curvature]);

  useEffect(() => {
    update();
    window.addEventListener('resize', update);
    const interval = window.setTimeout(update, 80); // post-layout settle
    return () => {
      window.removeEventListener('resize', update);
      window.clearTimeout(interval);
    };
  }, [update]);

  if (!path) return null;

  const grad = `url(#${id.replace(/[:]/g, '')}-grad)`;

  return (
    <svg
      width={size.w}
      height={size.h}
      viewBox={`0 0 ${size.w} ${size.h}`}
      className={cn('pointer-events-none absolute inset-0', className)}
      aria-hidden="true"
    >
      <defs>
        <linearGradient
          id={`${id.replace(/[:]/g, '')}-grad`}
          x1="0%"
          y1="0%"
          x2="100%"
          y2="0%"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0%" stopColor={gradientStart} stopOpacity="0" />
          <stop offset="50%" stopColor={reverse ? gradientStop : gradientStart} stopOpacity="1" />
          <stop offset="100%" stopColor={reverse ? gradientStart : gradientStop} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={path} stroke={pathColor} strokeOpacity={pathOpacity} strokeWidth="1.5" fill="none" />
      {!prefersReducedMotion && (
        <motion.path
          d={path}
          stroke={grad}
          strokeWidth="2"
          fill="none"
          strokeLinecap="round"
          initial={{ pathLength: 0, pathOffset: 0, opacity: 0.6 }}
          animate={{ pathLength: 1, pathOffset: reverse ? -1 : 1, opacity: [0, 0.9, 0] }}
          transition={{
            duration,
            repeat: Infinity,
            ease: [0.65, 0, 0.35, 1],
            delay,
          }}
        />
      )}
    </svg>
  );
}
