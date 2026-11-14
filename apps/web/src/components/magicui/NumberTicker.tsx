// Source: https://magicui.design/docs/components/number-ticker
// Licensed under MIT. Vendored implementation. Counts a number up (or
// down) to its target value once the element scrolls into view; uses a
// framer-motion `motionValue` so the count is composited on the GPU.
// Falls back to the final value immediately under `prefers-reduced-motion`.
'use client';

import {
  motion,
  useInView,
  useMotionValue,
  useReducedMotion,
  useSpring,
  useTransform,
} from 'framer-motion';
import { useEffect, useRef } from 'react';
import { cn } from '@/lib/utils';

interface NumberTickerProps {
  value: number;
  className?: string;
  /** Number of decimal places to render. Default 0. */
  decimalPlaces?: number;
  /** Direction of the count. */
  direction?: 'up' | 'down';
  /** Delay before the ticker begins, in seconds. */
  delay?: number;
  /** Locale used to format the rendered number. */
  locale?: string;
}

export function NumberTicker({
  value,
  className,
  decimalPlaces = 0,
  direction = 'up',
  delay = 0,
  locale = 'en-US',
}: NumberTickerProps) {
  const ref = useRef<HTMLSpanElement | null>(null);
  const isInView = useInView(ref, { once: true, margin: '0px' });
  const prefersReducedMotion = useReducedMotion();
  const start = direction === 'up' ? 0 : value;
  const target = direction === 'up' ? value : 0;
  const motionValue = useMotionValue(start);
  const spring = useSpring(motionValue, { damping: 28, stiffness: 90 });
  const formatted = useTransform(spring, (latest: number) =>
    Number(latest).toLocaleString(locale, {
      minimumFractionDigits: decimalPlaces,
      maximumFractionDigits: decimalPlaces,
    }),
  );

  useEffect(() => {
    if (!isInView) return;
    if (prefersReducedMotion) {
      motionValue.set(target);
      return;
    }
    const timeout = window.setTimeout(() => {
      motionValue.set(target);
    }, delay * 1000);
    return () => window.clearTimeout(timeout);
  }, [isInView, motionValue, prefersReducedMotion, target, delay]);

  return (
    <motion.span
      ref={ref}
      className={cn('tabular-nums', className)}
      aria-label={value.toLocaleString(locale, {
        minimumFractionDigits: decimalPlaces,
        maximumFractionDigits: decimalPlaces,
      })}
    >
      {formatted}
    </motion.span>
  );
}
