// Source: https://ui.aceternity.com/components/text-generate-effect
// Licensed under MIT. Vendored implementation tuned for the AiSOC hero H1:
// per-word framer-motion reveal with a 30 ms stagger and the `out-expo`
// easing curve from `docs/design/landing-page-design-tokens.md` §7.
'use client';

import { motion, useReducedMotion } from 'framer-motion';
import { useMemo } from 'react';
import { cn } from '@/lib/utils';

interface TextGenerateEffectProps {
  words: string;
  className?: string;
  /** Per-word stagger in seconds. */
  staggerDelay?: number;
  /** Total per-word fade duration in seconds. */
  duration?: number;
  /** Apply a 4 px blur during reveal. Defaults to `false` — at 56 px display the blur reads as a mistake. */
  filter?: boolean;
}

const OUT_EXPO = [0.16, 1, 0.3, 1] as const;

export function TextGenerateEffect({
  words,
  className,
  staggerDelay = 0.03,
  duration = 0.55,
  filter = false,
}: TextGenerateEffectProps) {
  const prefersReducedMotion = useReducedMotion();
  const tokens = useMemo(() => words.split(' '), [words]);

  if (prefersReducedMotion) {
    return <span className={className}>{words}</span>;
  }

  return (
    <span className={cn('inline-flex flex-wrap gap-x-[0.28em]', className)} aria-label={words}>
      {tokens.map((word, idx) => (
        <motion.span
          key={`${word}-${idx}`}
          initial={{ opacity: 0, y: '0.35em', filter: filter ? 'blur(4px)' : 'blur(0px)' }}
          animate={{ opacity: 1, y: '0em', filter: 'blur(0px)' }}
          transition={{ duration, delay: idx * staggerDelay, ease: OUT_EXPO }}
          className="inline-block will-change-transform"
          aria-hidden="true"
        >
          {word}
        </motion.span>
      ))}
    </span>
  );
}
