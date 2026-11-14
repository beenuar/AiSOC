// Source: https://ui.aceternity.com/components/spotlight
// Licensed under MIT — Aceternity UI is a copy-into-your-codebase library
// (no npm package), so this file is the vendored implementation. Rewritten
// in plain Tailwind 4 + framer-motion 11 to fit the AiSOC landing tokens.
'use client';

import type { CSSProperties } from 'react';
import { cn } from '@/lib/utils';

interface SpotlightProps {
  className?: string;
  /**
   * CSS color string for the spotlight fill. VelvetEdge default is
   * mint (`#34D399` at low alpha) so the corner glow harmonises with
   * the emerald page surface.
   */
  fill?: string;
  /** Use `style` to override the `top` / `left` positioning of the glow. */
  style?: CSSProperties;
}

/**
 * Corner radial glow that sits behind the hero / demo frame and softens
 * the otherwise hard surface-base. Pure SVG — no JS at runtime, so it
 * costs nothing on hydration and degrades to "nothing visible" if CSS
 * filters are blocked.
 */
export function Spotlight({ className, fill = 'rgba(52, 211, 153, 0.45)', style }: SpotlightProps) {
  return (
    <svg
      className={cn('pointer-events-none absolute z-0 h-[169%] w-[138%] opacity-0 animate-fade-in-up lg:w-[84%]', className)}
      style={{ animationDelay: '120ms', animationDuration: '900ms', ...style }}
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 3787 2842"
      fill="none"
      aria-hidden="true"
    >
      <g filter="url(#aisoc-spotlight-filter)">
        <ellipse cx="1924.71" cy="273.501" rx="1924.71" ry="273.501" transform="matrix(-0.822377 -0.568943 -0.568943 0.822377 3631.88 2291.09)" fill={fill} fillOpacity="0.21" />
      </g>
      <defs>
        <filter id="aisoc-spotlight-filter" x="0.860352" y="0.838989" width="3785.16" height="2840.26" filterUnits="userSpaceOnUse" colorInterpolationFilters="sRGB">
          <feFlood floodOpacity="0" result="BackgroundImageFix" />
          <feBlend mode="normal" in="SourceGraphic" in2="BackgroundImageFix" result="shape" />
          <feGaussianBlur stdDeviation="151" result="effect1_foregroundBlur_1065_8" />
        </filter>
      </defs>
    </svg>
  );
}
