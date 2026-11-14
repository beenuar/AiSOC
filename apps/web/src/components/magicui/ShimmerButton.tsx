// Source: https://magicui.design/docs/components/shimmer-button
// Licensed under MIT. Vendored implementation. A brand-tinted button that
// loops a soft sheen across its surface on hover only — never on mount —
// so the conversion target never competes with the H1 reveal for
// attention. Reduces to a solid brand-500 button under
// `prefers-reduced-motion`.
'use client';

import type { ButtonHTMLAttributes } from 'react';
import { forwardRef } from 'react';
import { cn } from '@/lib/utils';

type ShimmerButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  shimmerColor?: string;
  shimmerDuration?: string;
};

export const ShimmerButton = forwardRef<HTMLButtonElement, ShimmerButtonProps>(
  function ShimmerButton(
    {
      children,
      className,
      // VelvetEdge default — mint sheen (`#34D399` at low alpha) over the
      // emerald 135deg gradient body.
      shimmerColor = 'rgba(52,211,153,0.55)',
      shimmerDuration = '2.5s',
      ...rest
    },
    ref,
  ) {
    return (
      <button
        ref={ref}
        className={cn(
          'group/shimmer relative inline-flex h-11 cursor-pointer items-center justify-center overflow-hidden rounded-md bg-velvet-emerald-cta px-6 text-sm font-semibold text-velvet-content-primary shadow-[0_0_0_1px_rgba(6,78,59,0.35)] transition-[filter,box-shadow] duration-200 ease-landing-in-out-quad',
          'hover:brightness-110 motion-safe:hover:shadow-glow-emerald-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base',
          'motion-reduce:hover:shadow-none',
          className,
        )}
        style={
          {
            '--shimmer-color': shimmerColor,
            '--shimmer-duration': shimmerDuration,
          } as React.CSSProperties
        }
        {...rest}
      >
        <span
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 -translate-x-full bg-[linear-gradient(110deg,transparent_0%,var(--shimmer-color)_50%,transparent_100%)] opacity-0 transition-opacity duration-200 ease-out group-hover/shimmer:opacity-100 group-hover/shimmer:[animation:shimmer-pass_var(--shimmer-duration)_linear_infinite] motion-reduce:hidden"
        />
        <span className="relative z-10 flex items-center gap-2">{children}</span>
      </button>
    );
  },
);

// Keyframe lives here so a host page that imports the button gets the
// animation without needing to load it from globals.css separately. This
// is the one keyframe we keep co-located with its consumer — every other
// landing-page keyframe is in globals.css.
if (typeof document !== 'undefined' && !document.getElementById('shimmer-button-keyframe')) {
  const style = document.createElement('style');
  style.id = 'shimmer-button-keyframe';
  style.textContent = `@keyframes shimmer-pass { from { transform: translateX(-120%); } to { transform: translateX(120%); } }`;
  document.head.appendChild(style);
}
