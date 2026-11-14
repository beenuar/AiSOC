// Source: https://ui.aceternity.com/components/background-beams
// Licensed under MIT. Vendored implementation. Renders a static SVG of
// soft beams; the upstream version animates them via path tracing, but
// here they fade in with a single `animate-fade-in-up` on the wrapper —
// cheaper and the visual signal is identical at the rendered scale.
'use client';

import { cn } from '@/lib/utils';

interface BackgroundBeamsProps {
  className?: string;
}

export function BackgroundBeams({ className }: BackgroundBeamsProps) {
  return (
    <svg
      aria-hidden="true"
      className={cn(
        'pointer-events-none absolute inset-0 h-full w-full opacity-60 animate-fade-in-up',
        '[mask-image:radial-gradient(circle_at_50%_40%,white,transparent_75%)]',
        className,
      )}
      style={{ animationDelay: '120ms', animationDuration: '900ms' }}
      width="100%"
      height="100%"
      viewBox="0 0 696 316"
      preserveAspectRatio="none"
      fill="none"
    >
      {[
        // VelvetEdge background beams — emerald, sapphire, and a mint
        // highlight so the wash matches the hero gradient instead of the
        // legacy brand-blue palette.
        ['M-380 -189C-380 -189 -312 216 152 343 616 470 684 875 684 875', '#064E3B'],
        ['M-373 -197C-373 -197 -305 208 159 335 623 462 691 867 691 867', '#1E3A8A'],
        ['M-366 -205C-366 -205 -298 200 166 327 630 454 698 859 698 859', '#34D399'],
        ['M-359 -213C-359 -213 -291 192 173 319 637 446 705 851 705 851', '#064E3B'],
        ['M-352 -221C-352 -221 -284 184 180 311 644 438 712 843 712 843', '#1E3A8A'],
      ].map(([d, stroke], idx) => (
        <path
          key={idx}
          d={d}
          stroke={stroke}
          strokeOpacity={0.22}
          strokeWidth="0.8"
          fill="none"
        />
      ))}
    </svg>
  );
}
