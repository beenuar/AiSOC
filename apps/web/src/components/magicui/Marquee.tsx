// Source: https://magicui.design/docs/components/marquee
// Licensed under MIT. Vendored implementation. Renders an infinitely
// scrolling row by duplicating its children once and using a CSS keyframe
// (`animate-marquee` in `globals.css`) for the translate. Pauses on hover
// via the `marquee-pausable` wrapper class.
'use client';

import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

interface MarqueeProps {
  className?: string;
  /** Scroll right-to-left when false, left-to-right when true. */
  reverse?: boolean;
  /** Number of times to duplicate the children for visual seamlessness. */
  repeat?: number;
  /** Pause animation when the wrapper is hovered or focused. Default true. */
  pauseOnHover?: boolean;
  /** Scroll vertically. */
  vertical?: boolean;
  children: ReactNode;
}

export function Marquee({
  className,
  reverse = false,
  repeat = 2,
  pauseOnHover = true,
  vertical = false,
  children,
}: MarqueeProps) {
  return (
    <div
      className={cn(
        'group/marquee relative flex w-full overflow-hidden [--gap:1.5rem]',
        vertical ? 'flex-col' : 'flex-row',
        pauseOnHover && 'marquee-pausable',
        className,
      )}
    >
      {Array.from({ length: repeat }).map((_, idx) => (
        <div
          key={idx}
          className={cn(
            'flex shrink-0 justify-around gap-[--gap]',
            vertical
              ? 'animate-marquee-vertical flex-col'
              : 'animate-marquee flex-row',
            reverse && '[animation-direction:reverse]',
          )}
          aria-hidden={idx === 0 ? undefined : 'true'}
        >
          {children}
        </div>
      ))}
    </div>
  );
}
