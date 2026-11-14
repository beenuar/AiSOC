// Source: https://ui.aceternity.com/components/glowing-effect
// Licensed under MIT. Vendored implementation. Tracks the pointer position
// relative to the wrapped card and renders a conic-gradient halo that
// brightens as the cursor approaches. Honours `prefers-reduced-motion`
// per `docs/design/landing-page-motion-spec.md` §2.4.
'use client';

import { useEffect, useRef, useState } from 'react';
import { useReducedMotion } from 'framer-motion';
import { cn } from '@/lib/utils';

interface GlowingEffectProps {
  className?: string;
  /** When false, the halo is hidden entirely. */
  enabled?: boolean;
  /** Distance in px at which the halo starts to fade in. */
  proximity?: number;
  /** Fractional inner radius where the halo stays at max intensity. */
  inactiveZone?: number;
}

/**
 * Drop-in halo wrapper. Place inside a `relative` parent — the halo lives
 * underneath the card content via `pointer-events-none`. Renders nothing
 * when reduced-motion is on or `enabled={false}`.
 */
export function GlowingEffect({
  className,
  enabled = true,
  proximity = 80,
  inactiveZone = 0.4,
}: GlowingEffectProps) {
  const ref = useRef<HTMLDivElement | null>(null);
  const prefersReducedMotion = useReducedMotion();
  const [intensity, setIntensity] = useState(0);

  useEffect(() => {
    if (!enabled || prefersReducedMotion) return;
    const onMove = (event: MouseEvent) => {
      const node = ref.current;
      if (!node) return;
      const rect = node.getBoundingClientRect();
      const cx = event.clientX - rect.left - rect.width / 2;
      const cy = event.clientY - rect.top - rect.height / 2;
      const distance = Math.hypot(cx, cy);
      const radius = Math.max(rect.width, rect.height) / 2;
      const inner = radius * inactiveZone;
      if (distance <= inner) {
        setIntensity(1);
      } else if (distance <= radius + proximity) {
        setIntensity(1 - (distance - inner) / (radius + proximity - inner));
      } else {
        setIntensity(0);
      }
    };
    window.addEventListener('mousemove', onMove);
    return () => window.removeEventListener('mousemove', onMove);
  }, [enabled, inactiveZone, prefersReducedMotion, proximity]);

  if (!enabled || prefersReducedMotion) {
    return null;
  }

  return (
    <div
      ref={ref}
      aria-hidden="true"
      className={cn(
        'pointer-events-none absolute inset-0 rounded-[inherit] transition-opacity duration-300 ease-out',
        className,
      )}
      style={{
        opacity: intensity,
        // VelvetEdge halo — emerald → mint → sapphire conic so the proximity
        // glow stays inside the spec's two-jewel-tone-per-element rule (rule
        // 7). Reduced-motion users see no halo at all (component returns
        // null above).
        background:
          'conic-gradient(from 0deg at 50% 50%, rgba(6,78,59,0.20) 0deg, rgba(52,211,153,0.32) 120deg, rgba(30,58,138,0.22) 240deg, rgba(6,78,59,0) 360deg)',
        filter: 'blur(24px)',
      }}
    />
  );
}
