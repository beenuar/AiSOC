'use client';

/**
 * "Why we built this" — `problem` section from §6.3 of the brief.
 *
 * Renders three pain bullets in a three-up grid (single column below
 * `md`). Each card reveals once when it enters the viewport, staggered
 * 80 ms apart per §7 of the brief. The icon is a Lucide glyph that
 * matches the pain point, sitting inside a 40×40 brand-tinted tile.
 *
 * Copy is lifted verbatim from `docs/design/landing-page-content.md`
 * (headlines + bodies).
 */

import { motion, useReducedMotion } from 'framer-motion';
import { AlertTriangle, Layers, ScrollText } from 'lucide-react';
import type { ComponentType, SVGProps } from 'react';

interface Pain {
  icon: ComponentType<SVGProps<SVGSVGElement>>;
  headline: string;
  body: string;
}

const PAINS: ReadonlyArray<Pain> = [
  {
    icon: AlertTriangle,
    headline: 'Alert volume is up. Headcount is not.',
    body:
      'A typical mid-market SOC sees more alerts in a single shift than an analyst can read end-to-end, and the AI tools that promise to triage them ship as black boxes you cannot audit.',
  },
  {
    icon: Layers,
    headline: 'Context lives in eight tabs.',
    body:
      'SIEM, EDR, cloud console, ticketing, chat, identity provider, on-call, runbook. Every alert is the same context-switch tax.',
  },
  {
    icon: ScrollText,
    headline: 'You cannot defend a verdict you cannot read.',
    body:
      'When an autonomous tool closes an alert, your analyst, your manager, and your auditor all need to know exactly why. Most vendors do not show the rationale.',
  },
];

export function Problem() {
  const prefersReducedMotion = useReducedMotion();

  const initial = prefersReducedMotion ? false : { opacity: 0, y: 20 };
  const inView = { opacity: 1, y: 0 };

  return (
    <section
      id="problem"
      aria-labelledby="problem-heading"
      className="relative py-20 sm:py-24 lg:py-28"
    >
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-2xl text-center">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-velvet-emerald-mint">
            Why we built this
          </p>
          <h2
            id="problem-heading"
            className="font-velvet-display font-normal mt-3 text-3xl tracking-tight text-velvet-content-primary sm:text-4xl lg:text-[40px] lg:leading-[1.15] lg:tracking-[-0.015em]"
          >
            Your SOC is drowning in alerts.
          </h2>
          <p className="mt-4 text-base leading-relaxed text-velvet-content-secondary sm:text-lg">
            Three problems compound every shift. AiSOC was built to dissolve
            them, not paper over them.
          </p>
        </div>

        <ul className="mt-12 grid gap-4 sm:gap-6 md:grid-cols-3 lg:mt-16">
          {PAINS.map((pain, index) => {
            const Icon = pain.icon;
            return (
              <motion.li
                key={pain.headline}
                initial={initial}
                whileInView={inView}
                viewport={{ once: true, margin: '-15%' }}
                transition={{
                  duration: 0.55,
                  ease: [0.16, 1, 0.3, 1],
                  delay: index * 0.08,
                }}
                className="flex flex-col gap-4 rounded-2xl border border-velvet-border bg-velvet-surface-raised/60 p-6 backdrop-blur-sm transition-shadow duration-300 ease-landing-out-quart hover:motion-safe:shadow-glow-emerald-md"
              >
                <span
                  aria-hidden="true"
                  className="inline-flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-velvet-emerald/20 to-velvet-emerald-light/20 text-velvet-emerald-mint ring-1 ring-inset ring-velvet-emerald/30"
                >
                  <Icon className="h-5 w-5" />
                </span>
                <h3 className="font-velvet-display font-normal text-base leading-snug text-velvet-content-primary sm:text-lg">
                  {pain.headline}
                </h3>
                <p className="text-sm leading-relaxed text-velvet-content-secondary">
                  {pain.body}
                </p>
              </motion.li>
            );
          })}
        </ul>
      </div>
    </section>
  );
}
