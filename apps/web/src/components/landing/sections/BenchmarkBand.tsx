'use client';

/**
 * "Benchmarked, not vibes" — `benchmark` section from §6.9 of the
 * brief.
 *
 * Renders a three-up band of `NumberTicker`-driven metrics over a
 * brand-tinted gradient. Each tile shows:
 *   - A big mono metric (animated count-up from 0 when the band enters
 *     the viewport; suppressed under `prefers-reduced-motion`).
 *   - A caption labelling the metric source (substrate / wet-eval) so
 *     the page never claims a "real" number for a substrate gate. This
 *     matches the v1.4 eval-harness honesty contract from AGENTS.md.
 *
 * Two CTAs sit below the tiles: read the methodology, open the public
 * scoreboard. Both deep-link to /benchmark routes that already exist.
 */

import Link from 'next/link';
import { motion, useReducedMotion } from 'framer-motion';
import { ArrowRight, ExternalLink, GitCompare } from 'lucide-react';
import { NumberTicker } from '@/components/magicui/NumberTicker';
import { docs } from '@/lib/docs';

interface Metric {
  /**
   * If `value` is set, the tile animates a 0→value count-up. Otherwise
   * `label` is the visible metric (e.g. "Sub-minute p50").
   */
  value?: number;
  suffix?: string;
  label: string;
  caption: string;
}

const METRICS: ReadonlyArray<Metric> = [
  {
    value: 97,
    suffix: '%',
    label: '97.0%',
    caption: 'MITRE-tactic accuracy · substrate · per-case',
  },
  {
    value: undefined,
    label: 'Sub-minute p50',
    caption: 'End-to-end investigation latency · wet-eval target',
  },
  {
    value: 35,
    suffix: ' ms',
    label: '35 ms',
    caption: 'Full substrate suite runtime on a laptop',
  },
];

export function BenchmarkBand() {
  const prefersReducedMotion = useReducedMotion();
  const initial = prefersReducedMotion ? false : { opacity: 0, y: 16 };

  return (
    <section
      id="benchmark"
      aria-labelledby="benchmark-heading"
      className="relative py-20 sm:py-24 lg:py-28"
    >
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-3xl text-center">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-velvet-emerald-mint">
            Reproducible by anyone
          </p>
          <h2
            id="benchmark-heading"
            className="font-velvet-display font-normal mt-3 text-3xl tracking-tight text-velvet-content-primary sm:text-4xl lg:text-[40px] lg:leading-[1.15] lg:tracking-[-0.015em]"
          >
            Benchmarked, not vibes.
          </h2>
          <p className="mt-4 text-base leading-relaxed text-velvet-content-secondary sm:text-lg">
            Five pytest suites gate every PR. 200 synthetic incidents drawn
            from 55 templates plus a 361-event telemetry corpus across 14
            log sources. Per-template macros catch the regression the
            per-case mean hides. Every figure is labelled — substrate
            (gated per-PR) or wet-eval (weekly job).
          </p>
        </div>

        <div className="relative mt-12 overflow-hidden rounded-3xl border border-velvet-border bg-velvet-surface-raised/60 shadow-[0_30px_80px_-32px_rgba(15,23,42,0.7)] lg:mt-16">
          <div
            aria-hidden="true"
            className="absolute inset-0 bg-velvet-pillars-grad opacity-[0.08]"
          />
          <ul className="relative grid grid-cols-1 divide-y divide-velvet-border md:grid-cols-3 md:divide-x md:divide-y-0">
            {METRICS.map((metric, idx) => (
              <motion.li
                key={metric.label}
                initial={initial}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: '-15%' }}
                transition={{
                  duration: 0.55,
                  ease: [0.16, 1, 0.3, 1],
                  delay: idx * 0.08,
                }}
                className="flex flex-col items-center gap-2 px-6 py-10 text-center"
              >
                <p className="font-mono text-4xl font-semibold leading-none tracking-tight text-velvet-content-primary tabular-nums sm:text-5xl lg:text-[56px]">
                  {metric.value !== undefined ? (
                    <>
                      <NumberTicker
                        value={metric.value}
                        decimalPlaces={metric.value < 100 && metric.value !== 35 ? 1 : 0}
                      />
                      {metric.suffix ?? ''}
                    </>
                  ) : (
                    metric.label
                  )}
                </p>
                <p className="max-w-[20ch] text-xs leading-relaxed text-velvet-content-tertiary">
                  {metric.caption}
                </p>
              </motion.li>
            ))}
          </ul>
        </div>

        <div className="mx-auto mt-10 flex max-w-3xl flex-col items-center justify-center gap-3 text-center sm:flex-row sm:gap-5">
          <Link
            href="/benchmark"
            className="group inline-flex h-11 items-center gap-2 rounded-md bg-velvet-emerald-cta px-6 text-sm font-semibold text-velvet-content-primary shadow-[0_1px_0_rgba(255,255,255,0.18)_inset] transition-shadow duration-200 ease-landing-out-quart motion-safe:hover:shadow-glow-emerald-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base"
          >
            <GitCompare className="h-4 w-4" aria-hidden="true" />
            Read the methodology
            <ArrowRight
              className="h-4 w-4 transition-transform duration-200 group-hover:translate-x-0.5 motion-reduce:transition-none motion-reduce:group-hover:translate-x-0"
              aria-hidden="true"
            />
          </Link>
          <Link
            href={docs('benchmark')}
            className="inline-flex items-center gap-1 text-sm font-medium text-velvet-content-tertiary transition-colors duration-200 hover:text-velvet-content-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base"
          >
            Open the public scoreboard
            <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
          </Link>
        </div>
      </div>
    </section>
  );
}
