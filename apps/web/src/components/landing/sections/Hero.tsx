'use client';

/**
 * Hero section for the T6.5 landing page.
 *
 * Composes the vendored Aceternity / MagicUI primitives in a single,
 * GPU-cheap stack:
 *
 *   AnimatedGridPattern (random-fade grid)
 *     ↓ overlaid by
 *   Spotlight (static SVG glow, corner-anchored)
 *     ↓ overlaid by
 *   TextGenerateEffect (per-word reveal on H1)
 *     +
 *   AuroraText (the "auditable" accent)
 *
 * The H1 reveal totals ~750 ms (24 ms × 4 words × stagger + 0.55 s fade)
 * which is inside the §7 brief's 800 ms ceiling. The grid is purely SVG;
 * the Spotlight is one filter element with no JS. The background does
 * not paint to the canvas — Lighthouse LCP stays on the H1 string itself.
 *
 * Every animated path is suppressed under `prefers-reduced-motion` (the
 * primitives' own hooks handle that; this file only renders, never
 * conditions on the reduced-motion bit).
 */

import Link from 'next/link';
import { ArrowRight, Play } from 'lucide-react';
import { GithubMark } from './icons';
import { Spotlight } from '@/components/aceternity/Spotlight';
import { TextGenerateEffect } from '@/components/aceternity/TextGenerateEffect';
import { AnimatedGridPattern } from '@/components/magicui/AnimatedGridPattern';
import { AuroraText } from '@/components/magicui/AuroraText';
import { cn } from '@/lib/utils';
import { CONNECTOR_COUNT } from '@/data/connectorCount';

const PROOF_CHIPS: ReadonlyArray<string> = [
  `${CONNECTOR_COUNT} connectors · EDR · SIEM · cloud · IAM · SaaS · VCS · network`,
  '6,998 detections · 62 playbook packs · 57 plugins',
  'Self-host · Render · Fly.io · Helm · Terraform · air-gap',
];

export function Hero() {
  return (
    <section
      id="hero"
      aria-labelledby="hero-heading"
      className="relative isolate overflow-hidden pt-28 sm:pt-32 lg:pt-36"
    >
      <div
        aria-hidden="true"
        className="absolute inset-0 -z-10 bg-velvet-hero-grad opacity-90"
      />
      <AnimatedGridPattern
        className="-z-10 [mask-image:radial-gradient(ellipse_at_top,white,transparent_70%)]"
        numSquares={42}
        maxOpacity={0.07}
        duration={3.6}
        repeatDelay={1.2}
      />
      <Spotlight
        className="-top-40 left-0 md:-top-20 md:left-60"
        fill="rgba(52,211,153,0.45)"
      />

      <div className="mx-auto max-w-7xl px-4 pb-20 sm:px-6 lg:px-8 lg:pb-28">
        <div className="mx-auto max-w-3xl text-center">
          <p
            className={cn(
              'inline-flex items-center gap-2 rounded-full border border-velvet-border bg-velvet-surface-raised/60 px-3 py-1 text-xs font-medium text-velvet-content-tertiary backdrop-blur-sm',
              'animate-fade-in-up',
            )}
            style={{ animationDelay: '60ms' }}
          >
            <span
              aria-hidden="true"
              className="inline-block h-1.5 w-1.5 rounded-full bg-velvet-emerald-mint motion-safe:shadow-[0_0_0_2px_rgba(52,211,153,0.25),0_0_8px_rgba(52,211,153,0.45)]"
            />
            Open-source <span aria-hidden="true">·</span> MIT
            <span aria-hidden="true">·</span> self-hostable
          </p>

          <h1
            id="hero-heading"
            className="mt-6 font-velvet-display text-4xl font-normal leading-[1.1] tracking-tight text-velvet-content-primary sm:text-5xl lg:text-[64px] lg:leading-[1.05] lg:tracking-[-0.02em]"
          >
            <TextGenerateEffect
              words="Detect. Triage."
              staggerDelay={0.06}
              duration={0.55}
              className="block"
            />
            <span className="mt-1 block sm:mt-2">
              <AuroraText>Hunt.</AuroraText>{' '}
              <TextGenerateEffect
                words="Respond."
                staggerDelay={0.06}
                duration={0.55}
                className="inline"
              />
            </span>
          </h1>

          <p
            className="mx-auto mt-6 max-w-2xl text-base leading-relaxed text-velvet-content-secondary sm:text-lg sm:leading-[1.6] motion-safe:animate-fade-in-up"
            style={{ animationDelay: '420ms' }}
          >
            AiSOC is the open agentic Security Operations Center. Four named
            agents investigate every incident end-to-end, and every prompt,
            tool call, and rationale lands in a replayable ledger.
            Self-host in five minutes, take it air-gapped on a flag, or join
            the managed waitlist.
          </p>

          <div
            className="mt-8 flex flex-col items-center justify-center gap-3 motion-safe:animate-fade-in-up sm:flex-row sm:gap-4"
            style={{ animationDelay: '540ms' }}
          >
            <Link
              href="https://tryaisoc.com/dashboard"
              className="group inline-flex h-11 w-full items-center justify-center gap-2 rounded-md bg-velvet-emerald-cta px-6 text-sm font-semibold text-velvet-content-primary shadow-[0_1px_0_rgba(255,255,255,0.18)_inset] transition-[filter,box-shadow,transform] duration-200 ease-landing-out-quart hover:brightness-110 motion-safe:hover:shadow-glow-emerald-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base sm:w-auto"
            >
              Open the live dashboard
              <ArrowRight
                className="h-4 w-4 transition-transform duration-200 ease-landing-out-quart group-hover:translate-x-0.5 motion-reduce:transition-none motion-reduce:group-hover:translate-x-0"
                aria-hidden="true"
              />
            </Link>
            <a
              href="https://github.com/beenuar/AiSOC"
              target="_blank"
              rel="noreferrer"
              className="inline-flex h-11 w-full items-center justify-center gap-2 rounded-md border border-velvet-sapphire bg-transparent px-6 text-sm font-semibold text-velvet-sapphire-soft backdrop-blur-sm transition-[background-color,box-shadow] duration-200 ease-landing-out-quart hover:bg-velvet-sapphire/[0.12] motion-safe:hover:shadow-glow-sapphire-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-sapphire-soft focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base sm:w-auto"
            >
              <GithubMark className="h-4 w-4" />
              Self-host on GitHub
            </a>
          </div>

          <Link
            href="#demo"
            className="group mt-5 inline-flex items-center gap-2 text-sm font-medium text-velvet-content-tertiary transition-colors duration-200 ease-landing-out-quart hover:text-velvet-content-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base motion-safe:animate-fade-in-up"
            style={{ animationDelay: '660ms' }}
          >
            <Play
              className="h-3.5 w-3.5 fill-current opacity-70 transition-opacity duration-200 group-hover:opacity-100"
              aria-hidden="true"
            />
            Watch a 90-second investigation
            <ArrowRight
              className="h-3 w-3 transition-transform duration-200 ease-landing-out-quart group-hover:translate-x-0.5"
              aria-hidden="true"
            />
          </Link>
        </div>

        <ul
          className="mx-auto mt-14 flex max-w-5xl flex-wrap items-center justify-center gap-x-3 gap-y-2 motion-safe:animate-fade-in-up sm:mt-16"
          style={{ animationDelay: '780ms' }}
        >
          {PROOF_CHIPS.map((chip) => (
            <li
              key={chip}
              className="inline-flex items-center rounded-full border border-velvet-border bg-velvet-emerald/[0.08] px-3.5 py-1 text-xs font-medium text-velvet-emerald-mint shadow-[0_0_0_1px_rgba(52,211,153,0.06)_inset] backdrop-blur-sm"
            >
              {chip}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
