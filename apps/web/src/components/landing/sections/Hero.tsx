'use client';

/**
 * Hero section for the landing page.
 *
 * Rewritten from a centred, four-word, per-word-animated headline over a
 * "Open the live dashboard" call to action that pointed at the maintainers'
 * hosted host. Three things were wrong with that. The conversion this project
 * wants is a clone, not a sign-up, so the primary button now goes to the
 * repository. A self-hoster reading the open-source landing page should not
 * meet another deployment's hostname as the product's front door. And the
 * fold carried no picture of the product at all — the only "screenshot"
 * anywhere on the site was an invented one two sections down.
 *
 * The composition is left-aligned and asymmetric: argument in the left
 * column, a real capture of the console in the right, the two commands that
 * produce it underneath. The background keeps the SVG grid and the single
 * corner spotlight; both are static filter/mask work with no JS, so the LCP
 * element stays the H1 string.
 *
 * Every count on this surface is imported from the generated artefacts
 * (`connectorCount.ts`, `corpusStats.ts`). The landing page has published
 * three different wrong corpus figures by hand-typing them.
 */

import Image from 'next/image';
import Link from 'next/link';
import { ArrowRight } from 'lucide-react';
import { GithubMark } from './icons';
import { Spotlight } from '@/components/aceternity/Spotlight';
import { AnimatedGridPattern } from '@/components/magicui/AnimatedGridPattern';
import { docs } from '@/lib/docs';
import { CONNECTOR_COUNT } from '@/data/connectorCount';
import { EXECUTABLE_DETECTION_COUNT } from '@/data/corpusStats';

const REPO_URL = 'https://github.com/beenuar/AiSOC';

/**
 * Core-profile service count. Sourced from the deployment-profile table in
 * `apps/docs/docs/architecture.md`, which counts long-running containers and
 * excludes the one-shot model pull that exits after fetching the weights.
 */
const CORE_SERVICE_COUNT = 14;

const FACTS: ReadonlyArray<string> = [
  `${CONNECTOR_COUNT} connectors`,
  `${EXECUTABLE_DETECTION_COUNT.toLocaleString()} executable detection rules`,
  'Replayable decision ledger',
  'MIT licence, no private fork',
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
        className="-z-10 [mask-image:radial-gradient(ellipse_at_top_left,white,transparent_65%)]"
        numSquares={42}
        maxOpacity={0.07}
        duration={3.6}
        repeatDelay={1.2}
      />
      <Spotlight
        className="-top-40 left-0 md:-top-20 md:left-40"
        fill="rgba(52,211,153,0.4)"
      />

      <div className="mx-auto max-w-7xl px-4 pb-20 sm:px-6 lg:px-8 lg:pb-28">
        <div className="grid items-start gap-12 lg:grid-cols-[minmax(0,0.92fr)_minmax(0,1.08fr)] lg:items-center lg:gap-14 xl:gap-20">
          <div className="max-w-xl">
            <p
              className="inline-flex items-center gap-2 rounded-full border border-velvet-border bg-velvet-surface-raised/60 px-3 py-1 text-xs font-medium text-velvet-content-tertiary backdrop-blur-sm motion-safe:animate-fade-in-up"
              style={{ animationDelay: '60ms' }}
            >
              <span
                aria-hidden="true"
                className="inline-block h-1.5 w-1.5 rounded-full bg-velvet-emerald-mint motion-safe:shadow-[0_0_0_2px_rgba(52,211,153,0.25),0_0_8px_rgba(52,211,153,0.45)]"
              />
              Open source
              <span aria-hidden="true">·</span> MIT
              <span aria-hidden="true">·</span> self-hosted
            </p>

            <h1
              id="hero-heading"
              className="font-velvet-display mt-6 text-4xl font-normal leading-[1.08] tracking-tight text-velvet-content-primary sm:text-5xl lg:text-[58px] lg:leading-[1.04] lg:tracking-[-0.022em]"
            >
              An AI SOC that runs with no API keys, and shows its work.
            </h1>

            <p
              className="mt-6 text-base leading-relaxed text-velvet-content-secondary sm:text-lg sm:leading-[1.65] motion-safe:animate-fade-in-up"
              style={{ animationDelay: '220ms' }}
            >
              One command brings up {CORE_SERVICE_COUNT} services: ingest,
              detection, correlation, the analyst console, a model gateway with
              a local model behind it, and a live feed of known exploited
              vulnerabilities. No credentials of any kind. Alerts get triaged
              for real, and every prompt, tool call and verdict is written to a
              ledger you can replay.
            </p>

            <div
              className="mt-8 flex flex-col gap-3 motion-safe:animate-fade-in-up sm:flex-row sm:items-center sm:gap-4"
              style={{ animationDelay: '340ms' }}
            >
              <a
                href={REPO_URL}
                target="_blank"
                rel="noreferrer"
                className="group inline-flex h-11 w-full items-center justify-center gap-2 rounded-md bg-velvet-emerald-cta px-6 text-sm font-semibold text-velvet-content-primary shadow-[0_1px_0_rgba(255,255,255,0.18)_inset] transition-[filter,box-shadow,transform] duration-200 ease-landing-out-quart hover:brightness-110 motion-safe:hover:shadow-glow-emerald-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base sm:w-auto"
              >
                <GithubMark className="h-4 w-4" />
                Read the source on GitHub
                <ArrowRight
                  className="h-4 w-4 transition-transform duration-200 ease-landing-out-quart group-hover:translate-x-0.5 motion-reduce:transition-none motion-reduce:group-hover:translate-x-0"
                  aria-hidden="true"
                />
              </a>
              <Link
                href={docs('quickstart')}
                className="inline-flex h-11 w-full items-center justify-center gap-2 rounded-md border border-velvet-sapphire bg-transparent px-6 text-sm font-semibold text-velvet-sapphire-soft backdrop-blur-sm transition-[background-color,box-shadow] duration-200 ease-landing-out-quart hover:bg-velvet-sapphire/[0.12] motion-safe:hover:shadow-glow-sapphire-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-sapphire-soft focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base sm:w-auto"
              >
                Read the quickstart
              </Link>
            </div>

            <div
              className="mt-8 overflow-hidden rounded-lg border border-velvet-border bg-velvet-surface-raised/50 motion-safe:animate-fade-in-up"
              style={{ animationDelay: '460ms' }}
            >
              <pre className="overflow-x-auto px-4 py-3.5 text-xs leading-relaxed">
                <code className="block whitespace-pre font-mono">
                  <span className="select-none text-velvet-content-tertiary">$ </span>
                  <span className="text-velvet-emerald-mint">git clone</span>{' '}
                  <span className="text-velvet-content-primary">
                    https://github.com/beenuar/AiSOC
                  </span>
                  {'\n'}
                  <span className="select-none text-velvet-content-tertiary">$ </span>
                  <span className="text-velvet-emerald-mint">cd</span>{' '}
                  <span className="text-velvet-content-primary">AiSOC && make up</span>
                </code>
              </pre>
              <p className="border-t border-velvet-border/70 px-4 py-2.5 text-[11.5px] leading-relaxed text-velvet-content-tertiary">
                Generates its own secrets, creates an administrator and prints
                the password once. Then{' '}
                <code className="font-mono text-velvet-content-secondary">make smoke</code>{' '}
                pushes one real event through the spine and reports PASS or FAIL
                at each stage.
              </p>
            </div>

            <ul
              className="mt-8 flex flex-wrap items-center gap-x-2 gap-y-2 motion-safe:animate-fade-in-up"
              style={{ animationDelay: '560ms' }}
            >
              {FACTS.map((fact) => (
                <li
                  key={fact}
                  className="inline-flex items-center rounded-full border border-velvet-border bg-velvet-emerald/[0.07] px-3 py-1 text-xs font-medium text-velvet-emerald-mint"
                >
                  {fact}
                </li>
              ))}
            </ul>
          </div>

          <figure
            className="motion-safe:animate-fade-in-up lg:pt-4"
            style={{ animationDelay: '300ms' }}
          >
            <div className="overflow-hidden rounded-xl border border-velvet-border bg-velvet-surface-raised/70 shadow-[0_36px_90px_-36px_rgba(15,23,42,0.9)]">
              <div className="flex items-center gap-2.5 border-b border-velvet-border/80 px-3 py-2">
                <span className="flex gap-1.5" aria-hidden="true">
                  <span className="h-2 w-2 rounded-full bg-velvet-content-tertiary/40" />
                  <span className="h-2 w-2 rounded-full bg-velvet-content-tertiary/40" />
                  <span className="h-2 w-2 rounded-full bg-velvet-content-tertiary/40" />
                </span>
                <span className="font-mono text-[10.5px] text-velvet-content-tertiary">
                  localhost:3000/dashboard
                </span>
              </div>
              <Image
                src="/screenshots/dashboard.png"
                alt="The AiSOC dashboard on a live core stack: an operations funnel over real counts, pipeline health per stage, and a mean time to resolve that reads not measured because no case has been closed."
                width={1440}
                height={900}
                priority
                sizes="(min-width: 1024px) 55vw, 100vw"
                className="h-auto w-full"
              />
            </div>
            <figcaption className="mt-4 max-w-lg text-xs leading-relaxed text-velvet-content-tertiary">
              A real capture, not a mockup. Mean time to resolve reads{' '}
              <span className="text-velvet-content-secondary">
                not measured · no cases closed
              </span>{' '}
              rather than a confident zero, which is the habit this whole
              project is organised around.
            </figcaption>
          </figure>
        </div>
      </div>
    </section>
  );
}
