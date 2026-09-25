'use client';

/**
 * Closing call-to-action band.
 *
 * The primary button was "Try managed", in ruby, above a secondary
 * "Self-host on GitHub". That ordering is backwards for this project: the
 * conversion is a clone, not a sign-up, so the repository is now the primary
 * and the quickstart is the alternative.
 */

import Link from 'next/link';
import { motion, useReducedMotion } from 'framer-motion';
import { ArrowRight } from 'lucide-react';
import { BackgroundBeams } from '@/components/aceternity/BackgroundBeams';
import { docs } from '@/lib/docs';
import { GithubMark } from './icons';

export function FinalCta() {
  const prefersReducedMotion = useReducedMotion();

  return (
    <section
      id="cta"
      aria-labelledby="cta-heading"
      className="relative isolate overflow-hidden py-24 sm:py-28 lg:py-32"
    >
      <div className="absolute inset-0 -z-10 bg-velvet-cta-grad opacity-[0.18]" aria-hidden="true" />
      <div className="absolute inset-0 -z-10" aria-hidden="true">
        <BackgroundBeams />
      </div>

      <div className="mx-auto max-w-3xl px-4 text-center sm:px-6 lg:px-8">
        <motion.h2
          id="cta-heading"
          initial={prefersReducedMotion ? false : { opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-15%' }}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
          className="font-velvet-display text-4xl font-normal tracking-tight text-velvet-content-primary sm:text-5xl lg:text-[56px] lg:leading-[1.05] lg:tracking-[-0.02em]"
        >
          Clone it and see for yourself.
        </motion.h2>
        <motion.p
          initial={prefersReducedMotion ? false : { opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-15%' }}
          transition={{ duration: 0.55, ease: [0.16, 1, 0.3, 1], delay: 0.08 }}
          className="mx-auto mt-5 max-w-xl text-base leading-relaxed text-velvet-content-secondary sm:text-lg"
        >
          The connector and detection-rule counts on this page are generated
          from the registry and the compiled ruleset, and a CI gate fails the
          build if they drift. The quickest way to check any of it is to read
          the source.
        </motion.p>
        <motion.div
          initial={prefersReducedMotion ? false : { opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-15%' }}
          transition={{ duration: 0.55, ease: [0.16, 1, 0.3, 1], delay: 0.16 }}
          className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row sm:gap-4"
        >
          <a
            href="https://github.com/beenuar/AiSOC"
            rel="noreferrer"
            target="_blank"
            className="group inline-flex h-11 items-center justify-center gap-2 rounded-md bg-velvet-emerald-cta px-6 text-sm font-semibold text-velvet-content-primary shadow-[0_1px_0_rgba(255,255,255,0.18)_inset] transition-[filter,box-shadow] duration-200 ease-landing-out-quart hover:brightness-110 motion-safe:hover:shadow-glow-emerald-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base"
          >
            <GithubMark className="h-4 w-4" />
            Open the repository
            <ArrowRight
              className="h-3.5 w-3.5 transition-transform duration-200 group-hover:translate-x-0.5 motion-reduce:transition-none motion-reduce:group-hover:translate-x-0"
              aria-hidden="true"
            />
          </a>
          <Link
            href={docs('quickstart')}
            className="inline-flex h-11 items-center justify-center gap-2 rounded-md border border-velvet-sapphire bg-transparent px-6 text-sm font-semibold text-velvet-sapphire-soft backdrop-blur-sm transition-[background-color,box-shadow] duration-200 hover:bg-velvet-sapphire/[0.12] motion-safe:hover:shadow-glow-sapphire-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-sapphire-soft focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base"
          >
            Read the quickstart
          </Link>
        </motion.div>
        <p className="mt-6 text-xs text-velvet-content-tertiary">
          MIT-licensed · No account · No API key
        </p>
      </div>
    </section>
  );
}
