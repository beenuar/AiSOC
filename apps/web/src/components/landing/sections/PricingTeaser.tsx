'use client';

/**
 * "Free to self-host. Pay only when we host." — `pricing-teaser`
 * section from §6.13 of the brief.
 *
 * Three-column tier teaser (mobile: stacked). "Team" is the middle
 * card and carries the recommended treatment — a thicker emerald
 * border plus the brighter "Contact us — waitlist" CTA. The page
 * links out to the full pricing page for the bottom of the funnel;
 * this section is the scan-and-skim teaser.
 */

import Link from 'next/link';
import { motion, useReducedMotion } from 'framer-motion';
import { ArrowRight, Check } from 'lucide-react';
import { cn } from '@/lib/utils';
import { CONNECTOR_COUNT } from '@/data/connectorCount';

interface Tier {
  id: 'community' | 'team' | 'enterprise';
  name: string;
  price: string;
  tagline: string;
  includes: ReadonlyArray<string>;
  cta: { label: string; href: string };
  recommended?: boolean;
}

const TIERS: ReadonlyArray<Tier> = [
  {
    id: 'community',
    name: 'Community',
    price: 'Free',
    tagline: 'Self-host the full stack.',
    includes: [
      'MIT-licensed code',
      `All ${CONNECTOR_COUNT} connectors`,
      'Marketplace',
      'Public benchmark harness',
      'Community Discord',
    ],
    cta: { label: 'Clone on GitHub', href: 'https://github.com/beenuar/AiSOC' },
  },
  {
    id: 'team',
    name: 'Team',
    price: 'Waitlist',
    tagline: 'We run it. You log in.',
    includes: [
      'Everything in Community',
      'Managed instance on tryaisoc.com',
      'BYOK LLM',
      'Email support',
      'SOC 2 (in progress)',
    ],
    cta: { label: 'Join the waitlist', href: '/waitlist' },
    recommended: true,
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    price: 'Contact us',
    tagline: 'Sovereign, air-gap, or single-tenant in your VPC.',
    includes: [
      'Everything in Team',
      'Sovereign / air-gap deploy',
      'Named onboarding',
      'Architecture review',
      '24×7 incident channel',
    ],
    cta: { label: 'Talk to us', href: '/contact' },
  },
];

const FULL_PRICING_HREF = '/pricing';

function TierCard({
  tier,
  index,
  reduced,
}: {
  tier: Tier;
  index: number;
  reduced: boolean | null;
}) {
  return (
    <motion.li
      initial={reduced ? false : { opacity: 0, y: 16 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-15%' }}
      transition={{
        duration: 0.55,
        ease: [0.16, 1, 0.3, 1],
        delay: index * 0.08,
      }}
      className={cn(
        'relative flex flex-col gap-6 rounded-md border border-velvet-border bg-velvet-surface-raised p-6 backdrop-blur-sm sm:p-8',
        tier.recommended &&
          'border-2 border-velvet-emerald/60 sm:p-8 motion-safe:shadow-glow-emerald-md',
      )}
    >
      <div className="relative">
        <div className="flex items-center justify-between gap-2">
          <h3 className="font-velvet-display font-normal text-lg text-velvet-content-primary">{tier.name}</h3>
          {tier.recommended && (
            <span className="inline-flex items-center rounded-full bg-velvet-emerald/15 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-velvet-emerald-mint ring-1 ring-inset ring-velvet-emerald/40">
              Most asked for
            </span>
          )}
        </div>
        <p className="mt-3 font-velvet-display text-3xl font-normal tracking-tight text-velvet-content-primary">
          {tier.price}
        </p>
        <p className="mt-2 text-sm leading-relaxed text-velvet-content-secondary">
          {tier.tagline}
        </p>
      </div>
      <ul className="relative space-y-2 text-sm text-velvet-content-secondary">
        {tier.includes.map((line) => (
          <li key={line} className="flex items-start gap-2">
            <Check
              className="mt-0.5 h-4 w-4 flex-none text-velvet-emerald-mint"
              aria-hidden="true"
            />
            <span>{line}</span>
          </li>
        ))}
      </ul>
      <Link
        href={tier.cta.href}
        rel={tier.cta.href.startsWith('http') ? 'noreferrer' : undefined}
        target={tier.cta.href.startsWith('http') ? '_blank' : undefined}
        className={cn(
          'group relative mt-auto inline-flex h-10 items-center justify-center gap-1 rounded-md px-4 text-sm font-semibold transition-[filter,box-shadow,background-color] duration-200 ease-landing-out-quart focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base',
          tier.recommended
            ? 'bg-velvet-emerald-cta text-velvet-content-primary shadow-[0_1px_0_rgba(255,255,255,0.18)_inset] hover:brightness-110 motion-safe:hover:shadow-glow-emerald-sm'
            : 'border border-velvet-sapphire bg-transparent text-velvet-sapphire-soft hover:bg-velvet-sapphire/[0.12] motion-safe:hover:shadow-glow-sapphire-sm',
        )}
      >
        {tier.cta.label}
        <ArrowRight
          className="h-3.5 w-3.5 transition-transform duration-200 group-hover:translate-x-0.5 motion-reduce:transition-none motion-reduce:group-hover:translate-x-0"
          aria-hidden="true"
        />
      </Link>
    </motion.li>
  );
}

export function PricingTeaser() {
  const prefersReducedMotion = useReducedMotion();

  return (
    <section
      id="pricing"
      aria-labelledby="pricing-heading"
      className="relative py-20 sm:py-24 lg:py-28"
    >
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-3xl text-center">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-velvet-emerald-mint">
            Pricing
          </p>
          <h2
            id="pricing-heading"
            className="font-velvet-display font-normal mt-3 text-3xl tracking-tight text-velvet-content-primary sm:text-4xl lg:text-[40px] lg:leading-[1.15] lg:tracking-[-0.015em]"
          >
            Free to self-host. Pay only when we host.
          </h2>
        </div>

        <ul className="mt-12 grid gap-4 sm:gap-6 md:grid-cols-3 lg:mt-16 lg:gap-8">
          {TIERS.map((tier, idx) => (
            <TierCard
              key={tier.id}
              tier={tier}
              index={idx}
              reduced={prefersReducedMotion}
            />
          ))}
        </ul>

        <p className="mt-10 text-center text-sm text-velvet-content-tertiary">
          <Link
            href={FULL_PRICING_HREF}
            className="inline-flex items-center gap-1 text-velvet-emerald-mint transition-colors duration-200 hover:text-velvet-emerald-mint focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base"
          >
            See full pricing
            <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
          </Link>
        </p>
      </div>
    </section>
  );
}
