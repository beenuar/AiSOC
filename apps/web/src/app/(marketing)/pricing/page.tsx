import type { Metadata } from 'next';
import Link from 'next/link';
import { Check } from 'lucide-react';
import { LandingNav } from '@/components/landing/LandingNav';
import { Footer } from '@/components/landing/Footer';
import { CONNECTOR_COUNT } from '@/data/connectorCount';

/**
 * `/pricing` — full pricing page (the teaser on the homepage links here).
 *
 * Three tiers + a sovereign / air-gap row, with a FAQ at the bottom for
 * the procurement-side questions that come up before any technical
 * evaluation (data residency, SLA shape, audit posture, payment cadence).
 *
 * Numbers we cite that depend on the catalogue (connector count) are
 * imported from the same single source of truth Phase 1.1 added, so the
 * pricing page can never drift from the engineering reality.
 */

export const metadata: Metadata = {
  title: 'Pricing — AiSOC',
  description: `Three tiers — Community (free, self-host the full ${CONNECTOR_COUNT}-connector stack), Team (managed waitlist), and Enterprise (sovereign + air-gap + 24×7). MIT-licensed, no enterprise binary, no closed components.`,
  alternates: { canonical: '/pricing' },
  openGraph: {
    title: 'AiSOC pricing — free to self-host, pay only when we host',
    description:
      'Community / Team / Enterprise tiers with the procurement-side answers (residency, SLA, audit posture) up front.',
    type: 'article',
  },
};

interface Tier {
  id: 'community' | 'team' | 'enterprise' | 'sovereign';
  name: string;
  price: string;
  cadence?: string;
  tagline: string;
  recommended?: boolean;
  includes: ReadonlyArray<string>;
  excludes?: ReadonlyArray<string>;
  cta: { label: string; href: string };
}

const TIERS: ReadonlyArray<Tier> = [
  {
    id: 'community',
    name: 'Community',
    price: 'Free',
    tagline: 'Self-host the full stack. MIT licence, no asterisks.',
    includes: [
      `All ${CONNECTOR_COUNT} first-party connectors`,
      'All native detection rules + imported tiers',
      'Full marketplace (detections, playbooks, plugins)',
      'Public 200-incident benchmark harness',
      'L0–L4 automation maturity ladder',
      'Air-gap deploy on a single env flag',
      'Helm chart + Terraform modules (AWS, GCP, Azure, BYOC)',
      'Community support on GitHub Issues + Discord',
    ],
    excludes: [
      'No managed hosting',
      'No paid support SLA',
      'No private CVE pre-disclosure',
    ],
    cta: {
      label: 'Clone on GitHub',
      href: 'https://github.com/beenuar/AiSOC',
    },
  },
  {
    id: 'team',
    name: 'Team',
    price: 'Waitlist',
    cadence: 'monthly · seats',
    tagline: 'We host it. You log in. Same MIT stack, none of the ops.',
    recommended: true,
    includes: [
      'Everything in Community',
      'Managed instance on tryaisoc.com',
      'BYOK LLM (you supply the provider key)',
      'EU / US / India data residency',
      'Daily encrypted backups, 7-day point-in-time restore',
      'Email support (business-hours, 1-business-day SLA)',
      'SOC 2 (in progress) · GDPR (target)',
    ],
    cta: { label: 'Join the waitlist', href: '/waitlist' },
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    price: 'Contact us',
    cadence: 'annual',
    tagline: 'Sovereign, air-gap, or single-tenant in your VPC.',
    includes: [
      'Everything in Team',
      'Sovereign deploy in your VPC (AWS · GCP · Azure · BYOC)',
      'Air-gap overlay with local Ollama sidecar',
      'Custom data-residency region',
      'Named onboarding engineer',
      'Architecture review + tabletop exercise',
      '24×7 incident channel',
      'Private CVE pre-disclosure for the components you depend on',
    ],
    cta: {
      label: 'Talk to us',
      href: 'mailto:hello@tryaisoc.com?subject=AiSOC%20enterprise%20enquiry',
    },
  },
];

const FAQS: Array<{ q: string; a: string }> = [
  {
    q: 'Is the open-source tier really feature-complete?',
    a: 'Yes — every detection rule, connector, agent, playbook, and infrastructure module ships under MIT. The managed tier exists to absorb the ops burden (keys, backups, upgrades, on-call). There is no private fork that lags behind the public one.',
  },
  {
    q: 'What does "BYOK LLM" mean?',
    a: 'You supply the API key for OpenAI, Anthropic, Azure OpenAI, Bedrock, or a private LiteLLM gateway, and we point your tenant at it. Your prompts go directly to your provider — we are not in that traffic path, and your provider\'s data-handling policy applies.',
  },
  {
    q: 'Can you host AiSOC in a sovereign-cloud region (e.g. AWS GovCloud, Azure Germany)?',
    a: 'Yes — the Enterprise tier covers this. We use the same Terraform modules the open-source distribution ships, pointed at the region you require. Compliance posture is what your auditor signs off on (we surface the controls; we are not yet the audited entity).',
  },
  {
    q: 'How is the Team tier billed?',
    a: 'Per-seat monthly, billed in advance. We open seats in waves so the waitlist tells you where you are. There is no enterprise binary you have to upgrade into — Team and Enterprise both run the same MIT source tree.',
  },
];

function TierCard({ tier }: { tier: Tier }) {
  return (
    <li
      className={`relative flex flex-col gap-6 rounded-2xl border bg-white/[0.02] p-6 sm:p-7 ${
        tier.recommended
          ? 'border-emerald-500/60 ring-1 ring-emerald-500/30'
          : 'border-white/10'
      }`}
    >
      <div>
        <div className="flex items-center justify-between gap-2">
          <h3 className="text-lg font-semibold text-white">{tier.name}</h3>
          {tier.recommended && (
            <span className="inline-flex items-center rounded-full bg-emerald-500/15 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-emerald-300 ring-1 ring-inset ring-emerald-500/30">
              Most asked for
            </span>
          )}
        </div>
        <p className="mt-3 text-3xl font-bold tracking-tight text-white">
          {tier.price}
        </p>
        {tier.cadence && (
          <p className="mt-0.5 text-xs uppercase tracking-wider text-gray-500">
            {tier.cadence}
          </p>
        )}
        <p className="mt-3 text-sm leading-relaxed text-gray-300">
          {tier.tagline}
        </p>
      </div>

      <ul className="space-y-2 text-sm text-gray-300">
        {tier.includes.map((line) => (
          <li key={line} className="flex items-start gap-2">
            <Check
              className="mt-0.5 h-4 w-4 flex-none text-emerald-400"
              aria-hidden="true"
            />
            <span>{line}</span>
          </li>
        ))}
      </ul>

      {tier.excludes && (
        <ul className="space-y-2 text-sm text-gray-500">
          {tier.excludes.map((line) => (
            <li key={line} className="flex items-start gap-2">
              <span aria-hidden="true" className="mt-0.5 inline-block w-4">
                ·
              </span>
              <span>{line}</span>
            </li>
          ))}
        </ul>
      )}

      <Link
        href={tier.cta.href}
        rel={tier.cta.href.startsWith('http') ? 'noreferrer' : undefined}
        target={tier.cta.href.startsWith('http') ? '_blank' : undefined}
        className={`mt-auto inline-flex h-10 items-center justify-center gap-1 rounded-md px-4 text-sm font-semibold transition ${
          tier.recommended
            ? 'bg-emerald-500 text-white hover:bg-emerald-400'
            : 'border border-white/15 bg-white/[0.04] text-gray-100 hover:border-white/30 hover:bg-white/[0.08]'
        }`}
      >
        {tier.cta.label}
      </Link>
    </li>
  );
}

export default function PricingPage() {
  return (
    <main
      data-theme="dark"
      className="relative min-h-screen overflow-x-hidden bg-surface-base text-fg-primary"
    >
      <LandingNav />

      <section className="px-6 pt-32 pb-12">
        <div className="mx-auto max-w-4xl">
          <span className="text-xs font-semibold uppercase tracking-wider text-brand-300">
            Pricing
          </span>
          <h1 className="mt-3 text-4xl font-bold tracking-tight text-white md:text-5xl">
            Free to self-host. Pay only when we host.
          </h1>
          <p className="mt-5 max-w-2xl text-base leading-relaxed text-gray-400">
            Three tiers run the same MIT source tree — the price tag pays
            for the ops burden (keys, backups, upgrades, on-call), not
            for unlocked features. The full {CONNECTOR_COUNT}-connector
            catalogue, every detection rule, and every playbook ship in
            the Community tier.
          </p>
        </div>
      </section>

      <section className="px-6 pb-16">
        <div className="mx-auto max-w-6xl">
          <ul className="grid gap-5 sm:gap-6 md:grid-cols-3 lg:gap-8">
            {TIERS.map((tier) => (
              <TierCard key={tier.id} tier={tier} />
            ))}
          </ul>
        </div>
      </section>

      <section className="px-6 pb-16">
        <div className="mx-auto max-w-3xl">
          <h2 className="text-xl font-semibold text-white">
            Procurement FAQ
          </h2>
          <dl className="mt-6 space-y-6">
            {FAQS.map((qa) => (
              <div key={qa.q}>
                <dt className="text-base font-medium text-white">{qa.q}</dt>
                <dd className="mt-2 text-sm leading-relaxed text-gray-400">
                  {qa.a}
                </dd>
              </div>
            ))}
          </dl>
        </div>
      </section>

      <Footer />
    </main>
  );
}
