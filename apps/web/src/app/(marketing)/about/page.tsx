import type { Metadata } from 'next';
import Link from 'next/link';
import { CONNECTOR_COUNT } from '@/data/connectorCount';
// Site-wide nav + footer are rendered by `(marketing)/layout.tsx` so this
// page is content-only. See ISSUE-006 shell unification (2026-06-29).

/**
 * `/about` — short, opinionated company page.
 *
 * Buyers in regulated procurement need three pieces of information before
 * they can route an open-source project past their committee: who builds
 * it, what licence governs it, and how to verify both. The page is
 * intentionally short and links straight to the source of truth (GitHub,
 * LICENSE, SECURITY.md, MAINTAINERS.md) rather than reiterating it.
 */

export const metadata: Metadata = {
  title: 'About — AiSOC',
  description:
    'AiSOC is an MIT-licensed open-source AI Security Operations Center maintained by an independent community. Self-host the full stack or sign up for the managed waitlist at tryaisoc.com.',
  alternates: { canonical: '/about' },
  openGraph: {
    title: 'About AiSOC — open-source AI SOC',
    description:
      'Independent, MIT-licensed, community-maintained. No private fork, no enterprise binary, no closed components.',
    type: 'article',
  },
};

const FACTS: Array<{ label: string; value: string; href?: string }> = [
  { label: 'Licence', value: 'MIT', href: 'https://github.com/beenuar/AiSOC/blob/main/LICENSE' },
  {
    label: 'Source',
    value: 'github.com/beenuar/AiSOC',
    href: 'https://github.com/beenuar/AiSOC',
  },
  {
    label: 'Maintainers',
    value: 'AiSOC contributors',
    href: 'https://github.com/beenuar/AiSOC/graphs/contributors',
  },
  {
    label: 'Security disclosures',
    value: 'security@tryaisoc.com',
    href: 'https://github.com/beenuar/AiSOC/blob/main/SECURITY.md',
  },
  {
    label: 'Connector catalog',
    value: `${CONNECTOR_COUNT} first-party connectors`,
    href: 'https://github.com/beenuar/AiSOC/blob/main/services/connectors/app/connectors/__init__.py',
  },
];

export default function AboutPage() {
  return (
    <main
      data-theme="dark"
      className="relative overflow-x-hidden bg-surface-base text-fg-primary"
    >
      <section className="px-6 pt-32 pb-16">
        <div className="mx-auto max-w-3xl">
          <span className="text-xs font-semibold uppercase tracking-wider text-brand-300">
            About
          </span>
          <h1 className="mt-3 text-4xl font-bold tracking-tight text-white md:text-5xl">
            AiSOC is what a SOC looks like when the agent is the
            product.
          </h1>
          <p className="mt-6 text-lg leading-relaxed text-gray-400">
            We build an open-source AI Security Operations Center. The
            agent loop, the {CONNECTOR_COUNT}
            {/* Explicit space token: when a JSX text node wraps to a new
                line immediately after an expression like {CONNECTOR_COUNT},
                React's text-children whitespace rules silently drop the
                leading space of the next text segment, producing
                "the 69connectors" in SSR output. Forcing {' '} keeps the
                space whether or not we reflow the paragraph later. */}{' '}
            connectors, the detection rules, the benchmark dataset, the
            marketplace, and every piece of infrastructure code are
            released under the MIT licence — there is no closed-source
            &ldquo;Enterprise edition&rdquo; that the community version
            lags behind.
          </p>
          <p className="mt-5 text-base leading-relaxed text-gray-400">
            What we sell is the managed tier: someone else runs the
            cluster, rotates the keys, watches the metrics, and
            absorbs the support pager. The waitlist for that lives at{' '}
            <Link
              href="/waitlist"
              className="text-brand-300 underline decoration-brand-500/40 underline-offset-2"
            >
              tryaisoc.com/waitlist
            </Link>
            . Sovereign and air-gapped deployments are quoted
            individually —{' '}
            <a
              href="mailto:hello@tryaisoc.com?subject=AiSOC%20sovereign%20deployment"
              className="text-brand-300 underline decoration-brand-500/40 underline-offset-2"
            >
              hello@tryaisoc.com
            </a>
            .
          </p>
        </div>
      </section>

      <section className="px-6 pb-16">
        <div className="mx-auto max-w-3xl">
          <h2 className="text-xl font-semibold text-white">
            Facts you can verify
          </h2>
          <p className="mt-2 text-sm text-gray-500">
            Every row links to the source of truth in the repo.
          </p>
          <dl className="mt-6 grid gap-3 sm:grid-cols-2">
            {FACTS.map((fact) => (
              <div
                key={fact.label}
                className="rounded-xl border border-white/10 bg-white/[0.02] p-4"
              >
                <dt className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">
                  {fact.label}
                </dt>
                <dd className="mt-1.5 text-sm text-gray-200">
                  {fact.href ? (
                    <a
                      href={fact.href}
                      target="_blank"
                      rel="noreferrer"
                      className="text-brand-200 underline decoration-brand-500/40 underline-offset-2 hover:text-brand-100"
                    >
                      {fact.value}
                    </a>
                  ) : (
                    fact.value
                  )}
                </dd>
              </div>
            ))}
          </dl>
        </div>
      </section>

    </main>
  );
}
