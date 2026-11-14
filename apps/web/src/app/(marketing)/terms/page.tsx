import type { Metadata } from 'next';

/**
 * `/terms` — terms of service.
 *
 * The MIT licence already covers the open-source distribution; this page
 * adds the additional terms that govern the marketing site, the managed
 * waitlist, and (when it ships) the managed tier itself. Same
 * last-updated convention as /privacy.
 */

export const metadata: Metadata = {
  title: 'Terms — AiSOC',
  description:
    'Terms of service for AiSOC: MIT licence governs the open-source distribution; additional terms cover the marketing site, the managed waitlist, and the (waitlisted) managed tier.',
  alternates: { canonical: '/terms' },
  openGraph: {
    title: 'AiSOC terms of service',
    description:
      'MIT-licensed distribution + waitlist + managed-tier terms, plain English, in one page.',
    type: 'article',
  },
};

const LAST_UPDATED = '2026-06-28';

const SECTIONS: Array<{ heading: string; body: string[] }> = [
  {
    heading: 'Open-source distribution',
    body: [
      'The AiSOC source tree is released under the MIT licence — the canonical version lives at github.com/beenuar/AiSOC/blob/main/LICENSE. The licence text is the binding instrument. These terms do not modify, restrict, or replace it.',
    ],
  },
  {
    heading: 'Marketing site (tryaisoc.com)',
    body: [
      'The marketing site is provided as-is for informational purposes. Numbers we cite (connector count, detection count, benchmark scores) are auto-generated from the repo by the same scripts that gate CI, so they reflect the on-disk state of the main branch at build time. We make no warranty that this represents your fork or your deployment.',
      'Do not attempt to circumvent the published rate-limits, abuse the contact endpoints, or use the marketing site to host third-party content. If you find a vulnerability, report it via SECURITY.md rather than exercising it in the wild.',
    ],
  },
  {
    heading: 'Managed waitlist',
    body: [
      'Joining the managed waitlist does not constitute a binding offer of service. We open managed-tier seats in waves and contact waitlist members in the order they signed up, modulo regional capacity. You can withdraw at any time by emailing privacy@tryaisoc.com.',
    ],
  },
  {
    heading: 'Managed tier (when live)',
    body: [
      'When the managed tier ships, this section will include the service-level objectives, the data-processing addendum, the regional residency commitments, the export / deletion SLA, and the suspension policy. Until then there is no managed customer relationship in effect.',
    ],
  },
  {
    heading: 'No warranty for the open-source distribution',
    body: [
      'The MIT licence already disclaims warranties; we restate the headline here for the operator who skims: the open-source distribution is provided WITHOUT WARRANTY OF ANY KIND, including fitness for a particular purpose, merchantability, and non-infringement. Run it through your own risk-management process before pointing it at a regulated workload.',
    ],
  },
  {
    heading: 'Disputes',
    body: [
      'Disputes about the open-source distribution: governed by the MIT licence text. Disputes about the marketing site and the managed waitlist: governed by Singapore law; contact legal@tryaisoc.com first, before any formal action.',
    ],
  },
];

export default function TermsPage() {
  return (
    <main
      data-theme="dark"
      className="relative min-h-screen overflow-x-hidden bg-surface-base text-fg-primary"
    >
      <section className="px-6 pt-32 pb-16">
        <div className="mx-auto max-w-3xl">
          <span className="text-xs font-semibold uppercase tracking-wider text-brand-300">
            Terms of service
          </span>
          <h1 className="mt-3 text-4xl font-bold tracking-tight text-white md:text-5xl">
            MIT plus the small print for the parts that aren&apos;t MIT.
          </h1>
          <p className="mt-3 text-xs text-gray-500">Last updated: {LAST_UPDATED}</p>

          <div className="mt-10 space-y-10">
            {SECTIONS.map((section) => (
              <section key={section.heading}>
                <h2 className="text-xl font-semibold text-white">
                  {section.heading}
                </h2>
                <div className="mt-3 space-y-3 text-sm leading-relaxed text-gray-300">
                  {section.body.map((para, idx) => (
                    <p key={idx}>{para}</p>
                  ))}
                </div>
              </section>
            ))}
          </div>
        </div>
      </section>

    </main>
  );
}
