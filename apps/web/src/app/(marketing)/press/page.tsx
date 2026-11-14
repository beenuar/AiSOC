import type { Metadata } from 'next';
import Link from 'next/link';

/**
 * `/press` — press / media contact and asset directory.
 *
 * Same structure as /about (short, opinionated, links to the source of
 * truth) but framed for journalists, analysts, and conference organisers.
 * We do not yet ship a downloadable press kit; everything below points
 * either at the public repo or a direct email.
 */

export const metadata: Metadata = {
  title: 'Press — AiSOC',
  description:
    'Press, analyst, and speaking enquiries for AiSOC — the open-source AI Security Operations Center. Direct email and links to the public artefacts you can quote without asking.',
  alternates: { canonical: '/press' },
  openGraph: {
    title: 'AiSOC — press kit',
    description:
      'Direct contact, brand assets, and links to every public artefact you can quote.',
    type: 'article',
  },
};

const QUOTE_LINES = [
  'AiSOC is an MIT-licensed AI Security Operations Center: a self-hostable agent loop, a click-and-connect connector catalogue, and a public benchmark — released under MIT so any team can run, audit, and modify the full stack.',
];

const QUOTABLE_ARTEFACTS: Array<{ label: string; href: string }> = [
  { label: 'README + architecture', href: 'https://github.com/beenuar/AiSOC' },
  {
    label: 'CHANGELOG (release-by-release diffs)',
    href: 'https://github.com/beenuar/AiSOC/blob/main/CHANGELOG.md',
  },
  {
    label: 'ROADMAP',
    href: 'https://github.com/beenuar/AiSOC/blob/main/ROADMAP.md',
  },
  {
    label: 'Public benchmark methodology',
    href: '/benchmark',
  },
  {
    label: 'Security policy',
    href: 'https://github.com/beenuar/AiSOC/blob/main/SECURITY.md',
  },
];

export default function PressPage() {
  return (
    <main
      data-theme="dark"
      className="relative min-h-screen overflow-x-hidden bg-surface-base text-fg-primary"
    >
      <section className="px-6 pt-32 pb-12">
        <div className="mx-auto max-w-3xl">
          <span className="text-xs font-semibold uppercase tracking-wider text-brand-300">
            Press
          </span>
          <h1 className="mt-3 text-4xl font-bold tracking-tight text-white md:text-5xl">
            For media, analysts, and speakers.
          </h1>
          <p className="mt-5 text-base leading-relaxed text-gray-400">
            We do not ship a downloadable press kit — every artefact a
            journalist, analyst, or organiser typically asks for is
            either in the public repo or in this page. If you need a
            quote, a podcast guest, or a conference talk, write to{' '}
            <a
              href="mailto:press@tryaisoc.com"
              className="text-brand-300 underline decoration-brand-500/40 underline-offset-2"
            >
              press@tryaisoc.com
            </a>
            .
          </p>
        </div>
      </section>

      <section className="px-6 pb-10">
        <div className="mx-auto max-w-3xl">
          <h2 className="text-xl font-semibold text-white">
            Pre-cleared standing quote
          </h2>
          <p className="mt-2 text-sm text-gray-500">
            You can use this line without checking back first.
          </p>
          <blockquote className="mt-5 rounded-xl border border-white/10 bg-white/[0.02] p-5 text-base leading-relaxed text-gray-200">
            {QUOTE_LINES.map((line) => (
              <p key={line}>{line}</p>
            ))}
          </blockquote>
        </div>
      </section>

      <section className="px-6 pb-16">
        <div className="mx-auto max-w-3xl">
          <h2 className="text-xl font-semibold text-white">
            Verifiable artefacts
          </h2>
          <p className="mt-2 text-sm text-gray-500">
            Numbers and claims you can quote without asking — each links
            to the source of truth in the repo.
          </p>
          <ul className="mt-5 space-y-2.5">
            {QUOTABLE_ARTEFACTS.map((a) => (
              <li
                key={a.label}
                className="flex items-start gap-3 rounded-lg border border-white/10 bg-white/[0.02] px-4 py-3 text-sm"
              >
                <span aria-hidden="true" className="text-brand-300">
                  →
                </span>
                {a.href.startsWith('http') ? (
                  <a
                    href={a.href}
                    target="_blank"
                    rel="noreferrer"
                    className="text-brand-200 underline decoration-brand-500/40 underline-offset-2 hover:text-brand-100"
                  >
                    {a.label}
                  </a>
                ) : (
                  <Link
                    href={a.href}
                    className="text-brand-200 underline decoration-brand-500/40 underline-offset-2 hover:text-brand-100"
                  >
                    {a.label}
                  </Link>
                )}
              </li>
            ))}
          </ul>
        </div>
      </section>

    </main>
  );
}
