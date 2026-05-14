import type { Metadata } from 'next';
import Link from 'next/link';
import { LandingNav } from '@/components/landing/LandingNav';
import { Footer } from '@/components/landing/Footer';
import { listCustomers } from '@/lib/customers';

/**
 * `/customers` index — lists every published case study from
 * `apps/web/content/customers/*.mdx`. Drafts are filtered out so GTM can keep
 * unfinished studies in-tree without surfacing them publicly. The detail page
 * (`/customers/[slug]`) still resolves drafts for direct preview.
 */

export const metadata: Metadata = {
  title: 'Customers',
  description:
    'Reference customers running AiSOC in production: who they are, the security challenge, and the measurable outcome.',
  alternates: { canonical: '/customers' },
  openGraph: {
    title: 'Customers — AiSOC',
    description:
      'Real-world AiSOC deployments and the before/after metrics each team reports.',
    type: 'website',
  },
};

export default function CustomersIndexPage() {
  const studies = listCustomers(false);
  const hasStudies = studies.length > 0;

  return (
    <main
      data-theme="dark"
      className="relative min-h-screen overflow-x-hidden bg-surface-base text-fg-primary"
    >
      <LandingNav />

      <section className="px-6 pt-32 pb-12">
        <div className="mx-auto max-w-5xl">
          <span className="text-xs font-semibold uppercase tracking-wider text-brand-300">
            Customers
          </span>
          <h1 className="mt-3 text-4xl font-bold tracking-tight text-white md:text-5xl">
            Teams running AiSOC in production.
          </h1>
          <p className="mt-5 max-w-2xl text-lg leading-relaxed text-gray-400">
            Each case study below is a single MDX file in the repo. The
            challenge, the before/after numbers, and the analyst quote are
            taken directly from the customer — no marketing rewrite, no
            unverifiable vendor metrics.
          </p>
        </div>
      </section>

      <section className="px-6 pb-24">
        <div className="mx-auto max-w-5xl">
          {hasStudies ? (
            <div className="grid gap-4 md:grid-cols-2">
              {studies.map((s) => {
                const stats = s.frontmatter.result_numbers ?? [];
                const safeSlug = encodeURIComponent(s.slug);
                return (
                  <Link
                    key={safeSlug}
                    href={`/customers/${safeSlug}`}
                    className="group flex h-full flex-col rounded-2xl border border-white/10 bg-white/[0.02] p-6 transition hover:border-white/20 hover:bg-white/[0.04]"
                  >
                    <div className="flex items-center gap-3">
                      <span className="inline-flex items-center rounded-full border border-brand-500/20 bg-brand-500/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-brand-200">
                        {s.frontmatter.industry}
                      </span>
                      {s.frontmatter.region ? (
                        <span className="text-[11px] uppercase tracking-wider text-gray-500">
                          {s.frontmatter.region}
                        </span>
                      ) : null}
                    </div>
                    <h2 className="mt-4 text-xl font-semibold tracking-tight text-white group-hover:text-brand-200">
                      {s.frontmatter.title}
                    </h2>
                    <p className="mt-3 text-sm leading-relaxed text-gray-400">
                      {s.frontmatter.challenge}
                    </p>
                    {stats.length > 0 ? (
                      <dl className="mt-5 grid grid-cols-3 gap-3 border-t border-white/5 pt-4">
                        {stats.slice(0, 3).map((stat) => (
                          <div key={stat.metric}>
                            <dt className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                              {stat.metric}
                            </dt>
                            <dd className="mt-1 font-mono text-sm text-white">
                              {stat.before}
                              <span className="px-1 text-gray-500">→</span>
                              <span className="text-emerald-300">
                                {stat.after}
                              </span>
                            </dd>
                          </div>
                        ))}
                      </dl>
                    ) : null}
                    <div className="mt-5 inline-flex items-center gap-1 text-xs font-medium text-gray-400 group-hover:text-white">
                      Read the case study
                      <svg
                        viewBox="0 0 20 20"
                        className="h-3 w-3"
                        fill="currentColor"
                        aria-hidden="true"
                      >
                        <path d="M7.05 4.05a1 1 0 011.41 0l5 5a1 1 0 010 1.41l-5 5a1 1 0 11-1.41-1.41L11.09 10 7.05 5.46a1 1 0 010-1.41z" />
                      </svg>
                    </div>
                  </Link>
                );
              })}
            </div>
          ) : (
            <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-10 text-center">
              <p className="text-sm text-gray-400">
                No published customer stories yet. Drop an MDX file into{' '}
                <code className="rounded bg-white/5 px-1.5 py-0.5 font-mono text-xs text-gray-200">
                  apps/web/content/customers/
                </code>{' '}
                to publish one.
              </p>
            </div>
          )}

          <div className="mt-12 rounded-2xl border border-brand-500/20 bg-brand-500/[0.04] p-6">
            <h3 className="text-base font-semibold tracking-tight text-white">
              Running AiSOC in production?
            </h3>
            <p className="mt-2 max-w-2xl text-sm leading-relaxed text-gray-300">
              We&apos;d love to publish your numbers. Open an issue on{' '}
              <a
                href="https://github.com/beenuar/AiSOC/issues"
                target="_blank"
                rel="noreferrer"
                className="text-brand-300 underline underline-offset-2 hover:text-brand-200"
              >
                GitHub
              </a>{' '}
              or reach out to{' '}
              <a
                href="mailto:hello@aisoc.dev"
                className="text-brand-300 underline underline-offset-2 hover:text-brand-200"
              >
                hello@aisoc.dev
              </a>
              .
            </p>
          </div>
        </div>
      </section>

      <Footer />
    </main>
  );
}
