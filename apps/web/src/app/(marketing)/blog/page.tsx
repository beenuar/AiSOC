import type { Metadata } from 'next';
import Link from 'next/link';
import { formatPostDate, listPosts } from '@/lib/blog';

/**
 * `/blog` index — lists every published post from
 * `apps/web/content/blog/*.mdx`. Drafts are filtered out so editorial can keep
 * unfinished posts in-tree without surfacing them publicly. The detail page
 * (`/blog/[slug]`) still resolves drafts for direct preview.
 *
 * Mirrors the customers index pattern — a single MDX file is the source of
 * truth, and editorial owns the directory.
 */

export const metadata: Metadata = {
  title: 'Engineering blog — AiSOC',
  description:
    'Long-form, technical writing from the team building AiSOC: graph-at-ingest, sub-minute investigation latency, the L0–L4 SOC automation maturity model.',
  alternates: { canonical: '/blog' },
  openGraph: {
    title: 'Engineering blog — AiSOC',
    description:
      'Long-form, opinionated writing on agentic SOC architecture from the AiSOC engineering team.',
    type: 'website',
  },
};

export default function BlogIndexPage() {
  const posts = listPosts(false);
  const hasPosts = posts.length > 0;

  return (
    <main
      data-theme="dark"
      className="relative min-h-screen overflow-x-hidden bg-surface-base text-fg-primary"
    >
      <section className="px-6 pt-32 pb-12">
        <div className="mx-auto max-w-5xl">
          <span className="text-xs font-semibold uppercase tracking-wider text-brand-300">
            Blog
          </span>
          <h1 className="mt-3 text-4xl font-bold tracking-tight text-white md:text-5xl">
            Engineering writing from the AiSOC team.
          </h1>
          <p className="mt-5 max-w-2xl text-lg leading-relaxed text-gray-400">
            Architecture decisions, latency budgets, and opinionated takes on
            where agentic SOC tooling is and where it&apos;s heading. No
            roadmap-as-blog-post; no marketing rewrite of a press release.
          </p>
        </div>
      </section>

      <section className="px-6 pb-24">
        <div className="mx-auto max-w-5xl">
          {hasPosts ? (
            <ul className="grid gap-4 md:grid-cols-2">
              {posts.map((p) => (
                <li key={p.slug}>
                  <Link
                    href={`/blog/${encodeURIComponent(p.slug)}`}
                    className="group flex h-full flex-col rounded-2xl border border-white/10 bg-white/[0.02] p-6 transition hover:border-white/20 hover:bg-white/[0.04]"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      {p.frontmatter.tags.slice(0, 3).map((tag) => (
                        <span
                          key={tag}
                          className="inline-flex items-center rounded-full border border-brand-500/20 bg-brand-500/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-brand-200"
                        >
                          {tag}
                        </span>
                      ))}
                      <span className="text-[11px] uppercase tracking-wider text-gray-500">
                        {formatPostDate(p.frontmatter.date)} ·{' '}
                        {p.reading_minutes} min read
                      </span>
                    </div>
                    <h2 className="mt-4 text-xl font-semibold tracking-tight text-white group-hover:text-brand-200">
                      {p.frontmatter.title}
                    </h2>
                    <p className="mt-3 text-sm leading-relaxed text-gray-400">
                      {p.frontmatter.description}
                    </p>
                    <div className="mt-auto pt-5 text-xs text-gray-500">
                      {p.frontmatter.author}
                    </div>
                    <div className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-gray-400 group-hover:text-white">
                      Read post
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
                </li>
              ))}
            </ul>
          ) : (
            <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-10 text-center">
              <p className="text-sm text-gray-400">
                No published posts yet. Drop an MDX file into{' '}
                <code className="rounded bg-white/5 px-1.5 py-0.5 font-mono text-xs text-gray-200">
                  apps/web/content/blog/
                </code>{' '}
                to publish one.
              </p>
            </div>
          )}

          <div className="mt-12 rounded-2xl border border-brand-500/20 bg-brand-500/[0.04] p-6">
            <h3 className="text-base font-semibold tracking-tight text-white">
              Want to write for the AiSOC blog?
            </h3>
            <p className="mt-2 max-w-2xl text-sm leading-relaxed text-gray-300">
              Send a one-paragraph pitch to{' '}
              <a
                href="mailto:hello@tryaisoc.com"
                className="text-brand-300 underline underline-offset-2 hover:text-brand-200"
              >
                hello@tryaisoc.com
              </a>{' '}
              or open an issue on{' '}
              <a
                href="https://github.com/beenuar/AiSOC/issues"
                target="_blank"
                rel="noreferrer"
                className="text-brand-300 underline underline-offset-2 hover:text-brand-200"
              >
                GitHub
              </a>
              . We&apos;re especially interested in operator perspectives on
              gating autonomous response, agent latency tuning, and graph
              modelling at ingest time.
            </p>
          </div>
        </div>
      </section>

    </main>
  );
}
