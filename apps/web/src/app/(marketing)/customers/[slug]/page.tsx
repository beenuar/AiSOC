import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { MDXRemote } from 'next-mdx-remote/rsc';
import { mdxBodyComponents } from '@/components/marketing/MdxBody';
import {
  getCustomerBySlug,
  listCustomerSlugs,
  type CustomerStudy,
} from '@/lib/customers';

/**
 * `/customers/[slug]` — reference-customer detail page (T6.2).
 *
 * MDX file is the source of truth: hero (logo + industry + challenge), the
 * before/after stat band, the pull-quote, the long-form body, and any deep
 * links into the docs all flow from a single file in
 * `apps/web/content/customers/`. GTM ships a new case study by adding one
 * MDX file — no engineering involvement required.
 *
 * The page is statically generated for every slug on disk via
 * `generateStaticParams()` so case studies don't depend on the runtime
 * filesystem in production.
 */

type Params = { slug: string };

export async function generateStaticParams(): Promise<Params[]> {
  return listCustomerSlugs().map((slug) => ({ slug }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<Params>;
}): Promise<Metadata> {
  const { slug } = await params;
  const study = getCustomerBySlug(slug);
  if (!study) {
    return { title: 'Customer not found — AiSOC' };
  }
  const fm = study.frontmatter;
  return {
    title: `${fm.title} — AiSOC customer story`,
    description: fm.challenge,
    alternates: { canonical: `/customers/${slug}` },
    openGraph: {
      title: `${fm.title} — AiSOC customer story`,
      description: fm.challenge,
      type: 'article',
      images: fm.logo ? [{ url: fm.logo }] : undefined,
    },
  };
}

export default async function CustomerStoryPage({
  params,
}: {
  params: Promise<Params>;
}) {
  const { slug } = await params;
  const study = getCustomerBySlug(slug);
  if (!study) {
    notFound();
  }

  return (
    <main
      data-theme="dark"
      className="relative min-h-screen overflow-x-hidden bg-surface-base text-fg-primary"
    >
      <CustomerHero study={study} />
      <StatBand stats={study.frontmatter.result_numbers ?? []} />
      <PullQuote study={study} />
      <CustomerBody body={study.body} />
      <RelatedFeatures study={study} />
    </main>
  );
}

function CustomerHero({ study }: { study: CustomerStudy }) {
  const fm = study.frontmatter;
  return (
    <section className="px-6 pt-32 pb-12">
      <div className="mx-auto max-w-4xl">
        <Link
          href="/customers"
          className="inline-flex items-center gap-1 text-xs font-medium text-gray-400 transition hover:text-white"
        >
          <svg
            viewBox="0 0 20 20"
            className="h-3 w-3"
            fill="currentColor"
            aria-hidden="true"
          >
            <path d="M12.95 4.05a1 1 0 010 1.41L8.41 10l4.54 4.54a1 1 0 01-1.41 1.41l-5.25-5.25a1 1 0 010-1.41l5.25-5.25a1 1 0 011.41 0z" />
          </svg>
          All customers
        </Link>

        {fm.draft ? (
          <div className="mt-6 rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-xs text-amber-200">
            <strong className="font-semibold">Draft preview.</strong> This case
            study is marked <code className="font-mono">draft: true</code> in
            its frontmatter — it will not appear on the public{' '}
            <code className="font-mono">/customers</code> index until that flag
            is removed.
          </div>
        ) : null}

        <div className="mt-6 flex flex-wrap items-center gap-3">
          <span className="inline-flex items-center rounded-full border border-brand-500/20 bg-brand-500/10 px-3 py-1 text-xs font-semibold uppercase tracking-wider text-brand-200">
            {fm.industry}
          </span>
          {fm.region ? (
            <span className="text-xs uppercase tracking-wider text-gray-500">
              {fm.region}
            </span>
          ) : null}
        </div>

        <div className="mt-6 grid items-center gap-8 md:grid-cols-[1fr_auto]">
          <div>
            <h1 className="text-4xl font-bold tracking-tight text-white md:text-5xl">
              {fm.title}
            </h1>
            <p className="mt-5 text-lg leading-relaxed text-gray-300">
              {fm.challenge}
            </p>
          </div>
          {fm.logo ? (
            <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
              {/*
                Logos ship from /public/customers/<slug>/logo.svg. We use a
                native <img> rather than next/image so SVGs with custom
                viewBoxes render at their declared aspect ratio without us
                having to commit width/height into every customer file.
              */}
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={fm.logo}
                alt={`${fm.title} logo`}
                className="h-16 w-auto max-w-[260px] object-contain"
              />
            </div>
          ) : null}
        </div>
      </div>
    </section>
  );
}

function StatBand({
  stats,
}: {
  stats: CustomerStudy['frontmatter']['result_numbers'];
}) {
  if (!stats || stats.length === 0) return null;
  return (
    <section className="px-6 pb-16">
      <div className="mx-auto max-w-4xl">
        <div className="grid gap-px overflow-hidden rounded-2xl border border-white/10 bg-white/10 sm:grid-cols-2 lg:grid-cols-4">
          {stats.map((stat) => (
            <div
              key={stat.metric}
              className="bg-surface-base px-6 py-5"
            >
              <div className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                {stat.metric}
              </div>
              <div className="mt-3 flex items-baseline gap-2">
                <span className="font-mono text-base text-gray-400 line-through decoration-gray-600">
                  {stat.before}
                </span>
                <svg
                  viewBox="0 0 20 20"
                  className="h-3 w-3 text-gray-500"
                  fill="currentColor"
                  aria-hidden="true"
                >
                  <path d="M7.05 4.05a1 1 0 011.41 0l5 5a1 1 0 010 1.41l-5 5a1 1 0 11-1.41-1.41L11.09 10 7.05 5.46a1 1 0 010-1.41z" />
                </svg>
              </div>
              <div className="mt-1 font-mono text-2xl font-semibold text-emerald-300">
                {stat.after}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function PullQuote({ study }: { study: CustomerStudy }) {
  const fm = study.frontmatter;
  if (!fm.quote) return null;
  return (
    <section className="px-6 pb-16">
      <div className="mx-auto max-w-4xl rounded-2xl border border-brand-500/20 bg-brand-500/[0.04] p-8 md:p-10">
        <svg
          viewBox="0 0 24 24"
          className="h-6 w-6 text-brand-300"
          fill="currentColor"
          aria-hidden="true"
        >
          <path d="M9.6 14.4c0-2 .8-3.7 2.4-5.1l1.6 1.6c-1.1 1-1.7 2.1-1.7 3.5h2.1V18H8.7v-3.6h.9zm9.6 0c0-2 .8-3.7 2.4-5.1l1.6 1.6c-1.1 1-1.7 2.1-1.7 3.5h2.1V18h-5.3v-3.6h.9z" />
        </svg>
        <blockquote className="mt-4 text-xl font-medium leading-relaxed text-white md:text-2xl">
          “{fm.quote}”
        </blockquote>
        <figcaption className="mt-6 flex items-center gap-3 text-sm text-gray-400">
          <span className="h-px w-8 bg-brand-500/40" />
          <span>
            <span className="font-semibold text-gray-200">{fm.quote_role}</span>
            {fm.quote_company ? (
              <>
                {' '}
                · <span>{fm.quote_company}</span>
              </>
            ) : null}
          </span>
        </figcaption>
      </div>
    </section>
  );
}

function CustomerBody({ body }: { body: string }) {
  if (!body) return null;
  return (
    <section className="px-6 pb-16">
      <article className="mx-auto max-w-3xl">
        <MDXRemote source={body} components={mdxBodyComponents} />
      </article>
    </section>
  );
}

function RelatedFeatures({ study }: { study: CustomerStudy }) {
  const links = study.frontmatter.related_features ?? [];
  return (
    <section className="px-6 pb-24">
      <div className="mx-auto max-w-3xl rounded-2xl border border-white/10 bg-white/[0.02] p-6 md:p-8">
        <h2 className="text-base font-semibold uppercase tracking-wider text-gray-500">
          Where to dig in
        </h2>
        {links.length > 0 ? (
          <ul className="mt-4 grid gap-2 sm:grid-cols-2">
            {links.map((link) => {
              const external = link.href.startsWith('http');
              const inner = (
                <span className="flex items-center justify-between rounded-lg border border-white/10 bg-white/[0.02] px-4 py-3 text-sm text-gray-200 transition hover:border-white/20 hover:bg-white/[0.05]">
                  {link.label}
                  <svg
                    viewBox="0 0 20 20"
                    className="h-3.5 w-3.5 text-gray-500"
                    fill="currentColor"
                    aria-hidden="true"
                  >
                    <path d="M7.05 4.05a1 1 0 011.41 0l5 5a1 1 0 010 1.41l-5 5a1 1 0 11-1.41-1.41L11.09 10 7.05 5.46a1 1 0 010-1.41z" />
                  </svg>
                </span>
              );
              return (
                <li key={link.label}>
                  {external ? (
                    <a href={link.href} target="_blank" rel="noreferrer">
                      {inner}
                    </a>
                  ) : (
                    <Link href={link.href}>{inner}</Link>
                  )}
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="mt-3 text-sm text-gray-400">
            Add <code className="font-mono">related_features</code> to the
            frontmatter to deep-link into the docs from this page.
          </p>
        )}

        <div className="mt-6 flex flex-wrap gap-3 border-t border-white/5 pt-6">
          <Link
            href="/customers"
            className="inline-flex items-center gap-2 rounded-md border border-white/10 bg-white/[0.03] px-4 py-2 text-sm font-medium text-gray-300 transition hover:border-white/20 hover:bg-white/[0.06] hover:text-white"
          >
            More customer stories
          </Link>
          <a
            href="mailto:hello@tryaisoc.com"
            className="inline-flex items-center gap-2 rounded-md bg-brand-500 px-4 py-2 text-sm font-semibold text-white transition hover:bg-brand-400"
          >
            Talk to us
          </a>
        </div>
      </div>
    </section>
  );
}
