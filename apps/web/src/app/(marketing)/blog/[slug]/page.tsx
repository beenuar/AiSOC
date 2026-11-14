import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { MDXRemote } from 'next-mdx-remote/rsc';
import { mdxBodyComponents } from '@/components/marketing/MdxBody';
import {
  formatPostDate,
  getPostBySlug,
  listPostSlugs,
  type BlogPost,
} from '@/lib/blog';

/**
 * `/blog/[slug]` — long-form post detail page (T7.3).
 *
 * Mirrors `/customers/[slug]`: a single MDX file in `apps/web/content/blog/`
 * is the source of truth for the title, hero metadata, and body. The page
 * is statically generated for every slug on disk via `generateStaticParams()`
 * so posts never depend on runtime FS access in production.
 */

type Params = { slug: string };

export async function generateStaticParams(): Promise<Params[]> {
  return listPostSlugs().map((slug) => ({ slug }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<Params>;
}): Promise<Metadata> {
  const { slug } = await params;
  const post = getPostBySlug(slug);
  if (!post) return { title: 'Post not found — AiSOC' };
  const fm = post.frontmatter;
  return {
    title: `${fm.title} — AiSOC blog`,
    description: fm.description,
    alternates: { canonical: `/blog/${slug}` },
    openGraph: {
      title: fm.title,
      description: fm.description,
      type: 'article',
      publishedTime: fm.date,
      authors: [fm.author],
      tags: fm.tags,
      images: fm.og_image ? [{ url: fm.og_image, width: 1200, height: 630 }] : undefined,
    },
    twitter: {
      card: 'summary_large_image',
      title: fm.title,
      description: fm.description,
      images: fm.og_image ? [fm.og_image] : undefined,
    },
  };
}

export default async function BlogPostPage({
  params,
}: {
  params: Promise<Params>;
}) {
  const { slug } = await params;
  const post = getPostBySlug(slug);
  if (!post) notFound();

  return (
    <main
      data-theme="dark"
      className="relative min-h-screen overflow-x-hidden bg-surface-base text-fg-primary"
    >
      <PostHero post={post} />
      <PostBody body={post.body} />
      <PostFooter post={post} />
    </main>
  );
}

function PostHero({ post }: { post: BlogPost }) {
  const fm = post.frontmatter;
  return (
    <section className="px-6 pt-32 pb-12">
      <div className="mx-auto max-w-3xl">
        <Link
          href="/blog"
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
          All posts
        </Link>

        {fm.draft ? (
          <div className="mt-6 rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-xs text-amber-200">
            <strong className="font-semibold">Draft preview.</strong> This post
            is marked <code className="font-mono">draft: true</code> — it will
            not appear on the public <code className="font-mono">/blog</code>{' '}
            index until that flag is removed.
          </div>
        ) : null}

        <div className="mt-6 flex flex-wrap items-center gap-2">
          {fm.tags.map((tag) => (
            <span
              key={tag}
              className="inline-flex items-center rounded-full border border-brand-500/20 bg-brand-500/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-brand-200"
            >
              {tag}
            </span>
          ))}
        </div>

        <h1 className="mt-6 text-4xl font-bold tracking-tight text-white md:text-5xl">
          {fm.title}
        </h1>
        <p className="mt-5 text-lg leading-relaxed text-gray-300">
          {fm.description}
        </p>
        <div className="mt-6 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-gray-500">
          <span className="font-semibold text-gray-300">{fm.author}</span>
          <span>·</span>
          <time dateTime={fm.date}>{formatPostDate(fm.date)}</time>
          <span>·</span>
          <span>{post.reading_minutes} min read</span>
        </div>
      </div>
    </section>
  );
}

function PostBody({ body }: { body: string }) {
  if (!body) return null;
  return (
    <section className="px-6 pb-16">
      <article className="mx-auto max-w-3xl">
        <MDXRemote source={body} components={mdxBodyComponents} />
      </article>
    </section>
  );
}

function PostFooter({ post }: { post: BlogPost }) {
  const fm = post.frontmatter;
  return (
    <section className="px-6 pb-24">
      <div className="mx-auto max-w-3xl rounded-2xl border border-white/10 bg-white/[0.02] p-6 md:p-8">
        <h2 className="text-base font-semibold uppercase tracking-wider text-gray-500">
          Keep reading
        </h2>
        <p className="mt-3 text-sm leading-relaxed text-gray-400">
          More long-form writing on the AiSOC architecture and operating
          model. The full archive is on the{' '}
          <Link
            href="/blog"
            className="text-brand-300 underline underline-offset-2 hover:text-brand-200"
          >
            blog index
          </Link>
          .
        </p>
        <div className="mt-6 flex flex-wrap gap-3 border-t border-white/5 pt-6">
          <Link
            href="/blog"
            className="inline-flex items-center gap-2 rounded-md border border-white/10 bg-white/[0.03] px-4 py-2 text-sm font-medium text-gray-300 transition hover:border-white/20 hover:bg-white/[0.06] hover:text-white"
          >
            All posts
          </Link>
          <a
            href="mailto:hello@tryaisoc.com"
            className="inline-flex items-center gap-2 rounded-md bg-brand-500 px-4 py-2 text-sm font-semibold text-white transition hover:bg-brand-400"
          >
            Talk to {fm.author.split(',')[0]}
          </a>
        </div>
      </div>
    </section>
  );
}
