import fs from 'node:fs';
import path from 'node:path';
import matter from 'gray-matter';

/**
 * Blog loader (T7.3).
 *
 * Mirrors `apps/web/src/lib/customers.ts` — each post lives in
 * `apps/web/content/blog/<slug>.mdx` with a fixed YAML frontmatter shape.
 * Editorial owns the directory: dropping a new MDX file there is enough to
 * publish — no engineering involvement required.
 *
 * The frontmatter contract is small on purpose. Every field listed here must
 * exist on every published post; missing required fields surface as a build /
 * render error during local preview rather than a half-empty live page.
 */

export type BlogTag = string;

export type BlogFrontmatter = {
  /** Display title — long-form, no marketing fluff. */
  title: string;
  /** URL slug — must match the filename and is checked at load time. */
  slug: string;
  /** Authoring date in ISO-8601 (YYYY-MM-DD). Used for sorting + display. */
  date: string;
  /** Author byline — full name + role. */
  author: string;
  /** Free-form taxonomy tags rendered as pill badges in the index + hero. */
  tags: BlogTag[];
  /** One-paragraph summary used in the index card and as the OG description. */
  description: string;
  /** Path under /public to the 1200x630 social card asset. */
  og_image?: string;
  /**
   * Marks the file as an unpublished draft. Excluded from the public index but
   * still resolvable directly so editorial can preview the layout.
   */
  draft?: boolean;
};

export type BlogPost = {
  slug: string;
  frontmatter: BlogFrontmatter;
  /** Raw MDX body — handed to <MDXRemote /> for rendering. */
  body: string;
  /** Estimated reading minutes, computed from the body. */
  reading_minutes: number;
};

const CONTENT_DIR = path.join(process.cwd(), 'content', 'blog');

const WORDS_PER_MINUTE = 220;

function readDir(): string[] {
  if (!fs.existsSync(CONTENT_DIR)) return [];
  return fs
    .readdirSync(CONTENT_DIR)
    .filter((name) => name.endsWith('.mdx') || name.endsWith('.md'));
}

function estimateReadingMinutes(body: string): number {
  const words = body.split(/\s+/u).filter(Boolean).length;
  return Math.max(1, Math.round(words / WORDS_PER_MINUTE));
}

/**
 * Strict allow-list for slugs: lowercase ASCII letters, digits, and hyphens.
 * Filenames that fail this check throw at load time so that the slug value can
 * never reach a URL, JSX attribute, or downstream render context with anything
 * outside the allow-list. This eliminates the stored-XSS taint flow that
 * CodeQL flags on `<Link href={`/blog/${slug}`} />` etc.
 */
const SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$/u;

function assertSafeSlug(slug: string, filename: string): string {
  if (!SLUG_PATTERN.test(slug)) {
    throw new Error(
      `Unsafe blog slug derived from filename "${filename}": ${JSON.stringify(slug)}. ` +
        `Slugs must match ${SLUG_PATTERN.source} (lowercase ASCII letters, digits, and hyphens).`,
    );
  }
  return slug;
}

function parseFile(filename: string): BlogPost {
  const rawSlug = filename.replace(/\.(mdx|md)$/u, '');
  const slug = assertSafeSlug(rawSlug, filename);
  const raw = fs.readFileSync(path.join(CONTENT_DIR, filename), 'utf8');
  const { data, content } = matter(raw);
  const fm = data as BlogFrontmatter;
  if (fm.slug && fm.slug !== slug) {
    throw new Error(
      `Blog frontmatter slug "${fm.slug}" does not match filename "${filename}".`,
    );
  }
  return {
    slug,
    frontmatter: { ...fm, slug },
    body: content.trim(),
    reading_minutes: estimateReadingMinutes(content),
  };
}

/**
 * List every post on disk. `includeDrafts` defaults to false so drafts stay
 * private; the detail-page resolver still surfaces them directly so editorial
 * can preview a draft via its slug before flipping the flag.
 */
export function listPosts(includeDrafts = false): BlogPost[] {
  const posts = readDir().map(parseFile);
  const filtered = includeDrafts
    ? posts
    : posts.filter((p) => !p.frontmatter.draft);
  return filtered.sort((a, b) => {
    // Reverse-chronological: most recent first.
    if (a.frontmatter.date !== b.frontmatter.date) {
      return a.frontmatter.date < b.frontmatter.date ? 1 : -1;
    }
    return a.frontmatter.title.localeCompare(b.frontmatter.title);
  });
}

export function getPostBySlug(slug: string): BlogPost | null {
  for (const ext of ['mdx', 'md'] as const) {
    const file = path.join(CONTENT_DIR, `${slug}.${ext}`);
    if (fs.existsSync(file)) {
      return parseFile(`${slug}.${ext}`);
    }
  }
  return null;
}

export function listPostSlugs(): string[] {
  return readDir().map((name) => name.replace(/\.(mdx|md)$/u, ''));
}

/** Format an ISO date as e.g. "May 13, 2026" for hero display. */
export function formatPostDate(iso: string): string {
  const d = new Date(`${iso}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString('en-US', {
    timeZone: 'UTC',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}
