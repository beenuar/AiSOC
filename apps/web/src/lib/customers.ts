import fs from 'node:fs';
import path from 'node:path';
import matter from 'gray-matter';

/**
 * Reference-customer page loader (T6.2).
 *
 * Each case study lives in `apps/web/content/customers/<slug>.mdx` with a
 * fixed YAML frontmatter shape. GTM owns the directory: dropping a new MDX
 * file there is enough to publish — no engineering involvement required.
 *
 * The frontmatter contract is small on purpose. Every field listed here must
 * exist on every published case study; missing fields surface as a build /
 * render error during local preview rather than a half-empty live page.
 */

export type StatNumber = {
  metric: string;
  before: string;
  after: string;
};

export type CustomerLink = {
  label: string;
  href: string;
};

export type CustomerFrontmatter = {
  /** Display title — typically the customer name. */
  title: string;
  /** Vertical / industry the customer operates in (e.g. "FinTech"). */
  industry: string;
  /** Path to the customer logo asset under /public. */
  logo: string;
  /** One-line description of the security challenge the team faced. */
  challenge: string;
  /** Three-to-five before/after stats rendered in the hero stat band. */
  result_numbers: StatNumber[];
  /** Pull-quote rendered prominently below the stat band. */
  quote: string;
  /** Speaker role (e.g. "Head of SOC"). */
  quote_role: string;
  /** Speaker company (typically same as the customer). */
  quote_company: string;
  /** Optional region — surfaced as a hero badge alongside industry. */
  region?: string;
  /** Deep links into the docs / app for the features cited in the study. */
  related_features?: CustomerLink[];
  /**
   * Order hint on the index page — lower numbers float to the top. Defaults to
   * Number.POSITIVE_INFINITY so unordered entries fall to the bottom.
   */
  order?: number;
  /**
   * Marks the file as an unpublished template. Excluded from the public index
   * page but still resolvable directly so GTM can preview the layout.
   */
  draft?: boolean;
};

export type CustomerStudy = {
  slug: string;
  frontmatter: CustomerFrontmatter;
  /** Raw MDX body — handed to <MDXRemote /> for rendering. */
  body: string;
};

const CONTENT_DIR = path.join(process.cwd(), 'content', 'customers');

/**
 * Strict allow-list for slugs: lowercase ASCII letters, digits, and hyphens.
 * Filenames that fail this check throw at load time so that the slug value can
 * never reach a URL, JSX attribute, or downstream render context with anything
 * outside the allow-list. This eliminates the stored-XSS taint flow that
 * CodeQL flags on `<Link href={`/customers/${slug}`} />` etc.
 */
const SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$/u;

function assertSafeSlug(slug: string, filename: string): string {
  if (!SLUG_PATTERN.test(slug)) {
    throw new Error(
      `Unsafe customer slug derived from filename "${filename}": ${JSON.stringify(slug)}. ` +
        `Slugs must match ${SLUG_PATTERN.source} (lowercase ASCII letters, digits, and hyphens).`,
    );
  }
  return slug;
}

function readDir(): string[] {
  if (!fs.existsSync(CONTENT_DIR)) return [];
  return fs
    .readdirSync(CONTENT_DIR)
    .filter((name) => name.endsWith('.mdx') || name.endsWith('.md'));
}

function parseFile(filename: string): CustomerStudy {
  const rawSlug = filename.replace(/\.(mdx|md)$/u, '');
  const slug = assertSafeSlug(rawSlug, filename);
  const raw = fs.readFileSync(path.join(CONTENT_DIR, filename), 'utf8');
  const { data, content } = matter(raw);
  // gray-matter returns `data` as a generic object; we trust the file author
  // to keep the schema in sync (the index/detail pages will throw loudly on
  // missing required fields, which is the desired failure mode).
  return {
    slug,
    frontmatter: data as CustomerFrontmatter,
    body: content.trim(),
  };
}

/**
 * List every case study on disk. `includeDrafts` is true by default for
 * detail-page resolution (GTM should be able to preview a draft directly via
 * its slug); the index page passes `false` so drafts stay private.
 */
export function listCustomers(includeDrafts = true): CustomerStudy[] {
  const studies = readDir().map(parseFile);
  const filtered = includeDrafts
    ? studies
    : studies.filter((s) => !s.frontmatter.draft);
  return filtered.sort((a, b) => {
    const ao = a.frontmatter.order ?? Number.POSITIVE_INFINITY;
    const bo = b.frontmatter.order ?? Number.POSITIVE_INFINITY;
    if (ao !== bo) return ao - bo;
    return a.frontmatter.title.localeCompare(b.frontmatter.title);
  });
}

export function getCustomerBySlug(slug: string): CustomerStudy | null {
  for (const ext of ['mdx', 'md'] as const) {
    const file = path.join(CONTENT_DIR, `${slug}.${ext}`);
    if (fs.existsSync(file)) {
      return parseFile(`${slug}.${ext}`);
    }
  }
  return null;
}

export function listCustomerSlugs(): string[] {
  return readDir().map((name) => name.replace(/\.(mdx|md)$/u, ''));
}
