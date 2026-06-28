'use client';

/**
 * Footer — `footer` section from §6.16.
 *
 * Five-column link grid (Product · Resources · Company · Legal ·
 * Status & GitHub) plus a bottom row with the copyright, the social
 * icons (GitHub, Discord, X) and the static VERSION (`7.3.1` today —
 * sourced from /VERSION at build time once the metadata pass lands).
 *
 * No fancy motion. The page closes on the FinalCta band — the footer
 * is informational chrome.
 */

import type { ReactElement, SVGProps } from 'react';
import Link from 'next/link';
import { GithubMark } from './icons';
import { docs } from '@/lib/docs';

interface LinkSpec {
  label: string;
  href: string;
}

interface LinkColumn {
  heading: string;
  links: ReadonlyArray<LinkSpec>;
}

// Footer link targets. Where we have a real shipping artefact (LICENSE,
// SECURITY.md, ROADMAP.md, CHANGELOG.md, the docs portal, the GitHub repo)
// we link to it directly rather than wrapping it in a stub page that adds no
// information. Everything else routes to a real page under
// apps/web/src/app/(marketing)/ (about, contact, press, privacy, terms,
// pricing) or to the existing landing-page anchor.
const COLUMNS: ReadonlyArray<LinkColumn> = [
  {
    heading: 'Product',
    links: [
      // All four agents live in the same `#solution` section on the
      // home page. We surface them as separate footer links because
      // that's how buyers compare AI-SOC vendors — by named agent —
      // but they all land on the same anchor today. When the agent
      // deep-dives ship we'll point each row at its own page.
      { label: 'Detect agent', href: '/#solution' },
      { label: 'Triage agent', href: '/#solution' },
      { label: 'Hunt agent', href: '/#solution' },
      { label: 'Respond agent', href: '/#solution' },
      { label: 'Connectors', href: docs('connectors') },
      { label: 'Marketplace', href: '/marketplace' },
    ],
  },
  {
    heading: 'Resources',
    links: [
      { label: 'Docs', href: docs('intro') },
      { label: 'Architecture', href: docs('architecture') },
      { label: 'Benchmark', href: '/benchmark' },
      { label: 'Blog', href: '/blog' },
      {
        label: 'Changelog',
        href: 'https://github.com/beenuar/AiSOC/blob/main/CHANGELOG.md',
      },
      {
        label: 'Roadmap',
        href: 'https://github.com/beenuar/AiSOC/blob/main/ROADMAP.md',
      },
    ],
  },
  {
    heading: 'Company',
    links: [
      { label: 'About', href: '/about' },
      { label: 'Sovereign', href: '/sovereign' },
      { label: 'Customers', href: '/customers' },
      { label: 'Pricing', href: '/pricing' },
      { label: 'Contact', href: '/contact' },
      { label: 'Press', href: '/press' },
    ],
  },
  {
    heading: 'Legal',
    links: [
      {
        label: 'License (MIT)',
        href: 'https://github.com/beenuar/AiSOC/blob/main/LICENSE',
      },
      { label: 'Privacy', href: '/privacy' },
      { label: 'Terms', href: '/terms' },
      {
        label: 'Security policy',
        href: 'https://github.com/beenuar/AiSOC/blob/main/SECURITY.md',
      },
    ],
  },
  {
    heading: 'Status & GitHub',
    links: [
      { label: 'Status page', href: 'https://status.tryaisoc.com' },
      { label: 'GitHub repo', href: 'https://github.com/beenuar/AiSOC' },
      { label: 'Discord', href: 'https://discord.gg/aisoc' },
      { label: 'Releases', href: 'https://github.com/beenuar/AiSOC/releases' },
    ],
  },
];

const VERSION = '7.3.1';

function isExternal(href: string) {
  return /^https?:\/\//.test(href);
}

function FooterLink({ label, href }: LinkSpec) {
  const external = isExternal(href);
  return (
    <li>
      <Link
        href={href}
        rel={external ? 'noreferrer' : undefined}
        target={external ? '_blank' : undefined}
        className="text-sm text-velvet-content-tertiary transition-colors duration-200 hover:text-velvet-content-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base"
      >
        {label}
      </Link>
    </li>
  );
}

function DiscordIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" {...props}>
      <path d="M20.317 4.37a19.79 19.79 0 0 0-4.885-1.515.07.07 0 0 0-.07.035c-.21.378-.443.872-.608 1.26a18.27 18.27 0 0 0-5.487 0 12.51 12.51 0 0 0-.617-1.26.07.07 0 0 0-.07-.035 19.74 19.74 0 0 0-4.885 1.515.064.064 0 0 0-.03.027C.533 9.046-.32 13.58.099 18.057a.084.084 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.07.07 0 0 0 .076-.026 14.21 14.21 0 0 0 1.226-1.994.07.07 0 0 0-.038-.098 13.13 13.13 0 0 1-1.872-.892.07.07 0 0 1-.007-.116c.126-.094.252-.192.371-.291a.07.07 0 0 1 .073-.01c3.927 1.793 8.18 1.793 12.062 0a.07.07 0 0 1 .074.009c.12.099.246.198.372.292a.07.07 0 0 1-.006.116 12.32 12.32 0 0 1-1.873.891.07.07 0 0 0-.038.099c.36.698.772 1.362 1.225 1.993a.07.07 0 0 0 .076.027 19.84 19.84 0 0 0 6-3.03.07.07 0 0 0 .032-.056c.5-5.177-.838-9.674-3.548-13.66a.061.061 0 0 0-.03-.027ZM8.02 15.331c-1.182 0-2.157-1.085-2.157-2.419 0-1.333.956-2.418 2.157-2.418 1.21 0 2.176 1.094 2.157 2.418 0 1.334-.956 2.419-2.157 2.419Zm7.974 0c-1.182 0-2.156-1.085-2.156-2.419 0-1.333.955-2.418 2.156-2.418 1.21 0 2.176 1.094 2.157 2.418 0 1.334-.946 2.419-2.157 2.419Z" />
    </svg>
  );
}

function XIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" {...props}>
      <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231ZM17.083 19.77h1.833L7.084 4.126H5.117L17.083 19.77Z" />
    </svg>
  );
}

const SOCIAL_LINKS: ReadonlyArray<{
  label: string;
  href: string;
  Icon: (props: SVGProps<SVGSVGElement>) => ReactElement;
}> = [
  { label: 'GitHub', href: 'https://github.com/beenuar/AiSOC', Icon: GithubMark },
  { label: 'Discord', href: 'https://discord.gg/aisoc', Icon: DiscordIcon },
  { label: 'X (Twitter)', href: 'https://twitter.com/tryaisoc', Icon: XIcon },
];

export function Footer() {
  return (
    <footer className="relative border-t border-velvet-border bg-velvet-surface-base/80 backdrop-blur-sm">
      <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 sm:py-14 lg:px-8 lg:py-16">
        <div className="grid gap-10 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 lg:gap-8">
          {COLUMNS.map((column) => (
            <nav key={column.heading} aria-label={column.heading}>
              <h3 className="font-velvet-display font-normal text-xs uppercase tracking-[0.12em] text-velvet-content-primary">
                {column.heading}
              </h3>
              <ul className="mt-4 space-y-3">
                {column.links.map((link) => (
                  <FooterLink key={link.label} {...link} />
                ))}
              </ul>
            </nav>
          ))}
        </div>

        <div className="mt-12 flex flex-col items-start justify-between gap-4 border-t border-velvet-border pt-8 sm:flex-row sm:items-center">
          <p className="text-xs text-velvet-content-tertiary">
            © 2024–present AiSOC contributors · MIT-licensed · v{VERSION}
          </p>
          <ul className="flex items-center gap-3">
            {SOCIAL_LINKS.map(({ label, href, Icon }) => (
              <li key={label}>
                <Link
                  href={href}
                  rel="noreferrer"
                  target="_blank"
                  aria-label={`AiSOC on ${label}`}
                  className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-velvet-border text-velvet-content-tertiary transition-colors duration-200 hover:border-velvet-emerald/40 hover:text-velvet-content-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base"
                >
                  <Icon className="h-4 w-4" />
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </footer>
  );
}
