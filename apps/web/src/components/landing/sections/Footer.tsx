'use client';

/**
 * Footer — `footer` section from §6.16.
 *
 * Five-column link grid (Product · Resources · Company · Legal ·
 * GitHub & community) plus a bottom row with the copyright, the social
 * icons (GitHub, Discord, X) and the version.
 *
 * The version was the string `'7.3.1'`, typed here and never touched again —
 * seven major releases stale, and the most visible "this project is dead"
 * signal a footer can emit. It now reads `apps/web/package.json`, which the
 * release flow bumps, exactly as `components/layout/Sidebar.tsx` does for the
 * console.
 *
 * No fancy motion. The page closes on the FinalCta band — the footer
 * is informational chrome.
 */

import type { ReactElement, SVGProps } from 'react';
import Link from 'next/link';
import packageJson from '../../../../package.json';
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
    // Renamed from 'Status & GitHub'. The status.tryaisoc.com subdomain
    // does not exist yet (DNS returns NXDOMAIN), so we removed the
    // "Status page" row rather than ship a link to nowhere. Re-add it
    // here as `{ label: 'Status page', href: 'https://status.tryaisoc.com' }`
    // once the subdomain ships (e.g. Statuspage, Better Stack, or a
    // hosted Grafana panel) and the column heading can revert to
    // 'Status & GitHub'.
    heading: 'GitHub & community',
    links: [
      { label: 'GitHub repo', href: 'https://github.com/beenuar/AiSOC' },
      // Discussions, not Discord: the old invite answered "Unknown Invite"
      // from Discord's own API (checked 2026-11-22), and SUPPORT.md names
      // GitHub Discussions as the project's community venue. Same rule as
      // the status-page row above — no links to nowhere. Re-add a chat row
      // only once a working invite exists.
      {
        label: 'Discussions',
        href: 'https://github.com/beenuar/AiSOC/discussions',
      },
      { label: 'Releases', href: 'https://github.com/beenuar/AiSOC/releases' },
    ],
  },
];

const VERSION = packageJson.version;

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

function DiscussionsIcon(props: SVGProps<SVGSVGElement>) {
  // Speech-bubble glyph (Octicons `comment-discussion`, MIT) — the socials
  // row's Discord and X entries were removed on 2026-11-22 because both
  // destinations were dead (the invite answers "Unknown Invite"; the X
  // account 404s). GitHub Discussions is the venue SUPPORT.md names.
  return (
    <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true" {...props}>
      <path d="M1.75 1h8.5c.966 0 1.75.784 1.75 1.75v5.5A1.75 1.75 0 0 1 10.25 10H7.061l-2.574 2.573A1.458 1.458 0 0 1 2 11.543V10h-.25A1.75 1.75 0 0 1 0 8.25v-5.5C0 1.784.784 1 1.75 1ZM1.5 2.75v5.5c0 .138.112.25.25.25h1a.75.75 0 0 1 .75.75v2.19l2.72-2.72a.749.749 0 0 1 .53-.22h3.5a.25.25 0 0 0 .25-.25v-5.5a.25.25 0 0 0-.25-.25h-8.5a.25.25 0 0 0-.25.25Zm13 2a.25.25 0 0 0-.25-.25h-.5a.75.75 0 0 1 0-1.5h.5c.966 0 1.75.784 1.75 1.75v5.5A1.75 1.75 0 0 1 14.25 12H14v1.543a1.458 1.458 0 0 1-2.487 1.03L9.22 12.28a.749.749 0 0 1 .326-1.275.749.749 0 0 1 .734.215l2.22 2.22v-2.19a.75.75 0 0 1 .75-.75h1a.25.25 0 0 0 .25-.25Z" />
    </svg>
  );
}

const SOCIAL_LINKS: ReadonlyArray<{
  label: string;
  href: string;
  Icon: (props: SVGProps<SVGSVGElement>) => ReactElement;
}> = [
  { label: 'GitHub', href: 'https://github.com/beenuar/AiSOC', Icon: GithubMark },
  {
    label: 'Discussions',
    href: 'https://github.com/beenuar/AiSOC/discussions',
    Icon: DiscussionsIcon,
  },
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
