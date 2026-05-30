'use client';

/**
 * Sticky marketing nav for the T6.5 landing page (`apps/web/src/app/page.tsx`).
 *
 * The existing console nav (`landing/LandingNav.tsx`) is left in place because
 * it's still imported from `/sovereign`, `/blog`, `/customers`, etc. — this
 * file is the dedicated chrome for the GTM landing page only and is scoped
 * to `landing/sections/` so it cannot collide.
 *
 * Behaviour matches `docs/design/landing-page-brief.md` §6.1:
 *   - transparent at the very top of the page
 *   - opaque + 1 px hairline + backdrop-blur after 12 px of scroll
 *   - mobile collapses links into a sheet, body scroll-locked while open
 *   - `prefers-reduced-motion` suppresses the opacity / translate transitions
 */

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { ArrowRight, Menu, X } from 'lucide-react';
import { GithubMark } from './icons';
import { docs } from '@/lib/docs';
import { cn } from '@/lib/utils';

const NAV_LINKS: ReadonlyArray<{ label: string; href: string }> = [
  { label: 'Product', href: '#solution' },
  { label: 'Solutions', href: '#pillars' },
  { label: 'Connectors', href: '#connectors' },
  { label: 'Benchmark', href: '#benchmark' },
  { label: 'Pricing', href: '#pricing' },
  { label: 'Docs', href: docs('intro') },
];

export function StickyNav() {
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  useEffect(() => {
    if (typeof document === 'undefined') return;
    document.body.style.overflow = open ? 'hidden' : '';
    return () => {
      document.body.style.overflow = '';
    };
  }, [open]);

  return (
    <header
      className={cn(
        'fixed inset-x-0 top-0 z-50 transition-[background-color,border-color,backdrop-filter] duration-200 ease-landing-out-quart',
        scrolled
          ? 'border-b border-velvet-border bg-velvet-surface-base/85 backdrop-blur-md'
          : 'border-b border-transparent bg-transparent',
      )}
    >
      <nav
        aria-label="Primary"
        className="mx-auto flex h-16 max-w-7xl items-center justify-between gap-4 px-4 sm:px-6 lg:px-8"
      >
        <Link
          href="/"
          aria-label="AiSOC home"
          className="flex items-center gap-2 rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base"
        >
          <span
            aria-hidden="true"
            className="inline-flex h-8 w-8 items-center justify-center rounded-md bg-velvet-emerald-cta text-xs font-bold text-velvet-content-primary shadow-[inset_0_0_0_1px_rgba(255,255,255,0.18)] motion-safe:shadow-glow-emerald-sm"
          >
            Ai
          </span>
          <span className="font-velvet-display text-base font-normal tracking-tight text-velvet-content-primary">
            AiSOC
          </span>
        </Link>

        <ul className="hidden items-center gap-1 lg:flex">
          {NAV_LINKS.map((link) => (
            <li key={link.href}>
              <Link
                href={link.href}
                className="rounded-md px-3 py-2 text-sm font-medium text-velvet-content-secondary transition-colors duration-150 ease-landing-out-quart hover:text-velvet-content-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base"
              >
                {link.label}
              </Link>
            </li>
          ))}
        </ul>

        <div className="hidden items-center gap-2 lg:flex">
          <a
            href="https://github.com/beenuar/AiSOC"
            target="_blank"
            rel="noreferrer"
            aria-label="Star AiSOC on GitHub"
            className="inline-flex items-center gap-2 rounded-md border border-velvet-border bg-velvet-surface-raised/60 px-3 py-1.5 text-sm font-medium text-velvet-content-secondary transition-colors duration-150 ease-landing-out-quart hover:border-velvet-emerald/40 hover:text-velvet-content-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base"
          >
            <GithubMark className="h-3.5 w-3.5" />
            <span aria-hidden="true">Star on GitHub</span>
          </a>
          <Link
            href="#pricing"
            className="rounded-md px-3 py-1.5 text-sm font-medium text-velvet-content-secondary transition-colors duration-150 ease-landing-out-quart hover:text-velvet-content-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base"
          >
            Self-host
          </Link>
          <Link
            href="https://tryaisoc.com/dashboard"
            className="group inline-flex items-center gap-1 rounded-md bg-velvet-emerald-cta px-4 py-1.5 text-sm font-semibold text-velvet-content-primary shadow-[0_1px_0_rgba(255,255,255,0.18)_inset] transition-[filter,box-shadow] duration-200 ease-landing-out-quart hover:brightness-110 motion-safe:hover:shadow-glow-emerald-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base"
          >
            Open dashboard
            <ArrowRight
              className="h-3.5 w-3.5 transition-transform duration-200 ease-landing-out-quart group-hover:translate-x-0.5 motion-reduce:transition-none motion-reduce:group-hover:translate-x-0"
              aria-hidden="true"
            />
          </Link>
        </div>

        <button
          type="button"
          onClick={() => setOpen((value) => !value)}
          aria-expanded={open}
          aria-controls="aisoc-mobile-nav"
          aria-label={open ? 'Close menu' : 'Open menu'}
          className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-velvet-border bg-velvet-surface-raised/60 text-velvet-content-secondary transition-colors duration-150 ease-landing-out-quart hover:border-velvet-emerald/40 hover:text-velvet-content-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base lg:hidden"
        >
          {open ? (
            <X className="h-4 w-4" aria-hidden="true" />
          ) : (
            <Menu className="h-4 w-4" aria-hidden="true" />
          )}
        </button>
      </nav>

      <div
        id="aisoc-mobile-nav"
        className={cn(
          'lg:hidden',
          'overflow-hidden border-t border-velvet-border bg-velvet-surface-base/95 backdrop-blur-md transition-[max-height,opacity] duration-200 ease-landing-out-quart',
          open ? 'max-h-[60vh] opacity-100' : 'max-h-0 opacity-0',
        )}
      >
        <ul className="space-y-1 px-4 py-3">
          {NAV_LINKS.map((link) => (
            <li key={link.href}>
              <Link
                href={link.href}
                onClick={() => setOpen(false)}
                className="block rounded-md px-3 py-2 text-sm font-medium text-velvet-content-secondary transition-colors duration-150 ease-landing-out-quart hover:bg-velvet-surface-overlay hover:text-velvet-content-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint"
              >
                {link.label}
              </Link>
            </li>
          ))}
        </ul>
        <div className="flex gap-2 px-4 pb-4">
          <a
            href="https://github.com/beenuar/AiSOC"
            target="_blank"
            rel="noreferrer"
            className="flex-1 rounded-md border border-velvet-border bg-velvet-surface-raised/60 px-3 py-2 text-center text-sm font-medium text-velvet-content-secondary"
          >
            Self-host
          </a>
          <Link
            href="https://tryaisoc.com/dashboard"
            onClick={() => setOpen(false)}
            className="flex-1 rounded-md bg-velvet-emerald-cta px-3 py-2 text-center text-sm font-semibold text-velvet-content-primary motion-safe:shadow-glow-emerald-sm"
          >
            Open dashboard
          </Link>
        </div>
      </div>
    </header>
  );
}
