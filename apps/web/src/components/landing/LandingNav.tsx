'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import clsx from 'clsx';
import { Logo } from './Logo';

const NAV_LINKS = [
  { label: 'Platform', href: '/#features' },
  { label: 'How it works', href: '/#architecture' },
  { label: 'MITRE', href: '/#mitre' },
  { label: 'Why open source', href: '/why-open-source' },
  { label: 'Benchmark', href: '/benchmark' },
];

/**
 * Sticky landing-page navigation. Becomes opaque + bordered on scroll so the
 * hero feels open at the top but content underneath stays readable as you
 * scroll. Mobile collapses links into a sheet to keep the bar uncluttered.
 */
export function LandingNav() {
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <header
      className={clsx(
        'fixed inset-x-0 top-0 z-40 transition-all',
        scrolled
          ? 'border-b border-white/5 bg-surface-base/85 backdrop-blur-md'
          : 'border-b border-transparent bg-transparent',
      )}
    >
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
        <Link href="/" aria-label="AiSOC home" className="flex items-center gap-3">
          <Logo size={32} withWordmark />
        </Link>

        <nav className="hidden items-center gap-8 md:flex">
          {NAV_LINKS.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className="text-sm font-medium text-gray-400 transition-colors hover:text-white"
            >
              {link.label}
            </Link>
          ))}
        </nav>

        <div className="hidden items-center gap-3 md:flex">
          <a
            href="https://github.com/beenuar/AiSOC"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 rounded-md border border-white/10 bg-white/[0.03] px-3 py-1.5 text-sm font-medium text-gray-300 transition hover:border-white/20 hover:bg-white/[0.06] hover:text-white"
          >
            <svg viewBox="0 0 24 24" className="h-4 w-4" aria-hidden="true" fill="currentColor">
              <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.56 0-.28-.01-1.02-.02-2-3.2.69-3.88-1.54-3.88-1.54-.52-1.32-1.27-1.67-1.27-1.67-1.04-.71.08-.69.08-.69 1.15.08 1.76 1.18 1.76 1.18 1.02 1.75 2.68 1.24 3.34.95.1-.74.4-1.24.73-1.53-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.18-3.1-.12-.29-.51-1.46.11-3.05 0 0 .96-.31 3.15 1.18a10.9 10.9 0 015.74 0c2.19-1.49 3.15-1.18 3.15-1.18.62 1.59.23 2.76.11 3.05.74.81 1.18 1.84 1.18 3.1 0 4.42-2.7 5.39-5.27 5.68.41.36.78 1.06.78 2.14 0 1.55-.01 2.79-.01 3.17 0 .31.21.68.8.56C20.21 21.39 23.5 17.08 23.5 12 23.5 5.65 18.35.5 12 .5z" />
            </svg>
            GitHub
          </a>
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-2 rounded-md bg-brand-500 px-4 py-1.5 text-sm font-semibold text-white shadow-glow-sm transition hover:bg-brand-400"
          >
            Launch console
            <svg viewBox="0 0 20 20" className="h-3.5 w-3.5" fill="currentColor" aria-hidden="true">
              <path d="M7.05 4.05a1 1 0 011.41 0l5 5a1 1 0 010 1.41l-5 5a1 1 0 11-1.41-1.41L11.09 10 7.05 5.46a1 1 0 010-1.41z" />
            </svg>
          </Link>
        </div>

        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="md:hidden inline-flex h-9 w-9 items-center justify-center rounded-md border border-white/10 bg-white/[0.03] text-gray-300 hover:border-white/20"
          aria-expanded={open}
          aria-label="Toggle menu"
        >
          <svg viewBox="0 0 20 20" className="h-5 w-5" fill="currentColor" aria-hidden="true">
            {open ? (
              <path d="M6.28 5.22a.75.75 0 011.06 0L10 7.88l2.66-2.66a.75.75 0 111.06 1.06L11.06 8.94l2.66 2.66a.75.75 0 11-1.06 1.06L10 10l-2.66 2.66a.75.75 0 11-1.06-1.06l2.66-2.66-2.66-2.66a.75.75 0 010-1.06z" />
            ) : (
              <path d="M3 5.5A.5.5 0 013.5 5h13a.5.5 0 010 1h-13a.5.5 0 01-.5-.5zM3 10a.5.5 0 01.5-.5h13a.5.5 0 010 1h-13A.5.5 0 013 10zm.5 4a.5.5 0 000 1h13a.5.5 0 000-1h-13z" />
            )}
          </svg>
        </button>
      </div>

      {open && (
        <div className="border-t border-white/5 bg-surface-base/95 backdrop-blur-md md:hidden">
          <div className="space-y-1 px-4 py-3">
            {NAV_LINKS.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                onClick={() => setOpen(false)}
                className="block rounded-md px-3 py-2 text-sm text-gray-300 hover:bg-white/5 hover:text-white"
              >
                {link.label}
              </Link>
            ))}
            <div className="flex gap-2 pt-2">
              <a
                href="https://github.com/beenuar/AiSOC"
                target="_blank"
                rel="noreferrer"
                className="flex-1 rounded-md border border-white/10 bg-white/[0.03] px-3 py-2 text-center text-sm font-medium text-gray-300"
              >
                GitHub
              </a>
              <Link
                href="/dashboard"
                className="flex-1 rounded-md bg-brand-500 px-3 py-2 text-center text-sm font-semibold text-white"
              >
                Launch
              </Link>
            </div>
          </div>
        </div>
      )}
    </header>
  );
}
