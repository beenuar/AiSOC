import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowRight, Telescope } from 'lucide-react';
import { StickyNav } from '@/components/landing/sections/StickyNav';
import { Footer } from '@/components/landing/sections/Footer';
import { docs } from '@/lib/docs';
import { isDemoMode } from '@/lib/demoMode';

/**
 * Global 404 fallback.
 *
 * Before this page landed, Next.js shipped its default `not-found.tsx`
 * which is a bare white `404 | This page could not be found.` with no
 * navigation, no AiSOC branding, and no link home. On a dark-themed
 * marketing site it reads as "you have left tryaisoc.com" — exactly the
 * wrong signal for someone who landed on a stale `/signup` link or
 * mistyped a route.
 *
 * Design: keep the same `StickyNav` + `sections/Footer` chrome the rest
 * of the marketing site uses (so the user never feels like they have
 * left the site), and surface a small list of the destinations they
 * were probably looking for — interactive demo, pricing, contact, docs.
 *
 * Why the imports are direct (not the (marketing) layout)
 * --------------------------------------------------------
 * `not-found.tsx` lives at the app root, not inside the (marketing)
 * route group, because Next.js renders it for *any* unmatched route
 * — including ones outside the marketing surface. Route-group layouts
 * don't cascade across groups, so this page renders the canonical
 * chrome directly (same pair the landing page and the (marketing)
 * group use). See ISSUE-006 shell unification (2026-06-29).
 */

export const metadata: Metadata = {
  title: '404 — page not found · AiSOC',
  description:
    'That URL is not part of the AiSOC site. Jump back to the homepage, open the dashboard, or pick one of the popular destinations below.',
  // Tell crawlers we know this is a 404 surface; do not let them index it.
  robots: { index: false, follow: false },
};

interface Destination {
  label: string;
  href: string;
  blurb: string;
  external?: boolean;
}

/**
 * The dashboard card, which is the only one whose copy depends on the
 * deployment.
 *
 * It advertised "Anonymous, pre-seeded investigation. No signup. Demo data
 * resets daily at 00:00 UTC." unconditionally — on a self-hosted build with
 * demo mode off, an offer of seeded data that does not exist and a reset
 * schedule nothing runs. Same class of defect as a console announcing demo
 * resets over somebody's real alerts, pointing the other way.
 *
 * `isDemoMode()` is the flag the rest of the product gates on, and this file
 * is a Server Component, so it reads `AISOC_DEMO_MODE` from the running
 * container before falling back to the value compiled in at build time.
 */
function dashboardDestination(demo: boolean): Destination {
  return demo
    ? {
        label: 'Open the live dashboard',
        href: '/dashboard',
        blurb: 'Anonymous, pre-seeded investigation. No signup. Demo data resets daily at 00:00 UTC.',
      }
    : {
        label: 'Open the dashboard',
        href: '/dashboard',
        blurb: 'Alerts, cases and investigations for this deployment. Sign in to continue.',
      };
}

function destinations(demo: boolean): ReadonlyArray<Destination> {
  return [
    dashboardDestination(demo),
    {
      label: 'See pricing',
      href: '/pricing',
      blurb: 'Free to self-host. Pay only when we host.',
    },
    {
      label: 'Read the docs',
      href: docs('intro'),
      blurb: 'Architecture, agent contract, deployment recipes, connector SDK.',
      external: true,
    },
    {
      label: 'Contact the team',
      href: '/contact',
      blurb: 'Sovereign deployments, design-partner conversations, security disclosures.',
    },
  ];
}

export default function NotFoundPage() {
  const demo = isDemoMode();
  const DESTINATIONS = destinations(demo);

  return (
    <main
      data-theme="dark"
      className="relative min-h-screen overflow-x-hidden bg-surface-base text-fg-primary"
    >
      <StickyNav />

      <section className="px-6 pt-32 pb-12">
        <div className="mx-auto max-w-3xl text-center">
          <span className="inline-flex items-center gap-2 rounded-full border border-brand-500/30 bg-brand-500/10 px-3 py-1 text-xs font-semibold uppercase tracking-wider text-brand-300">
            <Telescope className="h-3.5 w-3.5" aria-hidden="true" />
            404 · page not found
          </span>
          <h1 className="mt-6 text-4xl font-bold tracking-tight text-white md:text-5xl">
            We do not have a page at that URL.
          </h1>
          <p className="mt-5 text-lg leading-relaxed text-gray-400">
            This usually means a link is out of date, a route was retired,
            or the URL has a typo. AiSOC is still live — pick one of the
            destinations below, or jump back to the homepage.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link
              href="/"
              className="inline-flex h-11 items-center gap-2 rounded-md bg-brand-500 px-5 text-sm font-semibold text-white shadow-[0_1px_0_rgba(255,255,255,0.18)_inset] transition-colors hover:bg-brand-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-300 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-base"
            >
              Back to home
              <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
            </Link>
            <Link
              href="/dashboard"
              className="inline-flex h-11 items-center gap-2 rounded-md border border-white/15 bg-white/[0.02] px-5 text-sm font-semibold text-white transition-colors hover:bg-white/[0.06] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-300 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-base"
            >
              {demo ? 'Open the live dashboard' : 'Open the dashboard'}
            </Link>
          </div>
        </div>
      </section>

      <section className="px-6 pb-24">
        <div className="mx-auto max-w-3xl">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-500">
            Popular destinations
          </h2>
          <ul className="mt-4 grid gap-3 sm:grid-cols-2">
            {DESTINATIONS.map((dest) => {
              const external = dest.external ?? false;
              return (
                <li key={dest.href}>
                  <Link
                    href={dest.href}
                    rel={external ? 'noreferrer' : undefined}
                    target={external ? '_blank' : undefined}
                    className="group flex h-full flex-col gap-1.5 rounded-xl border border-white/10 bg-white/[0.02] p-4 transition-colors hover:border-brand-500/40 hover:bg-white/[0.04] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-300 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-base"
                  >
                    <span className="flex items-center gap-2 text-sm font-semibold text-white">
                      {dest.label}
                      <ArrowRight
                        className="h-3.5 w-3.5 text-brand-300 transition-transform group-hover:translate-x-0.5"
                        aria-hidden="true"
                      />
                    </span>
                    <span className="text-sm text-gray-400">{dest.blurb}</span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      </section>

      <Footer />
    </main>
  );
}
