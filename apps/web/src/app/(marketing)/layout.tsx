import type { ReactNode } from 'react';
import { velvetFontVariables, VELVET_FONT_PRELOADS } from '@/lib/marketing-fonts';
import { FontPreloads } from '@/components/fonts/FontPreloads';
import { StickyNav } from '@/components/landing/sections/StickyNav';
import { Footer } from '@/components/landing/sections/Footer';

/**
 * Marketing route-group layout (T7.1 VelvetEdge retheme, ISSUE-006
 * shell unification 2026-06-29).
 *
 * Scopes the velvet jewel-tone fonts (DM Serif Display / Poppins /
 * Source Code Pro) and the `.velvet-root` CSS-variable boundary to
 * the marketing surfaces (`/sovereign`, `/customers`, `/blog`,
 * `/waitlist`, …) so they share the look of the root landing at `/`.
 *
 * Why nav + footer live here (and no longer in every page.tsx)
 * -----------------------------------------------------------
 * Before this refactor every (marketing) page imported `LandingNav`
 * and `landing/Footer` and rendered them in JSX. That meant:
 *   - 11 marketing pages plus a few standalones (`/benchmark`,
 *     `/why-open-source`, `/not-found`) had two *different* shells
 *     than the landing page itself, which used `StickyNav` and
 *     `sections/Footer`. Visitors saw the nav rebuild and the footer
 *     re-label every time they crossed a route boundary (Platform vs
 *     Product, 4 columns vs 5 columns, Sovereign vs Solutions).
 *   - The next person to add a marketing page could trivially forget
 *     either component and ship a chrome-less page.
 *
 * After this refactor:
 *   - The canonical site-wide chrome (`StickyNav` + `sections/Footer`)
 *     lives in exactly one place — here. Every (marketing) page is now
 *     a content-only component.
 *   - The landing page (`apps/web/src/app/page.tsx`) renders the same
 *     pair directly because Next.js layouts don't cascade across route
 *     groups; `/` is *not* under `(marketing)`.
 *   - `/benchmark`, `/why-open-source`, and the branded `not-found.tsx`
 *     also import the pair directly (they live at the app root, not
 *     inside the group).
 *   - The older `LandingNav` and `landing/Footer` files have been
 *     deleted; any future "marketing nav tweak" only needs to touch
 *     StickyNav.tsx and sections/Footer.tsx.
 *
 * The console (`/alerts`, `/cases`, …) lives in the `(app)` route
 * group, which has its own layout.tsx and is unaffected.
 */
export default function MarketingLayout({ children }: { children: ReactNode }) {
  return (
    <div
      data-theme="dark"
      className={`velvet-root relative min-h-screen bg-velvet-surface-base font-velvet-body text-velvet-content-primary ${velvetFontVariables}`}
    >
      <FontPreloads hrefs={VELVET_FONT_PRELOADS} />
      <StickyNav />
      {children}
      <Footer />
    </div>
  );
}
