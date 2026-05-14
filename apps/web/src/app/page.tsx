import type { Metadata } from 'next';
import { LandingNav } from '@/components/landing/LandingNav';
import { Features } from '@/components/landing/Features';
import { Architecture } from '@/components/landing/Architecture';
import { MitreStrip } from '@/components/landing/MitreStrip';
import { OpenSource } from '@/components/landing/OpenSource';
import { Footer } from '@/components/landing/Footer';
import { StartHero } from '@/components/onboarding/StartHero';

/**
 * AiSOC root (`/`) — onboarding-first landing page (WS-A2).
 *
 * The plan asks the root to be an onboarding surface, not a marketing page:
 * three CTAs (Try the demo / Connect first source / Skip & explore) live
 * above the fold, with platform context (features, architecture, MITRE,
 * open-source pitch) reused below for visitors who want to read more before
 * clicking. The legacy hero/CTA strip is intentionally retired — buyers
 * shouldn't have to choose between "open the demo" and "open console" without
 * context. The new hero collapses both into a single primary path.
 */

export const metadata: Metadata = {
  // Use `absolute` so the root layout's `template: '%s | AiSOC'` doesn't
  // append a redundant " | AiSOC" to a title that already leads with the
  // brand. Without this, the homepage tab renders
  // `AiSOC — open-source AI Security Operations Center | AiSOC`.
  title: { absolute: 'AiSOC — open-source AI Security Operations Center' },
  description:
    'Open-source AI SOC: 200-incident eval harness, 26 click-and-connect security sources, MITRE ATT&CK-mapped autonomous investigation. Try the live demo or self-host in under 5 minutes.',
  alternates: { canonical: '/' },
};

export default function HomePage() {
  // The marketing landing is intentionally locked to the dark palette via a
  // nested `data-theme="dark"` boundary. The hero is built around fixed dark
  // gradient overlays (see `StartHero`, `Architecture`, `Features`) and the
  // copy was tuned against that backdrop. Migrating every decorative layer
  // to themable tokens would balloon the WS-F1 diff for negligible buyer
  // value. The console chrome (TopBar / Sidebar / AppShell) — i.e. the
  // surfaces a buyer actually inhabits — *does* honour the toggle, which is
  // the buyer-visible promise. See apps/docs/docs/operations/theming.md.
  return (
    <main
      data-theme="dark"
      className="relative min-h-screen overflow-x-hidden bg-surface-base text-fg-primary"
    >
      <LandingNav />
      <StartHero />
      <Features />
      <Architecture />
      <MitreStrip />
      <OpenSource />
      <Footer />
    </main>
  );
}
