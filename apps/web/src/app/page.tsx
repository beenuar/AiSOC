import type { Metadata } from 'next';
import { LandingNav } from '@/components/landing/LandingNav';
import { Hero } from '@/components/landing/Hero';
import { Features } from '@/components/landing/Features';
import { Architecture } from '@/components/landing/Architecture';
import { MitreStrip } from '@/components/landing/MitreStrip';
import { OpenSource } from '@/components/landing/OpenSource';
import { Footer } from '@/components/landing/Footer';
import { DISCOVERY_KEYWORDS, getPublicSiteUrl } from '@/lib/site';

export const metadata: Metadata = {
  title: 'AiSOC — Free Open-Source AI Security Operations Center | Self-Hosted SOC',
  description:
    'AiSOC is a free, MIT-licensed AI-powered SOC platform. Features: real-time threat detection, alert fusion, MITRE ATT&CK investigation, purple-team simulations, detection-as-code, and eval-gated agentic triage. Self-host or try the live demo at tryaisoc.com.',
  keywords: [...DISCOVERY_KEYWORDS],
  alternates: { canonical: getPublicSiteUrl() },
  openGraph: {
    title: 'AiSOC — Free Open-Source AI Security Operations Center',
    description:
      'Self-hostable AI SOC: threat detection, alert fusion, MITRE ATT&CK mapping, purple-team drills, and detection-as-code. MIT licensed, community-driven. Try tryaisoc.com.',
    url: getPublicSiteUrl(),
    images: [{ url: '/og-image.svg', width: 1200, height: 630, alt: 'AiSOC platform dashboard' }],
    type: 'website',
    siteName: 'AiSOC',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'AiSOC — Free Open-Source AI SOC Platform',
    description:
      'AI-powered SOC: threat detection, alert fusion, purple team, MITRE ATT&CK, detection-as-code. Self-host free — tryaisoc.com.',
    site: '@aisoc_dev',
  },
};

export default function LandingPage() {
  return (
    <main className="relative min-h-screen overflow-x-hidden bg-surface-base text-white">
      <LandingNav />
      <Hero />
      <Features />
      <Architecture />
      <MitreStrip />
      <OpenSource />
      <Footer />
    </main>
  );
}
