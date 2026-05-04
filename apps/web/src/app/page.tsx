import type { Metadata } from 'next';
import { LandingNav } from '@/components/landing/LandingNav';
import { Hero } from '@/components/landing/Hero';
import { Features } from '@/components/landing/Features';
import { Architecture } from '@/components/landing/Architecture';
import { MitreStrip } from '@/components/landing/MitreStrip';
import { OpenSource } from '@/components/landing/OpenSource';
import { Footer } from '@/components/landing/Footer';

export const metadata: Metadata = {
  title: 'AiSOC — Open-source AI Security Operations Center',
  description:
    'Real-time detection, autonomous triage, and MITRE ATT&CK-aware investigation in one MIT-licensed platform. Self-hosted, extensible, free forever.',
  alternates: { canonical: '/' },
  openGraph: {
    title: 'AiSOC — Open-source AI Security Operations Center',
    description:
      'Real-time detection, autonomous triage, and MITRE ATT&CK-aware investigation. MIT licensed. Community-built.',
    images: ['/og-image.svg'],
    type: 'website',
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
