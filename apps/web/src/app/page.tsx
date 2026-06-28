import type { Metadata } from 'next';
import dynamic from 'next/dynamic';
import { docs } from '@/lib/docs';
import { getPublicSiteUrl } from '@/lib/site';
import { velvetFontVariables } from '@/lib/marketing-fonts';
import { StickyNav } from '@/components/landing/sections/StickyNav';
import { Hero } from '@/components/landing/sections/Hero';
import { ProofStrip } from '@/components/landing/sections/ProofStrip';
import { Problem } from '@/components/landing/sections/Problem';
import { CONNECTOR_COUNT } from '@/data/connectorCount';

/**
 * AiSOC root (`/`) — marketing landing page (T6.5).
 *
 * 16-section narrative for the v8.0 GTM push. Above-the-fold sections
 * (StickyNav, Hero, ProofStrip, Problem) are eagerly imported because
 * they sit inside the LCP window. Everything below the fold is loaded
 * via `next/dynamic` so the initial JS chunk shipped to the browser
 * stays well under the 180 kB gzipped budget in §12 of the brief.
 *
 * SSR is preserved for every section (`ssr: true` is the default of
 * `next/dynamic`); we only code-split the client-side bundle. That
 * keeps the SEO crawl path intact and lets the JSON-LD payload below
 * render the same copy a human visitor sees.
 *
 * The page is dark-locked via a nested `data-theme="dark"` boundary,
 * same pattern the previous root used — every gradient, glow, and
 * tinted overlay in the section components was tuned against the dark
 * palette and migrating each to themable tokens would balloon T6.5 for
 * no buyer-visible win. The console chrome (TopBar / Sidebar / etc.)
 * still honours the toggle, which is what AGENTS.md WS-F1 promised.
 */

const SolutionAgents = dynamic(
  () => import('@/components/landing/sections/SolutionAgents').then((m) => m.SolutionAgents),
);
const DemoEmbed = dynamic(
  () => import('@/components/landing/sections/DemoEmbed').then((m) => m.DemoEmbed),
);
const Pillars = dynamic(
  () => import('@/components/landing/sections/Pillars').then((m) => m.Pillars),
);
const FeatureGrid = dynamic(
  () => import('@/components/landing/sections/FeatureGrid').then((m) => m.FeatureGrid),
);
const ConnectorsMarquee = dynamic(
  () => import('@/components/landing/sections/ConnectorsMarquee').then((m) => m.ConnectorsMarquee),
);
const BenchmarkBand = dynamic(
  () => import('@/components/landing/sections/BenchmarkBand').then((m) => m.BenchmarkBand),
);
const DeployOptions = dynamic(
  () => import('@/components/landing/sections/DeployOptions').then((m) => m.DeployOptions),
);
const OpenSourceMoment = dynamic(
  () => import('@/components/landing/sections/OpenSourceMoment').then((m) => m.OpenSourceMoment),
);
const Testimonials = dynamic(
  () => import('@/components/landing/sections/Testimonials').then((m) => m.Testimonials),
);
const PricingTeaser = dynamic(
  () => import('@/components/landing/sections/PricingTeaser').then((m) => m.PricingTeaser),
);
const Faq = dynamic(
  () => import('@/components/landing/sections/Faq').then((m) => m.Faq),
);
const FinalCta = dynamic(
  () => import('@/components/landing/sections/FinalCta').then((m) => m.FinalCta),
);
const Footer = dynamic(
  () => import('@/components/landing/sections/Footer').then((m) => m.Footer),
);

const siteUrl = getPublicSiteUrl();

export const metadata: Metadata = {
  // Use `absolute` so the root layout's `template: '%s | AiSOC'` does not
  // append a redundant " | AiSOC" to a title that already leads with the
  // brand.
  title: { absolute: 'AiSOC — open-source AI Security Operations Center' },
  description: `AiSOC is an MIT-licensed, agentic SOC: four specialised agents (Detect, Triage, Hunt, Respond), ${CONNECTOR_COUNT} first-party connectors, a 200-incident benchmark harness, and air-gap deploy on a single flag. Self-host in five minutes or join the managed waitlist.`,
  alternates: { canonical: '/' },
  openGraph: {
    title: 'AiSOC — open-source AI Security Operations Center',
    description: `Four agents, ${CONNECTOR_COUNT} connectors, a public benchmark, and air-gap on a flag. Self-host the full stack under MIT, or join the managed waitlist at tryaisoc.com.`,
    url: siteUrl,
    siteName: 'AiSOC',
    type: 'website',
    locale: 'en_US',
    images: [
      {
        url: '/og-image.svg',
        width: 1200,
        height: 630,
        alt: `AiSOC — open-source AI SOC with four specialised agents and ${CONNECTOR_COUNT} connectors`,
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'AiSOC — open-source AI Security Operations Center',
    description: `Four agents. ${CONNECTOR_COUNT} connectors. A public benchmark. Air-gap on a flag. MIT-licensed.`,
    images: ['/og-image.svg'],
  },
};

const productJsonLd = {
  '@context': 'https://schema.org',
  '@type': 'SoftwareApplication',
  name: 'AiSOC',
  alternateName: ['AI SOC', 'AiSOC Platform', 'Agentic SOC'],
  applicationCategory: 'SecurityApplication',
  applicationSubCategory: 'Security Operations Center',
  operatingSystem: 'Linux, macOS, Docker',
  license: 'https://opensource.org/licenses/MIT',
  url: siteUrl,
  downloadUrl: 'https://github.com/beenuar/AiSOC',
  installUrl: docs('quickstart'),
  releaseNotes: 'https://github.com/beenuar/AiSOC/releases',
  description: `AiSOC is an MIT-licensed agentic Security Operations Center: four specialised agents (Detect, Triage, Hunt, Respond), ${CONNECTOR_COUNT} first-party connectors, a public 200-incident benchmark, and air-gap deploy on a single environment flag.`,
  featureList: [
    'Four specialised agents: Detect, Triage, Hunt, Respond',
    `${CONNECTOR_COUNT} first-party connectors across EDR, SIEM, cloud, IAM, SaaS, VCS, network`,
    'Public 200-incident benchmark harness with substrate self-consistency gates',
    'Air-gap mode (AISOC_AIRGAPPED=true) with local Ollama sidecar',
    'L0–L4 automation maturity ladder for human-in-the-loop guardrails',
    'Encrypted connector vault (Fernet AES-128-CBC + HMAC-SHA256)',
    'Self-host on Render, Docker Compose, Fly.io, Helm, or AWS Terraform',
  ],
  offers: {
    '@type': 'Offer',
    price: '0',
    priceCurrency: 'USD',
    description: 'Free, MIT-licensed, self-hostable. Paid managed tier on waitlist.',
  },
};

const faqJsonLd = {
  '@context': 'https://schema.org',
  '@type': 'FAQPage',
  mainEntity: [
    {
      '@type': 'Question',
      name: 'Is AiSOC really open source?',
      acceptedAnswer: {
        '@type': 'Answer',
        text:
          'Yes — the agent, the connectors, the detection rules, the benchmark dataset, and every piece of infrastructure code are MIT-licensed. There is no private fork.',
      },
    },
    {
      '@type': 'Question',
      name: 'What does the agent need to call out to?',
      acceptedAnswer: {
        '@type': 'Answer',
        text:
          'By default the Triage and Hunt agents call an LLM provider you configure (OpenAI, Anthropic, Azure, Bedrock, or a private LiteLLM gateway). Set AISOC_AIRGAPPED=true and the platform refuses every outbound call; an Ollama sidecar runs a local model in-cluster.',
      },
    },
    {
      '@type': 'Question',
      name: 'Where does my data live?',
      acceptedAnswer: {
        '@type': 'Answer',
        text:
          'Self-host: wherever you point Postgres, ClickHouse, and Redis. Managed: EU, US, or India region you pick at signup. Sovereign: a single-tenant VPC you control. The connector vault encrypts secrets with Fernet AES-128-CBC + HMAC-SHA256.',
      },
    },
    {
      '@type': 'Question',
      name: 'Can the agent take real-world action without a human?',
      acceptedAnswer: {
        '@type': 'Answer',
        text:
          'Only inside the maturity tier you configure. L0 keeps the agent advisory only; L2 (the production default) lets it run reversible containment actions; L4 allows whitelisted closed-loop actions. Every action class is gated against blast radius.',
      },
    },
    {
      '@type': 'Question',
      name: 'How is AiSOC kept secure and up to date?',
      acceptedAnswer: {
        '@type': 'Answer',
        text:
          'Every pull request runs a CI-gated security audit (pip-audit + pnpm audit) that blocks the merge on any unresolved CVE, alongside CodeQL static analysis. Dependencies are kept current — the cryptography floor was recently raised to 44.0.1 to clear CVE-2024-12797, and detection-loop lookups are tenant-scoped so cross-tenant reads are impossible. The audit policy lives in scripts/security_audit.py.',
      },
    },
    {
      '@type': 'Question',
      name: 'How is this benchmarked?',
      acceptedAnswer: {
        '@type': 'Answer',
        text:
          'Five pytest suites in services/agents/tests/ run on every PR. Three are substrate self-consistency gates; the fourth is a real measurement against a fixed 1,000-alert noisy stream; the fifth is a coverage gate on the synthetic telemetry corpus. The methodology page documents what each suite measures and what it does not.',
      },
    },
    {
      '@type': 'Question',
      name: 'How do connectors work?',
      acceptedAnswer: {
        '@type': 'Answer',
        text:
          'Each connector is a Python class that declares a schema, tests its credentials, polls on a schedule, and normalises events into OCSF. 69 ship in the box. The plugin SDKs (Python, TypeScript, Go) let you author your own in roughly 50 lines.',
      },
    },
  ],
};

export default function HomePage() {
  return (
    <>
      <script
        type="application/ld+json"
        // eslint-disable-next-line react/no-danger -- JSON-LD payload for crawlers
        dangerouslySetInnerHTML={{ __html: JSON.stringify(productJsonLd) }}
      />
      <script
        type="application/ld+json"
        // eslint-disable-next-line react/no-danger -- JSON-LD FAQ payload for crawlers
        dangerouslySetInnerHTML={{ __html: JSON.stringify(faqJsonLd) }}
      />
      <main
        data-theme="dark"
        className={`velvet-root relative min-h-screen overflow-x-hidden bg-velvet-surface-base font-velvet-body text-velvet-content-primary ${velvetFontVariables}`}
      >
        <StickyNav />
        <Hero />
        <ProofStrip />
        <Problem />
        <SolutionAgents />
        <DemoEmbed />
        <Pillars />
        <FeatureGrid />
        <ConnectorsMarquee />
        <BenchmarkBand />
        <DeployOptions />
        <OpenSourceMoment />
        <Testimonials />
        <PricingTeaser />
        <Faq />
        <FinalCta />
        <Footer />
      </main>
    </>
  );
}
