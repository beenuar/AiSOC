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
import { EXECUTABLE_DETECTION_COUNT } from '@/data/corpusStats';

/**
 * AiSOC root (`/`) — marketing landing page.
 *
 * Two sections here were arguments made out of nothing. `DemoEmbed` drew a
 * hand-authored Investigation Ledger — an invented incident id, an invented
 * confidence, an invented dollar spend against a named hosted model — and was
 * the only place the site claimed to show the console. `Testimonials` offered
 * to onboard reference partners through a window that had already closed.
 * They are replaced by `ProductTour`, which is four captures of a running
 * stack, and `HonestLimits`, which is the list of things the product does not
 * do yet. Both are server components; the pair they replace shipped
 * framer-motion, a BorderBeam and a meteor field to animate claims that were
 * not true.
 *
 * Above-the-fold sections
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
const ProductTour = dynamic(
  () => import('@/components/landing/sections/ProductTour').then((m) => m.ProductTour),
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
const HonestLimits = dynamic(
  () => import('@/components/landing/sections/HonestLimits').then((m) => m.HonestLimits),
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
  description: `AiSOC is an MIT-licensed, agentic SOC: four specialised agents (Detect, Triage, Hunt, Respond), ${CONNECTOR_COUNT} first-party connectors, ${EXECUTABLE_DETECTION_COUNT} executable detection rules and a replayable decision ledger. One command brings up the whole pipeline with a local model and a live CISA feed — no API keys of any kind.`,
  alternates: { canonical: '/' },
  openGraph: {
    title: 'AiSOC — open-source AI Security Operations Center',
    description: `Four agents, ${CONNECTOR_COUNT} connectors, ${EXECUTABLE_DETECTION_COUNT} executable detections and a replayable ledger. Runs the whole pipeline with no API keys. MIT-licensed, self-hosted.`,
    url: siteUrl,
    siteName: 'AiSOC',
    type: 'website',
    locale: 'en_US',
    images: [
      {
        url: '/og-image.png',
        width: 1200,
        height: 630,
        alt: `AiSOC — open-source AI SOC with four specialised agents and ${CONNECTOR_COUNT} connectors`,
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'AiSOC — open-source AI Security Operations Center',
    description: `Four agents. ${CONNECTOR_COUNT} connectors. ${EXECUTABLE_DETECTION_COUNT} executable detections. A replayable decision ledger. No API keys required. MIT-licensed.`,
    images: ['/og-image.png'],
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
  description: `AiSOC is an MIT-licensed agentic Security Operations Center: four specialised agents (Detect, Triage, Hunt, Respond), ${CONNECTOR_COUNT} first-party connectors, ${EXECUTABLE_DETECTION_COUNT} executable detection rules, and a core profile that brings the whole pipeline up with no credentials of any kind.`,
  featureList: [
    'Four specialised agents: Detect, Triage, Hunt, Respond',
    `${CONNECTOR_COUNT} first-party connectors across EDR, SIEM, cloud, IAM, SaaS, VCS, network`,
    `${EXECUTABLE_DETECTION_COUNT} executable detection rules loaded by the fusion engine`,
    'Runs with no API keys: a local model behind the gateway and a keyless CISA Known Exploited Vulnerabilities feed ship in the core profile',
    'Replayable Investigation Ledger recording every prompt, tool call, verdict, token count and cost',
    'Governed response actions: per-capability contracts, human approval, and a vendor-side probe that verifies the action landed',
    'Two-way SIEM writeback of agent dispositions, off by default',
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
      name: 'Do I need an API key to try it?',
      acceptedAnswer: {
        '@type': 'Answer',
        text:
          'No. The core profile brings up 14 services with no credentials of any kind: it generates its own secrets, creates an administrator, runs a local model behind the gateway so triage is real rather than stubbed, and polls the public CISA Known Exploited Vulnerabilities catalogue so the first thing you see is real threat intelligence.',
      },
    },
    {
      '@type': 'Question',
      name: 'How good is the model that ships with it?',
      acceptedAnswer: {
        '@type': 'Answer',
        text:
          'It is a 3B quantized model sized for CPU inference, and the difference from a frontier model is visible. In a measured run of 19 auto-triages on a core stack, 7 returned schema-valid output and 12 did not; the 12 fell back to the deterministic path and the Investigation Rail shows which path produced the verdict it is displaying. Point the gateway at a hosted provider and that changes — but no hosted provider has ever been exercised in this repository, so those rows read "not measured" rather than zero.',
      },
    },
    {
      '@type': 'Question',
      name: 'What does the agent call out to?',
      acceptedAnswer: {
        '@type': 'Answer',
        text:
          'Nothing, on a default install: the model runs beside the console and no prompt leaves the machine. Point the gateway at OpenAI, Anthropic, Azure or Bedrock by setting three variables in .env. Set AISOC_AIRGAPPED=true and the platform refuses every outbound call.',
      },
    },
    {
      '@type': 'Question',
      name: 'Where does my data live?',
      acceptedAnswer: {
        '@type': 'Answer',
        text:
          'Wherever you point Postgres, Kafka and Redis, because that is the whole deployment. Connector credentials are encrypted at rest with Fernet AES-128-CBC + HMAC-SHA256. Tenant isolation is enforced at the query layer in every store and by row-level security on 83 Postgres tables, with services connecting as a DML-only role so those policies actually apply to them.',
      },
    },
    {
      '@type': 'Question',
      name: 'Can the agent take real-world action without a human?',
      acceptedAnswer: {
        '@type': 'Answer',
        text:
          'No. An action is proposed, approved by someone who holds the required permission and who is not the person who requested it, executed, and then verified by probing the vendor rather than by reading an HTTP 200. Risk, reversibility and approval tier are declared per capability, and a capability whose effect cannot be verified is not eligible for automatic execution. Without vendor credentials an executor returns "simulated" and says so.',
      },
    },
    {
      '@type': 'Question',
      name: 'How is AiSOC kept secure and up to date?',
      acceptedAnswer: {
        '@type': 'Answer',
        text:
          'Every pull request runs a CI-gated security audit (pip-audit + pnpm audit) that blocks the merge on any unresolved CVE, alongside CodeQL static analysis with a gate that fails on an open alert at any severity and refuses to pass on an analysis that belongs to a different commit. The audit policy lives in scripts/security_audit.py.',
      },
    },
    {
      '@type': 'Question',
      name: 'How is this benchmarked?',
      acceptedAnswer: {
        '@type': 'Answer',
        text:
          'Carefully, and with the labels attached. Only MITRE-tactic accuracy measures the live agent, and the per-pull-request run grades it with the deterministic tier and no model behind it. The other published figures are substrate self-consistency gates over a fixed synthetic corpus — they measure the harness, not the agent, and every surface that quotes them says so. The methodology page documents what each suite measures and what it does not.',
      },
    },
    {
      '@type': 'Question',
      name: 'How do connectors work?',
      acceptedAnswer: {
        '@type': 'Answer',
        text: `Each connector is a Python class that declares a schema, tests its credentials, polls on a schedule, and normalises events into OCSF. ${CONNECTOR_COUNT} ship in the box. The plugin SDKs (Python, TypeScript, Go) let you author your own in roughly 50 lines.`,
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
        <ProductTour />
        <Pillars />
        <FeatureGrid />
        <ConnectorsMarquee />
        <BenchmarkBand />
        <DeployOptions />
        <OpenSourceMoment />
        <HonestLimits />
        <PricingTeaser />
        <Faq />
        <FinalCta />
        <Footer />
      </main>
    </>
  );
}
