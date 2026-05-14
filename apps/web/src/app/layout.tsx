import type { Metadata, Viewport } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import { Toaster } from 'react-hot-toast';
import './globals.css';
import { PwaBootstrap } from '@/components/pwa/PwaBootstrap';
import { ThemeProvider } from '@/components/theme/ThemeProvider';
import { themeBootstrapScript } from '@/components/theme/themeScript';
import { DISCOVERY_KEYWORDS, getPublicSiteUrl } from '@/lib/site';

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  display: 'swap',
  // Only load on demand — monospace font is used in code blocks, not every page,
  // so preloading eagerly causes "preloaded but unused" browser warnings.
  preload: false,
});

const siteUrl = getPublicSiteUrl();

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  applicationName: 'AiSOC',
  title: {
    default: 'AiSOC — Open-Source AI Security Operations Center',
    template: '%s | AiSOC',
  },
  description:
    'AiSOC is a free, self-hostable AI-powered Security Operations Center (SOC). Real-time threat detection, alert fusion, purple-team exercises, MITRE ATT&CK-aware autonomous investigation, and detection-as-code — MIT-licensed and community-driven.',
  keywords: [...DISCOVERY_KEYWORDS],
  authors: [{ name: 'AiSOC Community', url: 'https://github.com/beenuar/AiSOC' }],
  creator: 'AiSOC Community',
  publisher: 'AiSOC',
  category: 'cybersecurity',
  classification: 'Security Software',
  openGraph: {
    title: 'AiSOC — Free, Open-Source AI Security Operations Center',
    description:
      'Self-hostable AI SOC with real-time threat detection, alert fusion, purple-team drills, MITRE ATT&CK investigation, and detection-as-code. MIT-licensed. Try the live demo at tryaisoc.com.',
    type: 'website',
    siteName: 'AiSOC',
    url: siteUrl,
    locale: 'en_US',
    images: [
      {
        url: '/og-image.svg',
        width: 1200,
        height: 630,
        alt: 'AiSOC — open-source AI SOC platform for security operations teams',
        type: 'image/svg+xml',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'AiSOC — Free Open-Source AI SOC Platform',
    description:
      'AI-powered SOC: threat detection, alert fusion, purple team, MITRE ATT&CK mapping, detection-as-code, and eval harness in CI. Self-host for free — tryaisoc.com.',
    site: '@aisoc_dev',
    creator: '@aisoc_dev',
  },
  icons: {
    // Single SVG favicon — modern browsers (Chrome 80+, Safari 16+, Firefox 41+,
    // Edge) all support this. We intentionally do not advertise /favicon.ico
    // because we don't ship a binary .ico file; declaring one only produces
    // 404s in the browser network tab.
    icon: [{ url: '/favicon.svg', type: 'image/svg+xml' }],
    apple: [{ url: '/icons/icon-192.svg', type: 'image/svg+xml' }],
  },
  manifest: '/manifest.json',
  appleWebApp: {
    capable: true,
    title: 'AiSOC',
    statusBarStyle: 'black-translucent',
  },
  robots: { index: true, follow: true, googleBot: { index: true, follow: true } },
  alternates: { canonical: siteUrl },
};

export const viewport: Viewport = {
  themeColor: '#0a0d14',
  width: 'device-width',
  initialScale: 1,
};

const jsonLd = {
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@type': 'Organization',
      name: 'AiSOC',
      url: siteUrl,
      logo: `${siteUrl}/favicon.svg`,
      description:
        'Community-driven, MIT-licensed AI security operations platform with a public demo and self-host path.',
      sameAs: [
        'https://github.com/beenuar/AiSOC',
        'https://tryaisoc.com',
      ],
      contactPoint: {
        '@type': 'ContactPoint',
        contactType: 'technical support',
        url: 'https://github.com/beenuar/AiSOC/issues',
      },
    },
    {
      '@type': 'SoftwareApplication',
      name: 'AiSOC',
      alternateName: ['AI SOC', 'AiSOC Platform', 'Open Source SOC'],
      applicationCategory: 'SecurityApplication',
      applicationSubCategory: 'Security Operations Center',
      operatingSystem: 'Linux, macOS, Docker',
      license: 'https://opensource.org/licenses/MIT',
      offers: {
        '@type': 'Offer',
        price: '0',
        priceCurrency: 'USD',
        description: 'Free, open-source, self-hostable',
      },
      url: siteUrl,
      downloadUrl: 'https://github.com/beenuar/AiSOC',
      installUrl: 'https://github.com/beenuar/AiSOC#quick-start',
      releaseNotes: 'https://github.com/beenuar/AiSOC/releases',
      featureList: [
        'Click-and-connect 26 security sources (EDR, SIEM, cloud, IAM, SaaS) with encrypted credential vault',
        'Real-time threat detection and alert fusion',
        'Entity risk-based alerting (RBA) queue',
        'Autonomous alert triage agent with confidence-scored verdicts',
        'Conversational, multi-turn investigation copilot',
        'MITRE ATT&CK mapping, coverage heatmap, and gap advisor',
        'Purple team simulation with detection drift tracking',
        'Detection-as-code with Sigma rule support and NL authoring',
        'Federated search across Splunk, Sentinel, and Elastic',
        'Hunt-as-code threat hunting engine',
        'Detection proposals and community-driven rule lifecycle',
        'Adversary simulation eval harness (200 incidents)',
        'SLA tracking, automated compliance evidence, and AI-generated incident reports',
        'MSSP multi-tenant support, shift-handoff dashboard, and team analytics',
        'External Attack Surface Management (EASM) and detection tuning workbench',
        'STIX 2.1 / TAXII 2.1 publishing and air-gap deployment configuration',
        'Self-hosted deployment with Docker Compose',
      ],
      screenshot: `${siteUrl}/og-image.svg`,
    },
    {
      '@type': 'WebSite',
      name: 'AiSOC',
      url: siteUrl,
      description: 'Open-source AI-powered Security Operations Center — tryaisoc.com',
      potentialAction: {
        '@type': 'SearchAction',
        target: `${siteUrl}/search?q={search_term_string}`,
        'query-input': 'required name=search_term_string',
      },
    },
  ],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    // Default to `data-theme="dark"` for SSR so that the markup React sends
    // matches what the bootstrap script will write before hydration. The
    // bootstrap script (rendered first thing inside <body>) flips this to
    // light/system if the user previously chose so, before any pixels are
    // painted — that's why we don't see a flash.
    <html
      lang="en"
      data-theme="dark"
      className={`${inter.variable} ${jetbrainsMono.variable}`}
      suppressHydrationWarning
    >
      <body className="bg-surface-base text-fg-primary antialiased">
        <script
          // eslint-disable-next-line react/no-danger -- pre-hydration theme bootstrap
          dangerouslySetInnerHTML={{ __html: themeBootstrapScript }}
        />
        <script
          type="application/ld+json"
          // eslint-disable-next-line react/no-danger -- JSON-LD for SEO crawlers
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
        <PwaBootstrap />
        <ThemeProvider>
          {children}
          <Toaster
            position="bottom-right"
            toastOptions={{
              duration: 4000,
              // Toast styles read CSS variables so the toaster flips with
              // the rest of the chrome. `iconTheme` only takes hex values,
              // so we pin the brand semantic colors there.
              style: {
                background: 'var(--surface-raised)',
                color: 'var(--fg-primary)',
                border: '1px solid var(--surface-border)',
                fontSize: '0.875rem',
              },
              success: {
                iconTheme: { primary: '#22c55e', secondary: '#0a0d14' },
              },
              error: {
                iconTheme: { primary: '#ef4444', secondary: '#0a0d14' },
              },
            }}
          />
        </ThemeProvider>
      </body>
    </html>
  );
}
