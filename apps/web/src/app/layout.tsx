import type { Metadata, Viewport } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import { Toaster } from 'react-hot-toast';
import './globals.css';
import { PwaBootstrap } from '@/components/pwa/PwaBootstrap';
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
    icon: [
      { url: '/favicon.svg', type: 'image/svg+xml' },
      { url: '/favicon.ico', sizes: 'any' },
    ],
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
        'Real-time threat detection and alert fusion',
        'AI-assisted alert triage and investigation',
        'MITRE ATT&CK mapping and coverage analysis',
        'Purple team simulation and detection validation',
        'Detection-as-code with Sigma rule support',
        'Connectors for Splunk, Sentinel, CrowdStrike, Elastic',
        'SLA tracking and compliance reporting',
        'Hunt-as-code threat hunting engine',
        'MSSP multi-tenant support',
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
    <html lang="en" className={`${inter.variable} ${jetbrainsMono.variable}`}>
      <body className="bg-[#0a0d14] text-gray-100 antialiased">
        <script
          type="application/ld+json"
          // eslint-disable-next-line react/no-danger -- JSON-LD for SEO crawlers
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
        <PwaBootstrap />
        {children}
        <Toaster
          position="bottom-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#11151f',
              color: '#e2e8f0',
              border: '1px solid rgba(59,130,246,0.2)',
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
      </body>
    </html>
  );
}
