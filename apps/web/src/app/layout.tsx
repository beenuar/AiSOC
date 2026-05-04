import type { Metadata, Viewport } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import { Toaster } from 'react-hot-toast';
import './globals.css';
import { PwaBootstrap } from '@/components/pwa/PwaBootstrap';

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

export const metadata: Metadata = {
  title: {
    default: 'AiSOC — AI Security Operations Center',
    template: '%s | AiSOC',
  },
  description:
    'Open-source AI-powered Security Operations Center by Cyble. Real-time threat detection, autonomous investigation, MITRE ATT&CK-aware response — under MIT.',
  keywords: [
    'AiSOC',
    'SOC',
    'SIEM',
    'security operations',
    'AI security',
    'threat detection',
    'MITRE ATT&CK',
    'open source',
    'SOAR',
    'XDR',
    'Cyble',
  ],
  authors: [{ name: 'Cyble', url: 'https://cyble.com' }],
  creator: 'Cyble',
  metadataBase: new URL('https://aisoc.dev'),
  openGraph: {
    title: 'AiSOC — AI Security Operations Center',
    description:
      'Open-source AI-powered SOC. Real-time threat detection, autonomous investigation, MITRE ATT&CK-aware response.',
    type: 'website',
    siteName: 'AiSOC',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'AiSOC — AI Security Operations Center',
    description:
      'Open-source AI-powered SOC. Real-time threat detection, autonomous investigation, MITRE ATT&CK-aware response.',
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
  robots: { index: true, follow: true },
};

export const viewport: Viewport = {
  themeColor: '#0a0d14',
  width: 'device-width',
  initialScale: 1,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrainsMono.variable}`}>
      <body className="bg-[#0a0d14] text-gray-100 antialiased">
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
