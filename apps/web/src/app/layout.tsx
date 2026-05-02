import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'AiSOC - AI Security Operations Center',
  description: 'Open-source AI-powered Security Operations Center by Cyble. Real-time threat detection, automated investigation, and intelligent response.',
  keywords: ['SOC', 'SIEM', 'security operations', 'AI', 'threat detection', 'MITRE ATT&CK'],
  authors: [{ name: 'Cyble', url: 'https://cyble.com' }],
  icons: {
    icon: '/favicon.ico',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={inter.variable}>
      <body className="bg-[#0a0d14] text-gray-100 antialiased">
        {children}
      </body>
    </html>
  );
}
