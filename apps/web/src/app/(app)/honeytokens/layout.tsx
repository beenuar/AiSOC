import type { Metadata } from 'next';

// The honeytokens page itself is a client component (`"use client"`), so it
// can't export `metadata` directly. Defining it on a colocated server layout
// lets the page contribute a real <title> ("Honeytokens | AiSOC" via the root
// layout's title template) instead of falling through to the global default.
export const metadata: Metadata = {
  title: 'Honeytokens',
  description: 'Generate, deploy, and monitor honeytokens with first-touch alerting.',
};

export default function HoneytokensLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
