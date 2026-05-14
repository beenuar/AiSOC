import type { Metadata } from 'next';

// The purple-team page itself is a client component (`'use client'`), so it
// can't export `metadata` directly. Defining it on a colocated server layout
// lets the page contribute a real <title> ("Purple Team | AiSOC" via the root
// layout's title template) instead of falling through to the global default.
export const metadata: Metadata = {
  title: 'Purple Team',
  description:
    'Atomic Red Team execution, Caldera adversary emulation, ATT&CK coverage heatmap, and tabletop exercise simulator.',
};

export default function PurpleTeamLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
