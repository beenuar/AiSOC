'use client';

import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { CommandPalette } from './CommandPalette';
import { CopilotDock } from '@/components/copilot/CopilotDock';
import { DemoBanner } from '@/components/demo/DemoBanner';
import { isDemoMode } from '@/lib/demoMode';

interface AppShellProps {
  children: React.ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  // In demo mode the banner adds 36px (h-9) to the top, so push the main
  // content down to keep the TopBar from sliding underneath it.
  const demo = isDemoMode();
  const topPadClass = demo ? 'pt-[100px]' : 'pt-16';

  return (
    <div className="min-h-screen bg-[#0a0d14]">
      <DemoBanner />
      <Sidebar />
      <div className="ml-60">
        <TopBar demoOffset={demo} />
        <main className={`${topPadClass} min-h-screen`}>
          <div className="p-6">{children}</div>
        </main>
      </div>
      {/* Floating Copilot launcher (hidden on /copilot itself) */}
      <CopilotDock />
      {/* Global command palette (⌘K) */}
      <CommandPalette />
    </div>
  );
}
