'use client';

import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { CommandPalette } from './CommandPalette';
import { CopilotDock } from '@/components/copilot/CopilotDock';

interface AppShellProps {
  children: React.ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  return (
    <div className="min-h-screen bg-[#0a0d14]">
      <Sidebar />
      <div className="ml-60">
        <TopBar />
        <main className="pt-16 min-h-screen">
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
