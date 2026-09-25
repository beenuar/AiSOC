import { AppShell } from '@/components/layout/AppShell';
import { demoModeReport } from '@/lib/demoMode';

// A Server Component, which is what makes this the right place to answer
// "is this a demo". Server code reads the *running container's* environment,
// so `AISOC_DEMO_MODE` is visible here; the browser bundle only ever has the
// value that was compiled into it. Resolving once here and handing the answer
// down means the shell and the banner cannot disagree with the server — which
// they previously could, and did, as React hydration error #418.
export default function AppLayout({ children }: { children: React.ReactNode }) {
  return <AppShell demoMode={demoModeReport().enabled}>{children}</AppShell>;
}
