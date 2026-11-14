import { Suspense } from 'react';
import { OnboardingView } from '@/components/onboarding/OnboardingView';
import { SetupChecklist } from '@/components/onboarding/SetupChecklist';

export const metadata = {
  title: 'Get started',
};

// Onboarding has no static data — the catalog and any existing connectors
// come from the API at request time. Force dynamic so we never serve a
// stale "no connectors yet" snapshot to a tenant that has already onboarded.
export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';

export default function OnboardingPage() {
  return (
    <Suspense fallback={null}>
      {/* The checklist first: it answers "where am I and what is left",
          which is the question someone arriving here actually has. The
          connector picker below is the answer to the main step. */}
      <div className="mx-auto max-w-5xl px-6 pt-6">
        <SetupChecklist />
      </div>
      <OnboardingView />
    </Suspense>
  );
}
