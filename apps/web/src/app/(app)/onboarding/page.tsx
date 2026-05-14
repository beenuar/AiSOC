import { Suspense } from 'react';
import { OnboardingView } from '@/components/onboarding/OnboardingView';

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
      <OnboardingView />
    </Suspense>
  );
}
