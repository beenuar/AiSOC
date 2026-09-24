'use client';

import { Suspense } from 'react';
import dynamic from 'next/dynamic';

const AttackGraphView = dynamic(
  () =>
    import('@/components/graph/AttackGraphView').then(
      (m) => m.AttackGraphView,
    ),
  {
    ssr: false,
    loading: () => (
      <div className="flex h-[60vh] items-center justify-center text-gray-400">
        Loading attack graph…
      </div>
    ),
  },
);

export default function AttackGraphClient() {
  // `AttackGraphView` reads `?entity=` via `useSearchParams`, which Next
  // requires to sit under a Suspense boundary.
  return (
    <Suspense
      fallback={
        <div className="flex h-[60vh] items-center justify-center text-gray-400">
          Loading attack graph…
        </div>
      }
    >
      <AttackGraphView />
    </Suspense>
  );
}
