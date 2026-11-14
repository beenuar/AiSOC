import { Suspense } from 'react';
import { SettingsView } from '@/components/settings/SettingsView';
import { SkeletonCard } from '@/components/ui/Skeleton';

export const metadata = {
  title: 'Settings',
};

export default function SettingsPage() {
  return (
    <Suspense fallback={<SkeletonCard />}>
      <SettingsView />
    </Suspense>
  );
}
