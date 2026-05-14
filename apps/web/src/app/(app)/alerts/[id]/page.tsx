import { AlertDetailView } from '@/components/alerts/AlertDetailView';
import { ClientOnly } from '@/components/util/ClientOnly';
import { SkeletonCard } from '@/components/ui/Skeleton';

export const metadata = {
  title: 'Alert Detail',
};

export default async function AlertDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return (
    <ClientOnly
      fallback={
        <div className="space-y-4 p-6">
          <SkeletonCard />
          <SkeletonCard />
        </div>
      }
    >
      <AlertDetailView alertId={id} />
    </ClientOnly>
  );
}
