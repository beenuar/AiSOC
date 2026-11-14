import { RuleEditor } from '@/components/detections/RuleEditor';
import { ClientOnly } from '@/components/util/ClientOnly';
import { SkeletonCard } from '@/components/ui/Skeleton';

interface DetectionEditPageProps {
  params: Promise<{ id: string }>;
}

export const metadata = {
  title: 'Detection rule',
};

export default async function DetectionEditPage({
  params,
}: DetectionEditPageProps) {
  const { id } = await params;
  return (
    <ClientOnly
      fallback={
        <div className="space-y-4 p-6">
          <SkeletonCard />
        </div>
      }
    >
      <RuleEditor mode="edit" ruleId={id} />
    </ClientOnly>
  );
}
