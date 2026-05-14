import { CaseWorkspace } from '@/components/cases/CaseWorkspace';
import { ClientOnly } from '@/components/util/ClientOnly';
import { SkeletonCard } from '@/components/ui/Skeleton';

interface CasePageProps {
  params: Promise<{ id: string }>;
}

export const metadata = {
  title: 'Case workspace',
};

export default async function CaseDetailPage({ params }: CasePageProps) {
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
      <CaseWorkspace caseId={id} />
    </ClientOnly>
  );
}
