import { PlaybookEditor } from '@/components/playbooks/PlaybookEditor';
import { ClientOnly } from '@/components/util/ClientOnly';
import { SkeletonCard } from '@/components/ui/Skeleton';

export const metadata = {
  title: 'Playbook Editor',
};

export default async function PlaybookEditorPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return (
    <div className="h-full">
      <ClientOnly
        fallback={
          <div className="space-y-4 p-6">
            <SkeletonCard />
          </div>
        }
      >
        <PlaybookEditor playbookId={id} />
      </ClientOnly>
    </div>
  );
}
