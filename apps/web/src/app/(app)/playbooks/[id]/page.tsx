import { PlaybookEditor } from '@/components/playbooks/PlaybookEditor';

export const metadata = {
  title: 'Playbook Editor | AiSOC',
};

export default function PlaybookEditorPage({
  params,
}: {
  params: { id: string };
}) {
  return (
    <div className="h-full">
      <PlaybookEditor playbookId={params.id} />
    </div>
  );
}
