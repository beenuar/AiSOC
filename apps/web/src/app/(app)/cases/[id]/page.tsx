import { CaseWorkspace } from '@/components/cases/CaseWorkspace';

interface CasePageProps {
  params: { id: string };
}

export const metadata = {
  title: 'Case workspace | AiSOC',
};

export default function CaseDetailPage({ params }: CasePageProps) {
  return <CaseWorkspace caseId={params.id} />;
}
