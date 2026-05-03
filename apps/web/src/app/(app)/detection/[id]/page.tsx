import { RuleEditor } from '@/components/detections/RuleEditor';

interface DetectionEditPageProps {
  params: { id: string };
}

export const metadata = {
  title: 'Detection rule | AiSOC',
};

export default function DetectionEditPage({ params }: DetectionEditPageProps) {
  return <RuleEditor mode="edit" ruleId={params.id} />;
}
