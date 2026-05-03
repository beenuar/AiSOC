import { RuleEditor } from '@/components/detections/RuleEditor';

export const metadata = {
  title: 'New detection rule | AiSOC',
};

export default function NewDetectionPage() {
  return <RuleEditor mode="create" />;
}
