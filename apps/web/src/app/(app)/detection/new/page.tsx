import { RuleEditor } from '@/components/detections/RuleEditor';

export const metadata = {
  title: 'New detection rule',
};

export default function NewDetectionPage() {
  return <RuleEditor mode="create" />;
}
