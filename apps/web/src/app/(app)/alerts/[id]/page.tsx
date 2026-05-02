import { AlertDetailView } from '@/components/alerts/AlertDetailView';

export const metadata = {
  title: 'Alert Detail | AiSOC',
};

export default function AlertDetailPage({ params }: { params: { id: string } }) {
  return <AlertDetailView alertId={params.id} />;
}
