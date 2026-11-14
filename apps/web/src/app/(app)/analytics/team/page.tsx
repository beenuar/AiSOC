import { TeamAnalyticsView } from '@/components/analytics/TeamAnalyticsView';

export const metadata = { title: 'Team Analytics' };

export default function TeamAnalyticsPage() {
  return (
    <div className="p-6 max-w-7xl mx-auto">
      <TeamAnalyticsView />
    </div>
  );
}
