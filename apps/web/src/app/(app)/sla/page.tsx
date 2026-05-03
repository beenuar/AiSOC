import { SLADashboard } from '@/components/sla/SLADashboard';

export const metadata = { title: 'SLA Tracking — AiSOC' };

export default function SLAPage() {
  return (
    <div className="p-6 max-w-6xl mx-auto">
      <SLADashboard />
    </div>
  );
}
