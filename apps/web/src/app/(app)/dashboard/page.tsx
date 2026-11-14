import { DashboardView } from '@/components/dashboard/DashboardView';

export const metadata = {
  title: 'Dashboard',
};

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';

export default function DashboardPage() {
  return <DashboardView />;
}
