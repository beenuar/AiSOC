import type { Metadata } from 'next';
import { FimDashboard } from '@/components/fim/FimDashboard';

export const metadata: Metadata = {
  title: 'File Integrity Monitoring',
  description:
    'Real-time osquery file_events telemetry — track file creation, deletion, and modification across your fleet.',
};

export default function FimPage() {
  return <FimDashboard />;
}
