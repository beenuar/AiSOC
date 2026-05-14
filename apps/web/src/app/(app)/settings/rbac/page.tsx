import { RBACView } from '@/components/settings/RBACView';

export const metadata = {
  title: 'Roles & Permissions',
};

export default function RBACPage() {
  return (
    <div className="p-6">
      <RBACView />
    </div>
  );
}
