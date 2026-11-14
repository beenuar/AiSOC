import { UsersView } from '@/components/settings/UsersView';

export const metadata = {
  title: 'Users',
};

export default function UsersPage() {
  return (
    <div className="p-6">
      <div className="mb-4">
        <h2 className="text-xl font-bold text-gray-100">Users</h2>
        <p className="mt-0.5 text-sm text-gray-500">
          Manage members and their roles. Role changes revoke the member&apos;s active sessions and are audited.
        </p>
      </div>
      <UsersView />
    </div>
  );
}
