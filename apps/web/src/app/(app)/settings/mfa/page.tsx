import { MfaView } from '@/components/settings/MfaView';

export const metadata = {
  title: 'Two-factor authentication',
};

export default function MfaSettingsPage() {
  return (
    <div className="p-6">
      <MfaView />
    </div>
  );
}
