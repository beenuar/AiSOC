import { EASMView } from '@/components/easm/EASMView';

export const metadata = { title: 'EASM' };

export default function EASMPage() {
  return (
    <div className="p-6 max-w-7xl mx-auto">
      <EASMView />
    </div>
  );
}
