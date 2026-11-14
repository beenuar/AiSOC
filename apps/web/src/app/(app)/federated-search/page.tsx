import { FederatedSearchView } from '@/components/federated/FederatedSearchView';

export const metadata = {
  title: 'Federated search',
  description:
    'Query every connected SIEM in one place, with a per-backend verdict for each.',
};

// The view issues tenant-scoped, credential-backed queries. Nothing about it
// is cacheable across requests.
export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';

export default function FederatedSearchPage() {
  return <FederatedSearchView />;
}
