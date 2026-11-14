import { AccessReviewView } from '@/components/access-review/AccessReviewView';

export const metadata = {
  title: 'Access review',
  description:
    'What each principal was granted, through which object, and whether it was used. Read-only.',
};

// Tenant-scoped findings computed from this tenant's own posture and usage.
// Nothing here is cacheable across requests.
export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';

export default function AccessReviewPage() {
  return <AccessReviewView />;
}
