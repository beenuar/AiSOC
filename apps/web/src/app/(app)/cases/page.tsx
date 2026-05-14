import { CasesView } from '@/components/cases/CasesView';
import {
  normalizeCasesResponse,
  type CasesResponse,
} from '@/lib/api';

export const metadata = {
  title: 'Cases',
};

// The /cases page must reflect the current state of the backend on every
// request; static prerendering and CDN caching previously caused stale mock
// data to be served when client-side hydration failed.
export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';

const DEFAULT_TENANT_ID = '00000000-0000-0000-0000-000000000001';

function resolveServerApiBase(): string {
  // Prefer the in-cluster mesh URL when running on Fly so SSR doesn't depend
  // on public DNS or TLS. Fall back to the public API base for local dev.
  const internal = process.env.API_URL?.trim();
  if (internal) return internal.replace(/\/+$/, '');
  const publicBase = process.env.NEXT_PUBLIC_API_URL?.trim();
  if (publicBase) return publicBase.replace(/\/+$/, '');
  return '';
}

async function loadInitialCases(): Promise<CasesResponse | null> {
  const base = resolveServerApiBase();
  if (!base) return null;
  const tenantId =
    process.env.NEXT_PUBLIC_TENANT_ID?.trim() || DEFAULT_TENANT_ID;
  try {
    const res = await fetch(`${base}/api/v1/cases`, {
      headers: {
        Accept: 'application/json',
        'X-Tenant-Id': tenantId,
      },
      cache: 'no-store',
      next: { revalidate: 0 },
    });
    if (!res.ok) return null;
    const raw = await res.json();
    return normalizeCasesResponse(raw);
  } catch {
    return null;
  }
}

export default async function CasesPage() {
  const initialCases = await loadInitialCases();
  return <CasesView initialCases={initialCases ?? undefined} />;
}
