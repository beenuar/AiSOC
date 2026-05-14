'use client';

/**
 * `/admin/tenants` — support-team triage view for live tenants (T6.1).
 *
 * Lists every tenant from `GET /v1/admin/tenants`, sorted newest first
 * (the API already orders by ``created_at DESC``). Supports two
 * filters:
 *
 *   • Free-text search across slug and name (ILIKE on the API side).
 *   • Managed-only toggle (filters on ``settings->>'managed' = 'true'``,
 *     i.e. tenants that came in through the T6.1 provisioning flow).
 *
 * Click a tenant row to navigate to its detail page. The detail page
 * itself lives outside the T6.1 scope (Subagent A is wiring in the
 * tenant detail surface as part of the wave-2 stabilization push); we
 * link by slug so the URL stays correct once the detail page lands.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';

// ---------------------------------------------------------------------------
// Wire types — mirror services/api/app/api/v1/endpoints/tenant_provision.py
// ---------------------------------------------------------------------------

type TenantListEntry = {
  id: string;
  name: string;
  slug: string;
  plan: string;
  is_active: boolean;
  is_managed: boolean;
  provisioned_from_waitlist_id: string | null;
  provisioned_at: string | null;
  created_at: string;
};

type TenantListResponse = {
  tenants: TenantListEntry[];
  total: number;
};

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function AdminTenantsPage() {
  const [query, setQuery] = useState('');
  const [managedOnly, setManagedOnly] = useState(false);
  const [tenants, setTenants] = useState<TenantListEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchTenants = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      const trimmed = query.trim();
      if (trimmed) params.set('q', trimmed);
      if (managedOnly) params.set('managed_only', 'true');
      const qs = params.toString();
      const response = await fetch(
        `/api/v1/admin/tenants${qs ? `?${qs}` : ''}`,
        { method: 'GET', cache: 'no-store' },
      );
      if (!response.ok) {
        const body = await response.text().catch(() => '');
        throw new Error(`HTTP ${response.status}: ${body.slice(0, 240)}`);
      }
      const payload = (await response.json()) as TenantListResponse;
      setTenants(payload.tenants);
      setTotal(payload.total);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [query, managedOnly]);

  // Debounce the search input so we don't fire one request per
  // keystroke. 250ms is the same dwell the rest of the console uses.
  useEffect(() => {
    const handle = window.setTimeout(() => {
      void fetchTenants();
    }, 250);
    return () => window.clearTimeout(handle);
  }, [fetchTenants]);

  const managedCount = useMemo(
    () => tenants.filter((t) => t.is_managed).length,
    [tenants],
  );

  return (
    <div className="space-y-6 p-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight text-white">
          Tenants
        </h1>
        <p className="mt-1 text-sm text-gray-400">
          Read-only directory of every tenant in this AiSOC deployment.
          Managed tenants — provisioned through the waitlist flow on{' '}
          <code className="rounded bg-white/[0.05] px-1">app.aisoc.dev</code>{' '}
          — are tagged in the list so the support team can scope
          their attention.
        </p>
      </header>

      <section className="grid grid-cols-2 gap-3 md:grid-cols-3">
        <SummaryCard label="Tenants" value={total} />
        <SummaryCard label="Managed" value={managedCount} />
        <SummaryCard
          label="Self-hosted"
          value={Math.max(total - managedCount, 0)}
        />
      </section>

      <section className="flex flex-wrap items-center gap-3">
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search slug or name…"
          className="w-72 rounded-md border border-white/10 bg-white/[0.03] px-3 py-2 text-sm text-white placeholder:text-gray-500 focus:border-brand-500/50 focus:outline-none focus:ring-2 focus:ring-brand-500/20"
          aria-label="Search tenants"
        />
        <label className="inline-flex cursor-pointer items-center gap-2 text-xs text-gray-300">
          <input
            type="checkbox"
            checked={managedOnly}
            onChange={(e) => setManagedOnly(e.target.checked)}
            className="h-4 w-4 rounded border-white/20 bg-white/[0.03]"
          />
          Managed only
        </label>
        <button
          onClick={() => fetchTenants()}
          className="ml-auto rounded-md border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:border-white/20 hover:text-white"
        >
          Refresh
        </button>
      </section>

      {error && (
        <div
          role="alert"
          className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200"
        >
          {error}
        </div>
      )}

      <section className="overflow-x-auto rounded-2xl border border-white/10 bg-white/[0.02]">
        <table className="w-full min-w-[840px] border-collapse text-sm">
          <thead>
            <tr className="text-left text-[11px] font-semibold uppercase tracking-wider text-gray-500">
              <th className="px-5 py-3">Tenant</th>
              <th className="px-5 py-3">Slug</th>
              <th className="px-5 py-3">Plan</th>
              <th className="px-5 py-3">Active</th>
              <th className="px-5 py-3">Provisioned</th>
              <th className="px-5 py-3">Created</th>
            </tr>
          </thead>
          <tbody>
            {loading && tenants.length === 0 && (
              <tr>
                <td colSpan={6} className="px-5 py-8 text-center text-sm text-gray-400">
                  Loading…
                </td>
              </tr>
            )}
            {!loading && tenants.length === 0 && (
              <tr>
                <td colSpan={6} className="px-5 py-8 text-center text-sm text-gray-500">
                  No tenants matched your filter.
                </td>
              </tr>
            )}
            {tenants.map((tenant, i) => (
              <tr
                key={tenant.id}
                className={
                  'border-t border-white/5 transition ' +
                  (i % 2 === 0 ? '' : 'bg-white/[0.015]') +
                  ' hover:bg-white/[0.03]'
                }
              >
                <td className="px-5 py-3">
                  <Link
                    href={`/admin/tenants/${tenant.slug}`}
                    className="font-medium text-white hover:text-brand-300"
                  >
                    {tenant.name}
                  </Link>
                  {tenant.is_managed && (
                    <span className="ml-2 inline-flex items-center gap-1 rounded-full border border-brand-500/30 bg-brand-500/10 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-brand-300">
                      Managed
                    </span>
                  )}
                </td>
                <td className="px-5 py-3 font-mono text-xs text-brand-300">
                  {tenant.slug}
                </td>
                <td className="px-5 py-3 text-xs text-gray-300">{tenant.plan}</td>
                <td className="px-5 py-3 text-xs">
                  {tenant.is_active ? (
                    <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-300">
                      Active
                    </span>
                  ) : (
                    <span className="rounded-full border border-gray-500/30 bg-gray-500/10 px-2 py-0.5 text-[10px] font-medium text-gray-400">
                      Inactive
                    </span>
                  )}
                </td>
                <td className="px-5 py-3 text-xs text-gray-400">
                  {tenant.provisioned_at
                    ? formatDate(tenant.provisioned_at)
                    : '—'}
                </td>
                <td className="px-5 py-3 text-xs text-gray-400">
                  {formatDate(tenant.created_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-components + helpers
// ---------------------------------------------------------------------------

function SummaryCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.02] px-4 py-3">
      <div className="text-xs uppercase tracking-wide text-gray-500">{label}</div>
      <div className="mt-1 text-2xl font-semibold text-white">{value}</div>
    </div>
  );
}

function formatDate(iso: string): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
