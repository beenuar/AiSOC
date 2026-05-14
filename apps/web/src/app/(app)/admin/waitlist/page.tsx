'use client';

/**
 * `/admin/waitlist` — support-team triage view for the managed-instance
 * waitlist (T6.1).
 *
 * Lists every entry from `GET /v1/waitlist/entries` and lets an admin:
 *
 *   - Filter by status (new / contacted / onboarded / declined / all).
 *   - Patch the status of any entry inline.
 *   - "Promote to tenant" any entry → calls
 *     `POST /v1/admin/tenants/provision` and surfaces the resulting
 *     invite URL so the operator can paste it into the email they
 *     send to the customer's initial admin.
 *
 * The page intentionally keeps state in component-local React rather
 * than reaching for SWR — every action here triggers a refetch of
 * the entries list as the simplest possible cache-invalidation
 * strategy, and the list is small enough (~hundreds of rows at
 * worst) that re-rendering is a non-issue.
 *
 * Sits inside the existing `(app)` AppShell layout so navigation,
 * search palette, and theme behave identically to the rest of the
 * console.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';

// ---------------------------------------------------------------------------
// Wire types — mirror services/api/app/api/v1/endpoints/waitlist.py
// ---------------------------------------------------------------------------

type WaitlistStatus = 'new' | 'contacted' | 'onboarded' | 'declined';

type WaitlistEntry = {
  id: string;
  email: string;
  company: string;
  role: string;
  soc_stack: string[];
  motivation: string;
  status: WaitlistStatus;
  provisioned_tenant_id: string | null;
  created_at: string;
  contacted_at: string | null;
  onboarded_at: string | null;
};

type WaitlistEntriesResponse = {
  entries: WaitlistEntry[];
  total: number;
};

type ProvisionResponse = {
  tenant_id: string;
  tenant_slug: string;
  tenant_name: string;
  waitlist_entry_id: string;
  admin_user: { id: string; email: string; role: string };
  admin_invite: { token: string; expires_at: string; url: string };
  demo_seeded: boolean;
  aisoc_credential_key_fingerprint: string;
};

const STATUS_FILTERS: { label: string; value: WaitlistStatus | 'all' }[] = [
  { label: 'All', value: 'all' },
  { label: 'New', value: 'new' },
  { label: 'Contacted', value: 'contacted' },
  { label: 'Onboarded', value: 'onboarded' },
  { label: 'Declined', value: 'declined' },
];

const STATUS_ORDER: WaitlistStatus[] = ['new', 'contacted', 'onboarded', 'declined'];

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function AdminWaitlistPage() {
  const [statusFilter, setStatusFilter] = useState<WaitlistStatus | 'all'>('all');
  const [entries, setEntries] = useState<WaitlistEntry[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyRow, setBusyRow] = useState<string | null>(null);
  const [lastInvite, setLastInvite] = useState<ProvisionResponse | null>(null);

  const fetchEntries = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const qs = statusFilter === 'all' ? '' : `?status_filter=${statusFilter}`;
      const response = await fetch(`/api/v1/waitlist/entries${qs}`, {
        method: 'GET',
        cache: 'no-store',
      });
      if (!response.ok) {
        const body = await response.text().catch(() => '');
        throw new Error(`HTTP ${response.status}: ${body.slice(0, 240)}`);
      }
      const payload = (await response.json()) as WaitlistEntriesResponse;
      setEntries(payload.entries);
      setTotal(payload.total);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => {
    void fetchEntries();
  }, [fetchEntries]);

  const handleStatusChange = async (
    entryId: string,
    nextStatus: WaitlistStatus,
  ) => {
    setBusyRow(entryId);
    try {
      const response = await fetch(`/api/v1/waitlist/entries/${entryId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: nextStatus }),
      });
      if (!response.ok) {
        const body = await response.text().catch(() => '');
        throw new Error(`HTTP ${response.status}: ${body.slice(0, 240)}`);
      }
      await fetchEntries();
    } catch (err) {
      setError(`Could not patch entry: ${(err as Error).message}`);
    } finally {
      setBusyRow(null);
    }
  };

  const handlePromote = async (entryId: string) => {
    setBusyRow(entryId);
    setError(null);
    try {
      const response = await fetch('/api/v1/admin/tenants/provision', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ waitlist_entry_id: entryId, seed_demo: true }),
      });
      if (!response.ok) {
        const body = await response.text().catch(() => '');
        throw new Error(`HTTP ${response.status}: ${body.slice(0, 240)}`);
      }
      const payload = (await response.json()) as ProvisionResponse;
      setLastInvite(payload);
      await fetchEntries();
    } catch (err) {
      setError(`Could not provision tenant: ${(err as Error).message}`);
    } finally {
      setBusyRow(null);
    }
  };

  const counts = useMemo(() => {
    const buckets: Record<WaitlistStatus, number> = {
      new: 0,
      contacted: 0,
      onboarded: 0,
      declined: 0,
    };
    for (const entry of entries) {
      buckets[entry.status] = (buckets[entry.status] ?? 0) + 1;
    }
    return buckets;
  }, [entries]);

  return (
    <div className="space-y-6 p-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight text-white">
          Managed waitlist
        </h1>
        <p className="mt-1 text-sm text-gray-400">
          Triage incoming requests for <code className="rounded bg-white/[0.05] px-1">app.aisoc.dev</code>{' '}
          managed tenants. Promote an entry to mint the tenant, seed the
          demo dataset, and generate the initial admin invite link.
        </p>
      </header>

      <section className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {STATUS_ORDER.map((status) => (
          <div
            key={status}
            className="rounded-xl border border-white/10 bg-white/[0.02] px-4 py-3"
          >
            <div className="text-xs uppercase tracking-wide text-gray-500">
              {status}
            </div>
            <div className="mt-1 text-2xl font-semibold text-white">
              {counts[status]}
            </div>
          </div>
        ))}
      </section>

      <section className="flex flex-wrap items-center gap-2">
        {STATUS_FILTERS.map((opt) => (
          <button
            key={opt.value}
            onClick={() => setStatusFilter(opt.value)}
            className={
              'rounded-full border px-3 py-1.5 text-xs font-medium transition ' +
              (statusFilter === opt.value
                ? 'border-brand-500/40 bg-brand-500/10 text-brand-200'
                : 'border-white/10 bg-white/[0.03] text-gray-300 hover:border-white/20 hover:text-white')
            }
          >
            {opt.label}
          </button>
        ))}
        <button
          onClick={() => fetchEntries()}
          className="ml-auto rounded-md border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:border-white/20 hover:text-white"
        >
          Refresh
        </button>
      </section>

      {lastInvite && (
        <InviteCard
          invite={lastInvite}
          onDismiss={() => setLastInvite(null)}
        />
      )}

      {error && (
        <div
          role="alert"
          className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200"
        >
          {error}
        </div>
      )}

      <section className="overflow-x-auto rounded-2xl border border-white/10 bg-white/[0.02]">
        <table className="w-full min-w-[960px] border-collapse text-sm">
          <thead>
            <tr className="text-left text-[11px] font-semibold uppercase tracking-wider text-gray-500">
              <th className="px-5 py-3">Company / role</th>
              <th className="px-5 py-3">Email</th>
              <th className="px-5 py-3">Stack</th>
              <th className="px-5 py-3">Status</th>
              <th className="px-5 py-3">Created</th>
              <th className="px-5 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && entries.length === 0 && (
              <tr>
                <td colSpan={6} className="px-5 py-8 text-center text-sm text-gray-400">
                  Loading…
                </td>
              </tr>
            )}
            {!loading && entries.length === 0 && (
              <tr>
                <td colSpan={6} className="px-5 py-8 text-center text-sm text-gray-500">
                  No entries{statusFilter !== 'all' ? ` with status "${statusFilter}"` : ''}.
                </td>
              </tr>
            )}
            {entries.map((entry, i) => (
              <tr
                key={entry.id}
                className={
                  'border-t border-white/5 ' +
                  (i % 2 === 0 ? '' : 'bg-white/[0.015]')
                }
              >
                <td className="px-5 py-3 align-top">
                  <div className="font-medium text-white">{entry.company}</div>
                  <div className="text-xs text-gray-500">{entry.role}</div>
                  <div className="mt-1 line-clamp-2 max-w-md text-xs text-gray-400">
                    {entry.motivation}
                  </div>
                </td>
                <td className="px-5 py-3 align-top">
                  <a
                    href={`mailto:${entry.email}`}
                    className="font-mono text-xs text-brand-300 hover:underline"
                  >
                    {entry.email}
                  </a>
                </td>
                <td className="px-5 py-3 align-top">
                  <div className="flex max-w-xs flex-wrap gap-1">
                    {entry.soc_stack.length === 0 && (
                      <span className="text-xs text-gray-500">—</span>
                    )}
                    {entry.soc_stack.slice(0, 4).map((stack) => (
                      <span
                        key={stack}
                        className="rounded-full border border-white/10 bg-white/[0.03] px-2 py-0.5 text-[11px] text-gray-300"
                      >
                        {stack}
                      </span>
                    ))}
                    {entry.soc_stack.length > 4 && (
                      <span className="text-[11px] text-gray-500">
                        +{entry.soc_stack.length - 4}
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-5 py-3 align-top">
                  <select
                    value={entry.status}
                    onChange={(e) =>
                      handleStatusChange(entry.id, e.target.value as WaitlistStatus)
                    }
                    disabled={busyRow === entry.id}
                    className="rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 text-xs text-gray-200 focus:border-brand-500/50 focus:outline-none"
                    aria-label={`Status for ${entry.company}`}
                  >
                    {STATUS_ORDER.map((s) => (
                      <option key={s} value={s} className="bg-surface-base">
                        {s}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="px-5 py-3 align-top text-xs text-gray-400">
                  {formatDate(entry.created_at)}
                </td>
                <td className="px-5 py-3 text-right align-top">
                  <button
                    onClick={() => handlePromote(entry.id)}
                    disabled={
                      busyRow === entry.id ||
                      entry.status === 'declined' ||
                      !!entry.provisioned_tenant_id
                    }
                    className={
                      'rounded-md border px-3 py-1.5 text-xs font-medium transition ' +
                      (busyRow === entry.id ||
                      entry.status === 'declined' ||
                      entry.provisioned_tenant_id
                        ? 'cursor-not-allowed border-white/5 bg-white/[0.02] text-gray-600'
                        : 'border-brand-500/40 bg-brand-500/10 text-brand-200 hover:bg-brand-500/20')
                    }
                  >
                    {entry.provisioned_tenant_id
                      ? 'Provisioned'
                      : busyRow === entry.id
                        ? 'Promoting…'
                        : 'Promote to tenant'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <footer className="text-xs text-gray-500">
        Total entries returned: {total}
      </footer>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers + sub-components
// ---------------------------------------------------------------------------

function formatDate(iso: string): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

type InviteCardProps = {
  invite: ProvisionResponse;
  onDismiss: () => void;
};

function InviteCard({ invite, onDismiss }: InviteCardProps) {
  return (
    <section
      role="status"
      className="rounded-2xl border border-emerald-500/20 bg-emerald-500/[0.04] p-5"
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-white">
            Tenant provisioned:{' '}
            <span className="font-mono text-brand-300">{invite.tenant_slug}</span>
          </h2>
          <p className="mt-1 text-xs text-gray-300">
            Email the initial admin invite link below to{' '}
            <span className="font-mono text-emerald-200">
              {invite.admin_user.email}
            </span>
            . Demo dataset seeded:{' '}
            <strong className="text-white">
              {invite.demo_seeded ? 'yes' : 'no'}
            </strong>
            . Credential-key fingerprint:{' '}
            <code className="rounded bg-white/[0.05] px-1 text-[11px]">
              {invite.aisoc_credential_key_fingerprint || '—'}
            </code>
            .
          </p>
          <textarea
            readOnly
            rows={2}
            className="mt-3 w-full rounded-md border border-white/10 bg-black/30 px-3 py-2 font-mono text-xs text-emerald-200"
            value={invite.admin_invite.url}
          />
          <p className="mt-2 text-[11px] text-gray-500">
            Invite expires {new Date(invite.admin_invite.expires_at).toLocaleString()}.
          </p>
        </div>
        <button
          onClick={onDismiss}
          className="rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 text-xs text-gray-300 hover:border-white/20 hover:text-white"
        >
          Dismiss
        </button>
      </div>
    </section>
  );
}
