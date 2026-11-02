'use client';

/**
 * Standing grants into the tenants this operator manages.
 *
 * Wave 2, Phase 9.5.
 *
 * `/api/v1/mssp/delegations` has had list, create and revoke since the MSSP
 * work, bound by nothing in the console. A delegation is authority over
 * somebody else's tenant, so "the only way to see what is granted is a curl
 * command" is the wrong place for this to have stayed.
 *
 * What this surface has to be careful about
 * -----------------------------------------
 * - **A failed read renders the failure, never an empty list.** "Nobody holds
 *   a delegation" and "we could not read the delegations" are opposite
 *   conclusions about an access-control surface, and an empty table quietly
 *   asserts the first.
 * - **The route's refusals are the useful text.** It refuses a role the
 *   caller does not itself hold — 403 when the role exists and is above them,
 *   422 when it is not a role at all. Those are different operator actions,
 *   so the message is surfaced verbatim rather than flattened.
 * - **Revocation that fails must not look like it worked.** The row stays
 *   until the server confirms, because a grant shown as revoked while it is
 *   live is the dangerous direction.
 * - **An expiry is shown as a fact, not an em dash.** A grant with no expiry
 *   is a standing key into a customer's tenant, and that is exactly the row
 *   an operator is scanning for.
 */

import { useCallback, useEffect, useState } from 'react';
import { format } from 'date-fns';
import toast from 'react-hot-toast';

import { delegationsApi, msspApi, type ChildTenant, type Delegation } from '@/lib/api';
import { EmptyState } from '@/components/ui/EmptyState';

/**
 * Roles a delegation can carry.
 *
 * The route is the authority — it refuses anything the caller does not hold —
 * so this list is an affordance, not a check. The two wildcard roles are
 * deliberately absent: a delegation is scoped authority over one customer
 * tenant, and `admin` / `platform_admin` resolve to `*`.
 */
const GRANTABLE_ROLES = ['viewer', 'soc_analyst', 'threat_hunter', 'soc_lead', 'tenant_admin'];

function describeError(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}

export function DelegationsPanel() {
  const [delegations, setDelegations] = useState<Delegation[]>([]);
  const [children, setChildren] = useState<ChildTenant[]>([]);
  const [childrenUnavailable, setChildrenUnavailable] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [draftChild, setDraftChild] = useState('');
  const [draftRole, setDraftRole] = useState('soc_analyst');
  const [draftExpiry, setDraftExpiry] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setDelegations(await delegationsApi.list());
      setLoadError(null);
    } catch (err) {
      setDelegations([]);
      setLoadError(describeError(err, 'Could not load delegations.'));
    } finally {
      setLoading(false);
    }

    try {
      setChildren(await msspApi.listChildren());
      setChildrenUnavailable(false);
    } catch {
      setChildren([]);
      setChildrenUnavailable(true);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const nameFor = (tenantId: string): string =>
    children.find((c) => c.id === tenantId)?.name ?? tenantId;

  const grant = async () => {
    if (!draftChild) {
      toast.error('Choose the managed tenant this grant is for');
      return;
    }
    let expires: string | null = null;
    if (draftExpiry.trim()) {
      const parsed = new Date(draftExpiry);
      if (Number.isNaN(parsed.getTime())) {
        toast.error('Expiry must be a valid date');
        return;
      }
      expires = parsed.toISOString();
    }

    setBusy(true);
    try {
      await delegationsApi.create({
        child_tenant_id: draftChild,
        granted_role: draftRole,
        expires_at: expires,
      });
      setDraftChild('');
      setDraftExpiry('');
      await load();
      toast.success('Delegation granted.');
    } catch (err) {
      toast.error(describeError(err, 'Could not grant the delegation'));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (delegation: Delegation) => {
    setBusy(true);
    try {
      await delegationsApi.revoke(delegation.id);
      await load();
      toast.success('Delegation revoked.');
    } catch (err) {
      toast.error(describeError(err, 'Could not revoke the delegation'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div data-testid="delegations-panel">
      <div className="border-b border-gray-800 px-6 py-4">
        <h2 className="text-base font-semibold text-gray-100">Delegations</h2>
        <p className="mt-1 text-sm text-gray-500">
          Standing grants your organisation holds into the tenants it manages.
          Each one is authority over somebody else&apos;s data.
        </p>
      </div>

      <div className="space-y-5 px-6 py-5">
        <div className="flex flex-col gap-3 rounded-lg border border-gray-800 bg-gray-950/40 p-4 sm:flex-row sm:items-end">
          <label className="flex-1 text-sm">
            <span className="mb-1 block text-gray-400">Managed tenant</span>
            <select
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 disabled:opacity-40"
              value={draftChild}
              disabled={children.length === 0 || busy}
              aria-label="Managed tenant"
              onChange={(e) => setDraftChild(e.target.value)}
            >
              <option value="">Choose a tenant…</option>
              {children.map((child) => (
                <option key={child.id} value={child.id}>
                  {child.name}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm sm:w-48">
            <span className="mb-1 block text-gray-400">Role</span>
            <select
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100"
              value={draftRole}
              aria-label="Granted role"
              onChange={(e) => setDraftRole(e.target.value)}
            >
              {GRANTABLE_ROLES.map((role) => (
                <option key={role} value={role}>
                  {role}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm sm:w-48">
            <span className="mb-1 block text-gray-400">Expires</span>
            <input
              type="date"
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100"
              value={draftExpiry}
              aria-label="Expires on"
              onChange={(e) => setDraftExpiry(e.target.value)}
            />
          </label>
          <button
            type="button"
            onClick={() => void grant()}
            disabled={busy || children.length === 0}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
          >
            {busy ? 'Working…' : 'Grant'}
          </button>
        </div>

        <p className="text-xs text-gray-500">
          You can only grant a role you hold yourself. A role above yours is
          refused by the server, and the reason it gives is shown as-is.
        </p>

        {childrenUnavailable ? (
          <p data-testid="delegations-children-unavailable" className="text-xs text-amber-300/80">
            Could not read the tenants you manage, so new grants are
            unavailable on this page load. Existing grants below are
            unaffected, and tenants are shown by id rather than name.
          </p>
        ) : children.length === 0 ? (
          <p className="text-xs text-gray-500">You manage no child tenants, so there is nothing to delegate.</p>
        ) : null}

        {loadError ? (
          <EmptyState title="Could not load delegations" description={loadError} />
        ) : loading ? (
          <EmptyState title="Loading delegations…" description="" />
        ) : delegations.length === 0 ? (
          <EmptyState
            title="No delegations"
            description="Nobody in your organisation holds a standing grant into a managed tenant."
          />
        ) : (
          <div className="overflow-hidden rounded-lg border border-gray-800">
            <table className="w-full text-sm">
              <thead className="bg-gray-900/60 text-xs uppercase tracking-wide text-gray-500">
                <tr>
                  <th className="px-4 py-2 text-left">Tenant</th>
                  <th className="px-4 py-2 text-left">Role</th>
                  <th className="px-4 py-2 text-left">Granted</th>
                  <th className="px-4 py-2 text-left">Expires</th>
                  <th className="px-4 py-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800 bg-gray-950/40">
                {delegations.map((delegation) => (
                  <tr key={delegation.id}>
                    <td className="px-4 py-3 font-medium text-gray-100">
                      {nameFor(delegation.child_tenant_id)}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-300">{delegation.granted_role}</td>
                    <td className="px-4 py-3 text-xs text-gray-400" suppressHydrationWarning>
                      {format(new Date(delegation.created_at), 'PPP')}
                    </td>
                    <td className="px-4 py-3 text-xs" suppressHydrationWarning>
                      {delegation.expires_at ? (
                        <span className="text-gray-400">
                          {format(new Date(delegation.expires_at), 'PPP')}
                        </span>
                      ) : (
                        // Stated rather than dashed: a grant that never
                        // expires is the row an operator is looking for.
                        <span className="text-amber-300">Never</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        type="button"
                        onClick={() => void revoke(delegation)}
                        disabled={busy}
                        className="rounded border border-red-900/60 bg-red-950/40 px-2 py-1 text-xs text-red-300 hover:bg-red-950/70 disabled:opacity-40"
                      >
                        Revoke
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
