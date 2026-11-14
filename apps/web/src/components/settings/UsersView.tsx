'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import useSWR from 'swr';
import toast from 'react-hot-toast';
import {
  adminUsersApi,
  authApi,
  rbacApi,
  type AdminUserRow,
  type RbacRole,
} from '@/lib/api';

/**
 * Users — admin-only member management with role assignment.
 *
 * Storage is multi-role (`user_roles`), so this screen is multi-select and
 * shows the effective merged permission set live in the edit modal. The
 * server (`/api/v1/admin/users/*`) is the authorization gate: every route
 * requires `roles:write`, refuses the last-admin demotion (409), requires a
 * reason, and revokes the target's sessions on any change.
 */

const PAGE_SIZE = 20;

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

function RoleBadge({ name }: { name: string }) {
  const isAdmin = name === 'admin';
  return (
    <span
      className={
        isAdmin
          ? 'inline-block rounded bg-amber-500/20 px-2 py-0.5 text-xs font-bold uppercase tracking-wide text-amber-300 ring-1 ring-amber-500/40'
          : 'inline-block rounded bg-indigo-500/15 px-2 py-0.5 text-xs font-medium text-indigo-300 ring-1 ring-indigo-500/30'
      }
    >
      {name}
    </span>
  );
}

function StatusBadge({ active }: { active: boolean }) {
  return active ? (
    <span className="inline-flex items-center gap-1 text-xs text-emerald-300">
      <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" /> active
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-xs text-amber-300">
      <span className="h-1.5 w-1.5 rounded-full bg-amber-400" /> disabled
    </span>
  );
}

interface EditRolesModalProps {
  user: AdminUserRow;
  roles: RbacRole[];
  isSelf: boolean;
  onClose: () => void;
  onSaved: () => void;
}

function EditRolesModal({ user, roles, isSelf, onClose, onSaved }: EditRolesModalProps) {
  const [selected, setSelected] = useState<Set<string>>(new Set(user.roles));
  const [reason, setReason] = useState('');
  const [confirmAdmin, setConfirmAdmin] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const grantingAdmin = !user.roles.includes('admin') && selected.has('admin');
  const unchanged =
    selected.size === user.roles.length && user.roles.every((r) => selected.has(r));
  const canSave =
    !saving && !unchanged && selected.size > 0 && reason.trim().length > 0 &&
    user.is_active && (!grantingAdmin || confirmAdmin);

  // Live merged permission preview: union over every selected role.
  const effective = useMemo(() => {
    const names = new Set<string>();
    for (const r of roles) {
      if (selected.has(r.name)) for (const p of r.permissions) names.add(p.name);
    }
    return [...names].sort();
  }, [roles, selected]);

  const toggle = (name: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
    setConfirmAdmin(false);
  };

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      await adminUsersApi.setRoles(user.id, [...selected], reason.trim());
      toast.success(
        `${user.email} → ${[...selected].join(', ')}. Their active sessions were revoked; the new permissions apply on their next sign-in.`,
      );
      onSaved();
    } catch (e) {
      // Safe, human-readable server detail only — never a stack trace.
      const msg = (e as Error).message || 'Role change failed';
      setError(msg);
      toast.error(msg);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-2xl border border-gray-800 bg-gray-900 p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="text-base font-semibold text-gray-100">Edit roles</h3>
        <p className="mt-1 text-sm text-gray-400">
          {user.username || user.email} · {user.email}
          {!user.is_active && (
            <span className="ml-2 rounded bg-amber-500/20 px-1.5 py-0.5 text-[10px] uppercase text-amber-300">
              disabled — assignments refused
            </span>
          )}
        </p>

        {error && (
          <p className="mt-3 rounded-lg border border-red-900/60 bg-red-950/40 px-3 py-2 text-sm text-red-300" role="alert">
            {error}
          </p>
        )}

        <p className="mt-4 text-xs font-semibold uppercase tracking-wide text-gray-500">
          Roles (multi-select — permissions merge)
        </p>
        <div className="mt-1 space-y-1.5">
          {roles.map((r) => (
            <label
              key={r.id}
              className="flex cursor-pointer items-start gap-2 rounded-lg border border-gray-800 bg-gray-950/60 px-3 py-2 hover:border-gray-700"
            >
              <input
                type="checkbox"
                checked={selected.has(r.name)}
                onChange={() => toggle(r.name)}
                disabled={!user.is_active}
                className="mt-0.5 rounded border-gray-600 text-indigo-600"
              />
              <span className="min-w-0">
                <span className="block text-sm text-gray-100">
                  {r.label || r.name}
                  <span className="ml-2 font-mono text-[11px] text-gray-500">{r.name}</span>
                  {r.is_system && (
                    <span className="ml-2 rounded bg-indigo-100/10 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-indigo-300">system</span>
                  )}
                  {r.is_sso_default && (
                    <span className="ml-2 rounded bg-sky-500/20 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-sky-300">SSO default</span>
                  )}
                </span>
                {r.description && <span className="block text-xs text-gray-500">{r.description}</span>}
              </span>
            </label>
          ))}
        </div>

        <p className="mt-4 text-xs font-semibold uppercase tracking-wide text-gray-500">
          Effective permissions — {effective.length} (read-only preview)
        </p>
        <div className="mt-1 max-h-32 overflow-y-auto rounded-lg border border-gray-800 bg-gray-950/80 p-2">
          {effective.length === 0 ? (
            <p className="text-xs italic text-gray-600">Select at least one role.</p>
          ) : (
            <div className="flex flex-wrap gap-1">
              {effective.map((p) => (
                <span key={p} className="rounded bg-gray-800 px-1.5 py-0.5 font-mono text-[10px] text-gray-300">{p}</span>
              ))}
            </div>
          )}
        </div>

        <label className="mt-4 block text-xs font-semibold uppercase tracking-wide text-gray-500" htmlFor="users-role-reason">
          Reason (required, audited)
        </label>
        <textarea
          id="users-role-reason"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          rows={2}
          maxLength={500}
          placeholder="Why are these roles changing? Stored in the audit log with actor, target, old and new roles."
          className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:border-indigo-500 focus:outline-none"
        />

        {grantingAdmin && (
          <label className="mt-3 flex items-start gap-2 rounded-lg border border-amber-800/60 bg-amber-950/30 px-3 py-2 text-sm text-amber-200">
            <input type="checkbox" checked={confirmAdmin} onChange={(e) => setConfirmAdmin(e.target.checked)} className="mt-0.5" />
            <span>
              Granting <strong>admin</strong> confers full control of this workspace — users, roles, SSO and audit.
              Confirm you intend this.
            </span>
          </label>
        )}
        {isSelf && user.roles.includes('admin') && !selected.has('admin') && (
          <p className="mt-3 rounded-lg border border-red-900/60 bg-red-950/40 px-3 py-2 text-sm text-red-300" role="alert">
            You appear to be removing your own admin role. If you are the last active admin the server will refuse
            this with a 409 — promote another admin first.
          </p>
        )}

        <div className="mt-5 flex justify-end gap-3">
          <button type="button" onClick={onClose} className="rounded-lg px-4 py-2 text-sm text-gray-400 hover:bg-gray-800">
            Cancel
          </button>
          <button
            type="button"
            onClick={save}
            disabled={!canSave}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {saving ? 'Saving…' : unchanged ? 'No changes' : `Save ${selected.size} role${selected.size === 1 ? '' : 's'}`}
          </button>
        </div>
      </div>
    </div>
  );
}

export function UsersView() {
  const [search, setSearch] = useState('');
  const [appliedSearch, setAppliedSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [sort, setSort] = useState<'name' | 'email' | 'status' | 'created' | 'last_login'>('created');
  const [order, setOrder] = useState<'asc' | 'desc'>('desc');
  const [offset, setOffset] = useState(0);
  const [editing, setEditing] = useState<AdminUserRow | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const qs = new URLSearchParams();
  if (appliedSearch) qs.set('search', appliedSearch);
  if (roleFilter) qs.set('role', roleFilter);
  if (statusFilter) qs.set('status', statusFilter);
  qs.set('sort', sort);
  qs.set('order', order);
  qs.set('limit', String(PAGE_SIZE));
  qs.set('offset', String(offset));

  const { data, error, mutate, isLoading } = useSWR(
    `admin-users:${qs.toString()}`,
    () => adminUsersApi.listUsers(Object.fromEntries(qs.entries()) as never),
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );

  const { data: roles } = useSWR<RbacRole[]>('api/v1/rbac/roles', () => rbacApi.listRoles(), {
    revalidateOnFocus: false,
    shouldRetryOnError: false,
  });

  const refresh = useCallback(() => { void mutate(); }, [mutate]);

  // Comparing against the signed-in operator's own id so the modal can warn
  // about self-demotion; storage is client-only, hence the effect.
  const [meId, setMeId] = useState<string | null>(null);
  useEffect(() => { setMeId(authApi.currentUser()?.id ?? null); }, []);

  const setStatus = async (u: AdminUserRow, active: boolean) => {
    const verb = active ? 'enable' : 'disable';
    const reason = window.prompt(`Reason to ${verb} ${u.email} (audited):`);
    if (reason === null) return;
    if (!reason.trim()) { toast.error('A reason is required.'); return; }
    setBusyId(u.id);
    try {
      await adminUsersApi.setStatus(u.id, active, reason.trim());
      toast.success(`${u.email} ${active ? 'enabled' : 'disabled'}${active ? '' : ' — cannot log in; role preserved, active sessions revoked.'}`);
      await mutate();
    } catch (e) {
      toast.error((e as Error).message || `Could not ${verb} this member.`);
    } finally {
      setBusyId(null);
    }
  };

  // Triple gate on a destructive, irreversible action: reason + typed
  // email confirmation + explicit final confirm. The server refuses
  // self-deletion and last-admin deletion regardless; the UI just makes
  // an accidental click hard.
  const deleteUser = async (u: AdminUserRow) => {
    if (meId && u.id === meId) {
      toast.error('You cannot delete your own account. Disable it instead.');
      return;
    }
    const reason = window.prompt(`Reason to PERMANENTLY DELETE ${u.email} (audited):`);
    if (reason === null || !reason.trim()) {
      if (reason !== null) toast.error('A reason is required.');
      return;
    }
    const typed = window.prompt(`This removes the account for good (audit history is kept). Type the email to confirm:`);
    if (typed === null) return;
    if (typed.trim().toLowerCase() !== u.email.toLowerCase()) {
      toast.error('Confirmation email did not match. Nothing was deleted.');
      return;
    }
    if (!window.confirm(`Delete ${u.email}? SSO users will be re-provisioned as viewer at next login.`)) return;
    setBusyId(u.id);
    try {
      await adminUsersApi.deleteUser(u.id, reason.trim());
      toast.success(`${u.email} deleted — sessions revoked, audit written.`);
      await mutate();
    } catch (e) {
      toast.error((e as Error).message || 'Could not delete this member.');
    } finally {
      setBusyId(null);
    }
  };

  const rows = data?.items ?? [];
  const total = data?.total ?? 0;
  const failed = Boolean(error) && !data;
  const empty = !failed && !isLoading && rows.length === 0;

  const headerSort = (col: 'name' | 'email' | 'status' | 'created' | 'last_login', label: string) => (
    <button
      type="button"
      className="inline-flex items-center gap-1 text-xs font-semibold uppercase tracking-wide text-gray-500 hover:text-gray-300"
      onClick={() => {
        if (sort === col) setOrder(order === 'asc' ? 'desc' : 'asc');
        else { setSort(col); setOrder('asc'); }
        setOffset(0);
      }}
    >
      {label}
      {sort === col && <span className="text-indigo-400">{order === 'asc' ? '↑' : '↓'}</span>}
    </button>
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <form
          className="flex flex-wrap items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            setAppliedSearch(search.trim());
            setOffset(0);
          }}
        >
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search name or email…"
            className="w-56 rounded-lg border border-gray-700 bg-gray-950 px-3 py-1.5 text-sm text-gray-100 placeholder-gray-600 focus:border-indigo-500 focus:outline-none"
          />
          <select
            value={roleFilter}
            onChange={(e) => { setRoleFilter(e.target.value); setOffset(0); }}
            className="rounded-lg border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
          >
            <option value="">All roles</option>
            {(roles ?? []).map((r) => (
              <option key={r.id} value={r.name}>{r.label || r.name}</option>
            ))}
          </select>
          <select
            value={statusFilter}
            onChange={(e) => { setStatusFilter(e.target.value); setOffset(0); }}
            className="rounded-lg border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
          >
            <option value="">Any status</option>
            <option value="active">Active</option>
            <option value="disabled">Disabled</option>
          </select>
          <button type="submit" className="rounded-lg border border-gray-700 px-3 py-1.5 text-sm text-gray-200 hover:bg-gray-800">
            Search
          </button>
        </form>
        <span className="ml-auto text-xs text-gray-500">{failed ? '' : `${total} member${total === 1 ? '' : 's'}`}</span>
      </div>

      {failed && (
        <div className="rounded-xl border border-red-900/60 bg-red-950/30 px-4 py-6 text-center">
          <p className="text-sm text-red-300">The user list could not be loaded.</p>
          <p className="mt-1 text-[11px] text-gray-500">{(error as Error).message || 'Unknown error'}</p>
          <button type="button" onClick={refresh} className="mt-3 rounded-lg border border-red-800 px-3 py-1.5 text-xs text-red-200 hover:bg-red-900/40">
            Retry
          </button>
        </div>
      )}

      {empty && (
        <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 px-4 py-12 text-center">
          <p className="text-sm text-gray-300">No users match these filters.</p>
          <p className="mt-1 text-[11px] text-gray-600">
            This is an empty result set, not a load failure — the server answered successfully.
          </p>
        </div>
      )}

      {!failed && (
        <div className="overflow-x-auto rounded-xl border border-gray-800/60">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-gray-800 bg-gray-900/70">
              <tr>
                <th className="px-4 py-2.5">{headerSort('name', 'Name')}</th>
                <th className="px-4 py-2.5">{headerSort('email', 'Email')}</th>
                <th className="px-4 py-2.5">{headerSort('status', 'Status')}</th>
                <th className="px-4 py-2.5 text-xs font-semibold uppercase tracking-wide text-gray-500">Role(s)</th>
                <th className="px-4 py-2.5 text-xs font-semibold uppercase tracking-wide text-gray-500">Provider</th>
                <th className="px-4 py-2.5">{headerSort('last_login', 'Last login')}</th>
                <th className="px-4 py-2.5">{headerSort('created', 'Created')}</th>
                <th className="px-4 py-2.5 text-right text-xs font-semibold uppercase tracking-wide text-gray-500">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {isLoading && rows.length === 0 && (
                Array.from({ length: 4 }).map((_, i) => (
                  <tr key={i}>
                    {Array.from({ length: 8 }).map((__, j) => (
                      <td key={j} className="px-4 py-3"><div className="h-4 w-full max-w-28 animate-pulse rounded bg-gray-800/70" /></td>
                    ))}
                  </tr>
                ))
              )}
              {rows.map((u) => (
                <tr key={u.id} className="hover:bg-gray-900/50">
                  <td className="px-4 py-3 text-gray-100">{u.username || '—'}</td>
                  <td className="px-4 py-3 text-gray-300">{u.email}</td>
                  <td className="px-4 py-3"><StatusBadge active={u.is_active} /></td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {(u.roles.length ? u.roles : [u.role]).map((r) => <RoleBadge key={r} name={r} />)}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs uppercase tracking-wide text-gray-400">{u.provider}</td>
                  <td className="px-4 py-3 text-xs text-gray-400">{formatDate(u.last_login)}</td>
                  <td className="px-4 py-3 text-xs text-gray-400">{formatDate(u.created_at)}</td>
                  <td className="px-4 py-3">
                    <div className="flex justify-end gap-2">
                      <button
                        type="button"
                        onClick={() => setEditing(u)}
                        className="rounded-lg border border-gray-700 px-2.5 py-1 text-xs text-gray-200 hover:bg-gray-800"
                      >
                        Edit role
                      </button>
                      {u.is_active ? (
                        <button
                          type="button"
                          disabled={busyId === u.id}
                          onClick={() => setStatus(u, false)}
                          className="rounded-lg border border-amber-800/60 px-2.5 py-1 text-xs text-amber-300 hover:bg-amber-950/40 disabled:opacity-50"
                        >
                          Disable
                        </button>
                      ) : (
                        <button
                          type="button"
                          disabled={busyId === u.id}
                          onClick={() => setStatus(u, true)}
                          className="rounded-lg border border-emerald-800/60 px-2.5 py-1 text-xs text-emerald-300 hover:bg-emerald-950/40 disabled:opacity-50"
                        >
                          Enable
                        </button>
                      )}
                      <button
                        type="button"
                        disabled={busyId === u.id || (meId !== null && u.id === meId)}
                        onClick={() => deleteUser(u)}
                        title={meId !== null && u.id === meId ? 'You cannot delete your own account' : 'Permanently delete this member'}
                        className="rounded-lg border border-red-800/70 px-2.5 py-1 text-xs text-red-300 hover:bg-red-950/50 disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!failed && total > PAGE_SIZE && (
        <div className="flex items-center justify-end gap-3 text-sm text-gray-400">
          <button
            type="button"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            className="rounded-lg border border-gray-700 px-3 py-1.5 hover:bg-gray-800 disabled:opacity-40"
          >
            ← Prev
          </button>
          <span className="text-xs">
            {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}
          </span>
          <button
            type="button"
            disabled={offset + PAGE_SIZE >= total}
            onClick={() => setOffset(offset + PAGE_SIZE)}
            className="rounded-lg border border-gray-700 px-3 py-1.5 hover:bg-gray-800 disabled:opacity-40"
          >
            Next →
          </button>
        </div>
      )}

      {editing && roles && (
        <EditRolesModal
          user={editing}
          roles={roles}
          isSelf={editing.id === meId}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            // Row updates in place via SWR revalidation — no full reload.
            void mutate();
          }}
        />
      )}
    </div>
  );
}
