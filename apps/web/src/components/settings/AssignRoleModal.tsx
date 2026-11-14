'use client';

import { useState } from 'react';
import toast from 'react-hot-toast';
import { rbacApi, type RbacRole, type TenantUser } from '@/lib/api';

interface AssignRoleModalProps {
  user: TenantUser;
  roles: RbacRole[];
  isSelf: boolean;
  adminCount: number;
  onClose: () => void;
  onAssigned: () => void;
}

/**
 * Assign-role modal for one member.
 *
 * Product stance: single primary role. Storage is multi-role capable
 * (`user_roles`), and `POST /api/v1/rbac/users/{id}/roles` exists for it,
 * but the console deliberately assigns exactly one — half-supporting both
 * shapes is how two role columns start disagreeing about who someone is.
 * The chosen role replaces the previous assignment and takes effect on the
 * target's next request; no re-login is required.
 */
export function AssignRoleModal({ user, roles, isSelf, adminCount, onClose, onAssigned }: AssignRoleModalProps) {
  const [selected, setSelected] = useState<string>(user.role);
  const [reason, setReason] = useState('');
  const [confirmAdmin, setConfirmAdmin] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const grantingAdmin = selected === 'admin' && user.role !== 'admin';
  const demotingLastAdmin = isSelf && user.role === 'admin' && selected !== 'admin' && adminCount <= 1;
  const reasonMissing = reason.trim().length === 0;
  const canSave = !saving && !reasonMissing && !demotingLastAdmin && (!grantingAdmin || confirmAdmin) && selected !== user.role;

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const res = await rbacApi.setPrimaryRole(user.id, selected, reason.trim());
      toast.success(`${user.email} is now ${res.role_name} — effective on their next request.`);
      onAssigned();
    } catch (e) {
      const msg = (e as Error).message || 'Role assignment failed';
      setError(msg);
      toast.error(msg);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="w-full max-w-md rounded-2xl border border-gray-800 bg-gray-900 p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="text-base font-semibold text-gray-100">Assign role</h3>
        <p className="mt-1 text-sm text-gray-400">
          {user.username} · {user.email}
          {!user.is_active && <span className="ml-2 rounded bg-amber-500/20 px-1.5 py-0.5 text-[10px] uppercase text-amber-300">disabled — assignments refused</span>}
        </p>

        {error && (
          <p className="mt-3 rounded-lg border border-red-900/60 bg-red-950/40 px-3 py-2 text-sm text-red-300" role="alert">
            {error}
          </p>
        )}

        <label className="mt-4 block text-xs font-semibold uppercase tracking-wide text-gray-500" htmlFor="assign-role-select">
          Role
        </label>
        <select
          id="assign-role-select"
          value={selected}
          onChange={(e) => {
            setSelected(e.target.value);
            setConfirmAdmin(false);
          }}
          disabled={!user.is_active}
          className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 focus:border-indigo-500 focus:outline-none"
        >
          {roles.map((r) => (
            <option key={r.id} value={r.name}>
              {r.name}
              {r.is_sso_default ? ' — SSO default' : ''}
            </option>
          ))}
        </select>
        {roles.find((r) => r.name === selected)?.description && (
          <p className="mt-1.5 text-xs text-gray-500">{roles.find((r) => r.name === selected)?.description}</p>
        )}

        <label className="mt-4 block text-xs font-semibold uppercase tracking-wide text-gray-500" htmlFor="assign-role-reason">
          Reason (required, audited)
        </label>
        <textarea
          id="assign-role-reason"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          rows={2}
          maxLength={500}
          placeholder="Why is this role changing? Stored in the audit log with actor, target, old and new role."
          className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:border-indigo-500 focus:outline-none"
        />

        {grantingAdmin && (
          <label className="mt-3 flex items-start gap-2 rounded-lg border border-amber-800/60 bg-amber-950/30 px-3 py-2 text-sm text-amber-200">
            <input type="checkbox" checked={confirmAdmin} onChange={(e) => setConfirmAdmin(e.target.checked)} className="mt-0.5" />
            <span>
              Granting <strong>admin</strong> confers full control of this workspace, including user, role, SSO and
              audit management. Confirm you intend this.
            </span>
          </label>
        )}
        {demotingLastAdmin && (
          <p className="mt-3 rounded-lg border border-red-900/60 bg-red-950/40 px-3 py-2 text-sm text-red-300" role="alert">
            You are the only active admin. Promote another admin before changing your own role — the server refuses
            this request (409) and the break-glass account is the last door.
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
            {saving ? 'Assigning…' : selected === user.role ? 'Role unchanged' : `Assign ${selected}`}
          </button>
        </div>
      </div>
    </div>
  );
}
