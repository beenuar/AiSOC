'use client';

import { useState } from 'react';
import useSWR from 'swr';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';
import { demoFallback } from '@/lib/demoFallback';
import { FailureBanner } from '@/components/ui/FailureBanner';
import { describeApiFailure } from '@/lib/failure';
import { authedFetcher, rbacApi, type RbacRole } from '@/lib/api';
import toast from 'react-hot-toast';

interface Permission {
  id: string;
  name: string;
  description: string | null;
  category: string | null;
}

type Role = RbacRole;


// Throws `ApiError`, so the banner below can tell a 403 (this operator cannot
// read roles) from a 500 (the API is broken) from a 422 (the console is).

const CATEGORY_COLORS: Record<string, string> = {
  cases: 'bg-blue-500/20 text-blue-300',
  alerts: 'bg-red-500/20 text-red-300',
  playbooks: 'bg-purple-500/20 text-purple-300',
  detections: 'bg-orange-500/20 text-orange-300',
  connectors: 'bg-teal-500/20 text-teal-300',
  api_keys: 'bg-yellow-500/20 text-yellow-300',
  audit: 'bg-gray-500/20 text-gray-300',
  compliance: 'bg-green-500/20 text-green-300',
  admin: 'bg-pink-500/20 text-pink-300',
};

function PermissionBadge({ perm }: { perm: Permission }) {
  const cls = CATEGORY_COLORS[perm.category ?? ''] ?? 'bg-gray-500/20 text-gray-300';
  return (
    <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${cls}`} title={perm.description ?? ''}>
      {perm.name}
    </span>
  );
}

function RoleCard({ role, onEdit, onDelete }: { role: Role; onEdit: (r: Role) => void; onDelete: (r: Role) => void }) {
  return (
    <div className="rounded-xl border border-gray-800/60 bg-gray-900/60 p-5">
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-base font-semibold text-gray-100">{role.label || role.name}</span>
            {role.label && <span className="font-mono text-xs text-gray-500">{role.name}</span>}
            {role.is_system && (
              <span className="rounded bg-indigo-100 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-indigo-700">
                system
              </span>
            )}
          </div>
          {role.description && <p className="mt-0.5 text-sm text-gray-400">{role.description}</p>}
        </div>
        {!role.is_system && (
          <div className="flex shrink-0 gap-2">
            <button
              onClick={() => onEdit(role)}
              className="rounded px-2 py-1 text-xs text-gray-400 hover:bg-gray-800"
            >
              Edit
            </button>
            <button
              onClick={() => onDelete(role)}
              className="rounded px-2 py-1 text-xs text-red-400 hover:bg-red-900/30"
            >
              Delete
            </button>
          </div>
        )}
      </div>
      <div className="mt-3 flex items-center gap-3 text-xs text-gray-400">
        <span title="Users holding this role in this workspace">
          {role.user_count} user{role.user_count === 1 ? '' : 's'}
        </span>
        {role.is_sso_default && (
          <span className="rounded bg-sky-500/20 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-sky-300" title="New SSO sign-ins are provisioned with this role">
            SSO default · protected
          </span>
        )}
        {role.is_system && !role.is_sso_default && (
          <span className="rounded bg-gray-700/60 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-gray-300">
            protected · non-deletable
          </span>
        )}
      </div>
      {(() => {
        const byCat = new Map<string, Permission[]>();
        for (const p of role.permissions) {
          const cat = p.category ?? 'other';
          (byCat.get(cat) ?? byCat.set(cat, []).get(cat)!).push(p);
        }
        return role.permissions.length === 0 ? (
          <p className="mt-3 text-xs italic text-gray-600">No permissions assigned</p>
        ) : (
          <div className="mt-3 space-y-2">
            {[...byCat.entries()].sort().map(([cat, perms]) => (
              <div key={cat}>
                <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-gray-500">{cat}</p>
                <div className="flex flex-wrap gap-1.5">
                  {perms.map((p) => <PermissionBadge key={p.id} perm={p} />)}
                </div>
              </div>
            ))}
          </div>
        );
      })()}
    </div>
  );
}

interface RoleFormProps {
  allPermissions: Permission[];
  initial?: Role;
  onClose: () => void;
}

function RoleForm({ allPermissions, initial, onClose }: RoleFormProps) {
  const [name, setName] = useState(initial?.name ?? '');
  const [label, setLabel] = useState(initial?.label ?? initial?.name ?? '');
  const [description, setDescription] = useState(initial?.description ?? '');
  const [selectedNames, setSelectedNames] = useState<Set<string>>(
    new Set(initial?.permissions.map((p) => p.name) ?? [])
  );
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const categories = Array.from(new Set(allPermissions.map((p) => p.category ?? 'other'))).sort();

  const toggle = (pname: string) => {
    setSelectedNames((prev) => {
      const next = new Set(prev);
      if (next.has(pname)) next.delete(pname);
      else next.add(pname);
      return next;
    });
  };

  const save = async () => {
    if (!name.trim()) { setError('Name is required'); return; }
    setSaving(true);
    setError(null);
    try {
      // permission_names: every key is validated server-side against the
      // vocabulary; an unknown key returns a 400 that names it and lists
      // the valid set — never a silently dropped grant.
      if (initial) {
        await rbacApi.updateRole(initial.id, {
          label: label.trim() || initial.name,
          description: description || null,
          permission_names: [...selectedNames],
        });
        toast.success(`Role ${initial.name} updated — effective immediately for its ${initial.user_count} member(s).`);
      } else {
        await rbacApi.createRole({
          name: name.trim(),
          label: label.trim() || name.trim(),
          description: description || null,
          permission_names: [...selectedNames],
        });
        toast.success(`Role ${name.trim()} created.`);
      }
      onClose();
    } catch (e) {
      setError((e as Error).message || 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl bg-white shadow-2xl">
        <div className="flex items-center justify-between border-b px-6 py-4">
          <h2 className="text-lg font-semibold">{initial ? `Edit Role — ${initial.name}` : 'Create Role'}</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-700">✕</button>
        </div>
        <div className="space-y-4 px-6 py-4">
          {error && <p className="rounded bg-red-50 px-3 py-2 text-sm text-red-700" role="alert">{error}</p>}
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">Name (machine id, immutable)</label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              readOnly={Boolean(initial)}
              className="w-full rounded-lg border px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 read-only:bg-gray-100 read-only:text-gray-500"
              placeholder="e.g. threat-hunter"
            />
            <p className="mt-1 text-xs text-gray-500">
              {initial
                ? 'The machine name reaches tokens, audit records and URLs — it cannot be renamed. Edit the display label instead.'
                : 'Lowercase slug: letters, digits and dashes (e.g. threat-hunter). Reserved names (admin, viewer, infosec…) are refused.'}
            </p>
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">Display label</label>
            <input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              className="w-full rounded-lg border px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
              placeholder="e.g. Threat Hunter"
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">Description</label>
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full rounded-lg border px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
              placeholder="Optional description"
            />
          </div>
          <div>
            <label className="mb-2 block text-sm font-medium text-gray-700">
              Permissions ({selectedNames.size} selected)
            </label>
            <div className="max-h-64 space-y-3 overflow-y-auto rounded-lg border p-3">
              {categories.map((cat) => (
                <div key={cat}>
                  <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500">{cat}</p>
                  <div className="flex flex-wrap gap-2">
                    {allPermissions
                      .filter((p) => (p.category ?? 'other') === cat)
                      .map((perm) => (
                        <label key={perm.name} className="flex cursor-pointer items-center gap-1.5" title={perm.description ?? ''}>
                          <input
                            type="checkbox"
                            checked={selectedNames.has(perm.name)}
                            onChange={() => toggle(perm.name)}
                            className="rounded border-gray-300 text-indigo-600"
                          />
                          <span className="text-xs text-gray-700">{perm.name}</span>
                        </label>
                      ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-3 border-t px-6 py-4">
          <button onClick={onClose} className="rounded-lg px-4 py-2 text-sm text-gray-600 hover:bg-gray-100">
            Cancel
          </button>
          <button
            onClick={save}
            disabled={saving}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50"
          >
            {saving ? 'Saving…' : initial ? 'Save changes' : 'Create role'}
          </button>
        </div>
      </div>
    </div>
  );
}

const MOCK_PERMISSIONS: Permission[] = [
  { id: 'p1', name: 'alerts.read', description: 'View alerts', category: 'alerts' },
  { id: 'p2', name: 'alerts.write', description: 'Update alert status', category: 'alerts' },
  { id: 'p3', name: 'cases.read', description: 'View cases', category: 'cases' },
  { id: 'p4', name: 'cases.write', description: 'Create and edit cases', category: 'cases' },
  { id: 'p5', name: 'playbooks.read', description: 'View playbooks', category: 'playbooks' },
  { id: 'p6', name: 'playbooks.execute', description: 'Run playbooks', category: 'playbooks' },
  { id: 'p7', name: 'detections.read', description: 'View detection rules', category: 'detections' },
  { id: 'p8', name: 'detections.write', description: 'Manage detection rules', category: 'detections' },
  { id: 'p9', name: 'connectors.read', description: 'View connectors', category: 'connectors' },
  { id: 'p10', name: 'connectors.write', description: 'Manage connectors', category: 'connectors' },
  { id: 'p11', name: 'admin.settings', description: 'Manage settings', category: 'admin' },
  { id: 'p12', name: 'audit.read', description: 'View audit logs', category: 'audit' },
];

const MOCK_ROLES: Role[] = [
  {
    id: 'role-1', tenant_id: 'default', name: 'SOC Analyst', description: 'Front-line analyst with read access to alerts, cases, and playbooks',
    is_system: true,
    user_count: 0,
    is_sso_default: false,
    permissions: MOCK_PERMISSIONS.filter((p) => ['p1', 'p3', 'p5', 'p7', 'p9', 'p12'].includes(p.id)),
  },
  {
    id: 'role-2', tenant_id: 'default', name: 'SOC Lead', description: 'Senior analyst with write access and playbook execution',
    is_system: true,
    user_count: 0,
    is_sso_default: false,
    permissions: MOCK_PERMISSIONS.filter((p) => ['p1', 'p2', 'p3', 'p4', 'p5', 'p6', 'p7', 'p9', 'p12'].includes(p.id)),
  },
  {
    id: 'role-3', tenant_id: 'default', name: 'Admin', description: 'Full access to all features and settings',
    is_system: true,
    user_count: 0,
    is_sso_default: false,
    permissions: MOCK_PERMISSIONS,
  },
  {
    id: 'role-4', tenant_id: 'default', name: 'Detection Engineer', description: 'Manages detection rules and connector integrations',
    is_system: false,
    user_count: 0,
    is_sso_default: false,
    permissions: MOCK_PERMISSIONS.filter((p) => ['p1', 'p7', 'p8', 'p9', 'p10'].includes(p.id)),
  },
];

export function RBACView() {
  const {
    data: roles,
    error: rolesError,
    mutate: reloadRoles,
  } = useSWR<Role[]>('/api/v1/rbac/roles', authedFetcher, {
    fallbackData: demoFallback(MOCK_ROLES),
  });
  const { data: permissions } = useSWR<Permission[]>('/api/v1/rbac/permissions', authedFetcher, {
    fallbackData: demoFallback(MOCK_PERMISSIONS),
  });

  const [showCreate, setShowCreate] = useState(false);
  const [editingRole, setEditingRole] = useState<Role | null>(null);
  const [seeding, setSeeding] = useState(false);
  const [seedMsg, setSeedMsg] = useState<string | null>(null);

  // `roles:read` owns this screen server-side; a 403 means the operator is
  // not a platform admin. The management controls hide themselves rather
  // than rendering and failing — the server is the gate, the UI is just
  // honest about what the gate already answered.
  const rolesStatus = (rolesError as { status?: number } | undefined)?.status;
  const isAdmin = rolesStatus !== 403 && rolesStatus !== 401;

  const handleSeed = async () => {
    setSeeding(true);
    setSeedMsg(null);
    try {
      const res = await rbacApi.seedRoles();
      setSeedMsg(`Catalog seeded: ${res.roles} roles, ${res.permissions} permissions, ${res.user_roles} memberships.`);
      await reloadRoles();
    } catch (e) {
      setSeedMsg(`Seeding failed: ${(e as Error).message}`);
    } finally {
      setSeeding(false);
    }
  };

  const handleDelete = async (role: Role) => {
    if (!confirm(`Delete role "${role.label || role.name}"? This cannot be undone.`)) return;
    try {
      await rbacApi.deleteRole(role.id);
      toast.success(`Role ${role.name} deleted.`);
      await reloadRoles();
    } catch (e) {
      // 409 = still assigned (the server names the count); 403 = system role.
      toast.error((e as Error).message || 'Delete failed');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-100">Roles & Permissions</h2>
          <p className="mt-0.5 text-sm text-gray-500">Manage access control for your organization.</p>
        </div>
        {isAdmin && (
          <button
            onClick={() => setShowCreate(true)}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700"
          >
            + New Role
          </button>
        )}
      </div>

      {/* `roles` is `undefined` on failure outside the hosted demo, which
          suppressed both the skeleton below and the empty state under it — so
          "showing demo roles" was, literally, the only thing on the page. */}
      {rolesError && (
        <>
          <FailureBanner
            title="Roles unavailable"
            message={describeApiFailure(rolesError, { subject: 'role list' })}
            onRetry={() => reloadRoles()}
          />
          <div className="flex flex-col items-center justify-center gap-1 rounded-xl border border-gray-800/60 bg-gray-900/40 px-4 py-12 text-center">
            <p className="text-sm text-amber-200/80">The role list could not be loaded.</p>
            <p className="text-[11px] text-gray-600">
              Treat this as unknown rather than as a tenant with no roles defined.
            </p>
          </div>
        </>
      )}

      {!roles && !rolesError && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-32 animate-pulse rounded-xl bg-gray-800/60" />
          ))}
        </div>
      )}

      {roles && roles.length === 0 && (
        <EmptyState
          icon={EmptyStateIcons.shield}
          title="No roles defined yet"
          description="Seed the standard catalog (viewer, infosec, admin) with its permissions, or create a custom role. Seeding is idempotent and backfills existing members' memberships so nobody loses access."
          action={
            isAdmin ? (
              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={handleSeed}
                  disabled={seeding}
                  className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 transition-colors disabled:opacity-50"
                >
                  {seeding ? 'Seeding…' : 'Seed roles'}
                </button>
                <button
                  type="button"
                  onClick={() => setShowCreate(true)}
                  className="rounded-lg border border-gray-700 px-4 py-2 text-sm font-medium text-gray-200 hover:bg-gray-800 transition-colors"
                >
                  + New Role
                </button>
              </div>
            ) : undefined
          }
        />
      )}

      {seedMsg && (
        <p className="rounded-lg border border-indigo-800/60 bg-indigo-950/40 px-4 py-2 text-sm text-indigo-200">{seedMsg}</p>
      )}

      {roles && roles.length > 0 && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {roles.map((role) => (
            <RoleCard
              key={role.id}
              role={role}
              onEdit={isAdmin ? (r) => setEditingRole(r) : () => undefined}
              onDelete={isAdmin ? handleDelete : () => undefined}
            />
          ))}
        </div>
      )}

      {isAdmin && (showCreate || editingRole) && permissions && (
        <RoleForm
          allPermissions={permissions}
          initial={editingRole ?? undefined}
          onClose={() => {
            setShowCreate(false);
            setEditingRole(null);
          }}
        />
      )}
    </div>
  );
}
