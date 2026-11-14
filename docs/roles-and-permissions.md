# Roles & Permissions

The RBAC model this platform enforces at the API layer, how to assign roles,
and how SSO provisioning interacts with manual assignment.

Actual table/column names used (PostgreSQL):

| Table | Key columns | Notes |
|---|---|---|
| `users` | `id`, `tenant_id`, `email`, `role`, `is_active` | `role` is the legacy string column the JWT/static-map path reads. Kept in sync with `user_roles` on every assignment. |
| `roles` | `id`, `tenant_id`, `name`, `description`, `is_system` | Tenant-scoped. Unique on `(tenant_id, name)`. `is_system = TRUE` blocks edit/delete. |
| `permissions` | `id`, `name`, `description`, `category` | Platform-wide vocabulary. Unique on `name`. Includes `*` (the wildcard the admin role holds). |
| `role_permissions` | `role_id`, `permission_id` | Grants. PK on the pair. |
| `user_roles` | `user_id`, `role_id`, `assigned_at`, `assigned_by` | Assignments. `assigned_by IS NULL` marks system-seeded rows (rollback identifier). |
| `audit_log` | `actor_id`, `actor_email`, `action`, `resource`, `resource_id`, `changes` | Every role change writes a hash-chained row with old role, new role, reason. |

## Role definitions

| Role | Label | Default for | Management rights |
|---|---|---|---|
| `viewer` | Regular User | SSO JIT provisioning (connection `default_role`) | Read-only: alerts, cases, dashboards, detections, reports, connectors, threat intel reads, knowledge base. No mutations. |
| `infosec` | Infosec analyst / incident handler | — | Everything viewer holds plus alert triage (`alerts:write`), case work (`cases:write/assign/note`), playbook execution, threat-intel management, rules/detections writes, lake queries, investigations, report export. **No** user/role/SSO/settings/API-key/audit management. |
| `admin` | Platform administrator | local break-glass only (`bootstrap_admin`) | `*` — every permission in this tenant. |

All three are `is_system = TRUE`: the console shows them as
`protected · non-deletable`, and `PATCH/DELETE /api/v1/rbac/roles/{id}`
refuses them server-side. `viewer` additionally carries the
`SSO default` badge.

Deny-by-default: once a tenant has any `roles` row,
`permission_cache.resolve_permissions` answers exclusively from
`user_roles → role_permissions → permissions`. A permission not granted is
denied. The static `ROLE_PERMISSIONS` map is consulted only while a tenant
has no roles at all (bootstrap).

## Assign a role to a user (step by step, console)

1. Sign in as an admin.
2. **Settings → Workspace → Members** — every member shows their role pill.
3. Click **Assign role** on the target member. (Disabled for your own row
   when you are the only active admin.)
4. Pick the role from the dropdown (preselected to the current role; the
   list comes from `GET /api/v1/rbac/roles`, so it is the real catalog).
5. Fill in the **Reason** field — required, stored verbatim in the audit
   log.
6. If granting `admin`, tick the explicit confirmation box.
7. **Assign**. The row updates immediately; the target's change takes effect
   on their next request — no re-login required.

API equivalent:

```
PUT /api/v1/rbac/users/{user_id}/role
Authorization: Bearer <admin token>
{ "role_name": "infosec", "reason": "night-shift handler from 2026-10-06" }
```

Server behavior: `roles:write` gate (admin only) → target must exist in the
caller's tenant and be active → role name validated against the tenant's
seeded catalog (unknown → 400 naming the valid set) → granter may only
confer permissions they hold → last-admin guard → `user_roles` replaced,
`users.role` mirrored, audit row written, permission-cache version bumped.

Multi-role: assignment is multi-role end to end. `PUT …/role` replaces the
set, `POST …/roles` adds, `DELETE …/roles/{role_id}` removes one, and the
Users console assigns via checkboxes against the live catalog with a
server-computed effective-permissions preview in the same modal. The legacy
`users.role` column mirrors the highest-precedence assigned role so the
JWT/static-map path never disagrees with `user_roles`.

## Users administration (Settings → Users)

Admin-only screen adjacent to Roles & Permissions (hidden entirely from
viewer/infosec in the nav, enforced server-side by `require_permission`).
Server-side pagination, sort, free-text search, and role/status filters —
the list is never client-filtered, so a large tenant cannot leak past the
page window. Columns: name, email, status, role(s), SSO/provider, last
login, created, actions.

Lifecycle actions, all `roles:write`-gated, all audited with a mandatory
`reason`, all revoking the target's active sessions before responding:

| Action | Endpoint | Guards |
|---|---|---|
| List / search | `GET /api/v1/admin/users?q=&role=&status=&sort=&dir=&page=&size=` | admin only; tenant-scoped |
| Detail | `GET /api/v1/admin/users/{id}` | admin only; 404 cross-tenant |
| Replace roles | `PUT /api/v1/admin/users/{id}/roles` | catalog-validated ids; last-admin guard; sessions revoked; cache bumped |
| Add one role | `POST /api/v1/admin/users/{id}/roles` | same |
| Remove one role | `DELETE /api/v1/admin/users/{id}/roles/{role}` | last-admin guard |
| Enable / disable | `PATCH /api/v1/admin/users/{id}` `{"is_active": bool}` | last active admin cannot be disabled; disable revokes sessions |
| Delete (permanent) | `DELETE /api/v1/admin/users/{id}?reason=…` | see below |

Delete semantics: hard delete of the `users` row, audit-safe.
Migration `094_user_delete_fk.sql` rewrites the one RESTRICT edge
(`compliance_evidence.collected_by`) to `ON DELETE SET NULL`; every other
FK already cascades or SET NULLs. The audit row (`admin.users.deleted`)
snapshots the full identity — email, username, roles, provider, reason —
inside its payload, so attribution survives the actor FK going NULL.
Self-deletion → `409`; deleting the last active admin → `409`; missing
reason → `422`. The console gates it three times: reason prompt → typed
email confirmation → final confirm, and the button is disabled on your own
row. A deleted user whose identity still exists at the IdP can be
re-provisioned by JIT on next sign-in — as `viewer`, never higher.

## How default SSO provisioning works

1. The IdP assertion arrives; the tenant comes from the SSO connection row
   (`aisoc_sso_connections`), never from the assertion.
2. Email domain checked against `allowed_email_domains` — outside → denied,
   audited, no local row created.
3. Role resolved: groups → `group_role_mapping` (highest wins), unmapped →
   connection `default_role` (seeded `viewer`), anything outside the
   assignable allow-list → safe warning + `viewer`. `admin`/`platform_admin`
   are unreachable from SSO by construction.
4. First sign-in creates `users` with that role and attaches the matching
   seeded catalog row via `sync_user_catalog_role` (`user_roles`), so a
   JIT user on a database-backed tenant actually holds the permissions the
   catalog says `viewer` holds.
5. `first_login_only` (default mode): on every later sign-in the existing
   `users.role` wins — group sync can neither promote nor demote. Enforced
   in `provision_user`, not just documented: the catalog sync re-affirms
   the stored role, so manual admin assignments survive every SSO login.

## Group-to-role mapping vs manual assignment

- `first_login_only` (default): groups decide the role at provisioning
  **only**. After an admin manually assigns a role, SSO group sync does not
  touch it — verified: `provision_user` short-circuits to `previous_role`
  and the catalog sync attaches exactly that role.
- `authoritative`: groups re-decide on every sign-in, and the catalog
  membership follows in the same call. A stale group can still never grant
  `admin`: `ASSIGNABLE_ROLES` refuses it and the catalog has no such group
  mapping path.

## Last-admin protection

Every door that removes management authority — `PUT /rbac/users/{id}/role`
(demote), `DELETE /rbac/users/{id}/roles/{role_id}` (revoke the admin role
from its last holder), `PATCH /tenants/me/users/{id}` (role or deactive),
`PUT|DELETE /api/v1/admin/users/{id}/roles…` (replace/remove),
`PATCH /api/v1/admin/users/{id}` (disable) and
`DELETE /api/v1/admin/users/{id}` (delete) —
counts active wildcard-role admins in the tenant before writing and answers
`409` with `this is the last active administrator in the tenant; promote
another admin before demoting this one`. The UI disables the control for
your own row when you are that admin. The local break-glass account
(`bootstrap_admin`, role `admin`) is protected by the same rule and keeps
working regardless of SSO state — SSO never mints or removes it.

## Seeding and rollback

Seed (migration, applies automatically on deploy):
`services/api/migrations/092_rbac_catalog_seed.sql` — inserts the
permission vocabulary, the three system roles, their grants, and backfills
`user_roles` for every existing member (role match first, `viewer` for the
rest) **in one transaction**, because a tenant with roles but no memberships
resolves everybody to zero permissions. Re-runnable, no duplicates.

Seed (console/API, idempotent): empty-state button on the Roles screen, or
`POST /api/v1/rbac/roles/seed` (admin). Same code path as the migration's
vocabulary (`app/core/rbac_catalog.py`), also seeds tenants the migration
scope deliberately skips.

Rollback: the commented block at the bottom of the migration deletes exactly
what was seeded (`roles`, their `role_permissions`, and `assigned_by IS NULL`
memberships), returning the tenant to static-map bootstrap. Run it inside
one transaction. Manual assignments re-attach on re-apply through the
`users.role` mirror (every console assignment mirrors the column), and FK
CASCADE means removing a role removes its memberships — verified round trip:
rollback → 0/0/0, re-apply → 3 roles / 38 grants / correct memberships.

## Verification performed on the live stack (2026-10-05)

- `roles`: viewer/infosec/admin present (`is_system=TRUE`); `permissions`:
  61; `role_permissions`: 38; memberships backfilled.
- viewer: 403 on `PATCH /alerts/{id}`, `PATCH /cases/{id}`,
  `GET /rbac/roles`, `PUT /rbac/users/{id}/role`, `GET /tenants/me/users`.
- admin: `GET /rbac/roles` 200 with per-role `user_count`; round trip
  viewer→infosec→viewer persists; audit rows carry actor/target/old/new/
  reason; zero secret material in `changes`.
- Promotion takes effect on the **same** pre-minted token (no re-login):
  viewer token `PATCH alert` 403 → after admin assigns `infosec` → 200.
- `infosec` calling `PUT /rbac/users/{id}/role` → 403.
- Unknown role name → 400 naming the valid set (not 500).
- Last-admin demotion → 409.
- Delete matrix: create 200 · self-delete 409 · missing reason 422 ·
  viewer token 401 (fail-closed) · delete 204 · re-GET 404 · row and
  `user_roles` rows gone · audit row `admin.users.deleted` with full
  identity snapshot. Console chunk contains the triple-confirm Delete flow.
