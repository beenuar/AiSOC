---
id: users-administration
title: Users administration
sidebar_label: Users administration
---

# Users administration

The **Settings → Users** screen: who is in the tenant, what they hold, and
every control an administrator has over both. Added in v17.1.0.

Only administrators see it — the navigation entry is hidden entirely for
`viewer` and `infosec`, and every route behind it enforces `roles:write`
server-side, so hiding the menu is cosmetics rather than the control.

## The screen

A server-side paginated, searchable, filterable list over
`GET /api/v1/admin/users`. Each row carries the identity, active state,
role pills, and last-activity. From a row an administrator can:

- **Assign roles** — a checkbox modal (multi-role) with a **live
  effective-permissions preview**: it shows the union of permissions the
  selection resolves to *before* you commit, read from the real catalog
  (`GET /api/v1/rbac/roles`), so what you grant is what you saw. A `reason`
  is required and lands verbatim in the audit log. Granting a role you do
  not hold yourself is refused server-side — a granter can only confer
  what it has.
- **Enable / disable** — disabling also revokes the user's sessions, so
  "disabled" means *now*, not "after their token expires".
- **Delete permanently** — guarded three ways: a mandatory reason, a typed
  confirmation of the target's email, and a final confirm. Deleting
  yourself is refused, and so is any write that would leave the tenant
  with no active administrator.

## Delete is audit-safe

A user row can actually be deleted — migration `094` rewrote the one
`RESTRICT` foreign key (`compliance_evidence.collected_by`) to
`ON DELETE SET NULL`, the same retention model every other actor column
already used. The audit row for the deletion snapshots the full identity,
so attribution survives the row: compliance evidence outlives its
collector as "unknown collector" rather than blocking the deletion.

## The role model

| Role | Label | How it is acquired | What it holds |
|---|---|---|---|
| `viewer` | Regular User | SSO JIT default; manual assignment | Read-only across alerts, cases, dashboards, detections, reports. No mutations. |
| `infosec` | Infosec Analyst | Manual assignment or an explicit IdP group mapping | Viewer plus triage, case work, playbook execution, threat-intel and detection writes, lake queries, investigations. No user/role/SSO/settings/credential doors. |
| `admin` | Platform Administrator | Local break-glass (`bootstrap_admin`) or assignment by an existing admin | `*` — everything in the tenant. Unreachable from SSO without an explicit allowlisted group mapping. |

All three are system roles: the console labels them `protected ·
non-deletable` and the API refuses to edit or delete them. The **Roles &
Permissions** screen beside Users edits custom roles against the same
catalog.

Deny-by-default: once a tenant has any role rows, permissions resolve
exclusively from the database (`user_roles → role_permissions →
permissions`); the static map is consulted only during bootstrap, before a
tenant has roles at all.

## How SSO interacts with manual assignment

JIT-provisioned users land as `viewer`. With the default
`group_role_mode: first_login_only`, IdP groups set the role **once**, at
creation — after that, this screen is the source of truth and a manual
change survives every subsequent sign-in. See
[Enterprise SSO](../operations/enterprise-sso.md) for the connection-level
policy (`allowed_email_domains`, `jit_provisioning`, group mapping rules).

## Audit

Every mutation on this surface — role change, enable/disable, delete —
writes a hash-chained audit row with the acting credential, the old and new
state, and the required reason. Since v17.1.0 the audit chain records only
the **verified** principal: a request that fails authentication writes
nothing ([GHSA-w4r8-969c-67p2](https://github.com/beenuar/AiSOC/security/advisories/GHSA-w4r8-969c-67p2)).
